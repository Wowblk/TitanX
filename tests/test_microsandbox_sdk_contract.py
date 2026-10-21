"""Keep the microsandbox test fakes honest against the installed SDK.

``tests/test_microsandbox_backend.py`` injects a fake ``microsandbox`` module
so the suite never boots a microVM. Nothing else checks that fake against the
real package, so an SDK rename could leave those tests green while
``MicrosandboxSandboxBackend`` breaks.

This module imports the installed SDK (the project depends on
``microsandbox>=0.7.0,<0.8``; CI resolves that to 0.7.8 today) and checks
every call the backend actually makes:

* the attribute exists on the real SDK;
* async versus sync matches the fake and matches whether the backend awaits
  the call;
* the parameters the backend passes bind with ``inspect.Signature.bind``;
* every named parameter on the fake is an explicit parameter of that
  signature (a fake may omit unused optionals and may use ``**kwargs`` to
  record calls; it may not invent names);
* return attributes the backend reads exist on the SDK type and on the
  object the fake returns.

PyO3 publishes a lossy ``__text_signature__`` for ``Sandbox.create`` and
``Sandbox.restore`` (``**kwargs``) and ``inspect.iscoroutinefunction`` is
false for its async methods. The complete signature and the async flag come
from the ``_microsandbox.pyi`` stub shipped in the same wheel. Where the
runtime signature is fully explicit, it has to match that stub.
``Stdin`` and ``Network`` are ordinary Python classes, so
``inspect.signature`` on the live object is the contract.

No microsandbox server, network call, or microVM is started. SDK methods are
not invoked; ``Network.none`` is a pure constructor used only so the
``network=`` value is the object the backend really passes.

The empty module installed by ``tests/test_factory_backend_options.py`` only
has to be importable (``is_available``). Router and factory stubs implement
``SandboxBackend``, not the SDK. Those are outside this contract.

Extending the contract
----------------------
When the backend starts calling a new SDK method:

1. ``test_every_backend_sdk_call_is_registered`` fails with the source call
   id (for example ``sbx.kill``) and the line number.
2. Add a ``SURFACES`` entry for that call. Point it at the real class and
   method, and at the fake that stands in for it. The fake must be async
   exactly when the SDK method is, and every parameter name it declares must
   exist on the real signature.
3. Samples are built from the call as written. A new keyword is picked up
   automatically. A ``**splat`` is not: teach ``_samples`` how those keys are
   built. ``Sandbox.create`` is the existing case (image / cpus / memory /
   network / detached).
4. A new ``result.<attr>`` read, or ``getattr(snap, "<attr>")``, fails
   ``test_return_attributes_match_the_sdk_and_the_fakes`` until the attribute
   is added to ``_RETURN_READS`` and to the object the fake returns.
5. A new ``except`` handler fails
   ``test_backend_exception_handlers_do_not_name_sdk_types``. Handlers today
   are the builtins ``Exception`` and ``ImportError``. An SDK exception class
   has to be pinned on ``microsandbox`` and raised by the fake if a test
   needs it.
"""

from __future__ import annotations

import ast
import functools
import importlib.metadata
import inspect
from dataclasses import dataclass
from pathlib import Path

import pytest

import microsandbox
from tests.test_microsandbox_backend import (
    _FakeSandboxFactory,
    _Network,
    _RecordingFs,
    _RecordingSandbox,
    _Stdin,
)
from titanx.sandbox.backends.microsandbox import (
    MicrosandboxSandboxBackend,
    MicrosandboxSandboxBackendOptions,
)

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND_PATH = _ROOT / "titanx" / "sandbox" / "backends" / "microsandbox.py"
_STUB_PATH = Path(microsandbox.__file__).resolve().parent / "_microsandbox.pyi"

_VAR_KINDS = {inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL}
_POSITIONAL_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
}

# Attributes the backend reads off SDK return values. ``result`` is the
# ``Sandbox.exec`` return (``ExecOutput``). ``snap`` is the
# ``SandboxHandle.snapshot`` return (``Snapshot``); the backend probes it
# with ``getattr``.
_RETURN_READS = {
    "result": frozenset({"exit_code", "stdout_text", "stderr_text"}),
    "snap": frozenset({"reference", "id"}),
}
_RETURN_TYPES = {
    "result": microsandbox.ExecOutput,
    "snap": microsandbox.Snapshot,
}


@dataclass(frozen=True)
class Surface:
    """One backend call and the fake that stands in for it."""

    owner: str
    method: str
    fake_cls: type
    fake_method: str


@dataclass(frozen=True)
class Site:
    line: int
    nargs: int
    keywords: frozenset[str]
    splats: tuple[str, ...]
    awaited: bool


# Keys are how the call is written in microsandbox.py. ``sbx.fs.read`` is
# the ``read`` method of the object ``Sandbox.fs`` returns.
SURFACES = {
    "Network.none": Surface("Network", "none", _Network, "none"),
    "Sandbox.create": Surface("Sandbox", "create", _FakeSandboxFactory, "create"),
    "Stdin.bytes": Surface("Stdin", "bytes", _Stdin, "bytes"),
    "sbx.exec": Surface("Sandbox", "exec", _RecordingSandbox, "exec"),
    "sbx.stop": Surface("Sandbox", "stop", _RecordingSandbox, "stop"),
    "sbx.fs.write": Surface("SandboxFsOps", "write", _RecordingFs, "write"),
    "sbx.fs.read": Surface("SandboxFsOps", "read", _RecordingFs, "read"),
    "Sandbox.get": Surface("Sandbox", "get", _FakeSandboxFactory, "get"),
    "handle.snapshot": Surface("SandboxHandle", "snapshot", _RecordingSandbox, "snapshot"),
    "Sandbox.restore": Surface("Sandbox", "restore", _FakeSandboxFactory, "restore"),
}


def test_installed_sdk_matches_the_project_pin():
    # ``pip install -e ".[dev]"`` installs this dependency; it is not an extra.
    pyproject = (_ROOT / "pyproject.toml").read_text()
    assert 'microsandbox>=0.7.0,<0.8' in pyproject
    installed = importlib.metadata.version("microsandbox")
    major, minor = (int(part) for part in installed.split(".")[:2])
    assert (major, minor) == (0, 7), installed


def test_every_backend_sdk_call_is_registered():
    discovered = _discover_calls()
    missing = set(discovered) - set(SURFACES)
    stale = set(SURFACES) - set(discovered)
    detail = {
        call_id: [site.line for site in discovered[call_id]] for call_id in sorted(missing)
    }
    assert not missing and not stale, (
        "SDK call set drifted from SURFACES. "
        f"Add entries for {detail}; remove stale {sorted(stale)}. "
        "See the module docstring for how to extend the contract."
    )


# Builtin handlers only. ``Exception`` wraps SDK failures from ``execute`` and
# ``stop``. ``ImportError`` is ``is_available`` when the package is missing.
# Neither name is a microsandbox exception class.
_BUILTIN_EXCEPTION_HANDLERS = frozenset({"Exception", "ImportError"})


def test_backend_exception_handlers_do_not_name_sdk_types():
    found = set()
    for node in ast.walk(_backend_tree()):
        if isinstance(node, ast.ExceptHandler):
            found.add("bare" if node.type is None else ast.unparse(node.type))
    sdk_errors = {name for name in dir(microsandbox.errors) if not name.startswith("_")}
    assert found.isdisjoint(sdk_errors), (
        "the backend now catches an SDK exception; pin that class on the "
        f"installed package and on the fake. Found: {sorted(found & sdk_errors)}"
    )
    assert found == _BUILTIN_EXCEPTION_HANDLERS, (
        "the backend's except handlers changed. Update this contract. "
        f"Found: {sorted(found)}"
    )


@pytest.mark.parametrize("call_id", list(SURFACES))
def test_fake_matches_sdk_and_backend_calls_bind(call_id: str):
    surface = SURFACES[call_id]
    sites = _discover_calls()[call_id]
    owner = getattr(microsandbox, surface.owner)
    signature, is_async = _resolve(owner, surface.method)

    if not hasattr(surface.fake_cls, surface.fake_method):
        raise AssertionError(
            f"{surface.fake_cls.__name__} has no {surface.fake_method}; "
            f"the backend calls {call_id}"
        )
    fake = getattr(surface.fake_cls, surface.fake_method)
    fake_async = inspect.iscoroutinefunction(fake)
    if fake_async is not is_async:
        raise AssertionError(
            f"{surface.fake_cls.__name__}.{surface.fake_method} is "
            f"{'async' if fake_async else 'synchronous'} but "
            f"{surface.owner}.{surface.method} is "
            f"{'async' if is_async else 'synchronous'}"
        )
    fake_signature = _drop_self(inspect.signature(fake))
    _assert_fake_params(fake_signature, signature, call_id)

    if call_id.startswith("sbx.fs."):
        # ``sbx.fs.read`` / ``write`` are methods of the filesystem object,
        # not of ``Sandbox`` itself. The instance the fake returns has to
        # carry that object.
        assert inspect.isdatadescriptor(inspect.getattr_static(microsandbox.Sandbox, "fs"))
        assert isinstance(_RecordingSandbox().fs, _RecordingFs)

    for site in sites:
        if site.awaited is not is_async:
            how = "awaited" if site.awaited else "called without await"
            kind = "async" if is_async else "synchronous"
            raise AssertionError(
                f"{_BACKEND_PATH.name}:{site.line} {call_id} is {how} but "
                f"{surface.owner}.{surface.method} is {kind}"
            )

    for args, kwargs in _samples(call_id, sites):
        _bind(signature, args, kwargs, f"SDK {surface.owner}.{surface.method}")
        _bind(
            fake_signature,
            args,
            kwargs,
            f"fake {surface.fake_cls.__name__}.{surface.fake_method}",
        )


@pytest.mark.parametrize(
    ("owner_name", "method", "args", "kwargs"),
    [
        ("Sandbox", "create", (), {"name": "titanx-contract", "image": "python"}),
        ("Sandbox", "restore", ("snap-id",), {"name": "titanx-restored"}),
    ],
)
def test_resolved_signature_rejects_unknown_keywords(owner_name, method, args, kwargs):
    # create/restore's PyO3 text signature ends in ``**kwargs``. Binding
    # against that would stay green if the backend renamed a keyword.
    signature, _is_async = _resolve(getattr(microsandbox, owner_name), method)
    assert not any(
        param.kind is inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values()
    )
    with pytest.raises(TypeError):
        signature.bind(*args, **kwargs, not_a_real_parameter=True)


async def test_return_attributes_match_the_sdk_and_the_fakes():
    discovered = _return_reads()
    assert discovered == _RETURN_READS, (
        "the backend reads a different set of SDK attributes; update "
        f"_RETURN_READS and the fake return values. Found {discovered}"
    )
    for base, attrs in _RETURN_READS.items():
        sdk_type = _RETURN_TYPES[base]
        for attr in attrs:
            static = inspect.getattr_static(sdk_type, attr)
            assert inspect.isdatadescriptor(static), (
                f"{sdk_type.__name__}.{attr} is not a data attribute"
            )
            assert not callable(static)

    produced = await _fake_return_values()
    for base, attrs in _RETURN_READS.items():
        value = produced[base]
        for attr in attrs:
            assert hasattr(value, attr), f"fake {base} return has no {attr}"
            assert not callable(getattr(value, attr))


def _bind(signature: inspect.Signature, args: tuple, kwargs: dict, label: str) -> None:
    try:
        signature.bind(*args, **kwargs)
    except TypeError as exc:
        raise AssertionError(
            f"{label} signature {signature} rejected positional={args!r} "
            f"keyword={sorted(kwargs)}: {exc}"
        ) from exc


def _assert_fake_params(fake_sig: inspect.Signature, real_sig: inspect.Signature, label: str) -> None:
    real_params = real_sig.parameters
    for name, param in fake_sig.parameters.items():
        if param.kind in _VAR_KINDS:
            continue
        real = real_params.get(name)
        if real is None or real.kind in _VAR_KINDS:
            raise AssertionError(
                f"{label}: fake parameter {name!r} is not an explicit parameter "
                f"of the SDK signature {real_sig}"
            )
        if param.kind in _POSITIONAL_KINDS and real.kind not in _POSITIONAL_KINDS:
            raise AssertionError(
                f"{label}: fake accepts {name!r} positionally but the SDK "
                f"declares it {real.kind.description}"
            )


def _samples(call_id: str, sites: tuple[Site, ...]) -> list[tuple[tuple, dict]]:
    if call_id == "Sandbox.create":
        for site in sites:
            assert site.nargs == 0, site
            assert site.splats == ("kwargs",), site
            assert "name" in site.keywords, site
            unexpected = site.keywords - {"name", "detached"}
            assert not unexpected, (
                f"{_BACKEND_PATH.name}:{site.line} passes {sorted(unexpected)} "
                "to Sandbox.create; add them to the create samples"
            )
        calls = _create_kwargs_matrix()
        live = set().union(*(call.keys() for call in calls))
        source = _create_source_keys()
        assert live == source, (
            "Sandbox.create keys drifted. "
            f"Source builds {sorted(source)}; samples bind {sorted(live)}."
        )
        return [((), call) for call in calls]

    samples = []
    for site in sites:
        assert site.splats == (), (
            f"{_BACKEND_PATH.name}:{site.line} {call_id} splats **{site.splats}; "
            "teach _samples how those keys are built"
        )
        samples.append(((None,) * site.nargs, {name: None for name in site.keywords}))
    return samples


def _create_kwargs_matrix() -> list[dict]:
    """Every create-kwarg combination the backend can actually pass.

    ``cpus`` / ``memory`` are sent only when the option is set. ``network``
    is sent only when networking is left off (``Network.none()``).
    ``detached`` is sent for session create and ``create_session``, and
    omitted for the long-lived session-less microVM.
    """
    calls = []
    for cpus in (None, 1):
        for memory in (None, 128):
            for network_enabled in (False, True):
                for detached in (False, True):
                    backend = MicrosandboxSandboxBackend(
                        MicrosandboxSandboxBackendOptions(
                            image="python",
                            cpus=cpus,
                            memory=memory,
                            network_enabled=network_enabled,
                        )
                    )
                    kwargs = {
                        "name": "titanx-contract",
                        **backend._image_kwargs(),
                        **backend._network_kwargs(),
                    }
                    if detached:
                        kwargs["detached"] = True
                    calls.append(kwargs)
    return calls


def _create_source_keys() -> set[str]:
    tree = _backend_tree()
    keys = set()
    keys |= _literal_keys(_function(tree, "_image_kwargs"))
    keys |= _literal_keys(_function(tree, "_network_kwargs"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name)
            and node.value.id == "kwargs"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)
    for site in _discover_calls()["Sandbox.create"]:
        keys |= set(site.keywords)
    return keys


def _literal_keys(fn: ast.AST) -> set[str]:
    keys = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.add(key.value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            keys.add(node.slice.value)
    return keys


@functools.lru_cache(maxsize=1)
def _backend_tree() -> ast.AST:
    tree = ast.parse(_BACKEND_PATH.read_text())
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node  # type: ignore[attr-defined]
    return tree


@functools.lru_cache(maxsize=1)
def _discover_calls() -> dict[str, tuple[Site, ...]]:
    found: dict[str, list[Site]] = {}
    for node in ast.walk(_backend_tree()):
        if not isinstance(node, ast.Call):
            continue
        call_id = _call_id(node.func)
        if call_id is None:
            continue
        keywords: list[str] = []
        splats: list[str] = []
        for keyword in node.keywords:
            if keyword.arg is None:
                if not isinstance(keyword.value, ast.Name):
                    raise AssertionError(
                        f"{_BACKEND_PATH.name}:{node.lineno} has a non-name splat"
                    )
                splats.append(keyword.value.id)
            else:
                keywords.append(keyword.arg)
        found.setdefault(call_id, []).append(
            Site(
                line=node.lineno,
                nargs=len(node.args),
                keywords=frozenset(keywords),
                splats=tuple(splats),
                awaited=isinstance(getattr(node, "_parent", None), ast.Await),
            )
        )
    return {call_id: tuple(sites) for call_id, sites in found.items()}


def _call_id(func: ast.AST) -> str | None:
    if not isinstance(func, ast.Attribute):
        return None
    base = func.value
    if isinstance(base, ast.Name) and base.id in {"Sandbox", "Stdin", "Network", "sbx", "handle"}:
        return f"{base.id}.{func.attr}"
    if (
        isinstance(base, ast.Attribute)
        and isinstance(base.value, ast.Name)
        and base.value.id == "sbx"
        and base.attr == "fs"
    ):
        return f"sbx.fs.{func.attr}"
    return None


def _return_reads() -> dict[str, frozenset[str]]:
    found: dict[str, set[str]] = {}
    for node in ast.walk(_backend_tree()):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name)
            and node.value.id in _RETURN_READS
        ):
            found.setdefault(node.value.id, set()).add(node.attr)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            found.setdefault(node.args[0].id, set()).add(node.args[1].value)
    return {name: frozenset(attrs) for name, attrs in found.items()}


def _function(tree: ast.AST, name: str) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{_BACKEND_PATH.name} has no {name}")


@functools.lru_cache(maxsize=1)
def _stub_index() -> dict[tuple[str, str], ast.AST]:
    if not _STUB_PATH.is_file():
        raise AssertionError(
            f"no microsandbox type stub at {_STUB_PATH}; the contract reads it "
            "because PyO3 runtime signatures for create/restore are lossy"
        )
    tree = ast.parse(_STUB_PATH.read_text())
    index: dict[tuple[str, str], ast.AST] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            key = (node.name, item.name)
            if key in index:
                raise AssertionError(f"duplicate stub method {key}")
            index[key] = item
    return index


def _resolve(owner: type, method: str) -> tuple[inspect.Signature, bool]:
    """Return the signature to bind, and whether the SDK method is async.

    Native methods trust the wheel's ``.pyi`` when the runtime signature
    contains ``**kwargs`` or when PyO3 does not report the method as a
    coroutine function. A precise runtime signature has to match the stub.
    """
    fn = getattr(owner, method)
    runtime_sig = _drop_self(inspect.signature(fn))
    runtime_async = inspect.iscoroutinefunction(fn)
    if not _is_native(fn):
        return runtime_sig, runtime_async

    try:
        stub = _stub_index()[(owner.__name__, method)]
    except KeyError as exc:
        raise AssertionError(f"{_STUB_PATH.name} has no {owner.__name__}.{method}") from exc
    stub_sig = _drop_self(_signature_from_stub(stub))
    stub_async = isinstance(stub, ast.AsyncFunctionDef)
    label = f"{owner.__name__}.{method}"
    if _is_lossy(runtime_sig):
        _assert_explicit_subset(runtime_sig, stub_sig, label)
        signature = stub_sig
    else:
        _assert_same_shape(runtime_sig, stub_sig, label)
        signature = runtime_sig
    if _is_lossy(signature):
        raise AssertionError(
            f"{label} has no explicit signature to bind (runtime {runtime_sig}, stub {stub_sig})"
        )
    if runtime_async == stub_async:
        return signature, runtime_async
    # PyO3 async methods are not ``inspect`` coroutine functions.
    if stub_async and not runtime_async:
        return signature, True
    raise AssertionError(
        f"{label} stub async={stub_async} but inspect.iscoroutinefunction={runtime_async}"
    )


def _is_native(fn: object) -> bool:
    return type(fn).__name__ in {
        "builtin_function_or_method",
        "method_descriptor",
        "wrapper_descriptor",
    }


def _is_lossy(signature: inspect.Signature) -> bool:
    return any(param.kind in _VAR_KINDS for param in signature.parameters.values())


def _assert_same_shape(runtime: inspect.Signature, stub: inspect.Signature, label: str) -> None:
    if _shape(runtime) != _shape(stub):
        raise AssertionError(
            f"{label} runtime signature {runtime} does not match stub signature {stub}"
        )


def _assert_explicit_subset(runtime: inspect.Signature, stub: inspect.Signature, label: str) -> None:
    stub_params = stub.parameters
    for param in runtime.parameters.values():
        if param.kind in _VAR_KINDS:
            continue
        other = stub_params.get(param.name)
        if other is None or _shape_one(other) != _shape_one(param):
            raise AssertionError(
                f"{label} runtime parameter {param.name} ({runtime}) "
                f"is not on the stub ({stub})"
            )


def _shape(signature: inspect.Signature) -> list[tuple]:
    return [_shape_one(param) for param in signature.parameters.values()]


def _shape_one(param: inspect.Parameter) -> tuple:
    return (param.name, param.kind, param.default is inspect.Parameter.empty)


def _drop_self(signature: inspect.Signature) -> inspect.Signature:
    params = list(signature.parameters.values())
    if params and params[0].name in {"self", "cls"}:
        params = params[1:]
    return signature.replace(parameters=params)


def _signature_from_stub(node: ast.AST) -> inspect.Signature:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise AssertionError(f"stub node is {type(node).__name__}, not a function")
    args = node.args
    positional = list(args.posonlyargs) + list(args.args)
    kinds = [inspect.Parameter.POSITIONAL_ONLY] * len(args.posonlyargs) + [
        inspect.Parameter.POSITIONAL_OR_KEYWORD
    ] * len(args.args)
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    params = [
        inspect.Parameter(arg.arg, kind, default=_default_value(default))
        for arg, kind, default in zip(positional, kinds, defaults)
    ]
    if args.vararg:
        params.append(inspect.Parameter(args.vararg.arg, inspect.Parameter.VAR_POSITIONAL))
    params.extend(
        inspect.Parameter(arg.arg, inspect.Parameter.KEYWORD_ONLY, default=_default_value(default))
        for arg, default in zip(args.kwonlyargs, args.kw_defaults)
    )
    if args.kwarg:
        params.append(inspect.Parameter(args.kwarg.arg, inspect.Parameter.VAR_KEYWORD))
    return inspect.Signature(params)


def _default_value(node: ast.expr | None):
    if node is None:
        return inspect.Parameter.empty
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        # The value is unused; bind() only cares that a default exists.
        return object()


async def _fake_return_values() -> dict[str, object]:
    previous_error = _RecordingSandbox.snapshot_error
    previous_name = _RecordingSandbox.last_snapshot_name
    _RecordingSandbox.snapshot_error = None
    try:
        sandbox = _RecordingSandbox()
        return {
            "result": await sandbox.exec("echo", []),
            "snap": await sandbox.snapshot("contract-snap"),
        }
    finally:
        _RecordingSandbox.snapshot_error = previous_error
        _RecordingSandbox.last_snapshot_name = previous_name
