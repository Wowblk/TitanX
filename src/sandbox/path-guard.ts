import { normalize as posixNormalize } from "node:path/posix";

export function isPathAllowed(filePath: string, allowedPaths: string[]): boolean {
  const normalized = posixNormalize(filePath);
  if (normalized.includes("..")) return false;
  return allowedPaths.some((allowed) => {
    const normalizedAllowed = posixNormalize(allowed);
    const prefix = normalizedAllowed.endsWith("/") ? normalizedAllowed : normalizedAllowed + "/";
    return normalized === normalizedAllowed || normalized.startsWith(prefix);
  });
}

// Heuristic: detects shell redirect (> / >>) and tee write targets with absolute paths.
// Does not catch programmatic writes (open(), dd, cp dst) or variable-expanded paths.
const WRITE_TARGET_RE = /(?:>{1,2}|tee(?:\s+-a)?)\s+["']?(\/[^"'\s;|&<>]+)["']?/g;

export function extractShellWriteTargets(command: string, args?: string[]): string[] {
  const fullCommand = [command, ...(args ?? [])].join(" ");
  const targets: string[] = [];
  for (const match of fullCommand.matchAll(WRITE_TARGET_RE)) {
    targets.push(match[1]);
  }
  return targets;
}
