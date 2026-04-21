import { DEFAULT_PII_PATTERNS, type PiiPattern } from "./patterns.js";

export interface RedactionResult {
  content: string;
  redactedCount: number;
}

// Single-pass PII redactor: combines N patterns into one regex, replacing all
// PII types in a single .replace() call instead of N sequential passes.
// This reduces time complexity from O(N * text_length) to O(text_length).
export class PiiRedactor {
  private readonly combinedRegex: RegExp;
  private readonly replacements: string[];

  public constructor(patterns: PiiPattern[] = DEFAULT_PII_PATTERNS) {
    // Wrap each pattern in a capturing group so we can identify which matched.
    // Individual patterns must not contain their own capturing groups.
    const sources = patterns.map((p) => `(${p.regex.source})`);
    this.combinedRegex = new RegExp(sources.join("|"), "gi");
    this.replacements = patterns.map((p) => p.replacement);
  }

  public redact(content: string): RedactionResult {
    let redactedCount = 0;
    const replaced = content.replace(this.combinedRegex, (...args: unknown[]) => {
      // args layout: [fullMatch, group_0, group_1, ..., group_N-1, offset, string]
      const groups = args.slice(1, this.replacements.length + 1) as (string | undefined)[];
      const matchedIndex = groups.findIndex((g) => g !== undefined);
      redactedCount++;
      return matchedIndex >= 0 ? (this.replacements[matchedIndex] ?? "[REDACTED]") : "[REDACTED]";
    });
    return { content: replaced, redactedCount };
  }
}
