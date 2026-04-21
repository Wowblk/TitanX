import {
  DEFAULT_INJECTION_PATTERNS,
  DEFAULT_PII_PATTERNS,
  type InjectionPattern,
  type PiiPattern,
} from "./patterns.js";
import { PiiRedactor } from "./redactor.js";
import { InputValidator } from "./validator.js";
import type { SafetyLayerLike, SafetyResult } from "../types.js";

export interface SafetyLayerOptions {
  injectionPatterns?: InjectionPattern[];
  piiPatterns?: PiiPattern[];
}

export class SafetyLayer implements SafetyLayerLike {
  public readonly validator: InputValidator;
  private readonly redactor: PiiRedactor;
  private readonly injectionPatterns: InjectionPattern[];

  public constructor(options: SafetyLayerOptions = {}) {
    this.injectionPatterns = options.injectionPatterns ?? DEFAULT_INJECTION_PATTERNS;
    this.validator = new InputValidator(this.injectionPatterns);
    this.redactor = new PiiRedactor(options.piiPatterns ?? DEFAULT_PII_PATTERNS);
  }

  public checkInput(content: string): SafetyResult {
    const { content: sanitized } = this.redactor.redact(content);

    const violations: SafetyResult["violations"] = [];
    for (const pattern of this.injectionPatterns) {
      if (pattern.regex.test(sanitized)) {
        violations.push({ pattern: pattern.name, action: pattern.action });
      }
    }

    return {
      safe: !violations.some((v) => v.action === "block"),
      sanitizedContent: sanitized,
      violations,
    };
  }

  public sanitizeToolOutput(_toolName: string, output: string): { content: string } {
    const { content } = this.redactor.redact(output);
    return { content };
  }
}
