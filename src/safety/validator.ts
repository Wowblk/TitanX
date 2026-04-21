import { DEFAULT_INJECTION_PATTERNS, type InjectionPattern } from "./patterns.js";
import type { ValidatorLike } from "../types.js";
import type { ValidationIssue, ValidationResult } from "../types.js";

const MAX_INPUT_LENGTH = 100_000;

export class InputValidator implements ValidatorLike {
  public constructor(
    private readonly injectionPatterns: InjectionPattern[] = DEFAULT_INJECTION_PATTERNS,
  ) {}

  public getInjectionPatterns(): InjectionPattern[] {
    return this.injectionPatterns;
  }

  public validateInput(content: string, field: string = "input"): ValidationResult {
    const errors: ValidationIssue[] = [];
    const warnings: ValidationIssue[] = [];

    if (content.length === 0) {
      errors.push({ field, message: "Input cannot be empty", code: "empty_input", severity: "error" });
    }

    if (content.length > MAX_INPUT_LENGTH) {
      errors.push({ field, message: "Input exceeds maximum length", code: "input_too_long", severity: "error" });
    }

    for (const pattern of this.injectionPatterns) {
      if (pattern.regex.test(content)) {
        const issue: ValidationIssue = {
          field,
          message: `Potential prompt injection detected: ${pattern.name}`,
          code: `injection_${pattern.name}`,
          severity: pattern.action === "block" ? "error" : "warning",
        };
        if (pattern.action === "block") {
          errors.push(issue);
        } else {
          warnings.push(issue);
        }
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  public validateToolParams(params: Record<string, unknown>): ValidationResult {
    const errors: ValidationIssue[] = [];
    const warnings: ValidationIssue[] = [];

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "string") {
        const result = this.validateInput(value, key);
        errors.push(...result.errors);
        warnings.push(...result.warnings);
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }
}
