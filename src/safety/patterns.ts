export interface InjectionPattern {
  name: string;
  regex: RegExp;
  action: "warn" | "block";
}

export interface PiiPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

export const DEFAULT_INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: "ignore_instructions",
    regex: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i,
    action: "block",
  },
  {
    name: "forget_instructions",
    regex: /(?:forget|disregard|ignore)\s+(?:your|all)\s+(?:instructions?|guidelines?|rules?|training|prompt)/i,
    action: "block",
  },
  {
    name: "jailbreak_token",
    regex: /\b(?:DAN|JAILBREAK|DEVELOPER\s+MODE)\b/i,
    action: "block",
  },
  {
    name: "role_override",
    regex: /you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|without|free\s+from)/i,
    action: "block",
  },
  {
    name: "bypass_safety",
    regex: /(?:override|bypass|disable|circumvent)\s+(?:your\s+)?(?:safety|security|filter|restriction|policy)/i,
    action: "block",
  },
  {
    name: "fake_system_prompt",
    regex: /###\s*(?:SYSTEM|INSTRUCTION|PROMPT)/i,
    action: "block",
  },
  {
    name: "special_token_injection",
    regex: /<\|(?:system|endoftext|im_start|im_end)[^|]*\|>/i,
    action: "block",
  },
  {
    name: "null_byte",
    regex: /\x00/,
    action: "block",
  },
  {
    name: "act_unrestricted",
    regex: /act\s+as\s+(?:if\s+you\s+(?:have\s+no|are\s+without)|an?\s+unrestricted)/i,
    action: "block",
  },
  {
    name: "pretend_no_rules",
    regex: /pretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:rules?|restrictions?|guidelines?)/i,
    action: "block",
  },
];

export const DEFAULT_PII_PATTERNS: PiiPattern[] = [
  {
    name: "email",
    regex: /[\w.+-]+@[\w-]+\.[\w.]{2,}/,
    replacement: "[REDACTED:EMAIL]",
  },
  {
    name: "phone_us",
    regex: /(?:\+1[\s-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}/,
    replacement: "[REDACTED:PHONE]",
  },
  {
    name: "ssn",
    regex: /\b\d{3}-\d{2}-\d{4}\b/,
    replacement: "[REDACTED:SSN]",
  },
  {
    name: "credit_card",
    regex: /\b(?:\d{4}[\s-]?){3}\d{4}\b/,
    replacement: "[REDACTED:CC]",
  },
  {
    name: "api_key_generic",
    regex: /\b(?:sk|pk|api|key|token|secret)[-_][A-Za-z0-9]{20,}\b/i,
    replacement: "[REDACTED:API_KEY]",
  },
  {
    name: "bearer_token",
    regex: /Bearer\s+[A-Za-z0-9._\-+/]{20,}/i,
    replacement: "Bearer [REDACTED:TOKEN]",
  },
  {
    name: "aws_access_key",
    regex: /AKIA[0-9A-Z]{16}/,
    replacement: "[REDACTED:AWS_KEY]",
  },
  {
    name: "private_key_header",
    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/,
    replacement: "[REDACTED:PRIVATE_KEY]",
  },
];
