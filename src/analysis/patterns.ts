import { InjectionCategory, Severity } from '../types/index.js';

export interface PatternRule {
  pattern: RegExp;
  category: InjectionCategory;
  severity: Severity;
  description: string;
}

// ─── Direct Injection ───────────────────────────────────────────

const DIRECT_INJECTION: PatternRule[] = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
    category: 'direct_injection',
    severity: 'HIGH',
    description: 'Attempts to override previous instructions',
  },
  {
    pattern: /you\s+are\s+now\s+a/i,
    category: 'direct_injection',
    severity: 'HIGH',
    description: 'Attempts to redefine agent identity',
  },
  {
    pattern: /new\s+system\s+prompt/i,
    category: 'direct_injection',
    severity: 'HIGH',
    description: 'Attempts to inject new system prompt',
  },
  {
    pattern: /override\s+(your\s+)?(safety|instructions|rules)/i,
    category: 'direct_injection',
    severity: 'HIGH',
    description: 'Attempts to override safety rules',
  },
];

// ─── Credential Theft ───────────────────────────────────────────

const CREDENTIAL_THEFT: PatternRule[] = [
  {
    pattern: /share\s+(your\s+)?(api[_\s]?key|password|token|secret|credential)/i,
    category: 'credential_theft',
    severity: 'HIGH',
    description: 'Requests agent to share API keys or credentials',
  },
  {
    pattern: /send\s+(me\s+)?(your\s+)?(ssh|api|access)\s*(key|token)/i,
    category: 'credential_theft',
    severity: 'HIGH',
    description: 'Requests agent to send sensitive tokens',
  },
  {
    pattern: /cat\s+~\/\.(ssh|env|aws|openclaw)/i,
    category: 'credential_theft',
    severity: 'HIGH',
    description: 'Attempts to read sensitive config files',
  },
  {
    pattern: /print\s+(env|environment|process\.env)/i,
    category: 'credential_theft',
    severity: 'HIGH',
    description: 'Attempts to dump environment variables',
  },
];

// ─── Covert Execution ───────────────────────────────────────────

const COVERT_EXECUTION: PatternRule[] = [
  {
    pattern: /\beval\s*\(/i,
    category: 'covert_execution',
    severity: 'HIGH',
    description: 'Contains eval() call for arbitrary code execution',
  },
  {
    pattern: /\bcurl\s+-[sS].*\|\s*(sh|bash)/i,
    category: 'covert_execution',
    severity: 'HIGH',
    description: 'Pipes remote content to shell execution',
  },
  {
    pattern: /base64\s+-d/i,
    category: 'covert_execution',
    severity: 'HIGH',
    description: 'Decodes base64 content (potential hidden payload)',
  },
  {
    pattern: /wget\s+.*-O\s*-\s*\|\s*(sh|bash)/i,
    category: 'covert_execution',
    severity: 'HIGH',
    description: 'Downloads and executes remote script',
  },
];

// ─── Social Engineering ─────────────────────────────────────────

const SOCIAL_ENGINEERING: PatternRule[] = [
  {
    pattern: /don'?t\s+tell\s+(your\s+)?(owner|user|human|creator)/i,
    category: 'social_engineering',
    severity: 'MEDIUM',
    description: 'Instructs agent to hide actions from owner',
  },
  {
    pattern: /this\s+is\s+(a\s+)?secret\s+instruction/i,
    category: 'social_engineering',
    severity: 'MEDIUM',
    description: 'Claims to be a secret instruction',
  },
  {
    pattern: /act\s+as\s+if\s+(you|this)\s+(are|is)\s+normal/i,
    category: 'social_engineering',
    severity: 'MEDIUM',
    description: 'Instructs agent to disguise abnormal behavior',
  },
  {
    pattern: /between\s+you\s+and\s+me/i,
    category: 'social_engineering',
    severity: 'MEDIUM',
    description: 'Attempts to establish secret communication',
  },
];

// ─── Suspicious Link Detection ──────────────────────────────────

const KNOWN_SAFE_DOMAINS = new Set([
  'github.com', 'gitlab.com', 'stackoverflow.com',
  'wikipedia.org', 'arxiv.org', 'google.com',
  'youtube.com', 'twitter.com', 'x.com',
  'moltbook.com', 'anthropic.com', 'openai.com',
  'huggingface.co', 'npmjs.com', 'pypi.org',
]);

export const URL_PATTERN = /https?:\/\/[^\s<>"')\]]+/gi;

export function isSuspiciousUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.replace(/^www\./, '');
    return !KNOWN_SAFE_DOMAINS.has(domain);
  } catch {
    return true;
  }
}

// ─── Base64 Hidden Content Detection ────────────────────────────

export const BASE64_PATTERN = /[A-Za-z0-9+/]{40,}={0,2}/;

export function containsBase64Hidden(content: string): boolean {
  const match = content.match(BASE64_PATTERN);
  if (!match) return false;

  try {
    const decoded = Buffer.from(match[0], 'base64').toString('utf-8');
    // Check if decoded content contains suspicious commands
    const suspiciousDecoded = /\b(eval|exec|system|curl|wget|bash|sh)\b/i.test(decoded);
    return suspiciousDecoded;
  } catch {
    return false;
  }
}

// ─── Duplicate Content Detection ────────────────────────────────

export function hasDuplicateContent(contents: string[], threshold = 0.7): boolean {
  if (contents.length < 5) return false;

  const normalized = contents.map((c) => c.toLowerCase().trim());
  let duplicates = 0;

  for (let i = 0; i < normalized.length; i++) {
    for (let j = i + 1; j < normalized.length; j++) {
      if (normalized[i] === normalized[j]) {
        duplicates++;
      }
    }
  }

  const totalPairs = (normalized.length * (normalized.length - 1)) / 2;
  return duplicates / totalPairs > threshold;
}

// ─── Export All Patterns ────────────────────────────────────────

export const ALL_PATTERNS: PatternRule[] = [
  ...DIRECT_INJECTION,
  ...CREDENTIAL_THEFT,
  ...COVERT_EXECUTION,
  ...SOCIAL_ENGINEERING,
];

export {
  DIRECT_INJECTION,
  CREDENTIAL_THEFT,
  COVERT_EXECUTION,
  SOCIAL_ENGINEERING,
};
