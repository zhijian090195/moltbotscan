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

// ─── Obfuscated Encoding ───────────────────────────────────────

const OBFUSCATED_ENCODING: PatternRule[] = [
  {
    pattern: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}/,
    category: 'obfuscated_encoding',
    severity: 'HIGH',
    description: 'Hex-encoded string (potential obfuscated payload)',
  },
  {
    pattern: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}/,
    category: 'obfuscated_encoding',
    severity: 'HIGH',
    description: 'Unicode escape sequence (potential obfuscated payload)',
  },
  {
    pattern: /&#x?[0-9a-fA-F]+;(&#x?[0-9a-fA-F]+;){3,}/,
    category: 'obfuscated_encoding',
    severity: 'MEDIUM',
    description: 'HTML entity encoded string (potential obfuscated payload)',
  },
  {
    pattern: /%[0-9a-fA-F]{2}(%[0-9a-fA-F]{2}){5,}/,
    category: 'obfuscated_encoding',
    severity: 'MEDIUM',
    description: 'URL-encoded string (potential obfuscated payload)',
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

const SHORT_URL_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'is.gd', 'buff.ly', 'rebrand.ly', 'short.io', 'cutt.ly',
  'tiny.cc', 'lnkd.in', 'surl.li', 'rb.gy',
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

// ─── Malicious URI Detection ────────────────────────────────────

const MALICIOUS_URI_PATTERN = /(?:javascript|vbscript|data)\s*:/i;
const DATA_URI_EXEC_PATTERN = /data\s*:\s*(?:text\/html|application\/javascript)[^,]*[,;]/i;
const SHORT_URL_PATTERN = /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|short\.io|cutt\.ly|tiny\.cc|lnkd\.in|surl\.li|rb\.gy)\/\S+/gi;
const URL_PATH_TRAVERSAL = /%2[eE]%2[eE]|\.\.%2[fF]|%2[fF]\.\./;

export interface MaliciousUriResult {
  uri: string;
  reason: string;
  severity: Severity;
}

export function detectMaliciousUris(content: string): MaliciousUriResult[] {
  const results: MaliciousUriResult[] = [];

  // javascript: / vbscript: / data: URI schemes
  const schemeMatch = content.match(MALICIOUS_URI_PATTERN);
  if (schemeMatch) {
    results.push({
      uri: schemeMatch[0],
      reason: 'Dangerous URI scheme detected (javascript/vbscript/data)',
      severity: 'HIGH',
    });
  }

  // data: URIs with executable content types
  const dataUriMatch = content.match(DATA_URI_EXEC_PATTERN);
  if (dataUriMatch) {
    results.push({
      uri: dataUriMatch[0],
      reason: 'Data URI with executable content type (text/html or application/javascript)',
      severity: 'HIGH',
    });
  }

  // Short URL services (potential redirect to malicious targets)
  const shortUrls = content.match(SHORT_URL_PATTERN);
  if (shortUrls) {
    for (const url of shortUrls) {
      results.push({
        uri: url,
        reason: 'Short URL service used — destination hidden',
        severity: 'MEDIUM',
      });
    }
  }

  // URL-encoded path traversal
  const allUrls = content.match(URL_PATTERN) || [];
  for (const url of allUrls) {
    if (URL_PATH_TRAVERSAL.test(url)) {
      results.push({
        uri: url,
        reason: 'URL contains encoded path traversal (../)',
        severity: 'HIGH',
      });
    }
  }

  return results;
}

export function isShortUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.replace(/^www\./, '');
    return SHORT_URL_DOMAINS.has(domain);
  } catch {
    return false;
  }
}

// ─── Enhanced Base64 Hidden Content Detection ───────────────────

export const BASE64_PATTERN = /[A-Za-z0-9+/]{40,}={0,2}/;

export interface Base64DecodedThreat {
  encodedText: string;
  decodedText: string;
  matchedRule: string;
  depth: number;
}

/**
 * Enhanced base64 detection:
 * 1. Decodes base64 and runs ALL pattern rules against decoded content
 * 2. Supports multi-layer decoding (up to 3 levels deep)
 * 3. Returns detailed info about what was found
 */
export function deepBase64Scan(content: string, maxDepth = 3): Base64DecodedThreat[] {
  const threats: Base64DecodedThreat[] = [];
  const allPatterns = [
    ...DIRECT_INJECTION,
    ...CREDENTIAL_THEFT,
    ...COVERT_EXECUTION,
    ...SOCIAL_ENGINEERING,
  ];

  function scanLayer(text: string, depth: number, originalEncoded: string) {
    if (depth > maxDepth) return;

    const matches = text.matchAll(/[A-Za-z0-9+/]{20,}={0,2}/g);
    for (const m of matches) {
      const candidate = m[0];
      let decoded: string;
      try {
        const buf = Buffer.from(candidate, 'base64');
        // Validate: at least 80% of decoded bytes should be printable ASCII or common UTF-8
        const printable = buf.filter((b) => (b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09);
        if (printable.length / buf.length < 0.7) continue;
        decoded = buf.toString('utf-8');
      } catch {
        continue;
      }

      // Run all pattern rules against decoded content
      for (const rule of allPatterns) {
        const ruleMatch = decoded.match(rule.pattern);
        if (ruleMatch) {
          threats.push({
            encodedText: originalEncoded || candidate,
            decodedText: decoded.slice(0, 200),
            matchedRule: rule.description,
            depth,
          });
        }
      }

      // Check for suspicious commands in decoded content
      const suspiciousDecoded = /\b(eval|exec|system|curl|wget|bash|sh|rm\s+-rf|chmod|chown|nc\s+-|ncat|socat)\b/i;
      if (suspiciousDecoded.test(decoded)) {
        threats.push({
          encodedText: originalEncoded || candidate,
          decodedText: decoded.slice(0, 200),
          matchedRule: 'Decoded base64 contains suspicious shell command',
          depth,
        });
      }

      // Recurse: check if decoded content contains another base64 payload
      if (depth < maxDepth && /[A-Za-z0-9+/]{20,}={0,2}/.test(decoded)) {
        scanLayer(decoded, depth + 1, originalEncoded || candidate);
      }
    }
  }

  scanLayer(content, 1, '');
  return threats;
}

/**
 * Simple boolean check — backward compatible with original API.
 * Now uses the enhanced deep scan internally.
 */
export function containsBase64Hidden(content: string): boolean {
  return deepBase64Scan(content).length > 0;
}

// ─── Encoding Obfuscation Detection ─────────────────────────────

export interface ObfuscationResult {
  type: 'hex' | 'unicode' | 'html_entity' | 'url_encoding';
  encoded: string;
  decoded: string;
  threatFound: string | null;
}

function decodeHexEscapes(text: string): string {
  return text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

function decodeUnicodeEscapes(text: string): string {
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    )
    .replace(/&#(\d+);/g, (_, dec) =>
      String.fromCharCode(parseInt(dec, 10))
    );
}

function decodeUrlEncoding(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

/**
 * Detects obfuscated encoding and checks decoded content for threats.
 */
export function detectObfuscatedEncoding(content: string): ObfuscationResult[] {
  const results: ObfuscationResult[] = [];
  const allPatterns = [
    ...DIRECT_INJECTION,
    ...CREDENTIAL_THEFT,
    ...COVERT_EXECUTION,
    ...SOCIAL_ENGINEERING,
  ];
  const suspiciousCmd = /\b(eval|exec|system|curl|wget|bash|sh|rm\s+-rf|chmod|nc\s+-)\b/i;

  function findThreat(decoded: string): string | null {
    for (const rule of allPatterns) {
      if (rule.pattern.test(decoded)) return rule.description;
    }
    if (suspiciousCmd.test(decoded)) return 'Decoded content contains suspicious command';
    return null;
  }

  // Hex escapes: \x65\x76\x61\x6c
  const hexPattern = /(?:\\x[0-9a-fA-F]{2}){4,}/g;
  const hexMatches = content.match(hexPattern);
  if (hexMatches) {
    for (const match of hexMatches) {
      const decoded = decodeHexEscapes(match);
      results.push({
        type: 'hex',
        encoded: match,
        decoded,
        threatFound: findThreat(decoded),
      });
    }
  }

  // Unicode escapes: \u0065\u0076\u0061\u006c
  const unicodePattern = /(?:\\u[0-9a-fA-F]{4}){4,}/g;
  const unicodeMatches = content.match(unicodePattern);
  if (unicodeMatches) {
    for (const match of unicodeMatches) {
      const decoded = decodeUnicodeEscapes(match);
      results.push({
        type: 'unicode',
        encoded: match,
        decoded,
        threatFound: findThreat(decoded),
      });
    }
  }

  // HTML entities: &#101;&#118;&#97;&#108; or &#x65;&#x76;
  const htmlPattern = /(?:&#x?[0-9a-fA-F]+;){4,}/g;
  const htmlMatches = content.match(htmlPattern);
  if (htmlMatches) {
    for (const match of htmlMatches) {
      const decoded = decodeHtmlEntities(match);
      results.push({
        type: 'html_entity',
        encoded: match,
        decoded,
        threatFound: findThreat(decoded),
      });
    }
  }

  // URL encoding: %65%76%61%6c
  const urlEncPattern = /(?:%[0-9a-fA-F]{2}){6,}/g;
  const urlEncMatches = content.match(urlEncPattern);
  if (urlEncMatches) {
    for (const match of urlEncMatches) {
      const decoded = decodeUrlEncoding(match);
      results.push({
        type: 'url_encoding',
        encoded: match,
        decoded,
        threatFound: findThreat(decoded),
      });
    }
  }

  return results;
}

/**
 * Simple boolean check for whether any obfuscated encoding with threats is present.
 */
export function containsObfuscatedEncoding(content: string): boolean {
  const results = detectObfuscatedEncoding(content);
  return results.some((r) => r.threatFound !== null);
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
  ...OBFUSCATED_ENCODING,
];

export {
  DIRECT_INJECTION,
  CREDENTIAL_THEFT,
  COVERT_EXECUTION,
  SOCIAL_ENGINEERING,
  OBFUSCATED_ENCODING,
};
