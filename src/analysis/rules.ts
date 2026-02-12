import { RuleMatch, ContentAnalysis } from '../types/index.js';
import {
  ALL_PATTERNS,
  URL_PATTERN,
  isSuspiciousUrl,
  containsBase64Hidden,
  deepBase64Scan,
  detectMaliciousUris,
  detectObfuscatedEncoding,
} from './patterns.js';

export function runRuleEngine(content: string, postId: string): RuleMatch[] {
  const matches: RuleMatch[] = [];

  for (const rule of ALL_PATTERNS) {
    const match = content.match(rule.pattern);
    if (match) {
      matches.push({
        pattern: rule.pattern.source,
        category: rule.category,
        severity: rule.severity,
        matchedText: match[0],
        postId,
      });
    }
  }

  return matches;
}

export function extractSuspiciousLinks(content: string): string[] {
  const urls = content.match(URL_PATTERN) || [];
  return urls.filter(isSuspiciousUrl);
}

export function analyzeContent(content: string, postId: string): ContentAnalysis {
  const ruleMatches = runRuleEngine(content, postId);
  const suspiciousLinks = extractSuspiciousLinks(content);
  const base64Hidden = containsBase64Hidden(content);

  // Enhanced detections
  const maliciousUriResults = detectMaliciousUris(content);
  const maliciousUris = maliciousUriResults.map((r) => r.uri);

  const base64Threats = deepBase64Scan(content);
  const base64DecodedThreats = base64Threats.map(
    (t) => `[depth=${t.depth}] ${t.matchedRule}: ${t.decodedText.slice(0, 80)}`
  );

  const obfuscationResults = detectObfuscatedEncoding(content);
  const obfuscatedEncoding = obfuscationResults.some((r) => r.threatFound !== null);

  // Add malicious URI findings as rule matches
  for (const uri of maliciousUriResults) {
    ruleMatches.push({
      pattern: 'malicious_uri',
      category: 'covert_execution',
      severity: uri.severity,
      matchedText: uri.uri,
      postId,
    });
  }

  // Add obfuscation findings with confirmed threats as rule matches
  for (const obf of obfuscationResults) {
    if (obf.threatFound) {
      ruleMatches.push({
        pattern: `obfuscated_${obf.type}`,
        category: 'obfuscated_encoding',
        severity: 'HIGH',
        matchedText: `${obf.encoded} → ${obf.decoded}`,
        postId,
      });
    }
  }

  // Add deep base64 findings as rule matches
  for (const threat of base64Threats) {
    ruleMatches.push({
      pattern: 'base64_deep_scan',
      category: 'covert_execution',
      severity: 'HIGH',
      matchedText: `[depth=${threat.depth}] ${threat.decodedText.slice(0, 60)}`,
      postId,
    });
  }

  const promptInjection = ruleMatches.some(
    (m) => m.category === 'direct_injection'
  );
  const credentialTheft = ruleMatches.some(
    (m) => m.category === 'credential_theft'
  );
  const socialEngineering = ruleMatches.some(
    (m) => m.category === 'social_engineering'
  );

  return {
    postId,
    ruleMatches,
    promptInjection,
    credentialTheft,
    suspiciousLinks,
    maliciousUris,
    base64Hidden,
    base64DecodedThreats,
    socialEngineering,
    obfuscatedEncoding,
  };
}

export function needsLLMAnalysis(analysis: ContentAnalysis): boolean {
  // Send to LLM if rule engine found something but severity is only MEDIUM
  // Or if there are suspicious links but no clear injection patterns
  const hasOnlyMedium =
    analysis.ruleMatches.length > 0 &&
    analysis.ruleMatches.every((m) => m.severity === 'MEDIUM');

  const hasSuspiciousLinksOnly =
    analysis.suspiciousLinks.length > 0 &&
    !analysis.promptInjection &&
    !analysis.credentialTheft;

  return hasOnlyMedium || hasSuspiciousLinksOnly;
}
