import { RuleMatch, ContentAnalysis } from '../types/index.js';
import {
  ALL_PATTERNS,
  URL_PATTERN,
  isSuspiciousUrl,
  containsBase64Hidden,
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
    base64Hidden,
    socialEngineering,
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
