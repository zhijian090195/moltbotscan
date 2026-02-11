export {
  analyzeContent,
  runRuleEngine,
  extractSuspiciousLinks,
  needsLLMAnalysis,
} from '../analysis/rules.js';

export { LLMAnalyzer } from '../analysis/llm.js';

export {
  ALL_PATTERNS,
  DIRECT_INJECTION,
  CREDENTIAL_THEFT,
  COVERT_EXECUTION,
  SOCIAL_ENGINEERING,
  URL_PATTERN,
  BASE64_PATTERN,
  isSuspiciousUrl,
  containsBase64Hidden,
  hasDuplicateContent,
} from '../analysis/patterns.js';

export type { PatternRule } from '../analysis/patterns.js';
