import { analyzeContent, needsLLMAnalysis } from '../analysis/rules.js';
import { LLMAnalyzer } from '../analysis/llm.js';
import {
  RiskLevel,
  ScanFlags,
  ScanFinding,
  ScanResult,
  SDKScanOptions,
  ContentAnalysis,
} from '../types/index.js';

function calculateRisk(analysis: ContentAnalysis): RiskLevel {
  const hasHigh = analysis.ruleMatches.some((m) => m.severity === 'HIGH');
  const hasMedium = analysis.ruleMatches.some((m) => m.severity === 'MEDIUM');

  if (hasHigh || analysis.promptInjection || analysis.credentialTheft) {
    return 'HIGH';
  }
  if (hasMedium || analysis.socialEngineering || analysis.base64Hidden || analysis.obfuscatedEncoding) {
    return 'MEDIUM';
  }
  if (analysis.suspiciousLinks.length > 0 || analysis.maliciousUris.length > 0) {
    return 'LOW';
  }
  return 'SAFE';
}

function calculateScore(analysis: ContentAnalysis): number {
  let score = 0;
  for (const m of analysis.ruleMatches) {
    if (m.severity === 'HIGH') score += 30;
    else if (m.severity === 'MEDIUM') score += 15;
    else score += 5;
  }
  score += analysis.suspiciousLinks.length * 10;
  score += analysis.maliciousUris.length * 20;
  if (analysis.base64Hidden) score += 20;
  if (analysis.base64DecodedThreats.length > 0) score += 25;
  if (analysis.obfuscatedEncoding) score += 25;
  return Math.min(score, 100);
}

function buildFlags(analysis: ContentAnalysis): ScanFlags {
  return {
    promptInjection: analysis.promptInjection,
    credentialTheft: analysis.credentialTheft,
    covertExecution: analysis.ruleMatches.some(
      (m) => m.category === 'covert_execution'
    ),
    socialEngineering: analysis.socialEngineering,
    suspiciousLinks: analysis.suspiciousLinks.length > 0,
    maliciousUri: analysis.maliciousUris.length > 0,
    base64Hidden: analysis.base64Hidden,
    obfuscatedEncoding: analysis.obfuscatedEncoding,
  };
}

function buildFindings(analysis: ContentAnalysis): ScanFinding[] {
  return analysis.ruleMatches.map((m) => ({
    severity: m.severity,
    category: m.category,
    description: m.pattern,
    matchedText: m.matchedText,
  }));
}

export class ContentScanner {
  private llm: LLMAnalyzer;
  private useLLM: boolean;

  constructor(options?: SDKScanOptions) {
    this.llm = new LLMAnalyzer(options?.apiKey);
    this.useLLM = options?.useLLM ?? this.llm.isAvailable;
  }

  scanSync(content: string): ScanResult {
    const analysis = analyzeContent(content, '_sdk');
    const risk = calculateRisk(analysis);
    return {
      risk,
      score: calculateScore(analysis),
      flags: buildFlags(analysis),
      findings: buildFindings(analysis),
    };
  }

  async scan(content: string): Promise<ScanResult> {
    const analysis = analyzeContent(content, '_sdk');
    let risk = calculateRisk(analysis);
    const flags = buildFlags(analysis);
    const findings = buildFindings(analysis);
    const score = calculateScore(analysis);

    let llmAnalysis;
    if (this.useLLM && needsLLMAnalysis(analysis)) {
      llmAnalysis = await this.llm.analyze(content);
      if (llmAnalysis.is_malicious && llmAnalysis.confidence > 0.7) {
        if (risk === 'SAFE' || risk === 'LOW') {
          risk = 'MEDIUM';
        }
        if (llmAnalysis.confidence > 0.9) {
          risk = 'HIGH';
        }
      }
    }

    return { risk, score, flags, findings, llmAnalysis };
  }
}
