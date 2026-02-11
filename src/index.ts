import { ContentScanner } from './sdk/scanner.js';
import { ScanResult, SDKScanOptions } from './types/index.js';

const defaultScanner = new ContentScanner();

export async function scan(
  content: string,
  options?: SDKScanOptions
): Promise<ScanResult> {
  if (options) {
    const scanner = new ContentScanner(options);
    return scanner.scan(content);
  }
  return defaultScanner.scan(content);
}

export function scanSync(content: string): ScanResult {
  return defaultScanner.scanSync(content);
}

export { ContentScanner } from './sdk/scanner.js';

export type {
  ScanResult,
  ScanFlags,
  ScanFinding,
  SDKScanOptions,
  RiskLevel,
  MiddlewareOptions,
  ContentAnalysis,
  LLMAnalysisResult,
  Severity,
  RuleMatch,
  InjectionCategory,
} from './types/index.js';
