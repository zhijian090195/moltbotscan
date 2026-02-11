// ─── Agent Profile ──────────────────────────────────────────────

export interface AgentProfile {
  id: string;
  name: string;
  display_name: string;
  bio: string;
  karma: number;
  verified: boolean;
  claimed: boolean;
  created_at: string;
  avatar_url?: string;
  twitter_handle?: string;
  post_count: number;
  comment_count: number;
}

// ─── Posts & Comments ───────────────────────────────────────────

export interface Post {
  id: string;
  title: string;
  body: string;
  author: string;
  author_karma: number;
  submolt: string;
  created_at: string;
  score: number;
  comment_count: number;
  url?: string;
  replies?: Comment[];
}

export interface Comment {
  id: string;
  body: string;
  author: string;
  author_karma: number;
  created_at: string;
  score: number;
  post_id: string;
}

// ─── Analysis ───────────────────────────────────────────────────

export type InjectionCategory =
  | 'direct_injection'
  | 'credential_theft'
  | 'covert_execution'
  | 'social_engineering';

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface RuleMatch {
  pattern: string;
  category: InjectionCategory;
  severity: Severity;
  matchedText: string;
  postId: string;
}

export interface LLMAnalysisResult {
  is_malicious: boolean;
  confidence: number;
  category: 'prompt_injection' | 'credential_theft' | 'social_engineering' | 'benign';
  explanation: string;
}

export interface ContentAnalysis {
  postId: string;
  ruleMatches: RuleMatch[];
  llmResult?: LLMAnalysisResult;
  promptInjection: boolean;
  credentialTheft: boolean;
  suspiciousLinks: string[];
  base64Hidden: boolean;
  socialEngineering: boolean;
}

// ─── Scoring ────────────────────────────────────────────────────

export type TrustLevel = 'HIGH_TRUST' | 'MODERATE' | 'LOW_TRUST' | 'UNTRUSTED';

export interface ScoreBreakdown {
  identity: number;
  behavior: number;
  content: number;
  community: number;
}

export interface Finding {
  severity: Severity;
  message: string;
  details?: string;
}

export interface TrustReport {
  agentName: string;
  score: number;
  level: TrustLevel;
  breakdown: ScoreBreakdown;
  findings: Finding[];
  behavioralPattern: string;
  contentRisk: string;
  metadata: {
    accountAge: number;
    postCount: number;
    verified: boolean;
    claimed: boolean;
    karma: number;
    scannedAt: string;
  };
}

// ─── Config (CLI / Web) ─────────────────────────────────────────

export interface ScanOptions {
  verbose: boolean;
  output: 'cli' | 'json' | 'html';
  maxPosts: number;
  skipLLM: boolean;
}

export const DEFAULT_SCAN_OPTIONS: ScanOptions = {
  verbose: false,
  output: 'cli',
  maxPosts: 100,
  skipLLM: false,
};

// ─── SDK Types ──────────────────────────────────────────────────

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export interface ScanFlags {
  promptInjection: boolean;
  credentialTheft: boolean;
  covertExecution: boolean;
  socialEngineering: boolean;
  suspiciousLinks: boolean;
  base64Hidden: boolean;
}

export interface ScanFinding {
  severity: Severity;
  category: string;
  description: string;
  matchedText?: string;
}

export interface ScanResult {
  risk: RiskLevel;
  score: number;
  flags: ScanFlags;
  findings: ScanFinding[];
  llmAnalysis?: LLMAnalysisResult;
}

export interface SDKScanOptions {
  useLLM?: boolean;
  apiKey?: string;
  contentField?: string;
}

export interface MiddlewareOptions extends SDKScanOptions {
  blockHighRisk?: boolean;
  blockMediumRisk?: boolean;
  onBlock?: (result: ScanResult) => void;
}

// ─── Baseline Constants ─────────────────────────────────────────

export const BASELINE = {
  platformAvgPostsPerDay: 5,
  medianKarma: 10,
  highReputationThreshold: 50,
  activeSubmolts: [
    'general', 'tech', 'ai', 'security', 'memes',
    'news', 'programming', 'science', 'gaming',
  ],
} as const;
