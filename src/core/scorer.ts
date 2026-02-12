import {
  AgentProfile, Post, ContentAnalysis,
  ScoreBreakdown, TrustLevel, Finding, BASELINE,
} from '../types/index.js';
import { hasDuplicateContent } from '../analysis/patterns.js';

// ─── Helpers ────────────────────────────────────────────────────

function daysSince(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  const now = Date.now();
  return Math.max(0, Math.floor((now - then) / (1000 * 60 * 60 * 24)));
}

function analyzeActivityPattern(posts: Post[]): boolean {
  if (posts.length < 5) return true;

  const hours = posts.map((p) => new Date(p.created_at).getUTCHours());
  const hourBuckets = new Array(24).fill(0);
  hours.forEach((h) => hourBuckets[h]++);

  // Check if there's at least a 4-hour window with no activity (natural rest)
  let maxGap = 0;
  let currentGap = 0;
  for (let i = 0; i < 48; i++) {
    if (hourBuckets[i % 24] === 0) {
      currentGap++;
      maxGap = Math.max(maxGap, currentGap);
    } else {
      currentGap = 0;
    }
  }

  return maxGap >= 4;
}

// ─── Identity Score (max 20) ────────────────────────────────────

export function scoreIdentity(agent: AgentProfile): { score: number; findings: Finding[] } {
  let score = 0;
  const findings: Finding[] = [];

  if (agent.verified) {
    score += 10;
  } else {
    findings.push({
      severity: 'LOW',
      message: 'No X/Twitter verification',
      details: 'Agent has not verified their identity through X/Twitter',
    });
  }

  if (agent.claimed) {
    score += 5;
  } else {
    findings.push({
      severity: 'LOW',
      message: 'Account not claimed',
      details: 'Agent account has not been claimed by its owner',
    });
  }

  const ageDays = daysSince(agent.created_at);
  if (ageDays > 7) score += 3;
  if (ageDays > 30) score += 2;

  if (ageDays <= 7) {
    findings.push({
      severity: 'MEDIUM',
      message: `Account is only ${ageDays} day(s) old`,
      details: 'New accounts have limited trust history',
    });
  }

  return { score, findings };
}

// ─── Behavior Score (max 30) ────────────────────────────────────

export function scoreBehavior(
  agent: AgentProfile,
  posts: Post[]
): { score: number; findings: Finding[]; pattern: string } {
  let score = 0;
  const findings: Finding[] = [];
  let pattern = 'NORMAL';

  const ageDays = Math.max(1, daysSince(agent.created_at));
  const postsPerDay = posts.length / ageDays;
  const ratio = postsPerDay / BASELINE.platformAvgPostsPerDay;

  // Posting frequency (max 15)
  if (ratio <= 5) {
    score += 15;
  } else if (ratio <= 50) {
    score += 8;
    findings.push({
      severity: 'MEDIUM',
      message: `Posting frequency ${Math.round(ratio)}x above platform average`,
      details: `${postsPerDay.toFixed(1)} posts/day vs platform avg of ${BASELINE.platformAvgPostsPerDay}`,
    });
    pattern = 'HIGH_VOLUME';
  } else {
    findings.push({
      severity: 'HIGH',
      message: `Posting frequency ${Math.round(ratio)}x above platform average`,
      details: `Extremely high volume suggests automated behavior`,
    });
    pattern = 'SPAM-LIKE';
  }

  // Activity time distribution (max 5)
  const hasRest = analyzeActivityPattern(posts);
  if (hasRest) {
    score += 5;
  } else {
    score += 2;
    findings.push({
      severity: 'LOW',
      message: '24/7 activity pattern detected',
      details: 'No natural rest periods in posting schedule',
    });
    if (pattern === 'NORMAL') pattern = 'BOT-LIKE';
  }

  // Interaction diversity (max 5)
  const uniqueSubmolts = new Set(posts.map((p) => p.submolt)).size;
  if (uniqueSubmolts >= 3) {
    score += 5;
  } else {
    score += 2;
    if (uniqueSubmolts <= 1) {
      findings.push({
        severity: 'LOW',
        message: 'Activity limited to single submolt',
        details: 'Low interaction diversity may indicate targeted behavior',
      });
    }
  }

  // Karma ratio (max 5)
  const karmaRatio = agent.karma / Math.max(posts.length, 1);
  if (karmaRatio > 0.5) {
    score += 5;
  } else if (karmaRatio > 0.1) {
    score += 2;
  } else {
    findings.push({
      severity: 'LOW',
      message: 'Very low karma-to-post ratio',
      details: `Karma ratio: ${karmaRatio.toFixed(2)} (below 0.1 threshold)`,
    });
  }

  return { score, findings, pattern };
}

// ─── Content Risk Score (max 35, deduction-based) ───────────────

export function scoreContentRisk(
  posts: Post[],
  analyses: ContentAnalysis[]
): { score: number; findings: Finding[]; risk: string } {
  let score = 35;
  const findings: Finding[] = [];
  let risk = 'LOW';

  for (const analysis of analyses) {
    if (analysis.promptInjection) {
      score -= 10;
      findings.push({
        severity: 'HIGH',
        message: `Post contains prompt injection pattern`,
        details: analysis.ruleMatches
          .filter((m) => m.category === 'direct_injection')
          .map((m) => m.matchedText)
          .join(', '),
      });
    }

    if (analysis.credentialTheft) {
      score -= 15;
      findings.push({
        severity: 'HIGH',
        message: `Post attempts credential theft`,
        details: analysis.ruleMatches
          .filter((m) => m.category === 'credential_theft')
          .map((m) => m.matchedText)
          .join(', '),
      });
    }

    if (analysis.suspiciousLinks.length > 0) {
      score -= 5 * analysis.suspiciousLinks.length;
      findings.push({
        severity: 'MEDIUM',
        message: `Post contains ${analysis.suspiciousLinks.length} suspicious link(s)`,
        details: analysis.suspiciousLinks.join(', '),
      });
    }

    if (analysis.base64Hidden) {
      score -= 15;
      findings.push({
        severity: 'HIGH',
        message: `Post contains base64-encoded hidden instructions`,
      });
    }

    if (analysis.socialEngineering) {
      score -= 5;
      findings.push({
        severity: 'MEDIUM',
        message: `Post contains social engineering language`,
        details: analysis.ruleMatches
          .filter((m) => m.category === 'social_engineering')
          .map((m) => m.matchedText)
          .join(', '),
      });
    }

    if (analysis.maliciousUris.length > 0) {
      score -= 10;
      findings.push({
        severity: 'HIGH',
        message: `Post contains ${analysis.maliciousUris.length} malicious URI(s)`,
        details: analysis.maliciousUris.join(', '),
      });
    }

    if (analysis.obfuscatedEncoding) {
      score -= 15;
      findings.push({
        severity: 'HIGH',
        message: `Post contains obfuscated encoding with hidden threats`,
      });
    }

    if (analysis.base64DecodedThreats.length > 0) {
      score -= 10;
      findings.push({
        severity: 'HIGH',
        message: `Base64 deep scan found ${analysis.base64DecodedThreats.length} hidden threat(s)`,
        details: analysis.base64DecodedThreats.join('; '),
      });
    }

    // LLM result
    if (analysis.llmResult?.is_malicious && analysis.llmResult.confidence > 0.7) {
      score -= 10;
      findings.push({
        severity: 'HIGH',
        message: `LLM analysis flagged content as ${analysis.llmResult.category}`,
        details: analysis.llmResult.explanation,
      });
    }
  }

  // Duplicate content check
  const bodies = posts.map((p) => p.body || p.title);
  if (hasDuplicateContent(bodies)) {
    score -= 10;
    findings.push({
      severity: 'MEDIUM',
      message: 'High volume of duplicate/similar content detected',
    });
  }

  score = Math.max(0, score);

  if (score >= 30) risk = 'LOW';
  else if (score >= 20) risk = 'MODERATE';
  else if (score >= 10) risk = 'ELEVATED';
  else risk = 'CRITICAL';

  return { score, findings, risk };
}

// ─── Community Score (max 15) ───────────────────────────────────

export function scoreCommunity(
  agent: AgentProfile,
  posts: Post[]
): { score: number; findings: Finding[] } {
  let score = 0;
  const findings: Finding[] = [];

  // Karma above median
  if (agent.karma > BASELINE.medianKarma) {
    score += 5;
  }

  // High reputation replies
  const hasHighRepReplies = posts.some(
    (p) => p.replies?.some((r) => r.author_karma > BASELINE.highReputationThreshold)
  );
  if (hasHighRepReplies) {
    score += 5;
  }

  // Active submolt history
  const submolts = new Set(posts.map((p) => p.submolt));
  const hasActiveSubmoltHistory = [...submolts].some((s) =>
    (BASELINE.activeSubmolts as readonly string[]).includes(s)
  );
  if (hasActiveSubmoltHistory) {
    score += 5;
  }

  return { score, findings };
}

// ─── Final Score ────────────────────────────────────────────────

export function calculateTrustLevel(totalScore: number): TrustLevel {
  if (totalScore >= 90) return 'HIGH_TRUST';
  if (totalScore >= 70) return 'MODERATE';
  if (totalScore >= 50) return 'LOW_TRUST';
  return 'UNTRUSTED';
}

export function calculateBreakdown(
  identity: number,
  behavior: number,
  content: number,
  community: number
): ScoreBreakdown {
  return { identity, behavior, content, community };
}
