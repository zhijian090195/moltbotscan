import {
  scoreIdentity,
  scoreBehavior,
  scoreContentRisk,
  scoreCommunity,
  calculateTrustLevel,
} from '../src/core/scorer';
import { AgentProfile, Post, ContentAnalysis } from '../src/types';
import benignData from './fixtures/benign.json';
import maliciousData from './fixtures/malicious.json';

const benignAgent = benignData.agent as AgentProfile;
const benignPosts = benignData.posts as Post[];
const maliciousAgent = maliciousData.agent as AgentProfile;
const maliciousPosts = maliciousData.posts as Post[];

describe('Identity Scoring', () => {
  it('gives max score to verified + claimed + old account', () => {
    const { score } = scoreIdentity(benignAgent);
    expect(score).toBe(20); // verified(10) + claimed(5) + >7d(3) + >30d(2)
  });

  it('gives low score to unverified new account', () => {
    const { score, findings } = scoreIdentity(maliciousAgent);
    expect(score).toBeLessThanOrEqual(5);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Behavior Scoring', () => {
  it('gives high score to normal posting behavior', () => {
    const { score, pattern } = scoreBehavior(benignAgent, benignPosts);
    expect(score).toBeGreaterThanOrEqual(20);
    expect(pattern).toBe('NORMAL');
  });

  it('flags spam-like posting behavior with high volume', () => {
    // Simulate a truly spam-like agent: 500 posts in 6 days
    const spamPosts: Post[] = Array.from({ length: 500 }, (_, i) => ({
      id: `spam_${i}`,
      title: 'Spam post',
      body: 'Same content repeated',
      author: 'SpamBot',
      author_karma: 1,
      submolt: 'general',
      created_at: '2026-02-06T03:00:00Z',
      score: -1,
      comment_count: 0,
    }));
    const { score, pattern, findings } = scoreBehavior(maliciousAgent, spamPosts);
    expect(score).toBeLessThan(20);
    expect(findings.length).toBeGreaterThan(0);
    expect(['SPAM-LIKE', 'HIGH_VOLUME', 'BOT-LIKE']).toContain(pattern);
  });

  it('does not give max behavior score to suspicious agent', () => {
    const { score } = scoreBehavior(maliciousAgent, maliciousPosts);
    expect(score).toBeLessThan(30);
  });
});

describe('Content Risk Scoring', () => {
  it('gives full score for benign content', () => {
    const analyses: ContentAnalysis[] = benignPosts.map((p) => ({
      postId: p.id,
      ruleMatches: [],
      promptInjection: false,
      credentialTheft: false,
      suspiciousLinks: [],
      base64Hidden: false,
      socialEngineering: false,
    }));

    const { score, risk } = scoreContentRisk(benignPosts, analyses);
    expect(score).toBe(35);
    expect(risk).toBe('LOW');
  });

  it('deducts for malicious content', () => {
    const analyses: ContentAnalysis[] = [
      {
        postId: 'post_m001',
        ruleMatches: [],
        promptInjection: true,
        credentialTheft: true,
        suspiciousLinks: [],
        base64Hidden: false,
        socialEngineering: false,
      },
      {
        postId: 'post_m003',
        ruleMatches: [],
        promptInjection: false,
        credentialTheft: false,
        suspiciousLinks: ['https://evil-site.xyz/payload'],
        base64Hidden: false,
        socialEngineering: true,
      },
    ];

    const { score, risk } = scoreContentRisk(maliciousPosts, analyses);
    expect(score).toBeLessThan(20);
    expect(['ELEVATED', 'CRITICAL']).toContain(risk);
  });

  it('score never goes below 0', () => {
    const extremeAnalyses: ContentAnalysis[] = Array(10).fill({
      postId: 'x',
      ruleMatches: [],
      promptInjection: true,
      credentialTheft: true,
      suspiciousLinks: ['https://a.xyz', 'https://b.xyz'],
      base64Hidden: true,
      socialEngineering: true,
    });

    const { score } = scoreContentRisk([], extremeAnalyses);
    expect(score).toBe(0);
  });
});

describe('Community Scoring', () => {
  it('gives points for high karma agent', () => {
    const { score } = scoreCommunity(benignAgent, benignPosts);
    expect(score).toBeGreaterThan(0);
  });

  it('gives low score for low karma agent', () => {
    const { score } = scoreCommunity(maliciousAgent, maliciousPosts);
    expect(score).toBeLessThanOrEqual(5);
  });
});

describe('Trust Level Calculation', () => {
  it('classifies HIGH_TRUST correctly', () => {
    expect(calculateTrustLevel(95)).toBe('HIGH_TRUST');
    expect(calculateTrustLevel(90)).toBe('HIGH_TRUST');
  });

  it('classifies MODERATE correctly', () => {
    expect(calculateTrustLevel(85)).toBe('MODERATE');
    expect(calculateTrustLevel(70)).toBe('MODERATE');
  });

  it('classifies LOW_TRUST correctly', () => {
    expect(calculateTrustLevel(65)).toBe('LOW_TRUST');
    expect(calculateTrustLevel(50)).toBe('LOW_TRUST');
  });

  it('classifies UNTRUSTED correctly', () => {
    expect(calculateTrustLevel(49)).toBe('UNTRUSTED');
    expect(calculateTrustLevel(0)).toBe('UNTRUSTED');
  });
});
