import { MoltbookClient } from '../data/moltbook.js';
import { MoltbookScraper } from '../data/scraper.js';
import { analyzeContent, needsLLMAnalysis } from '../analysis/rules.js';
import { LLMAnalyzer } from '../analysis/llm.js';
import {
  scoreIdentity,
  scoreBehavior,
  scoreContentRisk,
  scoreCommunity,
  calculateTrustLevel,
} from './scorer.js';
import {
  TrustReport, ScanOptions, DEFAULT_SCAN_OPTIONS,
  ContentAnalysis, Finding, Post, AgentProfile,
} from '../types/index.js';

export class Scanner {
  private client: MoltbookClient;
  private scraper: MoltbookScraper;
  private llm: LLMAnalyzer;

  constructor() {
    this.client = new MoltbookClient();
    this.scraper = new MoltbookScraper();
    this.llm = new LLMAnalyzer();
  }

  async scan(agentName: string, opts?: Partial<ScanOptions>): Promise<TrustReport> {
    const options = { ...DEFAULT_SCAN_OPTIONS, ...opts };
    const name = agentName.replace(/^@/, '');

    // 1. Fetch agent profile
    let profile: AgentProfile;
    let posts: Post[];

    try {
      profile = await this.client.getAgentProfile(name);
      posts = await this.client.getAgentPosts(name, options.maxPosts);
    } catch (error) {
      // Fallback to scraper if API fails
      if (this.scraper.isAvailable) {
        const scraped = await this.scraper.scrapeAgent(name);
        if (!scraped.profile) {
          throw new Error(`Agent @${name} not found on Moltbook`);
        }
        profile = scraped.profile;
        posts = scraped.posts;
      } else {
        throw new Error(
          `Failed to fetch agent @${name}: ${error instanceof Error ? error.message : 'unknown error'}`
        );
      }
    }

    // 2. Analyze all post content
    const analyses: ContentAnalysis[] = [];
    for (const post of posts) {
      const content = `${post.title} ${post.body}`.trim();
      if (!content) continue;

      const analysis = analyzeContent(content, post.id);

      // Deep LLM analysis for suspicious content
      if (!options.skipLLM && needsLLMAnalysis(analysis) && this.llm.isAvailable) {
        analysis.llmResult = await this.llm.analyze(content);
      }

      analyses.push(analysis);
    }

    // 3. Calculate scores across all four dimensions
    const identityResult = scoreIdentity(profile);
    const behaviorResult = scoreBehavior(profile, posts);
    const contentResult = scoreContentRisk(posts, analyses);
    const communityResult = scoreCommunity(profile, posts);

    // 4. Calculate total score
    const totalScore =
      identityResult.score +
      behaviorResult.score +
      contentResult.score +
      communityResult.score;

    // 5. Merge all findings
    const allFindings: Finding[] = [
      ...contentResult.findings,
      ...behaviorResult.findings,
      ...identityResult.findings,
      ...communityResult.findings,
    ];

    // Sort findings by severity
    const severityOrder: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    allFindings.sort(
      (a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3)
    );

    // 6. Build report
    const daysSinceCreation = Math.max(
      0,
      Math.floor(
        (Date.now() - new Date(profile.created_at).getTime()) / (1000 * 60 * 60 * 24)
      )
    );

    return {
      agentName: `@${name}`,
      score: totalScore,
      level: calculateTrustLevel(totalScore),
      breakdown: {
        identity: identityResult.score,
        behavior: behaviorResult.score,
        content: contentResult.score,
        community: communityResult.score,
      },
      findings: allFindings,
      behavioralPattern: behaviorResult.pattern,
      contentRisk: contentResult.risk,
      metadata: {
        accountAge: daysSinceCreation,
        postCount: posts.length,
        verified: profile.verified,
        claimed: profile.claimed,
        karma: profile.karma,
        scannedAt: new Date().toISOString(),
      },
    };
  }
}
