import { AgentProfile, Post } from '../types/index.js';

const APIFY_BASE = 'https://api.apify.com/v2';
const ACTOR_ID = 'lofomachines~moltbook-scraper';

export class MoltbookScraper {
  private apifyToken: string;

  constructor(apifyToken?: string) {
    this.apifyToken = apifyToken || process.env.APIFY_TOKEN || '';
  }

  get isAvailable(): boolean {
    return this.apifyToken.length > 0;
  }

  async scrapeAgent(agentName: string): Promise<{
    profile: AgentProfile | null;
    posts: Post[];
  }> {
    if (!this.isAvailable) {
      throw new Error('Apify token not configured. Set APIFY_TOKEN environment variable.');
    }

    const name = agentName.replace(/^@/, '');

    const runResponse = await fetch(
      `${APIFY_BASE}/acts/${ACTOR_ID}/runs?token=${this.apifyToken}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          startUrls: [{ url: `https://www.moltbook.com/agent/${name}` }],
          maxItems: 100,
          scrapeComments: true,
        }),
      }
    );

    if (!runResponse.ok) {
      throw new Error(`Apify run failed: ${runResponse.status}`);
    }

    const run = await runResponse.json() as { data: { id: string } };
    const runId = run.data.id;

    // Poll for completion
    let status = 'RUNNING';
    while (status === 'RUNNING' || status === 'READY') {
      await new Promise((r) => setTimeout(r, 3000));
      const statusResponse = await fetch(
        `${APIFY_BASE}/actor-runs/${runId}?token=${this.apifyToken}`
      );
      const statusData = await statusResponse.json() as { data: { status: string } };
      status = statusData.data.status;
    }

    if (status !== 'SUCCEEDED') {
      throw new Error(`Apify run ended with status: ${status}`);
    }

    // Fetch results
    const datasetResponse = await fetch(
      `${APIFY_BASE}/actor-runs/${runId}/dataset/items?token=${this.apifyToken}`
    );
    const items = await datasetResponse.json() as Array<Record<string, unknown>>;

    const profile = this.extractProfile(items, name);
    const posts = this.extractPosts(items);

    return { profile, posts };
  }

  private extractProfile(items: Array<Record<string, unknown>>, name: string): AgentProfile | null {
    const agentItem = items.find((i) => i.type === 'agent');
    if (!agentItem) return null;

    return {
      id: String(agentItem.id || ''),
      name,
      display_name: String(agentItem.display_name || name),
      bio: String(agentItem.bio || ''),
      karma: Number(agentItem.karma) || 0,
      verified: Boolean(agentItem.verified),
      claimed: Boolean(agentItem.claimed),
      created_at: String(agentItem.created_at || ''),
      post_count: Number(agentItem.post_count) || 0,
      comment_count: Number(agentItem.comment_count) || 0,
    };
  }

  private extractPosts(items: Array<Record<string, unknown>>): Post[] {
    return items
      .filter((i) => i.type === 'post')
      .map((i) => ({
        id: String(i.id || ''),
        title: String(i.title || ''),
        body: String(i.body || ''),
        author: String(i.author || ''),
        author_karma: Number(i.author_karma) || 0,
        submolt: String(i.submolt || ''),
        created_at: String(i.created_at || ''),
        score: Number(i.score) || 0,
        comment_count: Number(i.comment_count) || 0,
      }));
  }
}
