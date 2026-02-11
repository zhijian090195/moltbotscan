import { AgentProfile, Post, Comment } from '../types/index.js';

const BASE_URL = 'https://www.moltbook.com/api/v1';
const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

export class MoltbookClient {
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.MOLTBOOK_API_KEY || '';
    if (!this.apiKey) {
      throw new Error(
        'Moltbook API key is required. Set MOLTBOOK_API_KEY environment variable or pass it to the constructor.'
      );
    }
  }

  private async fetchWithRetry(url: string, retries = MAX_RETRIES): Promise<Response> {
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const response = await fetch(url, {
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'User-Agent': 'AgentShield/0.1.0',
          },
        });

        if (response.status === 429) {
          const delay = BASE_DELAY_MS * Math.pow(2, attempt);
          await this.sleep(delay);
          continue;
        }

        if (!response.ok) {
          throw new Error(`Moltbook API error: ${response.status} ${response.statusText}`);
        }

        return response;
      } catch (error) {
        if (attempt === retries) throw error;
        const delay = BASE_DELAY_MS * Math.pow(2, attempt);
        await this.sleep(delay);
      }
    }

    throw new Error('Max retries exceeded');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async searchAgent(agentName: string): Promise<AgentProfile | null> {
    const name = agentName.replace(/^@/, '');
    const response = await this.fetchWithRetry(
      `${BASE_URL}/search?q=${encodeURIComponent(name)}&type=agent`
    );
    const data = await response.json() as { agents: AgentProfile[] };

    if (!data.agents || data.agents.length === 0) return null;

    const exact = data.agents.find(
      (a) => a.name.toLowerCase() === name.toLowerCase()
    );
    return exact || data.agents[0];
  }

  async getAgentProfile(agentName: string): Promise<AgentProfile> {
    const name = agentName.replace(/^@/, '');
    const response = await this.fetchWithRetry(
      `${BASE_URL}/agents/${encodeURIComponent(name)}`
    );
    return (await response.json()) as AgentProfile;
  }

  async getAgentPosts(agentName: string, limit = 100): Promise<Post[]> {
    const name = agentName.replace(/^@/, '');
    const posts: Post[] = [];
    let page = 1;
    const perPage = Math.min(limit, 25);

    while (posts.length < limit) {
      const response = await this.fetchWithRetry(
        `${BASE_URL}/agents/${encodeURIComponent(name)}/posts?page=${page}&per_page=${perPage}`
      );
      const data = await response.json() as { posts: Post[] };

      if (!data.posts || data.posts.length === 0) break;

      posts.push(...data.posts);
      page++;

      if (data.posts.length < perPage) break;
    }

    return posts.slice(0, limit);
  }

  async getAgentComments(agentName: string, limit = 100): Promise<Comment[]> {
    const name = agentName.replace(/^@/, '');
    const response = await this.fetchWithRetry(
      `${BASE_URL}/agents/${encodeURIComponent(name)}/comments?per_page=${limit}`
    );
    const data = await response.json() as { comments: Comment[] };
    return data.comments || [];
  }

  async getPostComments(postId: string): Promise<Comment[]> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/posts/${postId}/comments`
    );
    const data = await response.json() as { comments: Comment[] };
    return data.comments || [];
  }
}
