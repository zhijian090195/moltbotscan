#!/usr/bin/env ts-node

/**
 * Batch scan Moltbook posts from HuggingFace dataset (ronantakizawa/moltbook)
 * Downloads 6,105 public posts and runs AgentShield scanSync() on each.
 *
 * Usage: npx ts-node src/data/batch-scan.ts
 */

import { analyzeContent } from '../analysis/rules.js';
import { ContentAnalysis } from '../types/index.js';
import * as fs from 'fs';
import * as path from 'path';

// ─── HuggingFace Dataset API ────────────────────────────────────

const HF_API = 'https://datasets-server.huggingface.co/rows';
const DATASET = 'ronantakizawa/moltbook';
const CONFIG = 'posts';
const SPLIT = 'train';
const PAGE_SIZE = 100;

interface HFRow {
  row: {
    id: string;
    title: string;
    content: string;
    author: string;
    submolt: string;
    upvotes: number;
    downvotes: number;
    score: number;
    comment_count: number;
    created_at: string;
    post_url: string;
  };
}

interface HFResponse {
  rows: HFRow[];
  num_rows_total: number;
}

const THROTTLE_MS = 200;       // delay between requests
const MAX_RETRIES = 5;
const CACHE_FILE = path.join(__dirname, '../../results/dataset-cache.json');

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchPage(offset: number, attempt = 0): Promise<HFResponse> {
  const url = `${HF_API}?dataset=${encodeURIComponent(DATASET)}&config=${CONFIG}&split=${SPLIT}&offset=${offset}&length=${PAGE_SIZE}`;
  const res = await fetch(url, {
    headers: { 'User-Agent': 'AgentShield/0.1.0' },
  });

  if (res.status === 429) {
    if (attempt >= MAX_RETRIES) {
      throw new Error('Rate limited after max retries');
    }
    const backoff = Math.pow(2, attempt + 1) * 1000; // 2s, 4s, 8s, 16s, 32s
    process.stdout.write(`\n⏳ Rate limited, waiting ${backoff / 1000}s...`);
    await sleep(backoff);
    return fetchPage(offset, attempt + 1);
  }

  if (!res.ok) {
    throw new Error(`HuggingFace API error: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as HFResponse;
}

async function fetchAllPosts(): Promise<HFRow['row'][]> {
  // Check cache first
  if (fs.existsSync(CACHE_FILE)) {
    console.log('📦 Loading from cache...');
    const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf-8')) as HFRow['row'][];
    console.log(`📊 Loaded ${cached.length} posts from cache`);
    return cached;
  }

  const first = await fetchPage(0);
  const total = first.num_rows_total;
  const posts = first.rows.map((r) => r.row);
  console.log(`📊 Dataset total: ${total} posts`);

  for (let offset = PAGE_SIZE; offset < total; offset += PAGE_SIZE) {
    await sleep(THROTTLE_MS);
    const page = await fetchPage(offset);
    posts.push(...page.rows.map((r) => r.row));
    const pct = Math.round((posts.length / total) * 100);
    process.stdout.write(`\r⬇️  Downloaded ${posts.length}/${total} (${pct}%)`);
  }
  console.log('\n');

  // Save cache
  const cacheDir = path.dirname(CACHE_FILE);
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
  fs.writeFileSync(CACHE_FILE, JSON.stringify(posts));
  console.log('💾 Dataset cached for future runs\n');

  return posts;
}

// ─── Scan & Stats ───────────────────────────────────────────────

type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

function classifyRisk(analysis: ContentAnalysis): RiskLevel {
  const hasHigh = analysis.ruleMatches.some((m) => m.severity === 'HIGH');
  const hasMedium = analysis.ruleMatches.some((m) => m.severity === 'MEDIUM');
  if (hasHigh || analysis.promptInjection || analysis.credentialTheft) return 'HIGH';
  if (hasMedium || analysis.socialEngineering || analysis.base64Hidden) return 'MEDIUM';
  if (analysis.suspiciousLinks.length > 0) return 'LOW';
  return 'SAFE';
}

interface ScanStats {
  total: number;
  byRisk: Record<RiskLevel, number>;
  byCategory: Record<string, number>;
  bySubmolt: Record<string, { total: number; flagged: number }>;
  topOffenders: { author: string; highCount: number; posts: string[] }[];
  examples: { risk: RiskLevel; author: string; submolt: string; title: string; finding: string; matchedText: string }[];
  avgScanTimeMs: number;
}

async function runBatchScan() {
  console.log('🛡️  AgentShield Batch Scanner');
  console.log('─'.repeat(50));
  console.log(`Dataset: HuggingFace ${DATASET}\n`);

  const posts = await fetchAllPosts();

  const stats: ScanStats = {
    total: posts.length,
    byRisk: { HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 },
    byCategory: {},
    bySubmolt: {},
    topOffenders: [],
    examples: [],
    avgScanTimeMs: 0,
  };

  const authorHigh: Record<string, { count: number; posts: string[] }> = {};
  let totalTimeMs = 0;

  for (let i = 0; i < posts.length; i++) {
    const post = posts[i];
    const text = `${post.title}\n${post.content || ''}`;

    const start = performance.now();
    const analysis = analyzeContent(text, post.id);
    totalTimeMs += performance.now() - start;

    const risk = classifyRisk(analysis);
    stats.byRisk[risk]++;

    // Track submolt stats
    if (!stats.bySubmolt[post.submolt]) {
      stats.bySubmolt[post.submolt] = { total: 0, flagged: 0 };
    }
    stats.bySubmolt[post.submolt].total++;
    if (risk !== 'SAFE') {
      stats.bySubmolt[post.submolt].flagged++;
    }

    // Track categories
    for (const m of analysis.ruleMatches) {
      stats.byCategory[m.category] = (stats.byCategory[m.category] || 0) + 1;
    }

    // Track high-risk authors
    if (risk === 'HIGH') {
      if (!authorHigh[post.author]) {
        authorHigh[post.author] = { count: 0, posts: [] };
      }
      authorHigh[post.author].count++;
      authorHigh[post.author].posts.push(post.id);
    }

    // Collect example findings (limit to 20)
    if (risk !== 'SAFE' && stats.examples.length < 20) {
      const firstMatch = analysis.ruleMatches[0];
      stats.examples.push({
        risk,
        author: post.author,
        submolt: post.submolt,
        title: post.title.slice(0, 80),
        finding: firstMatch?.pattern || (analysis.suspiciousLinks.length > 0 ? 'suspicious_link' : 'unknown'),
        matchedText: firstMatch?.matchedText?.slice(0, 100) || '',
      });
    }

    // Progress
    if ((i + 1) % 500 === 0 || i === posts.length - 1) {
      process.stdout.write(`\r🔍 Scanned ${i + 1}/${posts.length}`);
    }
  }
  console.log('\n');

  stats.avgScanTimeMs = totalTimeMs / posts.length;

  // Top offenders (authors with most HIGH findings)
  stats.topOffenders = Object.entries(authorHigh)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 10)
    .map(([author, data]) => ({
      author,
      highCount: data.count,
      posts: data.posts.slice(0, 5),
    }));

  printReport(stats);
  saveResults(stats);
}

// ─── Output ─────────────────────────────────────────────────────

function printReport(stats: ScanStats) {
  const { total, byRisk, byCategory, topOffenders, avgScanTimeMs } = stats;
  const flagged = total - byRisk.SAFE;
  const flaggedPct = ((flagged / total) * 100).toFixed(1);

  console.log('═'.repeat(50));
  console.log('  AGENTSHIELD BATCH SCAN REPORT');
  console.log('═'.repeat(50));
  console.log();
  console.log(`  Total posts scanned:  ${total.toLocaleString()}`);
  console.log(`  Flagged (non-SAFE):   ${flagged.toLocaleString()} (${flaggedPct}%)`);
  console.log(`  Avg scan time:        ${avgScanTimeMs.toFixed(2)}ms per post`);
  console.log();
  console.log('  ─── Risk Distribution ───');
  console.log(`  🔴 HIGH:   ${byRisk.HIGH.toString().padStart(5)}  (${((byRisk.HIGH / total) * 100).toFixed(1)}%)`);
  console.log(`  🟡 MEDIUM: ${byRisk.MEDIUM.toString().padStart(5)}  (${((byRisk.MEDIUM / total) * 100).toFixed(1)}%)`);
  console.log(`  🟠 LOW:    ${byRisk.LOW.toString().padStart(5)}  (${((byRisk.LOW / total) * 100).toFixed(1)}%)`);
  console.log(`  🟢 SAFE:   ${byRisk.SAFE.toString().padStart(5)}  (${((byRisk.SAFE / total) * 100).toFixed(1)}%)`);
  console.log();

  if (Object.keys(byCategory).length > 0) {
    console.log('  ─── Threat Categories ───');
    for (const [cat, count] of Object.entries(byCategory).sort(([, a], [, b]) => b - a)) {
      console.log(`  ${cat.padEnd(22)} ${count}`);
    }
    console.log();
  }

  if (topOffenders.length > 0) {
    console.log('  ─── Top Risk Authors ───');
    for (const o of topOffenders.slice(0, 5)) {
      console.log(`  @${o.author.padEnd(20)} ${o.highCount} HIGH finding(s)`);
    }
    console.log();
  }

  // Top risky submolts
  const riskySubmolts = Object.entries(stats.bySubmolt)
    .filter(([, s]) => s.flagged > 0)
    .sort(([, a], [, b]) => b.flagged - a.flagged)
    .slice(0, 5);

  if (riskySubmolts.length > 0) {
    console.log('  ─── Riskiest Submolts ───');
    for (const [name, s] of riskySubmolts) {
      const pct = ((s.flagged / s.total) * 100).toFixed(0);
      console.log(`  s/${name.padEnd(20)} ${s.flagged}/${s.total} flagged (${pct}%)`);
    }
    console.log();
  }

  console.log('═'.repeat(50));
}

function saveResults(stats: ScanStats) {
  const outDir = path.join(__dirname, '../../results');
  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outPath = path.join(outDir, `batch-scan-${timestamp}.json`);
  fs.writeFileSync(outPath, JSON.stringify(stats, null, 2));
  console.log(`\n💾 Full results saved to: ${outPath}`);

  // Also generate a README snippet
  const snippet = generateReadmeSnippet(stats);
  const snippetPath = path.join(outDir, `readme-snippet.md`);
  fs.writeFileSync(snippetPath, snippet);
  console.log(`📝 README snippet saved to: ${snippetPath}`);
}

function generateReadmeSnippet(stats: ScanStats): string {
  const { total, byRisk, byCategory, avgScanTimeMs } = stats;
  const flagged = total - byRisk.SAFE;

  let md = `## Real-World Results\n\n`;
  md += `We scanned **${total.toLocaleString()} public Moltbook posts** from the `;
  md += `[ronantakizawa/moltbook](https://huggingface.co/datasets/ronantakizawa/moltbook) dataset.\n\n`;
  md += `| Risk Level | Count | % |\n`;
  md += `|:---:|---:|---:|\n`;
  md += `| HIGH | ${byRisk.HIGH} | ${((byRisk.HIGH / total) * 100).toFixed(1)}% |\n`;
  md += `| MEDIUM | ${byRisk.MEDIUM} | ${((byRisk.MEDIUM / total) * 100).toFixed(1)}% |\n`;
  md += `| LOW | ${byRisk.LOW} | ${((byRisk.LOW / total) * 100).toFixed(1)}% |\n`;
  md += `| SAFE | ${byRisk.SAFE} | ${((byRisk.SAFE / total) * 100).toFixed(1)}% |\n\n`;
  md += `**${flagged} posts** (${((flagged / total) * 100).toFixed(1)}%) contained potential threats `;
  md += `including ${Object.entries(byCategory).map(([c, n]) => `${n} ${c.replace(/_/g, ' ')}`).join(', ')}.\n\n`;
  md += `Average scan time: **${avgScanTimeMs.toFixed(2)}ms** per post (rules engine only, no LLM).\n`;

  return md;
}

// ─── Run ────────────────────────────────────────────────────────

runBatchScan().catch((err) => {
  console.error('\n❌ Batch scan failed:', err.message);
  process.exit(1);
});
