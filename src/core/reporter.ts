import { TrustReport, TrustLevel } from '../types/index.js';

// ─── Color / Emoji Helpers ──────────────────────────────────────

const LEVEL_DISPLAY: Record<TrustLevel, { label: string; color: string; emoji: string }> = {
  HIGH_TRUST: { label: 'HIGH TRUST', color: '\x1b[32m', emoji: '\u2705' },
  MODERATE: { label: 'MODERATE', color: '\x1b[33m', emoji: '\u26a0\ufe0f' },
  LOW_TRUST: { label: 'LOW TRUST', color: '\x1b[38;5;208m', emoji: '\u26a0\ufe0f' },
  UNTRUSTED: { label: 'UNTRUSTED', color: '\x1b[31m', emoji: '\u274c' },
};

const SEVERITY_EMOJI: Record<string, string> = {
  HIGH: '\u26a0\ufe0f HIGH',
  MEDIUM: '\u26a0\ufe0f MEDIUM',
  LOW: '\u2139\ufe0f LOW',
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

// ─── CLI Report ─────────────────────────────────────────────────

export function formatCLIReport(report: TrustReport, verbose = false): string {
  const display = LEVEL_DISPLAY[report.level];
  const width = 48;
  const hr = '\u2550'.repeat(width);
  const _thinHr = '\u2500'.repeat(width); // eslint-disable-line @typescript-eslint/no-unused-vars

  const lines: string[] = [];

  // Header
  lines.push(`\u2554${hr}\u2557`);
  lines.push(`\u2551  ${BOLD}AgentShield Trust Report: ${report.agentName}${RESET}${padRight('', width - 28 - report.agentName.length)}\u2551`);
  lines.push(`\u2560${hr}\u2563`);

  // Score
  lines.push(
    `\u2551  Trust Score:  ${display.color}${BOLD}${report.score}/100 ${display.emoji} ${display.label}${RESET}${padRight('', width - 30 - display.label.length - String(report.score).length)}\u2551`
  );
  lines.push(`\u2551  Account Age:  ${report.metadata.accountAge} days${padRight('', width - 18 - String(report.metadata.accountAge).length)}\u2551`);
  lines.push(`\u2551  Posts:        ${report.metadata.postCount}${padRight('', width - 16 - String(report.metadata.postCount).length)}\u2551`);
  lines.push(
    `\u2551  Verified:     ${report.metadata.verified ? '\u2705 Yes' : '\u274c No (unclaimed)'}${padRight('', width - (report.metadata.verified ? 20 : 28))}\u2551`
  );
  lines.push(`\u2551  Karma:        ${report.metadata.karma}${padRight('', width - 16 - String(report.metadata.karma).length)}\u2551`);

  // Findings
  if (report.findings.length > 0) {
    lines.push(`\u2560${hr}\u2563`);
    lines.push(`\u2551  ${BOLD}\ud83d\udd0d FINDINGS${RESET}${padRight('', width - 13)}\u2551`);
    lines.push(`\u2551${padRight('', width)}\u2551`);

    const maxFindings = verbose ? report.findings.length : Math.min(report.findings.length, 5);
    for (let i = 0; i < maxFindings; i++) {
      const f = report.findings[i];
      const emoji = SEVERITY_EMOJI[f.severity] || f.severity;
      const msg = `  ${emoji}: ${f.message}`;
      const truncated = msg.length > width - 2 ? msg.slice(0, width - 5) + '...' : msg;
      lines.push(`\u2551${truncated}${padRight('', width - stripAnsi(truncated).length)}\u2551`);

      if (verbose && f.details) {
        const detail = `     ${f.details}`;
        const detailTruncated = detail.length > width - 2 ? detail.slice(0, width - 5) + '...' : detail;
        lines.push(`\u2551${DIM}${detailTruncated}${RESET}${padRight('', width - detailTruncated.length)}\u2551`);
      }
      lines.push(`\u2551${padRight('', width)}\u2551`);
    }

    if (!verbose && report.findings.length > 5) {
      lines.push(`\u2551  ${DIM}... and ${report.findings.length - 5} more (use -v for details)${RESET}${padRight('', width - 40 - String(report.findings.length - 5).length)}\u2551`);
      lines.push(`\u2551${padRight('', width)}\u2551`);
    }
  }

  // Patterns
  lines.push(`\u2551  \ud83d\udcca Behavioral Pattern: ${BOLD}${report.behavioralPattern}${RESET}${padRight('', width - 27 - report.behavioralPattern.length)}\u2551`);
  lines.push(`\u2551  \ud83d\udcca Content Risk: ${BOLD}${report.contentRisk}${RESET}${padRight('', width - 20 - report.contentRisk.length)}\u2551`);

  // Score breakdown
  if (verbose) {
    lines.push(`\u2560${hr}\u2563`);
    lines.push(`\u2551  ${BOLD}SCORE BREAKDOWN${RESET}${padRight('', width - 17)}\u2551`);
    lines.push(`\u2551  Identity:   ${report.breakdown.identity}/20${padRight('', width - 18 - String(report.breakdown.identity).length)}\u2551`);
    lines.push(`\u2551  Behavior:   ${report.breakdown.behavior}/30${padRight('', width - 18 - String(report.breakdown.behavior).length)}\u2551`);
    lines.push(`\u2551  Content:    ${report.breakdown.content}/35${padRight('', width - 18 - String(report.breakdown.content).length)}\u2551`);
    lines.push(`\u2551  Community:  ${report.breakdown.community}/15${padRight('', width - 18 - String(report.breakdown.community).length)}\u2551`);
  }

  // Footer
  lines.push(`\u255a${hr}\u255d`);

  return lines.join('\n');
}

// ─── JSON Report ────────────────────────────────────────────────

export function formatJSONReport(report: TrustReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── HTML Report (Mac theme) ────────────────────────────────────

export function formatHTMLReport(report: TrustReport): string {
  const display = LEVEL_DISPLAY[report.level];
  const levelColor = {
    HIGH_TRUST: '#34C759',
    MODERATE: '#FF9F0A',
    LOW_TRUST: '#FF6B35',
    UNTRUSTED: '#FF3B30',
  }[report.level];

  const scorePercent = report.score;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield Report: ${report.agentName}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', sans-serif;
    background: #1C1C1E;
    color: #F2F2F7;
    min-height: 100vh;
    padding: 40px 20px;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 680px; margin: 0 auto; }
  .card {
    background: #2C2C2E;
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 16px;
    border: 1px solid #3A3A3C;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
  }
  .header {
    text-align: center;
    margin-bottom: 32px;
  }
  .header h1 {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 4px;
  }
  .header .subtitle {
    color: #8E8E93;
    font-size: 15px;
    font-weight: 400;
  }
  .score-ring {
    width: 160px; height: 160px;
    margin: 24px auto;
    position: relative;
  }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring .value {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    font-size: 42px;
    font-weight: 700;
    letter-spacing: -1px;
  }
  .score-ring .label {
    position: absolute;
    bottom: 18px; left: 50%;
    transform: translateX(-50%);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: ${levelColor};
  }
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-top: 20px;
  }
  .meta-item {
    background: #3A3A3C;
    border-radius: 12px;
    padding: 14px 16px;
  }
  .meta-item .meta-label {
    font-size: 12px;
    color: #8E8E93;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
  }
  .meta-item .meta-value {
    font-size: 20px;
    font-weight: 600;
  }
  .section-title {
    font-size: 13px;
    font-weight: 600;
    color: #8E8E93;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 12px;
  }
  .finding {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 0;
    border-bottom: 1px solid #3A3A3C;
  }
  .finding:last-child { border-bottom: none; }
  .finding .badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 6px;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .badge-high { background: rgba(255,59,48,0.2); color: #FF453A; }
  .badge-medium { background: rgba(255,159,10,0.2); color: #FF9F0A; }
  .badge-low { background: rgba(142,142,147,0.2); color: #8E8E93; }
  .finding .text { font-size: 14px; line-height: 1.4; }
  .finding .detail { font-size: 12px; color: #8E8E93; margin-top: 2px; }
  .breakdown-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
  }
  .breakdown-bar .name {
    width: 90px;
    font-size: 13px;
    color: #8E8E93;
  }
  .breakdown-bar .track {
    flex: 1;
    height: 8px;
    background: #3A3A3C;
    border-radius: 4px;
    overflow: hidden;
  }
  .breakdown-bar .fill {
    height: 100%;
    border-radius: 4px;
    background: ${levelColor};
    transition: width 0.6s ease;
  }
  .breakdown-bar .val {
    width: 50px;
    text-align: right;
    font-size: 14px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .pattern-badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 4px;
  }
  .pattern-badge {
    font-size: 13px;
    font-weight: 500;
    padding: 6px 14px;
    border-radius: 20px;
    background: #3A3A3C;
  }
  .footer {
    text-align: center;
    margin-top: 24px;
    font-size: 12px;
    color: #48484A;
  }
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>\ud83d\udee1\ufe0f AgentShield</h1>
    <div class="subtitle">Trust Report for ${report.agentName}</div>
  </div>

  <div class="card" style="text-align:center;">
    <div class="score-ring">
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="70" fill="none" stroke="#3A3A3C" stroke-width="10"/>
        <circle cx="80" cy="80" r="70" fill="none" stroke="${levelColor}" stroke-width="10"
          stroke-dasharray="${(scorePercent / 100) * 440} 440"
          stroke-linecap="round"/>
      </svg>
      <div class="value" style="color:${levelColor}">${report.score}</div>
      <div class="label">${display.label}</div>
    </div>

    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Account Age</div>
        <div class="meta-value">${report.metadata.accountAge}d</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Posts</div>
        <div class="meta-value">${report.metadata.postCount}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Verified</div>
        <div class="meta-value">${report.metadata.verified ? '\u2705 Yes' : '\u274c No'}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Karma</div>
        <div class="meta-value">${report.metadata.karma}</div>
      </div>
    </div>
  </div>

  ${report.findings.length > 0 ? `
  <div class="card">
    <div class="section-title">Findings</div>
    ${report.findings.map(f => `
    <div class="finding">
      <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
      <div>
        <div class="text">${escapeHtml(f.message)}</div>
        ${f.details ? `<div class="detail">${escapeHtml(f.details)}</div>` : ''}
      </div>
    </div>`).join('')}
  </div>` : ''}

  <div class="card">
    <div class="section-title">Score Breakdown</div>
    <div class="breakdown-bar">
      <div class="name">Identity</div>
      <div class="track"><div class="fill" style="width:${(report.breakdown.identity / 20) * 100}%"></div></div>
      <div class="val">${report.breakdown.identity}/20</div>
    </div>
    <div class="breakdown-bar">
      <div class="name">Behavior</div>
      <div class="track"><div class="fill" style="width:${(report.breakdown.behavior / 30) * 100}%"></div></div>
      <div class="val">${report.breakdown.behavior}/30</div>
    </div>
    <div class="breakdown-bar">
      <div class="name">Content</div>
      <div class="track"><div class="fill" style="width:${(report.breakdown.content / 35) * 100}%"></div></div>
      <div class="val">${report.breakdown.content}/35</div>
    </div>
    <div class="breakdown-bar">
      <div class="name">Community</div>
      <div class="track"><div class="fill" style="width:${(report.breakdown.community / 15) * 100}%"></div></div>
      <div class="val">${report.breakdown.community}/15</div>
    </div>
  </div>

  <div class="card">
    <div class="section-title">Analysis</div>
    <div class="pattern-badges">
      <span class="pattern-badge">\ud83d\udcca Behavioral: ${report.behavioralPattern}</span>
      <span class="pattern-badge">\ud83d\udee1\ufe0f Content Risk: ${report.contentRisk}</span>
    </div>
  </div>

  <div class="footer">
    Scanned at ${report.metadata.scannedAt} &bull; AgentShield v0.1.0
  </div>

</div>
</body>
</html>`;
}

// ─── Helpers ────────────────────────────────────────────────────

function padRight(str: string, len: number): string {
  if (len <= 0) return '';
  return str + ' '.repeat(len);
}

function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
