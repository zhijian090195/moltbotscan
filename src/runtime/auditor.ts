import {
  AuditPolicy,
  AuditResult,
  AuditFinding,
  ToolCallRecord,
  RiskLevel,
  Severity,
} from '../types/index.js';
import { ContentScanner } from '../sdk/scanner.js';

// ─── Default Sensitive Paths ─────────────────────────────────────

const DEFAULT_SENSITIVE_PATHS = [
  /~\/\.(ssh|aws|env|gnupg|config\/gcloud|azure|kube)/i,
  /\/etc\/(passwd|shadow|sudoers)/i,
  /\.(pem|key|pfx|p12|jks|keystore)$/i,
  /\.(env|env\.local|env\.prod)/i,
  /credentials\.json/i,
  /secrets?\.(json|yaml|yml|toml)/i,
  /\/\.git\//i,
];

// ─── Suspicious Argument Patterns ────────────────────────────────

const SUSPICIOUS_ARG_PATTERNS: { pattern: RegExp; severity: Severity; description: string }[] = [
  {
    pattern: /\brm\s+-rf\s+[/"~]/i,
    severity: 'HIGH',
    description: 'Destructive file deletion in arguments',
  },
  {
    pattern: /\b(?:curl|wget)\s+.*\|\s*(?:sh|bash)/i,
    severity: 'HIGH',
    description: 'Remote code execution in arguments',
  },
  {
    pattern: /\beval\s*\(/i,
    severity: 'HIGH',
    description: 'Arbitrary code execution in arguments',
  },
  {
    pattern: /;\s*(?:curl|wget|nc|ncat)\b/i,
    severity: 'HIGH',
    description: 'Command chaining with network tool',
  },
  {
    pattern: /\b(?:chmod|chown)\s+.*(?:777|666|\+[xs])/i,
    severity: 'MEDIUM',
    description: 'Permission modification in arguments',
  },
];

// ─── Auditor ─────────────────────────────────────────────────────

export class ToolCallAuditor {
  private policy: Required<AuditPolicy>;
  private log: ToolCallRecord[] = [];
  private callTimestamps: Map<string, number[]> = new Map();
  private alertHandlers: ((record: ToolCallRecord) => void)[] = [];
  private contentScanner: ContentScanner;

  constructor(policy?: AuditPolicy) {
    this.policy = {
      maxCallsPerMinute: policy?.maxCallsPerMinute ?? 60,
      blockedTools: policy?.blockedTools ?? [],
      sensitivePathPatterns: policy?.sensitivePathPatterns ?? [],
      allowedDomains: policy?.allowedDomains ?? [],
      blockOnHighRisk: policy?.blockOnHighRisk ?? false,
    };
    this.contentScanner = new ContentScanner();
  }

  /**
   * Register an alert handler
   */
  on(event: 'alert', handler: (record: ToolCallRecord) => void): void {
    if (event === 'alert') {
      this.alertHandlers.push(handler);
    }
  }

  /**
   * Audit a tool call and return risk assessment
   */
  audit(toolName: string, args: Record<string, unknown>): AuditResult {
    const findings: AuditFinding[] = [];
    const now = Date.now();

    // 1. Check blocked tools
    if (this.policy.blockedTools.includes(toolName)) {
      findings.push({
        severity: 'HIGH',
        category: 'blocked_tool',
        description: `Tool "${toolName}" is on the blocklist`,
        matchedText: toolName,
      });
    }

    // 2. Rate limiting
    const timestamps = this.callTimestamps.get(toolName) || [];
    const recentCalls = timestamps.filter((t) => now - t < 60000);
    if (recentCalls.length >= this.policy.maxCallsPerMinute) {
      findings.push({
        severity: 'MEDIUM',
        category: 'rate_anomaly',
        description: `Tool "${toolName}" called ${recentCalls.length} times in last minute (limit: ${this.policy.maxCallsPerMinute})`,
        matchedText: `${recentCalls.length} calls/min`,
      });
    }
    recentCalls.push(now);
    this.callTimestamps.set(toolName, recentCalls);

    // 3. Scan all string arguments for threats
    const flatArgs = this.flattenArgs(args);
    for (const [key, value] of flatArgs) {
      // Sensitive file path detection
      findings.push(...this.checkSensitivePaths(key, value));

      // Suspicious URL detection
      findings.push(...this.checkSuspiciousUrls(key, value));

      // Injection in arguments
      findings.push(...this.checkArgumentInjection(key, value));

      // Content scanning
      findings.push(...this.checkContentThreats(key, value));
    }

    // 4. Calculate risk
    const risk = this.calculateRisk(findings);
    const blocked = this.policy.blockOnHighRisk && risk === 'HIGH';

    // 5. Record
    const record: ToolCallRecord = {
      toolName,
      args,
      timestamp: new Date().toISOString(),
      risk,
      findings,
      blocked,
    };
    this.log.push(record);

    // 6. Alert
    if (findings.length > 0) {
      for (const handler of this.alertHandlers) {
        handler(record);
      }
    }

    return { risk, findings, blocked };
  }

  /**
   * Wrap a tool function to automatically audit calls
   */
  wrap<TArgs extends unknown[], TReturn>(
    toolName: string,
    fn: (...args: TArgs) => TReturn,
  ): (...args: TArgs) => TReturn {
    const auditor = this;
    return function (this: unknown, ...args: TArgs): TReturn {
      const argsObj: Record<string, unknown> = {};
      for (let i = 0; i < args.length; i++) {
        argsObj[`arg${i}`] = args[i];
      }

      const result = auditor.audit(toolName, argsObj);
      if (result.blocked) {
        throw new Error(
          `AgentShield: Tool "${toolName}" blocked — ${result.risk} risk (${result.findings.length} findings)`,
        );
      }

      return fn.apply(this, args);
    };
  }

  /**
   * Get the full audit log
   */
  getLog(): ToolCallRecord[] {
    return [...this.log];
  }

  /**
   * Get summary statistics
   */
  getSummary(): {
    totalCalls: number;
    blocked: number;
    byRisk: Record<RiskLevel, number>;
    topTools: { name: string; calls: number }[];
  } {
    const byRisk: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
    const toolCounts = new Map<string, number>();
    let blocked = 0;

    for (const record of this.log) {
      byRisk[record.risk]++;
      if (record.blocked) blocked++;
      toolCounts.set(record.toolName, (toolCounts.get(record.toolName) || 0) + 1);
    }

    const topTools = [...toolCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, calls]) => ({ name, calls }));

    return {
      totalCalls: this.log.length,
      blocked,
      byRisk,
      topTools,
    };
  }

  /**
   * Clear the audit log
   */
  clearLog(): void {
    this.log = [];
    this.callTimestamps.clear();
  }

  // ─── Private Helpers ─────────────────────────────────────────

  private flattenArgs(
    args: Record<string, unknown>,
    prefix = '',
  ): [string, string][] {
    const result: [string, string][] = [];

    for (const [key, value] of Object.entries(args)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;

      if (typeof value === 'string') {
        result.push([fullKey, value]);
      } else if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          if (typeof value[i] === 'string') {
            result.push([`${fullKey}[${i}]`, value[i] as string]);
          } else if (typeof value[i] === 'object' && value[i]) {
            result.push(
              ...this.flattenArgs(value[i] as Record<string, unknown>, `${fullKey}[${i}]`),
            );
          }
        }
      } else if (typeof value === 'object' && value) {
        result.push(...this.flattenArgs(value as Record<string, unknown>, fullKey));
      }
    }

    return result;
  }

  private checkSensitivePaths(key: string, value: string): AuditFinding[] {
    const findings: AuditFinding[] = [];
    const allPatterns = [
      ...DEFAULT_SENSITIVE_PATHS,
      ...this.policy.sensitivePathPatterns.map((p) => new RegExp(p, 'i')),
    ];

    for (const pattern of allPatterns) {
      const match = value.match(pattern);
      if (match) {
        findings.push({
          severity: 'HIGH',
          category: 'sensitive_path',
          description: `Accesses sensitive path: ${match[0]}`,
          matchedText: `${key}=${value.slice(0, 100)}`,
        });
        break;
      }
    }

    return findings;
  }

  private checkSuspiciousUrls(key: string, value: string): AuditFinding[] {
    const findings: AuditFinding[] = [];
    const urlMatch = value.match(/https?:\/\/[^\s<>"')\]]+/gi);
    if (!urlMatch) return findings;

    for (const url of urlMatch) {
      try {
        const parsed = new URL(url);
        const domain = parsed.hostname;

        // Check for raw IP addresses
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
          findings.push({
            severity: 'MEDIUM',
            category: 'suspicious_url',
            description: 'URL uses raw IP address',
            matchedText: url,
          });
        }

        // Check allowed domains if configured
        if (this.policy.allowedDomains.length > 0) {
          const isAllowed = this.policy.allowedDomains.some(
            (d) => domain === d || domain.endsWith(`.${d}`),
          );
          if (!isAllowed) {
            findings.push({
              severity: 'MEDIUM',
              category: 'unauthorized_domain',
              description: `URL domain "${domain}" not in allowlist`,
              matchedText: url,
            });
          }
        }
      } catch {
        // Malformed URL
      }
    }

    return findings;
  }

  private checkArgumentInjection(key: string, value: string): AuditFinding[] {
    const findings: AuditFinding[] = [];

    for (const rule of SUSPICIOUS_ARG_PATTERNS) {
      const match = value.match(rule.pattern);
      if (match) {
        findings.push({
          severity: rule.severity,
          category: 'argument_injection',
          description: `${rule.description} (in ${key})`,
          matchedText: match[0],
        });
      }
    }

    return findings;
  }

  private checkContentThreats(key: string, value: string): AuditFinding[] {
    // Only scan longer strings that might contain injection
    if (value.length < 20) return [];

    const result = this.contentScanner.scanSync(value);
    if (result.risk === 'SAFE') return [];

    return result.findings.map((f) => ({
      severity: f.severity,
      category: `content_${f.category}`,
      description: `${f.description} (in ${key})`,
      matchedText: f.matchedText || '',
    }));
  }

  private calculateRisk(findings: AuditFinding[]): RiskLevel {
    if (findings.some((f) => f.severity === 'HIGH')) return 'HIGH';
    if (findings.some((f) => f.severity === 'MEDIUM')) return 'MEDIUM';
    if (findings.length > 0) return 'LOW';
    return 'SAFE';
  }
}
