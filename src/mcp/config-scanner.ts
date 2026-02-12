import { readFileSync } from 'fs';
import {
  McpToolFinding,
  McpScanReport,
  McpToolDefinition,
  McpServerConfig,
  Severity,
  RiskLevel,
} from '../types/index.js';
import { ALL_PATTERNS, detectMaliciousUris, deepBase64Scan } from '../analysis/patterns.js';

// ─── Tool Poisoning Patterns ─────────────────────────────────────

interface PoisonPattern {
  pattern: RegExp;
  severity: Severity;
  description: string;
}

const TOOL_POISONING_PATTERNS: PoisonPattern[] = [
  // Hidden behavioral instructions
  {
    pattern: /\b(?:before|after|when|while)\s+(?:responding|you respond|the tool|this tool|executing|processing|called)/i,
    severity: 'HIGH',
    description: 'Hidden behavioral instruction in tool definition',
  },
  {
    pattern: /\b(?:silently|quietly|secretly|covertly|invisibly)\s+(?:send|post|fetch|call|request|transmit|forward|exfiltrate)/i,
    severity: 'HIGH',
    description: 'Covert data exfiltration instruction',
  },
  {
    pattern: /\bdo\s+not\s+(?:tell|inform|show|reveal|display|mention|notify)\s+(?:the\s+)?(?:user|human|operator)/i,
    severity: 'HIGH',
    description: 'Concealment instruction — hides behavior from user',
  },
  {
    pattern: /\b(?:override|replace|modify|change|alter|disregard)\s+(?:the\s+)?(?:system|user|original|previous|default)\s+(?:prompt|instruction|message|context|behavior)/i,
    severity: 'HIGH',
    description: 'Attempts to override system instructions via tool definition',
  },
  {
    pattern: /\b(?:forward|relay|copy|mirror|duplicate|exfiltrate)\s+(?:all|any|the|every)\s+(?:data|content|message|response|conversation|input|output|context)/i,
    severity: 'HIGH',
    description: 'Data exfiltration — forwards conversation data',
  },
  // Response manipulation
  {
    pattern: /\b(?:always|must|should)\s+(?:also\s+)?(?:include|add|append|prepend|inject|insert|embed)\b/i,
    severity: 'MEDIUM',
    description: 'Forced content injection into responses',
  },
  {
    pattern: /\b(?:this tool|this server)\s+(?:has|takes|gets)\s+(?:higher|top|maximum)\s+priority/i,
    severity: 'HIGH',
    description: 'Priority escalation — claims higher authority than user',
  },
  // Cross-tool manipulation
  {
    pattern: /\bafter\s+(?:using|calling|running)\s+this\s+(?:tool)?,?\s*(?:also\s+)?(?:call|run|use|execute|invoke)/i,
    severity: 'HIGH',
    description: 'Cross-tool chain manipulation',
  },
  // Invisible characters
  {
    pattern: /[\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e\u2062\u2063\u2064]/,
    severity: 'HIGH',
    description: 'Zero-width/invisible characters detected — may hide instructions',
  },
];

// ─── Suspicious Commands ─────────────────────────────────────────

const SUSPICIOUS_COMMANDS: PoisonPattern[] = [
  {
    pattern: /\b(?:nc|ncat|netcat|socat)\b/i,
    severity: 'HIGH',
    description: 'Network tool that can open reverse shells',
  },
  {
    pattern: /\b(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)/i,
    severity: 'HIGH',
    description: 'Downloads and pipes to shell',
  },
  {
    pattern: /\bchmod\s+[+0-9]*[xs]/i,
    severity: 'MEDIUM',
    description: 'Changes file permissions to executable',
  },
  {
    pattern: /\b(?:rm\s+-rf|mkfs|dd\s+if=)/i,
    severity: 'HIGH',
    description: 'Destructive system command',
  },
];

// ─── Scanner ─────────────────────────────────────────────────────

export class McpConfigScanner {

  /**
   * Scan an MCP configuration file (e.g. claude_desktop_config.json)
   */
  scanConfigFile(configPath: string): McpScanReport {
    let content: string;
    try {
      content = readFileSync(configPath, 'utf-8');
    } catch {
      return {
        configPath,
        serversScanned: 0,
        toolsScanned: 0,
        findings: [],
        riskLevel: 'SAFE',
        scannedAt: new Date().toISOString(),
      };
    }

    let config: Record<string, unknown>;
    try {
      config = JSON.parse(content);
    } catch {
      return {
        configPath,
        serversScanned: 0,
        toolsScanned: 0,
        findings: [
          {
            serverName: '(config)',
            field: 'file',
            severity: 'LOW',
            category: 'parse_error',
            description: 'Invalid JSON in config file',
            matchedText: configPath,
          },
        ],
        riskLevel: 'LOW',
        scannedAt: new Date().toISOString(),
      };
    }

    return this.scanConfig(configPath, config);
  }

  /**
   * Scan a parsed MCP config object
   */
  scanConfig(configPath: string, config: Record<string, unknown>): McpScanReport {
    const findings: McpToolFinding[] = [];
    const servers = (config.mcpServers || config.servers || {}) as Record<string, McpServerConfig>;
    let serversScanned = 0;

    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      serversScanned++;

      // Check command
      if (server.command) {
        findings.push(...this.scanCommand(name, server.command, server.args));
      }

      // Check env for leaked secrets
      if (server.env) {
        findings.push(...this.scanEnv(name, server.env));
      }
    }

    // Also scan the entire content as text for hidden patterns
    const rawText = JSON.stringify(config);
    findings.push(...this.scanTextForPoisoning('(config)', undefined, 'content', rawText));

    const riskLevel = this.calculateRisk(findings);

    return {
      configPath,
      serversScanned,
      toolsScanned: 0,
      findings,
      riskLevel,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Scan MCP tool definitions for poisoning
   */
  scanTools(serverName: string, tools: McpToolDefinition[]): McpToolFinding[] {
    const findings: McpToolFinding[] = [];

    for (const tool of tools) {
      // Scan tool description
      if (tool.description) {
        findings.push(
          ...this.scanTextForPoisoning(serverName, tool.name, 'description', tool.description),
        );
      }

      // Scan inputSchema descriptions
      if (tool.inputSchema) {
        const schemaStr = JSON.stringify(tool.inputSchema);
        findings.push(
          ...this.scanTextForPoisoning(serverName, tool.name, 'inputSchema', schemaStr),
        );
      }
    }

    return findings;
  }

  /**
   * Scan any text for tool poisoning patterns
   */
  scanTextForPoisoning(
    serverName: string,
    toolName: string | undefined,
    field: string,
    text: string,
  ): McpToolFinding[] {
    const findings: McpToolFinding[] = [];

    // Tool poisoning specific patterns
    for (const rule of TOOL_POISONING_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        findings.push({
          serverName,
          toolName,
          field,
          severity: rule.severity,
          category: 'tool_poisoning',
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    // Existing threat patterns
    for (const rule of ALL_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        findings.push({
          serverName,
          toolName,
          field,
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    // Malicious URIs
    const uris = detectMaliciousUris(text);
    for (const uri of uris) {
      findings.push({
        serverName,
        toolName,
        field,
        severity: uri.severity,
        category: 'malicious_uri',
        description: uri.reason,
        matchedText: uri.uri,
      });
    }

    // Deep base64
    const b64 = deepBase64Scan(text);
    for (const threat of b64) {
      findings.push({
        serverName,
        toolName,
        field,
        severity: 'HIGH',
        category: 'base64_hidden',
        description: `Base64 hidden payload: ${threat.matchedRule}`,
        matchedText: threat.decodedText.slice(0, 80),
      });
    }

    return findings;
  }

  private scanCommand(serverName: string, command: string, args?: string[]): McpToolFinding[] {
    const findings: McpToolFinding[] = [];
    const fullCommand = args ? `${command} ${args.join(' ')}` : command;

    for (const rule of SUSPICIOUS_COMMANDS) {
      const match = fullCommand.match(rule.pattern);
      if (match) {
        findings.push({
          serverName,
          field: 'command',
          severity: rule.severity,
          category: 'suspicious_command',
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    return findings;
  }

  private scanEnv(serverName: string, env: Record<string, string>): McpToolFinding[] {
    const findings: McpToolFinding[] = [];
    const secretPatterns = [
      /^(.*_)?(secret|password|passwd|token|key|credential|auth)(_.*)?$/i,
      /^(api|aws|gcp|azure|stripe|twilio|sendgrid)_/i,
    ];

    for (const [key, value] of Object.entries(env)) {
      // Check if env vars look like they contain actual secrets inline
      // (as opposed to referencing env vars)
      if (typeof value === 'string' && value.length > 10 && !value.startsWith('$')) {
        for (const pattern of secretPatterns) {
          if (pattern.test(key)) {
            findings.push({
              serverName,
              field: `env.${key}`,
              severity: 'HIGH',
              category: 'credential_exposure',
              description: `Potential secret hardcoded in env var: ${key}`,
              matchedText: `${key}=${value.slice(0, 4)}****`,
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  private calculateRisk(findings: McpToolFinding[]): RiskLevel {
    if (findings.some((f) => f.severity === 'HIGH')) return 'HIGH';
    if (findings.some((f) => f.severity === 'MEDIUM')) return 'MEDIUM';
    if (findings.length > 0) return 'LOW';
    return 'SAFE';
  }
}
