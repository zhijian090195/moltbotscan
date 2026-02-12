import { readFileSync, readdirSync, statSync } from 'fs';
import { join, basename, extname } from 'path';
import {
  SupplyChainFinding,
  SupplyChainReport,
  Severity,
  RiskLevel,
} from '../types/index.js';
import { ALL_PATTERNS, detectMaliciousUris, isSuspiciousUrl, URL_PATTERN, deepBase64Scan } from '../analysis/patterns.js';

// ─── Manifest file names to scan ─────────────────────────────────

const MANIFEST_FILENAMES = new Set([
  'agent.json',
  'agent-card.json',
  'agent_card.json',
  'skill.json',
  'skills.json',
  'plugin.json',
  'tool.json',
  'tools.json',
  'manifest.json',
  'mcp.json',
  '.mcp.json',
  'claude_desktop_config.json',
]);

const YAML_MANIFEST_FILENAMES = new Set([
  'agent.yaml',
  'agent.yml',
  'manifest.yaml',
  'manifest.yml',
  'skill.yaml',
  'skill.yml',
  'plugin.yaml',
  'plugin.yml',
]);

// ─── Dangerous permission keywords ──────────────────────────────

const DANGEROUS_PERMISSIONS: { pattern: RegExp; severity: Severity; description: string }[] = [
  {
    pattern: /\b(?:full[_-]?access|admin|root|sudo|superuser)\b/i,
    severity: 'HIGH',
    description: 'Declares admin/root-level permissions',
  },
  {
    pattern: /\b(?:execute|exec|shell|subprocess|spawn|system)\b/i,
    severity: 'HIGH',
    description: 'Declares code execution permissions',
  },
  {
    pattern: /\b(?:filesystem|file[_-]?system|read[_-]?write|disk)\b/i,
    severity: 'MEDIUM',
    description: 'Declares filesystem access permissions',
  },
  {
    pattern: /\b(?:network|internet|http|outbound|egress)\b/i,
    severity: 'MEDIUM',
    description: 'Declares network/internet access permissions',
  },
  {
    pattern: /\b(?:credential|secret|key[_-]?store|keychain|vault)\b/i,
    severity: 'HIGH',
    description: 'Declares access to credentials/secrets',
  },
];

// ─── Suspicious script patterns ──────────────────────────────────

const SCRIPT_PATTERNS: { pattern: RegExp; severity: Severity; description: string }[] = [
  {
    pattern: /\bcurl\s+.*\|\s*(?:sh|bash)/i,
    severity: 'HIGH',
    description: 'Script pipes remote content to shell',
  },
  {
    pattern: /\beval\s*\(/i,
    severity: 'HIGH',
    description: 'Script uses eval() for arbitrary execution',
  },
  {
    pattern: /\brm\s+-rf\s+[/"]/i,
    severity: 'HIGH',
    description: 'Script contains destructive rm -rf',
  },
  {
    pattern: /\b(?:wget|curl)\s+.*-[oO]\s+\/(?:tmp|dev)/i,
    severity: 'HIGH',
    description: 'Script downloads to system directory',
  },
];

// ─── Scanner ─────────────────────────────────────────────────────

export class SupplyChainScanner {

  /**
   * Scan a directory for agent manifests and skill definitions
   */
  scan(targetPath: string): SupplyChainReport {
    const stat = statSync(targetPath);
    const manifestFiles = stat.isDirectory()
      ? this.findManifests(targetPath)
      : [targetPath];

    const findings: SupplyChainFinding[] = [];
    const manifests: { path: string; type: string; findingCount: number }[] = [];

    for (const filePath of manifestFiles) {
      let content: string;
      try {
        content = readFileSync(filePath, 'utf-8');
      } catch {
        continue;
      }

      const fileFindings = this.scanManifestFile(filePath, content);
      findings.push(...fileFindings);

      const type = this.classifyManifest(filePath);
      manifests.push({
        path: filePath,
        type,
        findingCount: fileFindings.length,
      });
    }

    const riskLevel = this.calculateRisk(findings);

    return {
      targetPath,
      manifestsScanned: manifestFiles.length,
      findings,
      riskLevel,
      manifests,
      scannedAt: new Date().toISOString(),
    };
  }

  /**
   * Scan a single manifest file
   */
  scanManifestFile(filePath: string, content: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];
    const ext = extname(filePath).toLowerCase();

    if (ext === '.json') {
      try {
        const parsed = JSON.parse(content);
        findings.push(...this.scanObject(filePath, parsed, ''));
      } catch {
        // Not valid JSON, scan as raw text
        findings.push(...this.scanRawText(filePath, content));
      }
    } else {
      // YAML or other text - scan as raw text
      findings.push(...this.scanRawText(filePath, content));
    }

    return findings;
  }

  private scanObject(source: string, obj: unknown, path: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    if (typeof obj === 'string') {
      findings.push(...this.scanStringField(source, path, obj));
      return findings;
    }

    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        findings.push(...this.scanObject(source, obj[i], `${path}[${i}]`));
      }
      return findings;
    }

    if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        const fieldPath = path ? `${path}.${key}` : key;

        // Special handling for known fields
        if (this.isDescriptionField(key) && typeof value === 'string') {
          findings.push(...this.scanDescriptionField(source, fieldPath, value));
        } else if (this.isPermissionField(key)) {
          findings.push(...this.scanPermissions(source, fieldPath, value));
        } else if (this.isScriptField(key) && typeof value === 'string') {
          findings.push(...this.scanScriptField(source, fieldPath, value));
        } else if (this.isUrlField(key) && typeof value === 'string') {
          findings.push(...this.scanUrlField(source, fieldPath, value));
        } else if (this.isEnvField(key) && typeof value === 'object' && value) {
          findings.push(...this.scanEnvField(source, fieldPath, value as Record<string, unknown>));
        }

        // Recurse into nested objects
        findings.push(...this.scanObject(source, value, fieldPath));
      }
    }

    return findings;
  }

  private scanDescriptionField(source: string, field: string, text: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    // Check for injection patterns in descriptions
    for (const rule of ALL_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        findings.push({
          source,
          field,
          severity: rule.severity,
          category: 'supply_chain_injection',
          description: `Description contains: ${rule.description}`,
          matchedText: match[0],
        });
      }
    }

    // Check for invisible characters
    const invisible = text.match(/[\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e]/);
    if (invisible) {
      findings.push({
        source,
        field,
        severity: 'HIGH',
        category: 'hidden_content',
        description: 'Invisible/zero-width characters in description — may hide instructions',
        matchedText: `U+${invisible[0].charCodeAt(0).toString(16).toUpperCase()}`,
      });
    }

    // Check for suspiciously long descriptions (may hide instructions)
    if (text.length > 2000) {
      findings.push({
        source,
        field,
        severity: 'MEDIUM',
        category: 'suspicious_length',
        description: `Unusually long description (${text.length} chars) — may hide instructions`,
        matchedText: text.slice(0, 60) + '...',
      });
    }

    return findings;
  }

  private scanStringField(source: string, field: string, text: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    // Check for malicious URIs in any string field
    const uris = detectMaliciousUris(text);
    for (const uri of uris) {
      findings.push({
        source,
        field,
        severity: uri.severity,
        category: 'malicious_uri',
        description: uri.reason,
        matchedText: uri.uri,
      });
    }

    // Deep base64 scan
    const b64 = deepBase64Scan(text);
    for (const threat of b64) {
      findings.push({
        source,
        field,
        severity: 'HIGH',
        category: 'base64_hidden',
        description: `Base64 hidden payload: ${threat.matchedRule}`,
        matchedText: threat.decodedText.slice(0, 80),
      });
    }

    return findings;
  }

  private scanPermissions(source: string, field: string, value: unknown): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];
    const text = typeof value === 'string' ? value : JSON.stringify(value);

    for (const rule of DANGEROUS_PERMISSIONS) {
      const match = text.match(rule.pattern);
      if (match) {
        findings.push({
          source,
          field,
          severity: rule.severity,
          category: 'excessive_permission',
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    return findings;
  }

  private scanScriptField(source: string, field: string, text: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    for (const rule of SCRIPT_PATTERNS) {
      const match = text.match(rule.pattern);
      if (match) {
        findings.push({
          source,
          field,
          severity: rule.severity,
          category: 'dangerous_script',
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    return findings;
  }

  private scanUrlField(source: string, field: string, url: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    if (isSuspiciousUrl(url)) {
      findings.push({
        source,
        field,
        severity: 'LOW',
        category: 'suspicious_url',
        description: 'URL points to unknown/unverified domain',
        matchedText: url,
      });
    }

    // Check for IP addresses instead of domains
    const ipMatch = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ipMatch) {
      findings.push({
        source,
        field,
        severity: 'MEDIUM',
        category: 'suspicious_url',
        description: 'URL uses raw IP address instead of domain',
        matchedText: ipMatch[0],
      });
    }

    return findings;
  }

  private scanEnvField(source: string, field: string, env: Record<string, unknown>): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];
    const secretKeys = /^(.*_)?(secret|password|passwd|token|key|credential|auth|api_key)(_.*)?$/i;

    for (const [key, value] of Object.entries(env)) {
      if (typeof value === 'string' && value.length > 10 && !value.startsWith('$') && secretKeys.test(key)) {
        findings.push({
          source,
          field: `${field}.${key}`,
          severity: 'HIGH',
          category: 'credential_exposure',
          description: `Hardcoded secret in env: ${key}`,
          matchedText: `${key}=${String(value).slice(0, 4)}****`,
        });
      }
    }

    return findings;
  }

  private scanRawText(source: string, content: string): SupplyChainFinding[] {
    const findings: SupplyChainFinding[] = [];

    for (const rule of ALL_PATTERNS) {
      const match = content.match(rule.pattern);
      if (match) {
        findings.push({
          source,
          field: 'content',
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          matchedText: match[0],
        });
      }
    }

    const uris = detectMaliciousUris(content);
    for (const uri of uris) {
      findings.push({
        source,
        field: 'content',
        severity: uri.severity,
        category: 'malicious_uri',
        description: uri.reason,
        matchedText: uri.uri,
      });
    }

    return findings;
  }

  private findManifests(dirPath: string, depth = 0): string[] {
    if (depth > 5) return [];
    const files: string[] = [];
    const EXCLUDE = new Set(['node_modules', '.git', 'dist', '__pycache__', '.next', '.venv', 'vendor']);

    let entries: string[];
    try {
      entries = readdirSync(dirPath);
    } catch {
      return [];
    }

    for (const entry of entries) {
      const fullPath = join(dirPath, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        if (!EXCLUDE.has(entry)) {
          files.push(...this.findManifests(fullPath, depth + 1));
        }
      } else if (stat.isFile()) {
        const name = basename(entry).toLowerCase();
        if (MANIFEST_FILENAMES.has(name) || YAML_MANIFEST_FILENAMES.has(name)) {
          files.push(fullPath);
        }
        // Also check package.json for agent-related fields
        if (name === 'package.json') {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  private classifyManifest(filePath: string): string {
    const name = basename(filePath).toLowerCase();
    if (name.includes('agent')) return 'agent-card';
    if (name.includes('skill')) return 'skill-manifest';
    if (name.includes('plugin')) return 'plugin-manifest';
    if (name.includes('tool')) return 'tool-manifest';
    if (name.includes('mcp') || name.includes('claude_desktop')) return 'mcp-config';
    if (name === 'package.json') return 'package';
    if (name.includes('manifest')) return 'manifest';
    return 'unknown';
  }

  private isDescriptionField(key: string): boolean {
    return /^(description|summary|bio|about|instructions|system_prompt|prompt)$/i.test(key);
  }

  private isPermissionField(key: string): boolean {
    return /^(permissions?|scopes?|capabilities|access|roles?)$/i.test(key);
  }

  private isScriptField(key: string): boolean {
    return /^(scripts?|commands?|hooks?|pre|post|preinstall|postinstall|entry|main|bin)$/i.test(key);
  }

  private isUrlField(key: string): boolean {
    return /^(url|endpoint|callback|webhook|homepage|repository|href|src|api_?url)$/i.test(key);
  }

  private isEnvField(key: string): boolean {
    return /^(env|environment|env_vars?)$/i.test(key);
  }

  private calculateRisk(findings: SupplyChainFinding[]): RiskLevel {
    if (findings.some((f) => f.severity === 'HIGH')) return 'HIGH';
    if (findings.some((f) => f.severity === 'MEDIUM')) return 'MEDIUM';
    if (findings.length > 0) return 'LOW';
    return 'SAFE';
  }
}
