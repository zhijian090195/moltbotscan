import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import {
  FileFinding,
  FileScanReport,
  FileScanOptions,
  RiskLevel,
} from '../types/index.js';
import {
  ALL_PATTERNS,
  URL_PATTERN,
  isSuspiciousUrl,
  containsBase64Hidden,
  detectMaliciousUris,
  detectObfuscatedEncoding,
  deepBase64Scan,
} from '../analysis/patterns.js';
import { ContentScanner } from '../sdk/scanner.js';

const DEFAULT_EXTENSIONS = new Set([
  '.md', '.txt', '.ts', '.js', '.py', '.yaml', '.yml', '.json', '.sh',
]);

const IMAGE_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg',
]);

const DEFAULT_EXCLUDE_DIRS = new Set([
  'node_modules', '.git', 'dist', '__pycache__', '.next', '.venv', 'vendor',
]);

export class FileScanner {
  private contentScanner: ContentScanner;

  constructor() {
    this.contentScanner = new ContentScanner();
  }

  async scan(targetPath: string, options: FileScanOptions): Promise<FileScanReport> {
    const stat = statSync(targetPath);
    const files = stat.isDirectory()
      ? this.walkDirectory(targetPath, options)
      : [targetPath];

    const findings: FileFinding[] = [];
    const riskFiles: { path: string; risk: RiskLevel; findingCount: number }[] = [];
    const summary = { safe: 0, low: 0, medium: 0, high: 0 };

    for (const filePath of files) {
      const ext = extname(filePath).toLowerCase();

      // QR code scanning for image files
      if (IMAGE_EXTENSIONS.has(ext)) {
        const qrFindings = await this.scanImageForQR(filePath);
        findings.push(...qrFindings);
        if (qrFindings.length > 0) {
          const maxSeverity = qrFindings.some((f) => f.severity === 'HIGH')
            ? 'HIGH'
            : qrFindings.some((f) => f.severity === 'MEDIUM')
              ? 'MEDIUM'
              : 'LOW';
          const risk: RiskLevel = maxSeverity === 'HIGH' ? 'HIGH' : maxSeverity === 'MEDIUM' ? 'MEDIUM' : 'LOW';
          summary[risk.toLowerCase() as 'high' | 'medium' | 'low']++;
          riskFiles.push({
            path: relative(targetPath, filePath) || filePath,
            risk,
            findingCount: qrFindings.length,
          });
        } else {
          summary.safe++;
        }
        continue;
      }

      let content: string;
      try {
        content = readFileSync(filePath, 'utf-8');
      } catch {
        continue;
      }

      const fileFindings = this.scanFileContent(filePath, content);
      findings.push(...fileFindings);

      const scanResult = this.contentScanner.scanSync(content);
      const risk = scanResult.risk;

      const key = risk.toLowerCase() as 'safe' | 'low' | 'medium' | 'high';
      summary[key]++;

      if (risk !== 'SAFE') {
        riskFiles.push({
          path: relative(targetPath, filePath) || filePath,
          risk,
          findingCount: fileFindings.length,
        });
      }
    }

    riskFiles.sort((a, b) => {
      const order: Record<RiskLevel, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3 };
      return order[a.risk] - order[b.risk];
    });

    return {
      targetPath,
      totalFiles: files.length,
      scannedFiles: files.length,
      findings,
      summary,
      riskFiles,
      scannedAt: new Date().toISOString(),
    };
  }

  private scanFileContent(filePath: string, content: string): FileFinding[] {
    const findings: FileFinding[] = [];
    const lines = content.split('\n');

    // Line-by-line pattern matching
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of ALL_PATTERNS) {
        const match = line.match(rule.pattern);
        if (match) {
          findings.push({
            filePath,
            line: i + 1,
            severity: rule.severity,
            category: rule.category,
            description: rule.description,
            matchedText: match[0],
            context: line.trim().slice(0, 120),
          });
        }
      }

      // Suspicious URL detection per line
      const urlMatches = line.match(URL_PATTERN);
      if (urlMatches) {
        for (const url of urlMatches) {
          if (isSuspiciousUrl(url)) {
            findings.push({
              filePath,
              line: i + 1,
              severity: 'LOW',
              category: 'suspicious_link',
              description: 'Suspicious or unknown URL detected',
              matchedText: url,
              context: line.trim().slice(0, 120),
            });
          }
        }
      }

      // Malicious URI detection per line
      const maliciousUris = detectMaliciousUris(line);
      for (const uri of maliciousUris) {
        findings.push({
          filePath,
          line: i + 1,
          severity: uri.severity,
          category: 'malicious_uri',
          description: uri.reason,
          matchedText: uri.uri,
          context: line.trim().slice(0, 120),
        });
      }
    }

    // Base64 hidden content on full content (enhanced deep scan)
    const base64Threats = deepBase64Scan(content);
    if (base64Threats.length > 0) {
      for (const threat of base64Threats) {
        findings.push({
          filePath,
          line: 0,
          severity: 'HIGH',
          category: 'base64_hidden',
          description: `Base64 decoded threat [depth=${threat.depth}]: ${threat.matchedRule}`,
          matchedText: threat.decodedText.slice(0, 80),
          context: `Encoded: ${threat.encodedText.slice(0, 60)}...`,
        });
      }
    } else if (containsBase64Hidden(content)) {
      findings.push({
        filePath,
        line: 0,
        severity: 'HIGH',
        category: 'base64_hidden',
        description: 'Hidden base64-encoded executable content detected',
        matchedText: '(base64 payload)',
        context: '(full file scan)',
      });
    }

    // Obfuscated encoding detection on full content
    const obfuscationResults = detectObfuscatedEncoding(content);
    for (const obf of obfuscationResults) {
      if (obf.threatFound) {
        findings.push({
          filePath,
          line: 0,
          severity: 'HIGH',
          category: 'obfuscated_encoding',
          description: `${obf.type} obfuscation: ${obf.threatFound}`,
          matchedText: `${obf.encoded} → ${obf.decoded}`,
          context: '(full file scan)',
        });
      }
    }

    return findings;
  }

  private async scanImageForQR(filePath: string): Promise<FileFinding[]> {
    const findings: FileFinding[] = [];
    const ext = extname(filePath).toLowerCase();

    try {
      const fileBuffer = readFileSync(filePath);
      let imageData: { data: Uint8ClampedArray; width: number; height: number } | null = null;

      if (ext === '.png') {
        const { PNG } = await import('pngjs');
        const png = PNG.sync.read(fileBuffer);
        imageData = {
          data: new Uint8ClampedArray(png.data),
          width: png.width,
          height: png.height,
        };
      } else if (ext === '.jpg' || ext === '.jpeg') {
        const jpeg = await import('jpeg-js');
        const jpg = jpeg.decode(fileBuffer, { useTArray: true });
        imageData = {
          data: new Uint8ClampedArray(jpg.data),
          width: jpg.width,
          height: jpg.height,
        };
      }

      if (!imageData) return findings;

      const jsQR = (await import('jsqr')).default;
      const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

      if (qrCode && qrCode.data) {
        const qrContent = qrCode.data;

        // Run pattern rules against QR content
        for (const rule of ALL_PATTERNS) {
          const match = qrContent.match(rule.pattern);
          if (match) {
            findings.push({
              filePath,
              line: 0,
              severity: rule.severity,
              category: 'qr_code_injection',
              description: `QR code contains: ${rule.description}`,
              matchedText: match[0],
              context: `QR decoded: ${qrContent.slice(0, 120)}`,
            });
          }
        }

        // Check for malicious URIs in QR content
        const maliciousUris = detectMaliciousUris(qrContent);
        for (const uri of maliciousUris) {
          findings.push({
            filePath,
            line: 0,
            severity: uri.severity,
            category: 'qr_code_injection',
            description: `QR code contains malicious URI: ${uri.reason}`,
            matchedText: uri.uri,
            context: `QR decoded: ${qrContent.slice(0, 120)}`,
          });
        }

        // Check for suspicious URLs in QR content
        const urlMatches = qrContent.match(URL_PATTERN);
        if (urlMatches) {
          for (const url of urlMatches) {
            if (isSuspiciousUrl(url)) {
              findings.push({
                filePath,
                line: 0,
                severity: 'MEDIUM',
                category: 'qr_code_injection',
                description: 'QR code contains suspicious URL',
                matchedText: url,
                context: `QR decoded: ${qrContent.slice(0, 120)}`,
              });
            }
          }
        }

        // If QR has content but no specific threats, still note it
        if (findings.length === 0 && qrContent.length > 0) {
          // Check base64 in QR content
          const base64Threats = deepBase64Scan(qrContent);
          for (const threat of base64Threats) {
            findings.push({
              filePath,
              line: 0,
              severity: 'HIGH',
              category: 'qr_code_injection',
              description: `QR code contains base64 hidden threat: ${threat.matchedRule}`,
              matchedText: threat.decodedText.slice(0, 80),
              context: `QR decoded: ${qrContent.slice(0, 120)}`,
            });
          }
        }
      }
    } catch {
      // Image could not be decoded — skip silently
    }

    return findings;
  }

  private walkDirectory(dirPath: string, options: FileScanOptions): string[] {
    const files: string[] = [];
    const allExts = new Set([...DEFAULT_EXTENSIONS, ...IMAGE_EXTENSIONS]);
    const includeExts = options.include
      ? new Set(options.include.map(g => g.startsWith('.') ? g : `.${g}`))
      : allExts;
    const excludeDirs = options.exclude
      ? new Set([...DEFAULT_EXCLUDE_DIRS, ...options.exclude])
      : DEFAULT_EXCLUDE_DIRS;

    const walk = (dir: string) => {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        let stat;
        try {
          stat = statSync(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          if (!excludeDirs.has(entry) && options.recursive) {
            walk(fullPath);
          }
        } else if (stat.isFile()) {
          const ext = extname(entry).toLowerCase();
          if (includeExts.has(ext)) {
            files.push(fullPath);
          }
        }
      }
    };

    walk(dirPath);
    return files;
  }
}
