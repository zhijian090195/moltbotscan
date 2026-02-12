#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { ContentScanner } from '../sdk/scanner.js';
import { FileScanner } from '../core/file-scanner.js';
import { McpConfigScanner } from './config-scanner.js';
import { SupplyChainScanner } from '../supply-chain/scanner.js';
import { existsSync } from 'fs';

const server = new McpServer({
  name: 'agentshield',
  version: '0.5.0',
});

const contentScanner = new ContentScanner();
const fileScanner = new FileScanner();
const mcpScanner = new McpConfigScanner();
const supplyChainScanner = new SupplyChainScanner();

// Tool 1: scan_content — scan text content for threats
server.tool(
  'scan_content',
  'Scan text content for prompt injection, credential theft, social engineering, and other agent threats. Returns risk level (HIGH/MEDIUM/LOW/SAFE), score (0-100), and detailed findings.',
  {
    content: z.string().describe('The text content to scan for threats'),
  },
  async ({ content }) => {
    const result = contentScanner.scanSync(content);

    const summary = [
      `Risk: ${result.risk}`,
      `Score: ${result.score}/100`,
      `Findings: ${result.findings.length}`,
    ];

    if (result.findings.length > 0) {
      summary.push('');
      summary.push('Findings:');
      for (const f of result.findings) {
        summary.push(`  [${f.severity}] ${f.category}: ${f.description}`);
        if (f.matchedText) {
          summary.push(`    Matched: ${f.matchedText}`);
        }
      }
    }

    const flagsActive = Object.entries(result.flags)
      .filter(([, v]) => v)
      .map(([k]) => k);

    if (flagsActive.length > 0) {
      summary.push('');
      summary.push(`Active flags: ${flagsActive.join(', ')}`);
    }

    return {
      content: [
        {
          type: 'text' as const,
          text: summary.join('\n'),
        },
      ],
    };
  },
);

// Tool 2: scan_files — scan a directory or file for threats
server.tool(
  'scan_files',
  'Scan a local file or directory for prompt injection, credential theft, covert execution, and obfuscation threats. Supports text files, scripts, and QR codes in images.',
  {
    path: z.string().describe('Absolute path to file or directory to scan'),
    recursive: z.boolean().optional().default(true).describe('Scan subdirectories (default: true)'),
  },
  async ({ path, recursive }) => {
    if (!existsSync(path)) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `Error: Path not found: ${path}`,
          },
        ],
        isError: true,
      };
    }

    const report = await fileScanner.scan(path, {
      verbose: true,
      output: 'cli',
      skipLLM: true,
      recursive,
    });

    const { safe, low, medium, high } = report.summary;
    const lines: string[] = [
      `Target: ${report.targetPath}`,
      `Files scanned: ${report.scannedFiles}`,
      `Summary: ${safe} safe, ${low} low, ${medium} medium, ${high} high`,
      `Total findings: ${report.findings.length}`,
    ];

    if (report.riskFiles.length > 0) {
      lines.push('');
      lines.push('Risk files:');
      for (const f of report.riskFiles) {
        lines.push(`  [${f.risk}] ${f.path} (${f.findingCount} findings)`);
      }
    }

    if (report.findings.length > 0) {
      lines.push('');
      lines.push('Findings:');
      for (const f of report.findings) {
        const loc = f.line > 0 ? `${f.filePath}:${f.line}` : f.filePath;
        lines.push(`  [${f.severity}] ${f.category}: ${f.description}`);
        lines.push(`    Location: ${loc}`);
        lines.push(`    Matched: ${f.matchedText}`);
      }
    }

    return {
      content: [
        {
          type: 'text' as const,
          text: lines.join('\n'),
        },
      ],
    };
  },
);

// Tool 3: scan_mcp_config — detect tool poisoning in MCP configs
server.tool(
  'scan_mcp_config',
  'Scan an MCP configuration file for tool poisoning: hidden instructions in tool descriptions, suspicious commands, credential exposure, zero-width characters.',
  {
    config_path: z.string().describe('Absolute path to MCP config file (e.g. claude_desktop_config.json)'),
  },
  async ({ config_path }) => {
    if (!existsSync(config_path)) {
      return {
        content: [{ type: 'text' as const, text: `Error: File not found: ${config_path}` }],
        isError: true,
      };
    }

    const report = mcpScanner.scanConfigFile(config_path);
    const lines: string[] = [
      `Config: ${report.configPath}`,
      `Servers scanned: ${report.serversScanned}`,
      `Risk: ${report.riskLevel}`,
      `Findings: ${report.findings.length}`,
    ];

    if (report.findings.length > 0) {
      lines.push('');
      lines.push('Findings:');
      for (const f of report.findings) {
        const target = f.toolName ? `${f.serverName}/${f.toolName}` : f.serverName;
        lines.push(`  [${f.severity}] ${f.category}: ${f.description}`);
        lines.push(`    ${target} -> ${f.field}: ${f.matchedText}`);
      }
    }

    return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
  },
);

// Tool 4: scan_supply_chain — scan agent manifests and skill repos
server.tool(
  'scan_supply_chain',
  'Scan agent manifests, skill repos, and plugin configs for supply chain threats: poisoned definitions, suspicious URLs, excessive permissions, hidden content.',
  {
    path: z.string().describe('Absolute path to directory or manifest file to scan'),
  },
  async ({ path }) => {
    if (!existsSync(path)) {
      return {
        content: [{ type: 'text' as const, text: `Error: Path not found: ${path}` }],
        isError: true,
      };
    }

    const report = supplyChainScanner.scan(path);
    const lines: string[] = [
      `Target: ${report.targetPath}`,
      `Manifests scanned: ${report.manifestsScanned}`,
      `Risk: ${report.riskLevel}`,
      `Findings: ${report.findings.length}`,
    ];

    if (report.manifests.length > 0) {
      lines.push('');
      lines.push('Manifests:');
      for (const m of report.manifests) {
        lines.push(`  ${m.path} (${m.type}, ${m.findingCount} findings)`);
      }
    }

    if (report.findings.length > 0) {
      lines.push('');
      lines.push('Findings:');
      for (const f of report.findings) {
        lines.push(`  [${f.severity}] ${f.category}: ${f.description}`);
        lines.push(`    ${f.source} -> ${f.field}: ${f.matchedText}`);
      }
    }

    return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  process.stderr.write(`AgentShield MCP server error: ${error}\n`);
  process.exit(1);
});
