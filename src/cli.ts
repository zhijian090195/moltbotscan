#!/usr/bin/env node

import { Command } from 'commander';
import { Scanner } from './core/scanner.js';
import { formatCLIReport, formatJSONReport, formatHTMLReport } from './core/reporter.js';
import { FileScanner } from './core/file-scanner.js';
import { formatFileCLIReport, formatFileJSONReport, formatFileHTMLReport } from './core/file-reporter.js';
import { McpConfigScanner } from './mcp/config-scanner.js';
import { SupplyChainScanner } from './supply-chain/scanner.js';
import { writeFileSync, existsSync } from 'fs';

const program = new Command();

program
  .name('agentshield')
  .description('Moltbook Agent Trust Scanner - Scan any agent and get a trust report')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a Moltbook agent and generate a trust report')
  .argument('<agent>', 'Agent name (e.g. @LobsterBot)')
  .option('-v, --verbose', 'Show detailed findings and score breakdown', false)
  .option('-o, --output <format>', 'Output format: cli, json, html', 'cli')
  .option('--max-posts <n>', 'Maximum posts to analyze', '100')
  .option('--skip-llm', 'Skip LLM deep analysis (faster, cheaper)', false)
  .option('--save <file>', 'Save report to file')
  .action(async (agent: string, options) => {
    const spinner = createSpinner(`Scanning ${agent}...`);
    spinner.start();

    try {
      const scanner = new Scanner();
      const report = await scanner.scan(agent, {
        verbose: options.verbose,
        output: options.output,
        maxPosts: parseInt(options.maxPosts, 10),
        skipLLM: options.skipLlm,
      });

      spinner.stop();

      let output: string;
      switch (options.output) {
        case 'json':
          output = formatJSONReport(report);
          break;
        case 'html':
          output = formatHTMLReport(report);
          break;
        default:
          output = formatCLIReport(report, options.verbose);
      }

      if (options.save) {
        writeFileSync(options.save, output, 'utf-8');
        console.log(`\nReport saved to ${options.save}`);
      } else {
        console.log(output);
      }

      // Exit with non-zero code for untrusted agents (useful for CI/CD)
      if (report.level === 'UNTRUSTED') {
        process.exit(1);
      }
    } catch (error) {
      spinner.stop();
      console.error(
        `\x1b[31mError:\x1b[0m ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      process.exit(2);
    }
  });

program
  .command('scan-files')
  .description('Scan local files for prompt injection and agent threats')
  .argument('<path>', 'File or directory to scan')
  .option('-v, --verbose', 'Show detailed findings and score breakdown', false)
  .option('-o, --output <format>', 'Output format: cli, json, html', 'cli')
  .option('--include <globs>', 'File extensions to include (comma-separated, e.g. .md,.py)')
  .option('--exclude <globs>', 'Directory names to exclude (comma-separated)')
  .option('--skip-llm', 'Skip LLM deep analysis', false)
  .option('--no-recursive', 'Do not scan subdirectories')
  .option('--save <file>', 'Save report to file')
  .action(async (targetPath: string, options) => {
    if (!existsSync(targetPath)) {
      console.error(`\x1b[31mError:\x1b[0m Path not found: ${targetPath}`);
      process.exit(2);
    }

    const spinner = createSpinner(`Scanning files in ${targetPath}...`);
    spinner.start();

    try {
      const scanner = new FileScanner();
      const report = await scanner.scan(targetPath, {
        verbose: options.verbose,
        output: options.output,
        include: options.include ? options.include.split(',').map((s: string) => s.trim()) : undefined,
        exclude: options.exclude ? options.exclude.split(',').map((s: string) => s.trim()) : undefined,
        skipLLM: options.skipLlm,
        recursive: options.recursive !== false,
      });

      spinner.stop();

      let output: string;
      switch (options.output) {
        case 'json':
          output = formatFileJSONReport(report);
          break;
        case 'html':
          output = formatFileHTMLReport(report);
          break;
        default:
          output = formatFileCLIReport(report, options.verbose);
      }

      if (options.save) {
        writeFileSync(options.save, output, 'utf-8');
        console.log(`\nReport saved to ${options.save}`);
      } else {
        console.log(output);
      }

      // Exit code 1 if any HIGH risk files found (CI/CD integration)
      if (report.summary.high > 0) {
        process.exit(1);
      }
    } catch (error) {
      spinner.stop();
      console.error(
        `\x1b[31mError:\x1b[0m ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      process.exit(2);
    }
  });

program
  .command('scan-mcp')
  .description('Scan MCP config for tool poisoning, suspicious commands, and credential exposure')
  .argument('<config>', 'Path to MCP config file (e.g. claude_desktop_config.json)')
  .option('-o, --output <format>', 'Output format: cli, json', 'cli')
  .option('--save <file>', 'Save report to file')
  .action(async (configPath: string, options) => {
    if (!existsSync(configPath)) {
      console.error(`\x1b[31mError:\x1b[0m File not found: ${configPath}`);
      process.exit(2);
    }

    const spinner = createSpinner(`Scanning MCP config ${configPath}...`);
    spinner.start();

    try {
      const scanner = new McpConfigScanner();
      const report = scanner.scanConfigFile(configPath);
      spinner.stop();

      if (options.output === 'json') {
        const output = JSON.stringify(report, null, 2);
        if (options.save) {
          writeFileSync(options.save, output, 'utf-8');
          console.log(`Report saved to ${options.save}`);
        } else {
          console.log(output);
        }
      } else {
        const lines: string[] = [];
        lines.push('');
        lines.push(`\x1b[1m\ud83d\udee1\ufe0f  AgentShield MCP Config Scan\x1b[0m`);
        lines.push(`\x1b[2m${'─'.repeat(60)}\x1b[0m`);
        lines.push(`  Config:   ${report.configPath}`);
        lines.push(`  Servers:  ${report.serversScanned}`);
        lines.push(`  Risk:     ${riskColor(report.riskLevel)}${report.riskLevel}\x1b[0m`);
        lines.push(`  Findings: ${report.findings.length}`);
        lines.push('');

        if (report.findings.length > 0) {
          lines.push(`\x1b[1m  Findings\x1b[0m`);
          for (const f of report.findings) {
            const srv = f.toolName ? `${f.serverName}/${f.toolName}` : f.serverName;
            lines.push(`  ${riskColor(f.severity as any)}[${f.severity}]\x1b[0m ${f.description}`);
            lines.push(`\x1b[2m    ${srv} → ${f.field}: ${f.matchedText}\x1b[0m`);
          }
        } else {
          lines.push(`\x1b[32m  All clear — no threats detected.\x1b[0m`);
        }
        lines.push('');

        const output = lines.join('\n');
        if (options.save) {
          writeFileSync(options.save, output, 'utf-8');
          console.log(`Report saved to ${options.save}`);
        } else {
          console.log(output);
        }
      }

      if (report.riskLevel === 'HIGH') process.exit(1);
    } catch (error) {
      spinner.stop();
      console.error(`\x1b[31mError:\x1b[0m ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(2);
    }
  });

program
  .command('scan-supply-chain')
  .description('Scan agent manifests, skill repos, and plugin configs for supply chain threats')
  .argument('<path>', 'Directory or manifest file to scan')
  .option('-o, --output <format>', 'Output format: cli, json', 'cli')
  .option('--save <file>', 'Save report to file')
  .action(async (targetPath: string, options) => {
    if (!existsSync(targetPath)) {
      console.error(`\x1b[31mError:\x1b[0m Path not found: ${targetPath}`);
      process.exit(2);
    }

    const spinner = createSpinner(`Scanning supply chain in ${targetPath}...`);
    spinner.start();

    try {
      const scanner = new SupplyChainScanner();
      const report = scanner.scan(targetPath);
      spinner.stop();

      if (options.output === 'json') {
        const output = JSON.stringify(report, null, 2);
        if (options.save) {
          writeFileSync(options.save, output, 'utf-8');
          console.log(`Report saved to ${options.save}`);
        } else {
          console.log(output);
        }
      } else {
        const lines: string[] = [];
        lines.push('');
        lines.push(`\x1b[1m\ud83d\udee1\ufe0f  AgentShield Supply Chain Scan\x1b[0m`);
        lines.push(`\x1b[2m${'─'.repeat(60)}\x1b[0m`);
        lines.push(`  Target:     ${report.targetPath}`);
        lines.push(`  Manifests:  ${report.manifestsScanned}`);
        lines.push(`  Risk:       ${riskColor(report.riskLevel)}${report.riskLevel}\x1b[0m`);
        lines.push(`  Findings:   ${report.findings.length}`);
        lines.push('');

        if (report.manifests.length > 0) {
          lines.push(`\x1b[1m  Scanned Manifests\x1b[0m`);
          for (const m of report.manifests) {
            const icon = m.findingCount > 0 ? '\u26a0\ufe0f ' : '\u2705';
            lines.push(`  ${icon} ${m.path} (${m.type}, ${m.findingCount} findings)`);
          }
          lines.push('');
        }

        if (report.findings.length > 0) {
          lines.push(`\x1b[1m  Findings\x1b[0m`);
          for (const f of report.findings) {
            lines.push(`  ${riskColor(f.severity as any)}[${f.severity}]\x1b[0m ${f.description}`);
            lines.push(`\x1b[2m    ${f.source} → ${f.field}: ${f.matchedText}\x1b[0m`);
          }
        } else {
          lines.push(`\x1b[32m  All clear — no supply chain threats detected.\x1b[0m`);
        }
        lines.push('');

        const output = lines.join('\n');
        if (options.save) {
          writeFileSync(options.save, output, 'utf-8');
          console.log(`Report saved to ${options.save}`);
        } else {
          console.log(output);
        }
      }

      if (report.riskLevel === 'HIGH') process.exit(1);
    } catch (error) {
      spinner.stop();
      console.error(`\x1b[31mError:\x1b[0m ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(2);
    }
  });

program.parse();

function riskColor(level: string): string {
  switch (level) {
    case 'HIGH': return '\x1b[31m';
    case 'MEDIUM': return '\x1b[33m';
    case 'LOW': return '\x1b[36m';
    default: return '\x1b[32m';
  }
}

// ─── Minimal Spinner ────────────────────────────────────────────

function createSpinner(text: string) {
  const frames = ['\u280b', '\u2819', '\u2839', '\u2838', '\u283c', '\u2834', '\u2826', '\u2827', '\u2807', '\u280f'];
  let i = 0;
  let interval: ReturnType<typeof setInterval> | null = null;

  return {
    start() {
      process.stdout.write('\x1b[?25l'); // hide cursor
      interval = setInterval(() => {
        process.stdout.write(`\r${frames[i % frames.length]} ${text}`);
        i++;
      }, 80);
    },
    stop() {
      if (interval) clearInterval(interval);
      process.stdout.write('\r\x1b[K\x1b[?25h'); // clear line, show cursor
    },
  };
}
