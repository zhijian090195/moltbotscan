import express from 'express';
import path from 'path';
import { Scanner } from '../core/scanner.js';
import { generateDemoReport, getDemoAgentNames } from '../core/demo.js';
import { formatHTMLReport } from '../core/reporter.js';

const app = express();
const PORT = process.env.PORT || 3847;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// API: Demo — list available demo agents
app.get('/api/demo', (_req, res) => {
  res.json({ agents: getDemoAgentNames() });
});

// API: Demo — scan a demo agent (no API key required)
app.get('/api/demo/:agentName', (req, res) => {
  const { agentName } = req.params;
  const format = (req.query.format as string) || 'json';

  try {
    const report = generateDemoReport(agentName);

    if (format === 'html') {
      res.type('html').send(formatHTMLReport(report));
    } else {
      res.json(report);
    }
  } catch (error) {
    res.status(400).json({
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// API: Scan an agent (requires MOLTBOOK_API_KEY)
app.get('/api/scan/:agentName', async (req, res) => {
  const { agentName } = req.params;
  const format = (req.query.format as string) || 'json';

  try {
    const scanner = new Scanner();
    const report = await scanner.scan(agentName, {
      maxPosts: parseInt((req.query.maxPosts as string) || '100', 10),
      skipLLM: req.query.skipLLM === 'true',
    });

    if (format === 'html') {
      res.type('html').send(formatHTMLReport(report));
    } else {
      res.json(report);
    }
  } catch (error) {
    res.status(500).json({
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Moltbook Scan running at http://localhost:${PORT}`);
});

export default app;
