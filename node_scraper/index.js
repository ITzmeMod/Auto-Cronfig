#!/usr/bin/env node
/**
 * Auto-Cronfig v3 — Node.js Scraper Module
 * Scans pastebin, GitHub web search, and gists for secrets using axios + cheerio.
 * Output: newline-delimited JSON, one object per finding. Exit code always 0.
 */

'use strict';

const axios = require('axios');
const cheerio = require('cheerio');
const pLimit = require('p-limit');
const { program } = require('commander');

// Top 20 secret patterns (JS implementation)
const PATTERNS = [
  { name: 'AWS Access Key', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/ },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/ },
  { name: 'Stripe Test Key', regex: /sk_test_[0-9a-zA-Z]{24,}/ },
  { name: 'GitHub PAT', regex: /ghp_[A-Za-z0-9]{36}/ },
  { name: 'GitHub OAuth Token', regex: /gho_[A-Za-z0-9]{36}/ },
  { name: 'GitLab PAT', regex: /glpat-[A-Za-z0-9\-_]{20}/ },
  { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  { name: 'Discord Bot Token', regex: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/ },
  { name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/ },
  { name: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{48}/ },
  { name: 'Anthropic API Key', regex: /sk-ant-(?:api03-)?[A-Za-z0-9\-_]{93,}/ },
  { name: 'HuggingFace Token', regex: /hf_[A-Za-z0-9]{34,}/ },
  { name: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/ },
  { name: 'OpenSSH Private Key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/ },
  { name: 'MongoDB Connection', regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/ },
  { name: 'PostgreSQL Connection', regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/ },
  { name: 'Generic API Key', regex: /api[_\-\s]*key[\s]*[=:"']+\s*([A-Za-z0-9\-_]{20,80})/i },
  { name: 'Generic Password', regex: /password[\s]*[=:"']+\s*([^\s"']{8,80})/i },
  { name: 'Telegram Bot Token', regex: /[0-9]{8,10}:[A-Za-z0-9_\-]{35}/ },
];

/**
 * Scan content for all patterns. Returns array of matches.
 */
function scanContent(content) {
  const matches = [];
  for (const p of PATTERNS) {
    try {
      const m = content.match(p.regex);
      if (m) {
        const raw = m[1] || m[0];
        const preview = raw.slice(0, 4) + '*'.repeat(Math.max(0, raw.length - 8)) + raw.slice(-4);
        matches.push({ pattern: p.name, raw, preview });
      }
    } catch (e) {
      // Ignore regex errors
    }
  }
  return matches;
}

/**
 * Emit a finding as NDJSON to stdout.
 */
function emitFinding(source, url, pattern, preview, raw) {
  const obj = { source, url, pattern, preview, raw };
  process.stdout.write(JSON.stringify(obj) + '\n');
}

/**
 * Create an axios instance with a reasonable timeout and user-agent.
 */
function createAxios(token) {
  const headers = {
    'User-Agent': 'Auto-Cronfig/3.0 (github-scanner)',
    'Accept': 'text/html,application/json',
  };
  if (token) {
    headers['Authorization'] = `token ${token}`;
    headers['Accept'] = 'application/vnd.github.v3+json';
  }
  return axios.create({
    timeout: 15000,
    headers,
  });
}

// ── Paste scanner ──────────────────────────────────────────────────────────────

async function scanPastebin(limit) {
  const client = createAxios();
  const limiter = pLimit(3);

  let links = [];
  try {
    const resp = await client.get('https://pastebin.com/archive');
    const $ = cheerio.load(resp.data);
    $('table.maintable a').each((i, el) => {
      const href = $(el).attr('href');
      if (href && href.match(/^\/[a-zA-Z0-9]{8}$/)) {
        links.push(`https://pastebin.com/raw${href}`);
      }
    });
  } catch (e) {
    // pastebin may be blocked; silently skip
    return;
  }

  links = links.slice(0, limit || 20);

  await Promise.all(
    links.map(url =>
      limiter(async () => {
        try {
          const r = await client.get(url);
          const matches = scanContent(r.data);
          for (const m of matches) {
            emitFinding('pastebin', url, m.pattern, m.preview, m.raw);
          }
        } catch (e) {
          // Skip failed pastes
        }
      })
    )
  );
}

// ── GitHub web scraper ─────────────────────────────────────────────────────────

async function scanGitHubWeb(query, token) {
  const client = createAxios();
  const searchUrl = `https://github.com/search?q=${encodeURIComponent(query)}&type=code`;

  try {
    const resp = await client.get(searchUrl, {
      headers: {
        'Accept': 'text/html',
        'Cookie': token ? '' : '',
      },
    });
    const $ = cheerio.load(resp.data);

    // GitHub search result code snippets
    const snippets = [];
    $('.code-list .code-list-item').each((i, el) => {
      const code = $(el).find('table.blob-code').text() || $(el).text();
      const link = $(el).find('a.Link--muted').attr('href') || '';
      if (code) snippets.push({ code, url: `https://github.com${link}` });
    });

    // Also try newer GitHub search layout
    $('[data-testid="search-result"]').each((i, el) => {
      const code = $(el).find('pre').text() || '';
      const link = $(el).find('a').first().attr('href') || '';
      if (code) snippets.push({ code, url: `https://github.com${link}` });
    });

    for (const s of snippets) {
      const matches = scanContent(s.code);
      for (const m of matches) {
        emitFinding('github-web', s.url, m.pattern, m.preview, m.raw);
      }
    }
  } catch (e) {
    // GitHub web scraping may require auth; silently skip
  }
}

// ── Gist scanner ───────────────────────────────────────────────────────────────

async function scanGists(username, token) {
  const client = createAxios(token);
  const limiter = pLimit(3);

  let gists = [];
  try {
    const resp = await client.get(
      `https://api.github.com/users/${username}/gists`,
      { params: { per_page: 30 } }
    );
    gists = resp.data || [];
  } catch (e) {
    return;
  }

  await Promise.all(
    gists.map(gist =>
      limiter(async () => {
        const gistUrl = gist.html_url || '';
        for (const [filename, fileInfo] of Object.entries(gist.files || {})) {
          const rawUrl = fileInfo.raw_url;
          if (!rawUrl) continue;
          try {
            const r = await axios.get(rawUrl, { timeout: 10000 });
            const matches = scanContent(r.data);
            for (const m of matches) {
              emitFinding('gist', gistUrl, m.pattern, m.preview, m.raw);
            }
          } catch (e) {
            // Skip failed gist files
          }
        }
      })
    )
  );
}

// ── CLI ────────────────────────────────────────────────────────────────────────

program
  .name('auto-cronfig-scraper')
  .description('Auto-Cronfig v3 Node.js scraper module')
  .option('--mode <mode>', 'Scan mode: paste|github-web|gist', 'paste')
  .option('--query <query>', 'Search query (for github-web mode)')
  .option('--user <username>', 'GitHub username (for gist mode)')
  .option('--token <token>', 'GitHub token')
  .option('--limit <n>', 'Max items to scan', parseInt, 20)
  .parse(process.argv);

const opts = program.opts();

(async () => {
  try {
    const mode = opts.mode;
    const token = opts.token || process.env.GITHUB_TOKEN;

    if (mode === 'paste') {
      await scanPastebin(opts.limit);
    } else if (mode === 'github-web') {
      const query = opts.query || 'API_KEY=';
      await scanGitHubWeb(query, token);
    } else if (mode === 'gist') {
      const user = opts.user;
      if (!user) {
        process.stderr.write('--user required for gist mode\n');
      } else {
        await scanGists(user, token);
      }
    } else {
      process.stderr.write(`Unknown mode: ${mode}\n`);
    }
  } catch (e) {
    // Never crash — log to stderr and exit 0
    process.stderr.write(`Scraper error: ${e.message}\n`);
  }
  process.exit(0);
})();
