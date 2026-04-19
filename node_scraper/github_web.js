/**
 * Auto-Cronfig v3 — GitHub Web Scraper
 * Scrapes GitHub code search results and fetches gists via API.
 */

'use strict';

const axios = require('axios');
const cheerio = require('cheerio');

const USER_AGENT = 'Auto-Cronfig/3.0 (github-scanner)';

/**
 * Create an axios client with optional GitHub token authentication.
 * @param {string} [token] - GitHub personal access token
 */
function createClient(token) {
  const headers = {
    'User-Agent': USER_AGENT,
    'Accept': 'application/vnd.github.v3+json',
  };
  if (token) {
    headers['Authorization'] = `token ${token}`;
  }
  return axios.create({
    timeout: 15000,
    headers,
  });
}

/**
 * Scrape GitHub code search web results using axios + cheerio.
 * Returns array of { url, content, filename }.
 *
 * @param {string} query - Search query
 * @param {string} [token] - GitHub token for better rate limits
 * @returns {Promise<Array<{url:string,content:string,filename:string}>>}
 */
async function searchCodeWeb(query, token) {
  const client = createClient(token);
  const results = [];

  try {
    const resp = await client.get('https://github.com/search', {
      params: { q: query, type: 'code' },
      headers: {
        'Accept': 'text/html',
        'User-Agent': USER_AGENT,
      },
    });

    const $ = cheerio.load(resp.data);

    // Parse code search results (multiple GitHub layouts)
    // Layout 1: classic code-list
    $('.code-list .code-list-item').each((i, el) => {
      const codeEl = $(el).find('table.blob-code, .blob-code');
      const code = codeEl.text().trim();
      const linkEl = $(el).find('a.Link--muted, a[href*="/blob/"]').first();
      const href = linkEl.attr('href') || '';
      const filename = href.split('/').pop() || 'unknown';
      if (code) {
        results.push({
          url: href ? `https://github.com${href}` : 'https://github.com',
          content: code,
          filename,
        });
      }
    });

    // Layout 2: newer search results
    $('[data-testid="results-list"] [data-testid="search-result"]').each((i, el) => {
      const code = $(el).find('pre, code').text().trim();
      const href = $(el).find('a[href*="/blob/"]').first().attr('href') || '';
      const filename = href.split('/').pop() || 'unknown';
      if (code) {
        results.push({
          url: href ? `https://github.com${href}` : 'https://github.com',
          content: code,
          filename,
        });
      }
    });

    // Layout 3: basic link extraction
    if (results.length === 0) {
      $('a[href*="/blob/"]').each((i, el) => {
        const href = $(el).attr('href') || '';
        const text = $(el).closest('.f4').text().trim() || $(el).text().trim();
        if (href && text && text.length > 10) {
          results.push({
            url: `https://github.com${href}`,
            content: text,
            filename: href.split('/').pop() || 'unknown',
          });
        }
      });
    }
  } catch (e) {
    // GitHub web scraping may fail silently
  }

  return results;
}

/**
 * Fetch all public gists for a GitHub user via the API.
 * Returns array of { url, content, filename }.
 *
 * @param {string} username - GitHub username
 * @param {string} [token] - GitHub token
 * @returns {Promise<Array<{url:string,content:string,filename:string}>>}
 */
async function fetchGists(username, token) {
  const client = createClient(token);
  const results = [];

  let gists = [];
  try {
    const resp = await client.get(
      `https://api.github.com/users/${username}/gists`,
      { params: { per_page: 30 } }
    );
    gists = resp.data || [];
  } catch (e) {
    return results;
  }

  for (const gist of gists) {
    const gistUrl = gist.html_url || '';
    const files = gist.files || {};

    for (const [filename, fileInfo] of Object.entries(files)) {
      const rawUrl = fileInfo.raw_url;
      if (!rawUrl) continue;

      try {
        const r = await axios.get(rawUrl, {
          timeout: 10000,
          headers: { 'User-Agent': USER_AGENT },
        });
        const content = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
        if (content) {
          results.push({ url: gistUrl, content, filename });
        }
      } catch (e) {
        // Skip failed files
      }
    }
  }

  return results;
}

module.exports = { searchCodeWeb, fetchGists };
