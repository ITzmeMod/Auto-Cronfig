/**
 * Auto-Cronfig v3 — Paste Site Scanner
 * Scans pastebin.com, paste.ubuntu.com, and gist.github.com for secrets.
 */

'use strict';

const axios = require('axios');
const cheerio = require('cheerio');
const pLimit = require('p-limit');

const USER_AGENT = 'Auto-Cronfig/3.0 (secret-scanner)';

const _client = axios.create({
  timeout: 12000,
  headers: { 'User-Agent': USER_AGENT },
});

/**
 * Fetch a URL, returning text body or null on error.
 * @param {string} url
 * @returns {Promise<string|null>}
 */
async function fetchSafe(url) {
  try {
    const resp = await _client.get(url);
    return typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
  } catch (e) {
    return null;
  }
}

/**
 * Get recent paste links from pastebin.com/archive.
 * Returns array of { url: rawUrl, source: 'pastebin' }
 * @returns {Promise<Array<{url:string,source:string}>>}
 */
async function getPastebinLinks() {
  const html = await fetchSafe('https://pastebin.com/archive');
  if (!html) return [];
  const $ = cheerio.load(html);
  const links = [];
  $('table.maintable a').each((i, el) => {
    const href = $(el).attr('href');
    if (href && /^\/[a-zA-Z0-9]{8}$/.test(href)) {
      links.push({ url: `https://pastebin.com/raw${href}`, source: 'pastebin' });
    }
  });
  return links.slice(0, 25);
}

/**
 * Get recent pastes from paste.ubuntu.com.
 * Returns array of { url, source }
 * @returns {Promise<Array<{url:string,source:string}>>}
 */
async function getUbuntuPasteLinks() {
  const html = await fetchSafe('https://paste.ubuntu.com');
  if (!html) return [];
  const $ = cheerio.load(html);
  const links = [];
  $('a[href*="/p/"]').each((i, el) => {
    const href = $(el).attr('href');
    if (href && /\/p\/[a-zA-Z0-9]+\/?$/.test(href)) {
      const rawUrl = href.startsWith('http') ? href : `https://paste.ubuntu.com${href}`;
      links.push({ url: rawUrl, source: 'paste.ubuntu.com' });
    }
  });
  return links.slice(0, 15);
}

/**
 * Get recent public gists from gist.github.com/discover.
 * Returns array of { url, source }
 * @returns {Promise<Array<{url:string,source:string}>>}
 */
async function getGistDiscoverLinks() {
  const html = await fetchSafe('https://gist.github.com/discover');
  if (!html) return [];
  const $ = cheerio.load(html);
  const links = [];
  $('a.link-overlay').each((i, el) => {
    const href = $(el).attr('href');
    if (href && /^\/[a-zA-Z0-9]+\/[a-fA-F0-9]{20,}$/.test(href)) {
      links.push({ url: `https://gist.github.com${href}`, source: 'gist.github.com' });
    }
  });
  return links.slice(0, 15);
}

/**
 * Fetch actual content from a paste URL.
 * Handles different paste site formats.
 */
async function fetchPasteContent(url, source) {
  if (source === 'pastebin') {
    // Already a raw URL
    return await fetchSafe(url);
  } else if (source === 'paste.ubuntu.com') {
    // Try /plain/ endpoint
    const rawUrl = url.replace(/\/?$/, '/plain/');
    return await fetchSafe(rawUrl) || await fetchSafe(url);
  } else if (source === 'gist.github.com') {
    // Gist: need to parse page to find raw content URL
    const html = await fetchSafe(url);
    if (!html) return null;
    const $ = cheerio.load(html);
    const rawLink = $('a[href*="/raw/"]').first().attr('href');
    if (rawLink) {
      const rawUrl = rawLink.startsWith('http') ? rawLink : `https://gist.github.com${rawLink}`;
      return await fetchSafe(rawUrl);
    }
    // Extract code directly from page
    return $('.blob-code').map((i, el) => $(el).text()).get().join('\n');
  }
  return await fetchSafe(url);
}

/**
 * Main export: scan paste sites for secrets.
 * @param {string} [query] - Optional keyword to filter pastes (not all sites support this)
 * @returns {Promise<Array<{url:string,content:string,source:string}>>}
 */
async function scanPasteSites(query) {
  const limiter = pLimit(5);

  // Gather all links
  const [pastebinLinks, ubuntuLinks, gistLinks] = await Promise.all([
    getPastebinLinks(),
    getUbuntuPasteLinks(),
    getGistDiscoverLinks(),
  ]);

  const allLinks = [...pastebinLinks, ...ubuntuLinks, ...gistLinks];

  // Fetch content for each link
  const results = await Promise.all(
    allLinks.map(({ url, source }) =>
      limiter(async () => {
        const content = await fetchPasteContent(url, source);
        if (!content) return null;
        // If query provided, filter to only pastes containing the query
        if (query && !content.toLowerCase().includes(query.toLowerCase())) return null;
        return { url, content, source };
      })
    )
  );

  return results.filter(Boolean);
}

module.exports = { scanPasteSites };
