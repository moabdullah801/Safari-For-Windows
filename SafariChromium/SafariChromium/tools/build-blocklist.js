// Builds blocklist.txt (one host per line) from the filter lists bundled with
// uBlock Origin. Only precise, host-level network rules are used:
//   ||host^            ||host^$third-party        pgl.yoyo.org hosts lines
// Rules with paths, resource-type options or domain= options are skipped, so
// nothing is over-blocked. Run:  node tools/build-blocklist.js
const fs = require('fs');
const path = require('path');

const base = path.join(__dirname, '..', 'extensions', 'ublock0', 'assets');
const abpLists = [
  'thirdparties/easylist/easylist.txt',
  'thirdparties/easylist/easyprivacy.txt',
  'thirdparties/urlhaus-filter/urlhaus-filter-online.txt',
  'ublock/filters.min.txt',
  'ublock/privacy.min.txt',
  'ublock/badware.min.txt',
  'ublock/unbreak.min.txt',
];
const hostsLists = ['thirdparties/pgl.yoyo.org/as/serverlist'];

// Never block these, whatever a list says.
const SAFE = new Set([
  'google.com', 'gstatic.com', 'googleapis.com', 'youtube.com', 'ytimg.com',
  'github.com', 'githubusercontent.com', 'githubassets.com', 'microsoft.com',
  'apple.com', 'icloud.com', 'cloudflare.com', 'duckduckgo.com', 'wikipedia.org',
  'amazon.com', 'facebook.com', 'twitter.com', 'x.com', 'live.com', 'bing.com',
]);
const OK_OPTIONS = new Set(['third-party', '3p', 'important', 'all']);
const RULE = /^\|\|([a-z0-9][a-z0-9.-]*\.[a-z0-9-]+)\^?(?:\$(.+))?$/i;

const block = new Set();
const allow = new Set();

for (const rel of abpLists) {
  const file = path.join(base, rel);
  if (!fs.existsSync(file)) { console.warn('missing', rel); continue; }
  for (let line of fs.readFileSync(file, 'utf8').split('\n')) {
    line = line.trim();
    if (!line || line[0] === '!' || line[0] === '[') continue;
    if (line.includes('##') || line.includes('#@#') || line.includes('#?#') || line.includes('#$#') || line.includes('+js(')) continue;
    const exception = line.startsWith('@@');
    const m = RULE.exec(exception ? line.slice(2) : line);
    if (!m) continue;
    const host = m[1].toLowerCase();
    const opts = m[2] ? m[2].split(',') : [];
    if (opts.some((o) => !OK_OPTIONS.has(o))) continue;
    (exception ? allow : block).add(host);
  }
}

for (const rel of hostsLists) {
  const file = path.join(base, rel);
  if (!fs.existsSync(file)) { console.warn('missing', rel); continue; }
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = /^(?:127\.0\.0\.1|0\.0\.0\.0)\s+([a-z0-9.-]+\.[a-z0-9-]+)/i.exec(line.trim());
    if (m) block.add(m[1].toLowerCase());
  }
}

const out = [...block].filter((h) => {
  if (allow.has(h)) return false;
  if (/^[\d.]+$/.test(h)) return false; // bare IP addresses
  const parts = h.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    if (SAFE.has(parts.slice(i).join('.'))) return false;
  }
  return true;
}).sort();

fs.writeFileSync(path.join(__dirname, '..', 'blocklist.txt'), out.join('\n') + '\n');
console.log(`blocklist.txt: ${out.length} hosts (from ${block.size} rules, ${allow.size} exceptions)`);
