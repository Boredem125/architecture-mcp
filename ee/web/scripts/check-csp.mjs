/**
 * CSP compatibility checker (no external dependencies).
 *
 * Scans dist/index.html and all dist/**\/*.js for patterns that would violate
 * the strict CSP sent by the Caddy proxy:
 *
 *   default-src 'self'; script-src 'self'; style-src 'self';
 *   img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';
 *   base-uri 'none'; form-action 'self'; object-src 'none'
 *
 * Checks:
 *   1. <script> without a src attribute (inline script) in HTML
 *   2. style= attribute in HTML
 *   3. eval( in JS
 *   4. new Function( in JS
 *
 * Exits non-zero on any violation.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const DIST = resolve(import.meta.dirname, "..", "dist");

const violations = [];

function collectFiles(dir, ext) {
  const result = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...collectFiles(full, ext));
    } else if (entry.name.endsWith(ext)) {
      result.push(full);
    }
  }
  return result;
}

function checkHtml(filePath) {
  const content = readFileSync(filePath, "utf-8");

  // Inline <script> (no src attribute).
  // Match <script...> tags that do NOT have a src= attribute.
  const scriptTags = content.matchAll(/<script\b([^>]*)>/gi);
  for (const m of scriptTags) {
    const attrs = m[1];
    if (!/\bsrc\s*=/i.test(attrs)) {
      violations.push(`${filePath}: inline <script> without src attribute`);
    }
  }

  // style= attribute in HTML.
  // Look for style=" or style=' in the HTML content (outside of script tags).
  if (/\bstyle\s*=/i.test(content)) {
    violations.push(`${filePath}: style= attribute found`);
  }
}

function checkJs(filePath) {
  const content = readFileSync(filePath, "utf-8");

  if (/\beval\s*\(/.test(content)) {
    violations.push(`${filePath}: eval( found`);
  }

  if (/\bnew\s+Function\s*\(/.test(content)) {
    violations.push(`${filePath}: new Function( found`);
  }
}

// -- main -------------------------------------------------------------------

try {
  statSync(DIST);
} catch {
  console.error(`check-csp: dist/ directory not found at ${DIST}`);
  process.exit(1);
}

const htmlFile = join(DIST, "index.html");
try {
  checkHtml(htmlFile);
} catch {
  console.error(`check-csp: cannot read ${htmlFile}`);
  process.exit(1);
}

for (const jsFile of collectFiles(DIST, ".js")) {
  checkJs(jsFile);
}

if (violations.length > 0) {
  console.error("CSP violations found:");
  for (const v of violations) {
    console.error(`  - ${v}`);
  }
  process.exit(1);
}

console.log("check-csp: all clear");
