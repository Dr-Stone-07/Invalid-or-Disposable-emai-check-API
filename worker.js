// worker.js — Cloudflare Worker (ES Modules syntax)

// In-memory cache for the disposable-email blocklist

let cachedDomains = null;
let cacheTimestamp = 0;
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

const DISPOSABLE_LIST_URL =
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf";

// Google DNS-over-HTTPS endpoint (primary).
// Avoids Cloudflare to Cloudflare resolver edge cases that can return
// stale or misleading results for parked / non-existent domains.

const GOOGLE_DOH = "https://dns.google/resolve";

// Cloudflare DNS over HTTPS endpoint.
const CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query";

// Strict email format regex
// Requires:
//   - Local part: one or more characters that are NOT whitespace or @
//   - Exactly one @ symbol
//   - Domain labels: alphanumeric/hyphens separated by dots
//   - TLD: 2–63 alphabetic characters (no numeric-only TLDs, no single-char)

const emailRegex =
  /^[^\s@]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}$/;


// Local fallback disposable-domain list
const LOCAL_DISPOSABLE_DOMAINS = new Set([
  "gcervera.com",
  "mailinator.com",
  "guerrillamail.com",
  "guerrillamail.net",
  "guerrillamail.org",
  "guerrillamail.de",
  "grr.la",
  "guerrillamailblock.com",
  "tempmail.com",
  "temp-mail.org",
  "temp-mail.io",
  "throwaway.email",
  "throwaway.com",
  "yopmail.com",
  "yopmail.fr",
  "yopmail.net",
  "sharklasers.com",
  "guerrillamail.info",
  "spam4.me",
  "trashmail.com",
  "trashmail.me",
  "trashmail.net",
  "dispostable.com",
  "maildrop.cc",
  "mailnesia.com",
  "tempail.com",
  "tempr.email",
  "discard.email",
  "fakeinbox.com",
  "mailcatch.com",
  "mintemail.com",
  "mohmal.com",
  "burnermail.io",
  "10minutemail.com",
  "10minutemail.net",
  "getairmail.com",
  "harakirimail.com",
  "crazymailing.com",
  "tmail.ws",
  "mailnull.com",
  "incognitomail.org",
  "emailondeck.com",
  "getnada.com",
  "tmpmail.net",
  "tmpmail.org",
  "emailfake.com",
  "generator.email",
  "emltmp.com",
]);


// Helpers
/**
 * Fetches and caches the disposable-domain blocklist (in-memory, 1 h TTL).
 * Merges the fetched list with the hardcoded LOCAL_DISPOSABLE_DOMAINS so that
 * known temp-mail providers are always caught even if the remote list is
 * incomplete or the fetch fails.
 *
 * Returns a Set<string> of lowercase domain names.
 */
async function getDisposableDomains() {
  const now = Date.now();

  if (cachedDomains && now - cacheTimestamp < CACHE_TTL) {
    return cachedDomains;
  }

  try {
    const response = await fetch(DISPOSABLE_LIST_URL);
    if (!response.ok) {
      throw new Error(`Blocklist fetch failed: ${response.status}`);
    }
    const text = await response.text();

    const remoteDomains = text
      .split("\n")
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line.length > 0 && !line.startsWith("#") && !line.startsWith("//"));

    // Merge remote list + local fallback into one Set
    const domains = new Set([...remoteDomains, ...LOCAL_DISPOSABLE_DOMAINS]);

    cachedDomains = domains;
    cacheTimestamp = now;
    return domains;
  } catch (err) {
    console.error("Failed to fetch disposable blocklist:", err);
    // Fall back to stale cache, or local list alone, so the worker keeps running
    if (cachedDomains) return cachedDomains;
    return new Set(LOCAL_DISPOSABLE_DOMAINS);
  }
}

// DNS-over-HTTPS helpers
/**
 * Performs a single DNS-over-HTTPS query against the given provider.
 * Returns the parsed JSON response or null on failure.
 * Uses AbortController to enforce a 5-second timeout per request.
 *
 * @param {string} provider - Base URL (e.g. "https://dns.google/resolve")
 * @param {string} name     - Domain name to query
 * @param {string} type     - DNS record type ("MX", "A", etc.)
 * @returns {Promise<object|null>}
 */
async function dohFetch(provider, name, type) {
  const url = `${provider}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      console.error(`DoH ${type} query to ${provider} for "${name}" → HTTP ${res.status}`);
      return null;
    }
    return await res.json();
  } catch (err) {
    clearTimeout(timeoutId);
    console.error(`DoH ${type} query to ${provider} for "${name}" failed:`, err.message || err);
    return null;
  }
}

/**
 * Queries DNS-over-HTTPS for a given name and record type.
 * Tries Google first, then falls back to Cloudflare.
 * Returns the parsed JSON body or null if both providers fail.
 *
 * @param {string} name  - Domain name to query
 * @param {string} type  - DNS record type, e.g. "MX" or "A"
 * @returns {Promise<object|null>}
 */
async function dohQuery(name, type) {
  // Try Google first
  const googleResult = await dohFetch(GOOGLE_DOH, name, type);
  if (googleResult !== null) return googleResult;

  // Fall back to Cloudflare
  const cfResult = await dohFetch(CLOUDFLARE_DOH, name, type);
  return cfResult; // may be null if both failed
}

/**
 * Checks whether a DNS response indicates NXDOMAIN (domain does not exist).
 * DNS RCODE 3 = NXDOMAIN per RFC 1035 §4.1.1.
 *
 * @param {object|null} dnsResponse
 * @returns {boolean}
 */
function isNxdomain(dnsResponse) {
  return dnsResponse !== null && dnsResponse.Status === 3;
}

/**
 * Extracts MX records from a DoH response.
 * Filters to only type-15 (MX) records, strips trailing dots, and sorts
 * by priority (lowest number = highest priority).
 *
 * Also detects RFC 7505 "null MX" (a single MX of "0 .") which explicitly
 * declares that the domain does NOT accept email.
 *
 * Returns { records: Array, isNullMx: boolean }
 */
function parseMxRecords(dnsResponse) {
  if (
    !dnsResponse ||
    !Array.isArray(dnsResponse.Answer) ||
    dnsResponse.Answer.length === 0
  ) {
    return { records: [], isNullMx: false };
  }

  const mxEntries = dnsResponse.Answer
    .filter((r) => r.type === 15) // 15 = MX
    .map((r) => {
      const parts = r.data.trim().split(/\s+/);
      const priority = parseInt(parts[0], 10);
      const host = (parts[1] || "").replace(/\.$/, "");
      return { host, priority };
    })
    .sort((a, b) => a.priority - b.priority);

  // Null MX check (RFC 7505): "0 ." means domain refuses all email
  const isNullMx =
    mxEntries.length === 1 &&
    mxEntries[0].priority === 0 &&
    (mxEntries[0].host === "" || mxEntries[0].host === ".");

  return {
    records: isNullMx ? [] : mxEntries,
    isNullMx,
  };
}

/**
 * Extracts the first A record (IPv4 address) from a DoH response.
 * Returns the IP string or null.
 */
function parseARecord(dnsResponse) {
  if (
    !dnsResponse ||
    !Array.isArray(dnsResponse.Answer) ||
    dnsResponse.Answer.length === 0
  ) {
    return null;
  }
  const aRecord = dnsResponse.Answer.find((r) => r.type === 1); // 1 = A
  return aRecord ? aRecord.data : null;
}

/**
 * Performs a complete DNS validation of a domain for email capability.
 *
 * Queries MX and A records IN PARALLEL for speed, then applies strict
 * validation logic:
 *   1. NXDOMAIN (Status 3) → domain does not exist
 *   2. MX records found → resolve best MX host's IP → valid if reachable
 *   3. No MX but A record exists → domain exists but can't receive mail
 *   4. Neither MX nor A → no mail server found
 *
 * @param {string} domain - Lowercase domain to validate
 * @returns {Promise<{ valid_format: boolean, reason: string|null,
 *           mx_host: string|null, mx_info: string|null, mx_ip: string|null }>}
 */
async function validateDomainDns(domain) {
  const asciiDomain = toAsciiDomain(domain);

  // Fire MX and A queries in parallel — don't wait for one to finish
  const [mxResponse, aResponse] = await Promise.all([
    dohQuery(asciiDomain, "MX"),
    dohQuery(asciiDomain, "A"),
  ]);


  // 1) NXDOMAIN - the domain does not exist in DNS at all

  if (isNxdomain(mxResponse) || isNxdomain(aResponse)) {
    return {
      valid_format: false,
      reason: "Domain Does Not Exist",
      mx_host: null,
      mx_info: null,
      mx_ip: null,
    };
  }

  
  // 2) Parse MX records
  
  const { records: mxRecords, isNullMx } = parseMxRecords(mxResponse);
  const domainIp = parseARecord(aResponse);

  // Null MX (RFC 7505) — domain explicitly refuses email
  if (isNullMx) {
    return {
      valid_format: false,
      reason: "No Mail Server (MX) Found",
      mx_host: null,
      mx_info: "Domain has a null MX record — explicitly refuses email",
      mx_ip: domainIp, // include A record IP for informational purposes
    };
  }

  
  // 3) MX records found — resolve the best MX host's A record

  if (mxRecords.length > 0) {
    const bestMx = mxRecords[0];
    const mxIp = await dohQuery(bestMx.host, "A").then((r) => parseARecord(r));

    if (mxIp) {
      return {
        valid_format: true,
        reason: null,
        mx_host: bestMx.host,
        mx_info: `Using MX pointer ${bestMx.host} from DNS with priority: ${bestMx.priority}`,
        mx_ip: mxIp,
      };
    }

    // MX record exists but the mail server hostname doesn't resolve
    return {
      valid_format: false,
      reason: "No Mail Server (MX) Found",
      mx_host: bestMx.host,
      mx_info: `MX pointer ${bestMx.host} found but does not resolve to an IP`,
      mx_ip: null,
    };
  }

  
  // 4) No MX records — check if at least an A record exists
  
  if (domainIp) {
    // Domain exists (has an IP) but has zero MX records → cannot receive mail
    return {
      valid_format: false,
      reason: "No Mail Server (MX) Found",
      mx_host: null,
      mx_info: `Domain resolves to ${domainIp} but has no MX records — cannot receive mail`,
      mx_ip: domainIp,
    };
  }

  
  // 5) Neither MX nor A records — completely unreachable
  
  return {
    valid_format: false,
    reason: "No Mail Server (MX) Found",
    mx_host: null,
    mx_info: null,
    mx_ip: null,
  };
}


// IDN / Punycode helper (zero dependencies)

/**
 * Converts an internationalized domain (e.g. bücher.de) to its ASCII /
 * Punycode equivalent (xn--bcher-kva.de) using the URL constructor,
 * which performs IDNA encoding internally on all modern runtimes.
 *
 * @param {string} domain
 * @returns {string} ASCII-safe domain
 */
function toAsciiDomain(domain) {
  try {
    return new URL(`http://${domain}`).hostname;
  } catch {
    return domain;
  }
}


// Subdomain-recursive disposable check

/**
 * Checks whether a domain — or any of its parent domains — appears in the
 * disposable blocklist.  For example, "sub.mailinator.com" will match if
 * either "sub.mailinator.com" or "mailinator.com" is in the Set.
 *
 * @param {string}      domain
 * @param {Set<string>} blocklist
 * @returns {boolean}
 */
function isDisposableDomain(domain, blocklist) {
  if (blocklist.has(domain)) return true;

  const parts = domain.split(".");
  // Walk up: skip index 0, stop before we reach a bare TLD
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join(".");
    if (blocklist.has(parent)) return true;
  }
  return false;
}


// CORS helper
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
    },
  });
}


// Main request handler

async function handleRequest(request) {
  // Handle CORS pre-flight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // Only allow GET
  if (request.method !== "GET") {
    return jsonResponse({ error: "Method Not Allowed" }, 405);
  }

  const url = new URL(request.url);

  // URLSearchParams.get() decodes '+' as a space per the
  // application/x-www-form-urlencoded spec, which breaks plus-addressed
  // emails like user+tag@gmail.com.  Restore spaces → '+' before processing.
  const rawEmail = url.searchParams.get("email");
  const email = rawEmail ? rawEmail.replace(/ /g, "+") : null;

  // Require the email parameter
  if (!email) {
    return jsonResponse(
      { error: "Missing 'email' query parameter. Usage: ?email=user@example.com" },
      400
    );
  }

  // Strict regex validation 
  // The regex requires a proper domain with a 2–63 char alphabetic TLD.
  // Addresses like "user@localhost" or "user@.com" are rejected here.
  const regexValid = emailRegex.test(email);
  const domain = regexValid ? email.split("@")[1].toLowerCase() : null;

  // If the format is invalid at the regex level, short-circuit: no DNS
  // lookups needed.
  if (!regexValid) {
    return jsonResponse({
      email,
      domain: null,
      valid_format: false,
      is_disposable: false,
      reason: "Invalid Email Format",
      mx_host: null,
      mx_info: null,
      mx_ip: null,
    });
  }

  // --- Parallel: fetch blocklist + full DNS validation ---
  // Both tasks start at the same time; we await them together.
  // validateDomainDns internally runs MX and A queries in parallel too.
  const [disposableDomains, dnsResult] = await Promise.all([
    getDisposableDomains(),
    validateDomainDns(domain),
  ]);

  // Disposable check (subdomain recursion: checks full domain + parents) 
  const is_disposable = isDisposableDomain(domain, disposableDomains);

  // Determine reason
  let reason;
  if (is_disposable) {
    reason = "Blacklist";
  } else if (dnsResult.reason) {
    reason = dnsResult.reason;
  } else {
    reason = "None";
  }

  // Build response 
  const result = {
    email,
    domain,
    valid_format: dnsResult.valid_format,
    is_disposable,
    reason,
    mx_host: dnsResult.mx_host,
    mx_info: dnsResult.mx_info,
    mx_ip: dnsResult.mx_ip,
  };

  return jsonResponse(result);
}


// Cloudflare Worker entry-point (ES Modules)
export default {
  async fetch(request) {
    return handleRequest(request);
  },
};
