/**
 * RSS feed rewriter + media proxy Worker
 * - /feed?src={encodedFeedUrl}
 * - /u/{base64url}
 *
 * Deployment: wrangler publish
 *
 * Notes:
 * - Set WORKER_TOKEN env var in Cloudflare dashboard (recommended). If set, include ?t=TOKEN on feed URLs.
 * - Adjust ALLOWED_MEDIA_HOSTS if needed.
 */

const ALLOWED_MEDIA_HOSTS = new Set([
  "pbs.twimg.com",
  "video.twimg.com",
  "ton.twimg.com",
  "p.twimg.com",
  "twimg.com",
  "api.twitter.com",
  "abs.twimg.com"
]);

const FEED_CACHE_TTL = 300; // seconds
const MEDIA_CACHE_TTL = 24 * 3600; // seconds

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event));
});

async function handleRequest(event) {
  const req = event.request;
  const url = new URL(req.url);
  const pathname = url.pathname.replace(/\/+$/, ""); // trim trailing slash

  // Token enforcement (optional)
  const WORKER_TOKEN = SECRET_TOKEN(); // wrapper to read from environment safely
  if (WORKER_TOKEN) {
    const t = url.searchParams.get("t") || "";
    if (!t || t !== WORKER_TOKEN) return new Response("Unauthorized", { status: 401 });
    // remove token param for processing/cache-key consistency
    url.searchParams.delete("t");
  }

  // Route: /u/{b64} -> media proxy
  if (pathname.startsWith("/u/")) {
    const b64 = pathname.slice(3); // after /u/
    return mediaProxyHandler(event, req, b64);
  }

  // Route: /feed
  if (pathname === "/feed") {
    return feedRewriteHandler(event, req, url);
  }

  return new Response("Not found", { status: 404 });
}

async function feedRewriteHandler(event, req, url) {
  const src = url.searchParams.get("src");
  if (!src) return new Response("Missing src param", { status: 400 });

  // decode src: accept percent-encoded URL or base64url (auto-detect)
  let feedUrl;
  try {
    feedUrl = decodeURIComponent(src);
    // quick validation
    new URL(feedUrl);
  } catch (e) {
    // fallback: try base64url decode
    try {
      feedUrl = base64urlDecodeToString(src);
      new URL(feedUrl);
    } catch (err) {
      return new Response("Invalid src param", { status: 400 });
    }
  }

  // Fetch upstream feed
  const downstreamHeaders = {
    "user-agent": "Mozilla/5.0 (compatible; rss-media-proxy/1.0)",
    "accept": "application/rss+xml, application/xml, text/xml, */*"
  };

  let upstreamResp;
  try {
    upstreamResp = await fetch(feedUrl, { headers: downstreamHeaders, redirect: "follow" });
  } catch (e) {
    return new Response("Upstream fetch failed", { status: 502 });
  }

  if (!upstreamResp.ok) {
    return new Response("Upstream returned " + upstreamResp.status, { status: 502 });
  }

  let text;
  try {
    text = await upstreamResp.text();
  } catch (e) {
    return new Response("Failed reading upstream feed", { status: 502 });
  }

  // Rewrite URLs: replace absolute https://... occurrences used in attributes and text
  // Safe rewrite: only rewrite https URLs (not protocol-relative or relative)
  const hostOrigin = req.headers.get("host") ? `https://${req.headers.get("host")}` : new URL(req.url).origin;
  const tokenParam = (SECRET_TOKEN() ? `?t=${SECRET_TOKEN()}` : "");

  // We will rewrite:
  // - src="https://..."
  // - href="https://..."
  // - url="https://..." (used by media:content, enclosure)
  // - <media:content url="https://...">
  // Use a replacer that encodes original URL into base64url and returns /u/{b64}
  const rewritten = text.replace(/https:\/\/[^\s"'<>]+/g, (match) => {
    try {
      // Only rewrite if the URL is not already pointing to this worker domain
      if (match.startsWith(hostOrigin)) return match;
      const b64 = base64urlEncode(match);
      return `${hostOrigin}/u/${b64}${tokenParam}`;
    } catch (e) {
      return match;
    }
  });

  const headers = new Headers();
  headers.set("Content-Type", deriveContentType(upstreamResp) || "application/rss+xml; charset=utf-8");
  headers.set("Cache-Control", `public, max-age=${FEED_CACHE_TTL}`);
  headers.set("Access-Control-Allow-Origin", "*");

  return new Response(rewritten, { status: 200, headers });
}

async function mediaProxyHandler(event, req, b64) {
  // decode base64url to original URL
  let original;
  try {
    original = base64urlDecodeToString(b64);
  } catch (e) {
    return new Response("Invalid encoded URL", { status: 400 });
  }

  let target;
  try {
    target = new URL(original);
  } catch (e) {
    return new Response("Invalid target URL", { status: 400 });
  }

  if (!ALLOWED_MEDIA_HOSTS.has(target.hostname)) {
    return new Response("Host not allowed", { status: 403 });
  }

  // Build outgoing fetch preserving Range-like headers
  const outgoing = new Headers();
  for (const h of ["range", "if-range", "accept", "accept-language"]) {
    const v = req.headers.get(h);
    if (v) outgoing.set(h, v);
  }
  outgoing.set("user-agent", "Mozilla/5.0 (compatible; rss-media-proxy/1.0)");

  const fetchReq = new Request(target.toString(), {
    method: req.method,
    headers: outgoing,
    redirect: "follow"
  });

  const cache = caches.default;
  const cacheKey = fetchReq.clone();

  // Try cache for GET
  if (req.method === "GET") {
    const cached = await cache.match(cacheKey);
    if (cached) return sanitizeResponse(cached);
  }

  let originResp;
  try {
    originResp = await fetch(fetchReq);
  } catch (e) {
    return new Response("Upstream fetch failed", { status: 502 });
  }

  // Sanitize
  const sanitized = sanitizeResponse(originResp);

  // Cache successful GET responses with 200 or 206
  if (req.method === "GET" && (originResp.status === 200 || originResp.status === 206)) {
    const cacheable = sanitized.clone();
    cacheable.headers.set("Cache-Control", `public, max-age=${MEDIA_CACHE_TTL}`);
    // event.waitUntil works here because event is available in scope
    try { event.waitUntil(cache.put(cacheKey, cacheable)); } catch (e) { /* noop */ }
  }

  return sanitized;
}

function sanitizeResponse(response) {
  const headers = new Headers(response.headers);
  // Remove sensitive/tracking headers
  ["set-cookie", "set-cookie2", "x-request-id", "server", "x-amz-request-id", "via"].forEach(h => headers.delete(h));
  // Allow cross-origin use by RSS clients/players
  headers.set("Access-Control-Allow-Origin", "*");
  // Preserve content-type and content-length as-is
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

/* Utilities */

function deriveContentType(upstreamResp) {
  const ct = upstreamResp.headers.get("content-type");
  if (!ct) return null;
  // For feeds, prefer rss/xml types; otherwise return upstream content-type
  return ct;
}

function base64urlEncode(str) {
  return Buffer.from(str, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecodeToString(b64) {
  // accept both padded and unpadded base64url
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - b64.length % 4) % 4);
  const buf = Buffer.from(padded, "base64");
  return buf.toString("utf8");
}

// Read secret token from environment (WORKER_TOKEN). Using global this.__STATIC_CONTENT_MANIFEST__ would be wrong.
// Wrangler exposes env via bindings; for simplicity, use global variable injected by wrangler define (see README) or Cloudflare dashboard secret.
// Here we attempt to read from global variable WORKER_TOKEN if set.
function SECRET_TOKEN() {
  try {
    // eslint-disable-next-line no-undef
    if (typeof WORKER_TOKEN !== "undefined" && WORKER_TOKEN) return WORKER_TOKEN;
  } catch (e) {}
  try {
    // Cloudflare environment: global variable set by wrangler define
    // eslint-disable-next-line no-undef
    if (typeof __ENV !== "undefined" && __ENV.WORKER_TOKEN) return __ENV.WORKER_TOKEN;
  } catch (e) {}
  // If no token provided, return empty string (token disabled)
  return "";
}
