/**
 * analyzer.js — Cookie & Session Analyzer
 * Yesha Patel Portfolio
 * Parses Set-Cookie / Cookie headers and JSON cookie exports, audits each cookie
 * against OWASP Session Management guidance, and generates hardened headers.
 * Runs entirely client-side — no network requests.
 */

(function (root) {
  'use strict';

  const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];
  const WEIGHT = { critical: 40, high: 20, medium: 10, low: 4, info: 0 };
  const ATTRS = ['path', 'domain', 'expires', 'max-age', 'secure', 'httponly', 'samesite', 'partitioned', 'priority'];
  const DAY = 86400;

  const SESSION_RE = /(sess|sid$|^sid|token|auth|jwt|login|remember|identity|access|refresh|bearer|jsessionid|phpsessid|connect\.sid|aspxauth|asp\.net|_session|user_?id)/i;
  const CSRF_RE = /(csrf|xsrf)/i;
  const TRACKING_RE = /^(_ga|_gid|_gat|_fbp|_fbc|_gcl|_hj|ajs_|mp_|_uet|_clck|_clsk|__utm)/i;
  const PRIV_RE = /(admin|role|privilege|perm|group|user_?id|uid|username|is_?staff|level|tier|plan)/i;
  const SENSITIVE_RE = /(passw|pwd|secret|ssn|credit|card_?num|cvv|api_?key|private)/i;
  const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

  /* ── Encoding helpers ── */

  function b64decode(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length < 4) return null;
    while (s.length % 4) s += '=';
    try {
      const bin = typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary');
      try {
        return decodeURIComponent(escape(bin)); // UTF-8
      } catch (e) {
        return bin;
      }
    } catch (e) {
      return null;
    }
  }

  function isPrintable(str) {
    if (!str) return false;
    let ok = 0;
    for (const ch of str) {
      const c = ch.charCodeAt(0);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c > 159) ok++;
    }
    return ok / str.length > 0.95;
  }

  function tryJSON(str) {
    if (!str) return null;
    const t = str.trim();
    if (!/^[[{]/.test(t)) return null;
    try {
      return JSON.parse(t);
    } catch (e) {
      return null;
    }
  }

  function safeURIDecode(str) {
    try {
      return decodeURIComponent(str.replace(/\+/g, ' '));
    } catch (e) {
      return str;
    }
  }

  function randomToken(bytes) {
    const buf = new Uint8Array(bytes);
    const c = root.crypto || (typeof require === 'function' ? require('crypto').webcrypto : null);
    c.getRandomValues(buf);
    let bin = '';
    buf.forEach((b) => (bin += String.fromCharCode(b)));
    const b64 = typeof btoa === 'function' ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fmtDuration(sec) {
    const a = Math.abs(sec);
    if (a >= 365 * DAY) return (a / (365 * DAY)).toFixed(1) + ' years';
    if (a >= DAY) return Math.round(a / DAY) + ' days';
    if (a >= 3600) return Math.round(a / 3600) + ' hours';
    return Math.round(a / 60) + ' minutes';
  }

  /* ── Parsing ── */

  function emptyAttrs() {
    return { secure: false, httponly: false, samesite: null, domain: null, path: null, expires: null, maxAge: null, partitioned: false };
  }

  function parseSetCookie(str) {
    const parts = str.split(';');
    const first = parts.shift();
    const eq = first.indexOf('=');
    const name = (eq === -1 ? '' : first.slice(0, eq)).trim();
    let value = (eq === -1 ? first : first.slice(eq + 1)).trim();
    if (/^".*"$/.test(value)) value = value.slice(1, -1);
    const attrs = emptyAttrs();
    parts.forEach((p) => {
      const i = p.indexOf('=');
      const k = (i === -1 ? p : p.slice(0, i)).trim().toLowerCase();
      const v = i === -1 ? '' : p.slice(i + 1).trim();
      if (k === 'secure') attrs.secure = true;
      else if (k === 'httponly') attrs.httponly = true;
      else if (k === 'partitioned') attrs.partitioned = true;
      else if (k === 'samesite') attrs.samesite = v ? v.charAt(0).toUpperCase() + v.slice(1).toLowerCase() : '';
      else if (k === 'domain') attrs.domain = v;
      else if (k === 'path') attrs.path = v;
      else if (k === 'expires') attrs.expires = v;
      else if (k === 'max-age') attrs.maxAge = v;
    });
    return { source: 'set-cookie', name, value, attrs, raw: str.trim() };
  }

  // source 'cookie' = request header (attributes unknown),
  // source 'js' = document.cookie output (attributes unknown, but HttpOnly is known to be absent)
  function parseCookiePairs(str, source) {
    return str.split(';').map((p) => p.trim()).filter(Boolean).map((p) => {
      const eq = p.indexOf('=');
      return {
        source,
        name: (eq === -1 ? '' : p.slice(0, eq)).trim(),
        value: (eq === -1 ? p : p.slice(eq + 1)).trim(),
        attrs: null,
        raw: p,
      };
    });
  }

  function fromJSONCookie(o) {
    const attrs = emptyAttrs();
    attrs.secure = !!o.secure;
    attrs.httponly = !!(o.httpOnly || o.httponly || o.HttpOnly);
    const ss = String(o.sameSite || o.samesite || '').toLowerCase();
    attrs.samesite = ss === 'no_restriction' || ss === 'none' ? 'None' : ss === 'lax' ? 'Lax' : ss === 'strict' ? 'Strict' : null;
    // Browser exports store the domain of host-only cookies too; only a leading dot means Domain= was sent
    if (o.hostOnly === false || (o.domain && String(o.domain).charAt(0) === '.')) attrs.domain = o.domain;
    attrs.path = o.path || null;
    const exp = o.expirationDate != null ? o.expirationDate : o.expires;
    if (!o.session && typeof exp === 'number' && exp > 0) attrs.expires = new Date(exp * 1000).toUTCString();
    const raw = o.name + '=' + o.value;
    return { source: 'json', name: String(o.name || ''), value: String(o.value == null ? '' : o.value), attrs, raw };
  }

  function parseInput(text) {
    const trimmed = text.trim();
    const json = tryJSON(trimmed);
    if (json) {
      const list = Array.isArray(json) ? json : Array.isArray(json.cookies) ? json.cookies : [json];
      return list.filter((o) => o && typeof o === 'object' && 'name' in o).map(fromJSONCookie);
    }

    const cookies = [];
    trimmed.split(/\r?\n/).forEach((line) => {
      line = line.trim();
      if (!line || /^HTTP\/\d/i.test(line)) return;
      const header = line.match(/^([A-Za-z0-9-]+)\s*:\s*(.*)$/);
      if (header) {
        const h = header[1].toLowerCase();
        if (h === 'set-cookie') cookies.push(parseSetCookie(header[2]));
        else if (h === 'cookie') cookies.push(...parseCookiePairs(header[2], 'cookie'));
        return; // any other header is ignored
      }
      if (!line.includes('=')) return;
      const keys = line.split(';').slice(1).map((p) => p.split('=')[0].trim().toLowerCase());
      if (keys.some((k) => ATTRS.includes(k))) cookies.push(parseSetCookie(line));
      else cookies.push(...parseCookiePairs(line, 'js'));
    });
    return cookies.filter((c) => c.name || c.value);
  }

  /* ── Value analysis ── */

  function decodeJWT(value) {
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value)) return null;
    const [h, p, s] = value.split('.');
    const header = tryJSON(b64decode(h));
    const payload = tryJSON(b64decode(p));
    if (!header || !payload || !('alg' in header)) return null;
    return { header, payload, signed: s.length > 0 };
  }

  function entropy(value) {
    if (!value) return { bits: 0, charset: 'empty', pool: 0 };
    let pool;
    let charset;
    if (/^\d+$/.test(value)) { pool = 10; charset = 'numeric'; }
    else if (/^[0-9a-f]+$/i.test(value)) { pool = 16; charset = 'hex'; }
    else if (/^[A-Za-z0-9_-]+$/.test(value)) { pool = 64; charset = 'base64url / alphanumeric'; }
    else if (/^[A-Za-z0-9+/]+=*$/.test(value)) { pool = 64; charset = 'base64'; }
    else { pool = 95; charset = 'mixed / printable'; }

    const freq = {};
    for (const ch of value) freq[ch] = (freq[ch] || 0) + 1;
    let h = 0;
    Object.values(freq).forEach((n) => {
      const p = n / value.length;
      h -= p * Math.log2(p);
    });
    // Shannon entropy of a short sample is capped by its length, so compare against the
    // best achievable for that length; repetitive values (aaaa, abab…) are penalised.
    const maxPerChar = Math.log2(pool);
    const achievable = Math.min(maxPerChar, Math.log2(value.length)) || 1;
    const diversity = Math.min(1, h / achievable);
    return { bits: Math.round(value.length * maxPerChar * diversity), charset, pool, shannon: h };
  }

  function classify(c, jwt) {
    if (CSRF_RE.test(c.name)) return 'csrf';
    if (TRACKING_RE.test(c.name)) return 'tracking';
    if (jwt || SESSION_RE.test(c.name)) return 'session';
    return 'other';
  }

  function lifetime(attrs) {
    if (!attrs) return null;
    if (attrs.maxAge != null && attrs.maxAge !== '') {
      const n = parseInt(attrs.maxAge, 10);
      if (!isNaN(n)) return n;
    }
    if (attrs.expires) {
      const t = Date.parse(attrs.expires);
      if (!isNaN(t)) return Math.round((t - Date.now()) / 1000);
    }
    return null; // session (browser-lifetime) cookie
  }

  /* ── Audit ── */

  function analyzeCookie(c) {
    const findings = [];
    const add = (severity, title, detail, fix, ref) => findings.push({ severity, title, detail, fix, ref });

    const decodedURI = safeURIDecode(c.value);
    const jwt = decodeJWT(decodedURI);
    const kind = classify(c, jwt);
    const isSession = kind === 'session';
    const a = c.attrs;
    const known = !!a;
    const httpOnlyKnownFalse = c.source === 'js' || (known && !a.httponly);
    const ttl = lifetime(a);
    const ent = jwt ? null : entropy(decodedURI);
    const decoded = { uri: decodedURI !== c.value ? decodedURI : null, base64: null, json: null, jwt };

    /* Attribute checks */
    if (!known) {
      add('info', 'Cookie attributes not visible',
        c.source === 'js'
          ? 'Input looks like document.cookie output: the cookie is readable by JavaScript, but Secure / SameSite / Domain / lifetime cannot be seen.'
          : 'A Cookie request header only carries name=value pairs, so security flags cannot be audited.',
        'Paste the Set-Cookie response headers (DevTools → Network → response headers) for a full audit.');
    }

    if (isSession && c.source === 'js') {
      add('high', 'Session token is readable by JavaScript',
        'This value was returned by document.cookie, so any XSS payload can read and exfiltrate it (session hijacking).',
        'Set HttpOnly on the session cookie.', 'OWASP Session Mgmt §HttpOnly · CWE-1004');
    }

    if (known) {
      if (!a.secure) {
        if (isSession) add('high', 'Missing Secure flag on session cookie',
          'The token can be sent over plain HTTP and captured by anyone on the network path (public Wi-Fi, SSL-strip).',
          'Add Secure and serve the site exclusively over HTTPS with HSTS.', 'OWASP Session Mgmt §Secure · CWE-614');
        else add('low', 'Missing Secure flag',
          'Cookie may be transmitted over unencrypted HTTP.', 'Add Secure.', 'CWE-614');
      }
      if (!a.httponly) {
        if (isSession) add('high', jwt ? 'JWT stored in a JavaScript-readable cookie' : 'Missing HttpOnly flag on session cookie',
          'document.cookie exposes this token to any injected script — a single XSS becomes full account takeover.',
          'Add HttpOnly.', 'OWASP Session Mgmt §HttpOnly · CWE-1004');
        else if (kind === 'csrf') add('info', 'CSRF token is JavaScript-readable',
          'Expected for the double-submit pattern where the frontend copies it into a header.',
          'Keep it SameSite=Strict and never treat it as an authentication credential.');
      }

      const ss = a.samesite;
      if (ss === 'None' && !a.secure) {
        add('high', 'SameSite=None without Secure',
          'Modern browsers reject this cookie outright, and older ones send it on every cross-site request.',
          'Use SameSite=Lax, or add Secure if cross-site delivery is genuinely needed.', 'RFC 6265bis §5.6.7');
      } else if (ss === 'None' && isSession) {
        add('medium', 'Session cookie sent on cross-site requests',
          'SameSite=None attaches the session to requests initiated by other sites, leaving CSRF defence entirely to tokens.',
          'Use SameSite=Lax (or Strict) unless the app is intentionally embedded cross-site.', 'CWE-352');
      } else if (!ss) {
        if (isSession) add('medium', 'SameSite attribute not set',
          'Behaviour depends on the browser default (Chrome assumes Lax after a 2-minute grace window; others differ), so CSRF protection is inconsistent.',
          'Set SameSite=Lax explicitly (Strict for high-value admin sessions).', 'CWE-352');
        else add('low', 'SameSite attribute not set', 'Cross-site behaviour is left to browser defaults.', 'Set SameSite=Lax explicitly.');
      } else if (!['Lax', 'Strict', 'None'].includes(ss)) {
        add('medium', 'Invalid SameSite value "' + ss + '"', 'Browsers ignore unknown values and fall back to defaults.', 'Use Lax, Strict or None.');
      }

      if (a.domain) {
        const d = a.domain.replace(/^\./, '');
        if (isSession) add('medium', 'Session cookie shared with every subdomain',
          'Domain=' + a.domain + ' sends the token to *.' + d + ' — a compromised or user-controlled subdomain can steal or overwrite (cookie tossing) the session.',
          'Remove the Domain attribute so the cookie is host-only, ideally with the __Host- prefix.', 'OWASP Session Mgmt §Domain');
        else add('low', 'Cookie scoped to all subdomains', 'Domain=' + a.domain + ' widens exposure to *.' + d + '.', 'Omit Domain unless subdomains really need it.');
      }

      if (c.name.startsWith('__Host-') && (!a.secure || a.path !== '/' || a.domain)) {
        add('high', '__Host- prefix requirements violated',
          '__Host- cookies must have Secure, Path=/ and no Domain. Browsers silently drop this cookie, which usually breaks login.',
          'Set Secure; Path=/ and remove Domain.', 'RFC 6265bis §4.1.3.2');
      } else if (c.name.startsWith('__Secure-') && !a.secure) {
        add('high', '__Secure- prefix requires Secure', 'Browsers silently drop this cookie.', 'Add Secure.', 'RFC 6265bis §4.1.3.1');
      } else if (isSession && !c.name.startsWith('__Host-') && !c.name.startsWith('__Secure-')) {
        add('info', 'No cookie prefix', 'The __Host- prefix makes the browser enforce Secure, Path=/ and host-only scope, blocking subdomain cookie injection.', 'Rename to __Host-' + c.name + '.');
      }

      if (ttl != null && ttl <= 0) {
        add('info', 'Cookie is already expired', 'This header deletes the cookie (typical for logout).', '');
      } else if (ttl != null && isSession) {
        if (ttl > 30 * DAY) add('medium', 'Long-lived persistent session (' + fmtDuration(ttl) + ')',
          'The token survives browser restarts and stays valid on shared/stolen devices for ' + fmtDuration(ttl) + '.',
          'Use a browser-session cookie with a server-side idle timeout (15–30 min) and absolute timeout; issue a separate rotating remember-me token if needed.',
          'OWASP Session Mgmt §Session Expiration · CWE-613');
        else if (ttl > DAY) add('low', 'Persistent session (' + fmtDuration(ttl) + ')',
          'Session token is written to disk and outlives the browser session.', 'Prefer session cookies plus server-side expiry.', 'CWE-613');
      } else if (ttl != null && ttl > 400 * DAY) {
        add('low', 'Expiry beyond browser cap (' + fmtDuration(ttl) + ')', 'Browsers clamp cookie lifetime to 400 days.', 'Use Max-Age ≤ 34560000.');
      }
    }

    if ((c.name + c.value).length > 4096) {
      add('low', 'Cookie exceeds 4 KB', 'Browsers may truncate or drop it, and it is resent on every request.', 'Store bulky state server-side.');
    }

    /* Token / value checks */
    if (jwt) {
      const { header, payload } = jwt;
      const alg = String(header.alg || '');
      const now = Date.now() / 1000;
      if (alg.toLowerCase() === 'none' || !jwt.signed) {
        add('critical', 'Unsigned JWT (alg: ' + (alg || 'missing') + ')',
          'Anyone can edit the claims (e.g. change "sub" or "role") and the server may accept it if it honours the token header.',
          'Reject alg "none" server-side and pin the expected algorithm when verifying.', 'CVE-2015-9235 · CWE-347');
      } else if (/^HS/i.test(alg)) {
        add('info', 'HMAC-signed JWT (' + alg + ')',
          'Security depends entirely on the shared secret; weak secrets are cracked offline from a single captured token (hashcat -m 16500).',
          'Use a random secret of at least 256 bits, or switch to RS256/EdDSA.');
      }
      if (header.jku || header.x5u || (header.kid && /[./\\'"]/.test(String(header.kid)))) {
        add('medium', 'Risky JWT header parameter', 'jku/x5u or a path-like kid can enable key-injection attacks if the server trusts them.', 'Ignore jku/x5u and treat kid as an allow-listed identifier.');
      }
      if (payload.exp == null) {
        add('high', 'JWT has no expiry (exp)', 'A stolen token stays valid forever — JWTs cannot be revoked without extra server state.', 'Issue short-lived access tokens (≤ 15 min) with an exp claim and refresh-token rotation.', 'RFC 8725 · CWE-613');
      } else if (payload.exp < now) {
        add('low', 'JWT is expired', 'Expired ' + fmtDuration(now - payload.exp) + ' ago — confirm the server rejects it.', '');
      } else if (payload.exp - (payload.iat || now) > DAY) {
        add('medium', 'Long-lived JWT (' + fmtDuration(payload.exp - (payload.iat || now)) + ')', 'Long validity increases the impact of token theft.', 'Keep access-token lifetime ≤ 15–60 minutes.', 'RFC 8725');
      }
      const claims = JSON.stringify(payload);
      if (SENSITIVE_RE.test(Object.keys(payload).join(' '))) {
        add('high', 'Sensitive data inside JWT', 'JWT payloads are only base64-encoded — anyone holding the token can read every claim.', 'Remove secrets from the payload or use JWE.', 'CWE-312');
      }
      if (EMAIL_RE.test(claims)) {
        add('medium', 'PII (email) exposed in JWT payload', 'The payload is readable by anyone who obtains the token, including logs and proxies.', 'Reference users by opaque ID instead.', 'CWE-359');
      }
    } else {
      // Signed-but-readable formats (Flask / itsdangerous, Express cookie-session, etc.)
      const segs = decodedURI.replace(/^\./, '').split('.');
      const b64 = b64decode(segs[0]);
      const signedFormat = segs.length >= 2 && segs[segs.length - 1].length >= 16;
      if (b64 && isPrintable(b64) && /[A-Za-z]{3}|[{=:]/.test(b64)) decoded.base64 = b64;
      const text = decoded.base64 || decodedURI;
      decoded.json = tryJSON(text);
      const structured = decoded.json || /^[\w.-]+=[^&]*(&[\w.-]+=[^&]*)*$/.test(text) ? text : null;

      if (decoded.base64 || structured) {
        const shown = (decoded.base64 || text).slice(0, 160);
        if (PRIV_RE.test(shown) || /^(admin|root|true|1|yes)$/i.test(text.trim())) {
          if (signedFormat) add('medium', 'Readable session data (signed, not encrypted)',
            'Decodes to: ' + shown + ' — integrity appears protected by a signature, but contents are visible to the user and anyone who captures it.',
            'Keep only an opaque ID client-side, or encrypt the payload.', 'CWE-312');
          else add('high', 'Tamperable client-side authorization data',
            'Decodes to: ' + shown + ' — there is no visible signature, so a user can change the value (e.g. role/user ID) and replay it to escalate privileges.',
            'Store authorization state server-side, keyed by a random session ID; if state must live client-side, sign it (HMAC) and verify on every request.',
            'OWASP A01 Broken Access Control · CWE-565');
        } else if (decoded.base64) {
          add('low', 'Encoded (not encrypted) value', 'Base64 decodes to: ' + shown, 'Base64 is encoding, not protection — do not store meaningful data here.', 'CWE-311');
        }
      }

      if (EMAIL_RE.test(text)) {
        add('medium', 'PII (email address) stored in cookie', 'Readable by the user, browser extensions, proxies and server logs.', 'Reference users by opaque ID.', 'CWE-359');
      }

      if (isSession && ent && !structured) {
        const digits = /^\d+$/.test(decodedURI);
        if (digits && (decodedURI.length === 10 || decodedURI.length === 13)) {
          const ms = decodedURI.length === 10 ? +decodedURI * 1000 : +decodedURI;
          const yr = new Date(ms).getUTCFullYear();
          if (yr >= 2000 && yr <= 2100) {
            add('critical', 'Session ID is a Unix timestamp',
              'Decodes to ' + new Date(ms).toISOString() + '. An attacker can enumerate tokens issued around a known time and hijack sessions.',
              'Generate session IDs from a CSPRNG with ≥ 128 bits of randomness (e.g. secrets.token_urlsafe(32)).', 'CWE-330 · CWE-6');
          }
        }
        if (digits && decodedURI.length <= 12 && !findings.some((f) => f.severity === 'critical')) {
          add('critical', 'Sequential / guessable numeric session ID',
            'A ' + decodedURI.length + '-digit number gives ≈' + ent.bits + ' bits — incrementing or brute-forcing it reveals other users\' sessions.',
            'Generate session IDs from a CSPRNG with ≥ 128 bits of randomness.', 'CWE-330 · CWE-6');
        } else if (!digits && ent.bits < 64) {
          add('high', 'Low session-token entropy (≈' + ent.bits + ' bits)',
            'OWASP requires at least 64 bits of entropy so session IDs cannot be brute-forced or predicted.',
            'Use ≥ 128 bits from a CSPRNG (32+ hex chars or 22+ base64url chars).', 'OWASP Session Mgmt §Session ID Entropy · CWE-331');
        } else if (!digits && ent.bits < 128) {
          add('low', 'Session-token entropy below recommended 128 bits (≈' + ent.bits + ' bits)', 'Meets the 64-bit minimum but not current best practice.', 'Use 128+ bits.');
        }
      }
    }

    findings.sort((x, y) => SEVERITY.indexOf(x.severity) - SEVERITY.indexOf(y.severity));
    const score = Math.max(0, 100 - findings.reduce((s, f) => s + WEIGHT[f.severity], 0));
    const result = { cookie: c, kind, findings, score, entropy: ent, ttl, decoded };
    result.hardened = harden(result);
    return result;
  }

  /* ── Hardened header generation ── */

  function harden(r) {
    const c = r.cookie;
    const a = c.attrs || emptyAttrs();
    const notes = [];
    let name = c.name;
    let value = c.value;
    const parts = [];

    const weak = r.findings.some((f) => /guessable|timestamp|entropy \(|Tamperable|Unsigned JWT/.test(f.title) && f.severity !== 'low');
    if (weak) {
      value = randomToken(32);
      notes.push('value regenerated (256-bit CSPRNG) — map it to session state server-side');
    } else if (r.decoded.jwt && r.decoded.jwt.payload.exp == null) {
      notes.push('re-issue the JWT with a short exp claim (≤ 15 min) and refresh-token rotation');
    }

    if (r.kind === 'session') {
      if (!name.startsWith('__Host-') && !name.startsWith('__Secure-')) {
        name = '__Host-' + name;
        notes.push('renamed with __Host- prefix — update the name in application code');
      }
      parts.push('Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax');
      if (/remember/i.test(c.name)) parts.push('Max-Age=' + 30 * DAY);
      else if (r.ttl != null && r.ttl > 0 && r.ttl <= DAY) parts.push('Max-Age=' + r.ttl);
      else if (r.ttl != null && r.ttl > DAY) notes.push('persistence removed — enforce idle/absolute timeouts server-side');
    } else if (r.kind === 'csrf') {
      if (!name.startsWith('__Host-') && !name.startsWith('__Secure-')) name = '__Host-' + name;
      parts.push('Path=/', 'Secure', 'SameSite=Strict');
    } else {
      if (name.startsWith('__Host-')) parts.push('Path=/');
      else {
        parts.push('Path=' + (a.path || '/'));
        if (a.domain) parts.push('Domain=' + a.domain);
      }
      parts.push('Secure');
      if (a.httponly) parts.push('HttpOnly');
      parts.push(a.samesite === 'Strict' ? 'SameSite=Strict' : 'SameSite=Lax');
      if (r.ttl != null && r.ttl > 0) parts.push('Max-Age=' + Math.min(r.ttl, 400 * DAY));
    }
    if (a.partitioned) parts.push('Partitioned');

    return { header: 'Set-Cookie: ' + name + '=' + value + '; ' + parts.join('; '), notes };
  }

  function grade(results) {
    if (!results.length) return null;
    const scores = results.map((r) => r.score);
    const avg = scores.reduce((s, n) => s + n, 0) / scores.length;
    const score = Math.round(Math.min(avg, Math.min(...scores) + 15));
    const all = results.flatMap((r) => r.findings);
    const counts = {};
    SEVERITY.forEach((s) => (counts[s] = all.filter((f) => f.severity === s).length));
    let letter = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
    if (counts.critical) letter = 'F';
    else if (counts.high && 'AB'.includes(letter)) letter = 'C';
    return { score, letter, counts };
  }

  function analyze(text) {
    const results = parseInput(text).map(analyzeCookie);
    return { results, grade: grade(results) };
  }

  function toJSONReport(report) {
    return {
      tool: 'Cookie & Session Analyzer — yesshhaa.github.io',
      generatedAt: new Date().toISOString(),
      grade: report.grade.letter,
      score: report.grade.score,
      findingCounts: report.grade.counts,
      cookies: report.results.map((r) => ({
        name: r.cookie.name,
        classification: r.kind,
        source: r.cookie.source,
        score: r.score,
        attributes: r.cookie.attrs,
        lifetimeSeconds: r.ttl,
        entropyBits: r.entropy ? r.entropy.bits : null,
        jwt: r.decoded.jwt ? { header: r.decoded.jwt.header, payload: r.decoded.jwt.payload } : null,
        findings: r.findings,
        hardenedHeader: r.hardened.header,
        hardeningNotes: r.hardened.notes,
      })),
    };
  }

  function toMarkdownReport(report) {
    const g = report.grade;
    const lines = [
      '# Cookie & Session Security Report',
      '',
      '_Generated ' + new Date().toISOString() + ' by Cookie & Session Analyzer_',
      '',
      '**Grade: ' + g.letter + ' (' + g.score + '/100)** — ' +
        SEVERITY.filter((s) => g.counts[s]).map((s) => g.counts[s] + ' ' + s).join(', '),
      '',
    ];
    report.results.forEach((r) => {
      lines.push('## `' + r.cookie.name + '` — ' + r.kind + ' (' + r.score + '/100)', '');
      if (!r.findings.length) lines.push('No issues found.', '');
      r.findings.forEach((f) => {
        lines.push('- **[' + f.severity.toUpperCase() + '] ' + f.title + '** — ' + f.detail);
        if (f.fix) lines.push('  - Fix: ' + f.fix);
        if (f.ref) lines.push('  - Ref: ' + f.ref);
      });
      lines.push('', '```http', r.hardened.header, '```', '');
    });
    return lines.join('\n');
  }

  const api = { analyze, parseInput, analyzeCookie, entropy, decodeJWT, toJSONReport, toMarkdownReport };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined') return;

  /* ── UI ── */

  const SAMPLES = {
    vulnerable: [
      'HTTP/1.1 200 OK',
      'Content-Type: text/html; charset=utf-8',
      'Set-Cookie: PHPSESSID=1048576; Path=/',
      'Set-Cookie: user_role=YWRtaW4=; Path=/; Expires=Fri, 31 Dec 2032 23:59:59 GMT',
      'Set-Cookie: profile=eyJ1c2VyX2lkIjogNDIsICJlbWFpbCI6ICJqYW5lQGV4YW1wbGUuY29tIiwgImlzX2FkbWluIjogZmFsc2V9; Domain=.example.com; Path=/',
      'Set-Cookie: remember_token=1729700000; Max-Age=315360000; Path=/',
      'Set-Cookie: ab_test=variant-b; SameSite=None',
    ].join('\n'),
    jwt: [
      'Set-Cookie: access_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMDAxIiwidXNlcm5hbWUiOiJqYW5lIiwicm9sZSI6InVzZXIifQ.; Path=/; Secure; SameSite=Lax',
      'Set-Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImVtYWlsIjoiamFuZUBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyOTcwMDAwMH0.pYJ0mGqBf7jC6M0X6tJ2eN8K4q1Z9sVwR3xLh5dUoAs; Path=/; Secure',
    ].join('\n'),
    hardened: [
      'HTTP/2 200',
      'set-cookie: __Host-sid=q8Rk3vZ1yT6pN0wLs2HbX9cFjEa4Gm7Ud5KiOrPeYQ0; Path=/; Secure; HttpOnly; SameSite=Lax',
      'set-cookie: __Host-csrf=Vw3nX0aZ8kQe2LtR5yHs9uB1; Path=/; Secure; SameSite=Strict',
      'set-cookie: theme=dark; Path=/; Secure; SameSite=Lax; Max-Age=31536000',
    ].join('\n'),
    json: JSON.stringify([
      { domain: '.shop.example', hostOnly: false, name: 'connect.sid', value: 's%3AaB3dE5fG7hJ.9kLmN0pQrS2tUvW4xYz6AbCdEfGhIjKlMnOpQrStUvWx', path: '/', secure: true, httpOnly: true, sameSite: 'no_restriction', session: true },
      { domain: 'shop.example', hostOnly: true, name: 'cart', value: 'eyJpdGVtcyI6WzEyLDQ0XSwidXNlcl9pZCI6NzcxfQ%3D%3D', path: '/', secure: false, httpOnly: false, sameSite: 'unspecified', expirationDate: Date.now() / 1000 + 90 * DAY, session: false },
      { domain: '.shop.example', hostOnly: false, name: '_ga', value: 'GA1.1.1234567890.1729700000', path: '/', secure: false, httpOnly: false, sameSite: 'lax', expirationDate: Date.now() / 1000 + 700 * DAY, session: false },
    ], null, 2),
  };

  const $ = (id) => document.getElementById(id);
  const input = $('input');
  let lastReport = null;

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'class') n.className = v;
      else n.setAttribute(k, v);
    });
    children.flat().forEach((ch) => {
      if (ch == null || ch === false) return;
      n.appendChild(typeof ch === 'string' || typeof ch === 'number' ? document.createTextNode(String(ch)) : ch);
    });
    return n;
  }

  const sevColor = (letter) => ({ A: 'sev-low', B: 'sev-low', C: 'sev-medium', D: 'sev-high', F: 'sev-critical' }[letter]);

  function flagMeta(label, on) {
    return el('span', { class: 'meta ' + (on ? 'on' : 'off') }, label);
  }

  function renderCookie(r) {
    const c = r.cookie;
    const a = c.attrs;
    const meta = el('div', { class: 'cookie-meta' }, el('span', { class: 'meta' }, r.kind), el('span', { class: 'meta' }, 'from ' + c.source));
    if (a) {
      meta.append(flagMeta('Secure', a.secure), flagMeta('HttpOnly', a.httponly), flagMeta('SameSite' + (a.samesite ? '=' + a.samesite : ''), !!a.samesite));
      if (a.domain) meta.append(el('span', { class: 'meta' }, 'Domain=' + a.domain));
      if (a.path) meta.append(el('span', { class: 'meta' }, 'Path=' + a.path));
    } else if (c.source === 'js') {
      meta.append(flagMeta('HttpOnly', false));
    }

    const scoreClass = r.score >= 90 ? 'sev-low' : r.score >= 65 ? 'sev-medium' : r.score >= 50 ? 'sev-high' : 'sev-critical';
    const value = c.value.length > 72 ? c.value.slice(0, 72) + '…' : c.value;
    const stats = el('div', { class: 'stats' },
      el('div', { class: 'stat' }, el('b', null, 'Value'), el('span', null, value || '(empty)')),
      el('div', { class: 'stat' }, el('b', null, 'Length'), el('span', null, c.value.length + ' chars')),
      el('div', { class: 'stat' }, el('b', null, r.decoded.jwt ? 'Format' : 'Entropy (est.)'),
        el('span', null, r.decoded.jwt ? 'JWT · alg ' + r.decoded.jwt.header.alg : r.entropy.bits + ' bits · ' + r.entropy.charset)),
      el('div', { class: 'stat' }, el('b', null, 'Lifetime'),
        el('span', null, !a ? 'unknown' : r.ttl == null ? 'browser session' : r.ttl <= 0 ? 'expired' : fmtDuration(r.ttl))));

    const findings = el('div', { class: 'findings' });
    if (!r.findings.length) findings.append(el('div', { class: 'no-findings' }, '✓ No issues found for this cookie.'));
    r.findings.forEach((f) => {
      findings.append(el('div', { class: 'finding sev-' + f.severity },
        el('div', { class: 'finding-title' }, el('span', { class: 'pill sev-' + f.severity }, f.severity), el('strong', null, f.title)),
        el('p', null, f.detail),
        f.fix ? el('p', { class: 'fix' }, '→ ' + f.fix) : null,
        f.ref ? el('p', { class: 'ref' }, f.ref) : null));
    });

    let decodedBlock = null;
    const d = r.decoded;
    if (d.jwt || d.base64 || d.uri) {
      const body = d.jwt
        ? 'Header:  ' + JSON.stringify(d.jwt.header, null, 2) + '\nPayload: ' + JSON.stringify(d.jwt.payload, null, 2)
        : d.json ? JSON.stringify(d.json, null, 2) : d.base64 || d.uri;
      decodedBlock = el('details', { class: 'decoded' }, el('summary', null, 'Decoded value'), el('pre', { class: 'code' }, body));
    }

    return el('article', { class: 'panel' },
      el('div', { class: 'cookie-head' },
        el('div', null, el('div', { class: 'cookie-name' }, c.name || '(unnamed)'), meta),
        el('div', { class: 'score ' + scoreClass }, String(r.score), el('small', null, ' /100'))),
      stats, findings, decodedBlock);
  }

  function render(report) {
    const results = $('results');
    const list = $('cookies');
    list.textContent = '';
    if (!report.results.length) {
      results.hidden = false;
      $('grade').textContent = '?';
      $('grade').className = 'grade sev-info';
      $('verdict').textContent = 'No cookies found';
      $('verdict-sub').textContent = 'Paste Set-Cookie headers, a Cookie header, document.cookie output, or a JSON cookie export.';
      $('counts').textContent = '';
      $('fixed').textContent = '';
      return;
    }
    const g = report.grade;
    $('grade').textContent = g.letter;
    $('grade').className = 'grade ' + sevColor(g.letter);
    $('verdict').textContent = { A: 'Strong session configuration', B: 'Mostly solid', C: 'Needs hardening', D: 'Weak session security', F: 'Session hijacking risk' }[g.letter];
    $('verdict-sub').textContent = report.results.length + ' cookie' + (report.results.length > 1 ? 's' : '') + ' analyzed · score ' + g.score + '/100';
    const counts = $('counts');
    counts.textContent = '';
    SEVERITY.forEach((s) => counts.append(el('span', { class: 'pill sev-' + s }, g.counts[s] + ' ' + s)));

    $('fixed').textContent = report.results.map((r) =>
      (r.hardened.notes.length ? r.hardened.notes.map((n) => '# ' + r.cookie.name + ': ' + n).join('\n') + '\n' : '') + r.hardened.header
    ).join('\n');

    report.results.forEach((r) => list.append(renderCookie(r)));
    results.hidden = false;
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = el('a', { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function flash(btn, text) {
    const orig = btn.textContent;
    btn.textContent = text;
    setTimeout(() => (btn.textContent = orig), 1400);
  }

  function run() {
    lastReport = analyze(input.value);
    render(lastReport);
    $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('analyze').addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run();
  });
  $('clear').addEventListener('click', () => {
    input.value = '';
    $('results').hidden = true;
    input.focus();
  });
  document.querySelectorAll('[data-sample]').forEach((b) =>
    b.addEventListener('click', () => {
      input.value = SAMPLES[b.dataset.sample];
      run();
    }));
  $('copy-fixed').addEventListener('click', (e) => {
    const btn = e.currentTarget;
    navigator.clipboard.writeText($('fixed').textContent).then(() => flash(btn, 'Copied ✓'), () => flash(btn, 'Copy failed'));
  });
  $('export-json').addEventListener('click', () => {
    if (lastReport && lastReport.results.length) download('cookie-report.json', JSON.stringify(toJSONReport(lastReport), null, 2), 'application/json');
  });
  $('export-md').addEventListener('click', () => {
    if (lastReport && lastReport.results.length) download('cookie-report.md', toMarkdownReport(lastReport), 'text/markdown');
  });
})(typeof window !== 'undefined' ? window : globalThis);
