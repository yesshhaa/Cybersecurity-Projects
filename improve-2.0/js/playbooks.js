/**
 * playbooks.js — Remediation knowledge base for Improve 2.0
 *
 * Each playbook turns a raw finding into:
 *   means    → what the issue is, in plain language
 *   exploit  → how an attacker would realistically use it
 *   fix      → concrete steps, grouped by platform
 *   verify   → a check you can run, with the result that proves the fix
 *
 * Template tokens filled in per finding:
 *   {host} {port} {url} {domain} {pkg} {installed} {fixed} {file} {line} {cve}
 *
 * match: cve (exact), rule (tool rule / plugin IDs), cwe (numbers), kw (regex on title + description)
 * exploitability: 1 = needs unusual conditions, 2 = commonly abused, 3 = trivially / actively exploited
 * effort: 'minutes' | 'hours' | 'days'
 */

(function (global) {
  'use strict';

  const PLAYBOOKS = [
    /* ───────────── Actively exploited, network-level ───────────── */
    {
      id: 'log4shell',
      title: 'Log4Shell — remote code execution in Apache Log4j',
      category: 'Vulnerable component',
      exploitability: 3,
      effort: 'hours',
      match: { cve: ['CVE-2021-44228', 'CVE-2021-45046'], kw: [/log4shell/i, /log4j.*(jndi|remote code)/i] },
      means: 'A Java logging library on this system will fetch and run code from the internet if an attacker gets a specially crafted string (like ${jndi:ldap://…}) into anything that gets logged — a username, a search box, a User-Agent header.',
      exploit: 'Attackers spray the payload at every input on every internet-facing Java app. When it lands in a log line, the server downloads and runs their code. This was mass-exploited within hours of disclosure and is still scanned for daily.',
      impact: 'Full server takeover, typically followed by ransomware or crypto-miners.',
      fix: [
        { label: 'Upgrade (the real fix)', steps: [
          'Find every copy: `find / -name "log4j-core-*.jar" 2>/dev/null` (also check inside fat JARs/WARs).',
          'Upgrade log4j-core to 2.17.1 or later (2.12.4 for Java 7, 2.3.2 for Java 6) and redeploy.',
          'If it ships inside a vendor product, apply the vendor\'s patched release — do not swap JARs by hand.' ] },
        { label: 'Stop-gap if you cannot patch today', steps: [
          'Remove the JndiLookup class: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`',
          'Block outbound LDAP/RMI (ports 389, 636, 1099) from the server at the firewall.' ] }
      ],
      verify: [
        { check: 'No vulnerable log4j-core JARs remain on disk', cmd: 'find / -name "log4j-core-*.jar" 2>/dev/null | grep -Ev "2\\.(1[7-9]|[2-9][0-9])\\."', expect: 'No output.' },
        { check: 'Re-scan the host with the original tool', cmd: 're-run your scanner against {host}', expect: '{cve} no longer reported.' }
      ]
    },
    {
      id: 'smbv1',
      title: 'SMBv1 enabled / EternalBlue (MS17-010)',
      category: 'Network service',
      exploitability: 3,
      effort: 'minutes',
      match: { cve: ['CVE-2017-0143', 'CVE-2017-0144', 'CVE-2017-0145', 'CVE-2017-0146', 'CVE-2017-0148'], kw: [/smb ?v1/i, /ms17-010/i, /eternalblue/i, /smb.*version 1/i] },
      means: 'This machine still speaks the 1980s version of Windows file sharing (SMBv1). It has no modern protections and has well-known, wormable flaws.',
      exploit: 'WannaCry and NotPetya spread machine-to-machine through SMBv1 with no user interaction. One infected laptop on the network is enough to reach this host.',
      impact: 'Remote code execution as SYSTEM; network-wide ransomware spread.',
      fix: [
        { label: 'Windows (PowerShell, as admin)', steps: [
          'Install the latest cumulative Windows update (covers MS17-010).',
          '`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`',
          '`Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`',
          'Reboot during a maintenance window.' ] },
        { label: 'Fleet-wide', steps: [ 'Group Policy / Intune: disable SMB1 client and server on all endpoints.', 'Block TCP 445 at the internet edge — it should never be exposed.' ] }
      ],
      verify: [
        { check: 'SMBv1 is off on the host', cmd: 'Get-SmbServerConfiguration | Select EnableSMB1Protocol', expect: 'EnableSMB1Protocol : False' },
        { check: 'Remote check from another machine', cmd: 'nmap -p445 --script smb-protocols {host}', expect: 'The dialect list does not include "NT LM 0.12 (SMBv1)".' }
      ]
    },
    {
      id: 'rdp-exposed',
      title: 'Remote Desktop exposed or weakly configured',
      category: 'Network service',
      exploitability: 3,
      effort: 'hours',
      match: { cve: ['CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182'], kw: [/remote desktop/i, /\brdp\b/i, /terminal services/i, /bluekeep/i, /network level authentication/i] },
      means: 'Windows Remote Desktop is reachable on this host. If it is reachable from the internet, anyone in the world can try to log in to it.',
      exploit: 'RDP is the #1 initial-access route for ransomware crews: automated password guessing, stolen credentials bought online, or unpatched bugs like BlueKeep.',
      impact: 'Interactive admin access to the machine and a foothold into the rest of the network.',
      fix: [
        { label: 'Remove internet exposure', steps: [
          'Close TCP 3389 on the router/firewall. Put RDP behind a VPN, Remote Desktop Gateway, or a zero-trust access tool with MFA.',
          'Apply the latest Windows security updates.' ] },
        { label: 'Harden what remains', steps: [
          'Require Network Level Authentication: System Properties → Remote → "Allow connections only from computers running Remote Desktop with NLA".',
          'Enable account lockout (e.g. 10 attempts / 15 min) and restrict the "Remote Desktop Users" group.' ] }
      ],
      verify: [
        { check: 'Port is closed from outside your network', cmd: 'nmap -Pn -p3389 {host}   # run from an external network', expect: '3389/tcp filtered or closed.' },
        { check: 'NLA is enforced', cmd: 'nmap -p3389 --script rdp-enum-encryption {host}', expect: 'Shows "CredSSP (NLA): SUCCESS" and does not allow "Native RDP".' }
      ]
    },
    {
      id: 'ssh-weak',
      title: 'Weak SSH configuration',
      category: 'Network service',
      exploitability: 2,
      effort: 'minutes',
      match: { kw: [/ssh.*(password auth|root login|weak|cbc|arcfour|sha1|diffie-hellman-group1|terrapin)/i, /openssh/i, /ssh server/i], cve: ['CVE-2023-48795', 'CVE-2024-6387'] },
      means: 'The SSH service on this host accepts weak login methods or outdated cryptography, or runs a version with known flaws.',
      exploit: 'Bots try common username/password pairs against every SSH server on the internet around the clock. Weak ciphers make interception possible for well-placed attackers.',
      impact: 'Shell access to the server.',
      fix: [
        { label: 'OpenSSH (/etc/ssh/sshd_config)', steps: [
          'Update OpenSSH via your package manager: `sudo apt update && sudo apt install --only-upgrade openssh-server` (or dnf/yum).',
          'Set `PasswordAuthentication no`, `PermitRootLogin no`, `KbdInteractiveAuthentication no` — make sure your key login works first!',
          'Remove weak algorithms: drop any `*-cbc`, `arcfour*`, `hmac-sha1*`, `diffie-hellman-group1-sha1` entries.',
          '`sudo sshd -t && sudo systemctl reload ssh`' ] }
      ],
      verify: [
        { check: 'Password logins are refused', cmd: 'ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no test@{host}', expect: 'Permission denied (publickey).' },
        { check: 'No weak algorithms offered', cmd: 'nmap -p{port} --script ssh2-enum-algos {host} | grep -Ei "cbc|arcfour|group1|hmac-sha1"', expect: 'No output.' }
      ]
    },
    {
      id: 'eol-software',
      title: 'Unsupported (end-of-life) software',
      category: 'Patching',
      exploitability: 2,
      effort: 'days',
      match: { kw: [/unsupported/i, /end[- ]of[- ]life/i, /\beol\b/i, /no longer (supported|maintained)/i, /obsolete/i] },
      means: 'The vendor no longer releases security fixes for this software. Every new vulnerability found from now on stays open forever.',
      exploit: 'Attackers target EOL systems specifically because published exploits will keep working — nothing will ever patch them.',
      impact: 'Depends on the software; usually a growing list of unfixable remote-code-execution bugs.',
      fix: [
        { label: 'Plan the upgrade', steps: [
          'Identify the oldest supported version you can move to and what depends on it.',
          'Schedule the upgrade or replacement; budget it like a project, not a ticket.',
          'Until then: isolate the system (own VLAN, no internet inbound), restrict who can reach it, and monitor it closely.' ] }
      ],
      verify: [
        { check: 'Installed version is vendor-supported', cmd: 'check the version on {host} against the vendor lifecycle page (endoflife.date is a good index)', expect: 'Version listed as "supported" with a future end date.' },
        { check: 'Re-scan', cmd: 're-run your scanner against {host}', expect: 'Unsupported-software finding is gone.' }
      ]
    },
    {
      id: 'missing-os-patches',
      title: 'Missing operating system security updates',
      category: 'Patching',
      exploitability: 2,
      effort: 'hours',
      match: { kw: [/security update/i, /cumulative update/i, /\bKB\d{6,7}\b/, /ms\d{2}-\d{3}/i, /(usn|dsa|rhsa|alas)-\d/i, /missing patch/i] },
      means: 'The operating system is behind on security updates that the vendor has already released.',
      exploit: 'Once a patch ships, attackers reverse-engineer it to build exploits — often within days. Unpatched machines are the easy targets.',
      impact: 'Varies by patch; commonly privilege escalation or remote code execution.',
      fix: [
        { label: 'Windows', steps: [ 'Settings → Windows Update → Check for updates, install all, reboot.', 'For a fleet: approve the update in WSUS/Intune and set a deadline.' ] },
        { label: 'Linux', steps: [ 'Debian/Ubuntu: `sudo apt update && sudo apt upgrade`', 'RHEL/Fedora: `sudo dnf upgrade --security`', 'Reboot if the kernel or libc was updated (`[ -f /var/run/reboot-required ] && echo reboot`).' ] },
        { label: 'Prevent recurrence', steps: [ 'Turn on automatic security updates (unattended-upgrades / Windows Update for Business).' ] }
      ],
      verify: [
        { check: 'No pending security updates', cmd: 'Windows: Get-HotFix | Sort InstalledOn -Desc | Select -First 5   ·   Linux: apt list --upgradable 2>/dev/null | grep -i security', expect: 'Latest patch date is this month / no security packages pending.' },
        { check: 'Re-scan', cmd: 're-run your scanner against {host}', expect: 'Missing-update finding is gone.' }
      ]
    },
    {
      id: 'cleartext-service',
      title: 'Cleartext protocol in use (Telnet / FTP / HTTP login)',
      category: 'Network service',
      exploitability: 2,
      effort: 'hours',
      match: { cwe: [319, 523], kw: [/telnet/i, /\bftp\b/i, /cleartext/i, /clear[- ]text/i, /unencrypted/i, /anonymous (ftp|login)/i, /basic auth.*http\b/i] },
      means: 'This service sends data — including usernames and passwords — across the network without encryption.',
      exploit: 'Anyone on the same Wi-Fi, network segment, or path (or anyone who compromises a single device on it) can read the traffic and lift the passwords.',
      impact: 'Credential theft; anonymous FTP may also expose or accept files from anyone.',
      fix: [
        { label: 'Replace the protocol', steps: [
          'Telnet → SSH. FTP → SFTP or FTPS. HTTP logins → HTTPS only.',
          'Disable the old service: e.g. `sudo systemctl disable --now telnet.socket vsftpd`',
          'If anonymous FTP is enabled and not needed, set `anonymous_enable=NO` in vsftpd.conf.' ] }
      ],
      verify: [
        { check: 'Old service no longer listening', cmd: 'nmap -Pn -p21,23 {host}', expect: 'Ports closed or filtered.' },
        { check: 'Anonymous login refused (if FTP must stay)', cmd: 'nmap -p21 --script ftp-anon {host}', expect: 'No "Anonymous FTP login allowed".' }
      ]
    },
    {
      id: 'snmp-default',
      title: 'SNMP using default community string',
      category: 'Network service',
      exploitability: 2,
      effort: 'minutes',
      match: { kw: [/snmp.*(community|public|default)/i, /snmp agent default/i] },
      means: 'The device answers SNMP management queries using the default password ("public" or "private").',
      exploit: 'An attacker can read the full device configuration, network map and sometimes change settings — all by guessing a well-known word.',
      impact: 'Network reconnaissance; with "private", reconfiguration of routers/switches/printers.',
      fix: [
        { label: 'On the device', steps: [ 'Disable SNMP if nobody uses it.', 'Otherwise move to SNMPv3 with authPriv (SHA + AES) and remove v1/v2c communities.', 'Restrict SNMP to your monitoring server\'s IP.' ] }
      ],
      verify: [
        { check: 'Default community rejected', cmd: 'snmpwalk -v2c -c public {host} system', expect: 'Timeout: No Response from {host}.' }
      ]
    },
    {
      id: 'default-creds',
      title: 'Default or weak credentials',
      category: 'Identity',
      exploitability: 3,
      effort: 'minutes',
      match: { cwe: [521, 1392, 1393], kw: [/default (password|credential|account|login)/i, /weak password/i, /blank password/i, /admin\/admin/i] },
      means: 'An account on this system uses a factory-default, blank, or easily guessed password.',
      exploit: 'Default passwords are published in manuals and scanned for by botnets (Mirai was built entirely on this). It is the cheapest possible break-in.',
      impact: 'Whatever that account can do — often full admin.',
      fix: [
        { label: 'Fix it', steps: [ 'Change the password to a unique, generated one stored in your password manager.', 'Disable or rename default admin accounts where the system allows.', 'Turn on MFA for the admin interface if supported.' ] }
      ],
      verify: [
        { check: 'Default login fails', cmd: 'try the default username/password on {url} (or {host}:{port})', expect: 'Login rejected.' },
        { check: 'Re-scan', cmd: 're-run your scanner against {host}', expect: 'Finding is gone.' }
      ]
    },
    {
      id: 'mfa-missing',
      title: 'Multi-factor authentication not enforced',
      category: 'Identity',
      exploitability: 3,
      effort: 'hours',
      match: { kw: [/\bmfa\b/i, /multi[- ]factor/i, /two[- ]factor/i, /\b2fa\b/i] },
      means: 'Users can sign in with only a password. If that password leaks, nothing else stands in the way.',
      exploit: 'Phishing and password reuse are how most small-business breaches start. A stolen password plus no MFA is a complete login.',
      impact: 'Email takeover, invoice fraud, data theft, and a foothold for ransomware.',
      fix: [
        { label: 'Microsoft 365 / Entra ID', steps: [ 'Turn on Security Defaults (free) or a Conditional Access policy requiring MFA for all users.', 'Block legacy authentication (IMAP/POP/SMTP AUTH) which bypasses MFA.' ] },
        { label: 'Google Workspace', steps: [ 'Admin console → Security → 2-Step Verification → Enforce, with a short enrollment window.' ] },
        { label: 'Everything else', steps: [ 'Start with admin accounts, email, VPN, finance and remote access.' ] }
      ],
      verify: [
        { check: 'Sign-in prompts for a second factor', cmd: 'sign in to the service from a private browser window with a test user', expect: 'A second factor is required after the password.' },
        { check: 'Coverage report', cmd: 'export the MFA/registration report from your identity provider', expect: '100% of active users registered and enforced.' }
      ]
    },
    {
      id: 'email-auth',
      title: 'Missing SPF / DKIM / DMARC email protection',
      category: 'Email',
      exploitability: 2,
      effort: 'hours',
      match: { kw: [/\bdmarc\b/i, /\bspf\b/i, /\bdkim\b/i, /email spoof/i] },
      means: 'Your domain does not tell other mail servers which senders are legitimate, so anyone can send email that appears to come from you.',
      exploit: 'Attackers send invoices and "urgent payment" requests from your exact domain to your customers and staff. Spoofing is a staple of business-email-compromise fraud.',
      impact: 'Fraud, phishing of your customers, and damaged email deliverability.',
      fix: [
        { label: 'DNS records', steps: [
          'SPF: one TXT record on {domain} listing your senders, ending in `-all` or `~all` (e.g. `v=spf1 include:spf.protection.outlook.com -all`).',
          'DKIM: enable signing in your mail provider and publish the selector records it gives you.',
          'DMARC: TXT on `_dmarc.{domain}`: start with `v=DMARC1; p=none; rua=mailto:dmarc@{domain}`, review reports, then move to `p=quarantine` and `p=reject`.' ] }
      ],
      verify: [
        { check: 'SPF published', cmd: 'dig +short TXT {domain} | grep spf1', expect: 'One record starting "v=spf1" and ending in -all or ~all.' },
        { check: 'DMARC published and enforcing', cmd: 'dig +short TXT _dmarc.{domain}', expect: '"v=DMARC1; p=quarantine…" or p=reject.' }
      ]
    },

    /* ───────────── TLS / HTTPS ───────────── */
    {
      id: 'tls-weak',
      title: 'Outdated TLS/SSL protocol or weak ciphers',
      category: 'Encryption',
      exploitability: 1,
      effort: 'minutes',
      match: { cwe: [326, 327], cve: ['CVE-2014-3566', 'CVE-2016-2183', 'CVE-2013-2566', 'CVE-2015-2808'], kw: [/sslv[23]/i, /tls ?(version |v)?1\.[01]\b/i, /weak cipher/i, /\brc4\b/i, /sweet32/i, /poodle/i, /\b3des\b/i, /medium strength cipher/i] },
      means: 'The server still accepts old encryption versions (SSLv3, TLS 1.0/1.1) or weak ciphers that have known breaks.',
      exploit: 'An attacker positioned on the network path can downgrade or slowly decrypt traffic. Practical attacks need effort, but the fix is cheap and auditors (PCI, cyber-insurance) flag it every time.',
      impact: 'Possible interception of session data; compliance failures.',
      fix: [
        { label: 'Nginx', steps: [ '`ssl_protocols TLSv1.2 TLSv1.3;`', '`ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4;`', '`sudo nginx -t && sudo systemctl reload nginx`' ] },
        { label: 'Apache', steps: [ '`SSLProtocol -all +TLSv1.2 +TLSv1.3`', '`SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4`', '`sudo apachectl configtest && sudo systemctl reload apache2`' ] },
        { label: 'Windows / IIS', steps: [ 'Use IIS Crypto (Nartac) → "Best Practices" template, or disable TLS 1.0/1.1 under SCHANNEL\\Protocols in the registry; reboot.' ] }
      ],
      verify: [
        { check: 'TLS 1.0 is refused', cmd: 'openssl s_client -connect {host}:{port} -tls1 </dev/null', expect: 'Handshake failure / "no protocols available".' },
        { check: 'Only strong ciphers offered', cmd: 'nmap --script ssl-enum-ciphers -p {port} {host}', expect: 'Only TLSv1.2/1.3 listed; least strength grade "A".' }
      ]
    },
    {
      id: 'tls-cert',
      title: 'Certificate expired, self-signed, or untrusted',
      category: 'Encryption',
      exploitability: 1,
      effort: 'minutes',
      match: { cwe: [295, 296, 297, 298], kw: [/certificate.*(expired|expir|self[- ]signed|untrusted|cannot be trusted|mismatch|wrong host)/i, /self[- ]signed/i] },
      means: 'Browsers cannot confirm this server is really who it claims to be — the certificate is expired, self-issued, or for a different name.',
      exploit: 'Users learn to click through warnings, which is exactly what an attacker impersonating the site needs them to do.',
      impact: 'Makes man-in-the-middle attacks and phishing far more convincing; breaks trust and integrations.',
      fix: [
        { label: 'Get a trusted certificate', steps: [
          'Public sites: use Let\'s Encrypt — `sudo certbot --nginx -d {domain}` (or `--apache`).',
          'Internal systems: issue from your internal CA and deploy the CA cert to managed devices.',
          'Set up auto-renewal (`sudo systemctl list-timers | grep certbot`) and an expiry alert.' ] }
      ],
      verify: [
        { check: 'Certificate is valid and trusted', cmd: 'echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -issuer -subject -dates', expect: 'Issuer is a public/internal CA (not the subject itself) and notAfter is in the future.' },
        { check: 'Chain verifies', cmd: 'curl -sS -o /dev/null -w "%{ssl_verify_result}\\n" https://{host}:{port}/', expect: '0' }
      ]
    },
    {
      id: 'hsts',
      title: 'Missing HTTP Strict-Transport-Security (HSTS)',
      category: 'Web hardening',
      exploitability: 1,
      effort: 'minutes',
      match: { rule: ['10035'], kw: [/strict[- ]transport[- ]security/i, /\bhsts\b/i] },
      means: 'The site does not tell browsers "only ever talk to me over HTTPS", so a first visit or a typed URL can still start over plain HTTP.',
      exploit: 'On hostile Wi-Fi, an attacker can intercept that first HTTP request and keep the victim on an unencrypted copy of the site (SSL stripping).',
      impact: 'Session hijacking and credential theft on untrusted networks.',
      fix: [
        { label: 'Nginx', steps: [ '`add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`' ] },
        { label: 'Apache', steps: [ '`Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`' ] },
        { label: 'Note', steps: [ 'Start with a short max-age (e.g. 300) if any subdomain might still be HTTP-only, then raise it.' ] }
      ],
      verify: [
        { check: 'Header present on HTTPS responses', cmd: 'curl -sI https://{host}/ | grep -i strict-transport-security', expect: 'strict-transport-security: max-age=31536000; includeSubDomains' }
      ]
    },
    {
      id: 'csp',
      title: 'Missing or weak Content-Security-Policy',
      category: 'Web hardening',
      exploitability: 1,
      effort: 'hours',
      match: { rule: ['10038', '10055'], kw: [/content[- ]security[- ]policy/i, /\bcsp\b/i] },
      means: 'The site does not restrict where scripts are allowed to load from. CSP is a safety net that limits the damage if an XSS bug slips in.',
      exploit: 'Not an attack by itself — but without CSP, any injection flaw becomes full script execution in your users\' browsers.',
      impact: 'Amplifies XSS and third-party script compromises.',
      fix: [
        { label: 'Roll out safely', steps: [
          'Start in report-only mode: `Content-Security-Policy-Report-Only: default-src \'self\'; object-src \'none\'; frame-ancestors \'self\'`',
          'Watch the browser console / report endpoint for a week and allow the sources you actually use.',
          'Switch the header name to `Content-Security-Policy` to enforce. Avoid `unsafe-inline` for scripts.' ] }
      ],
      verify: [
        { check: 'Enforcing policy is sent', cmd: 'curl -sI {url} | grep -i "^content-security-policy:"', expect: 'A policy with default-src or script-src and no \'unsafe-inline\' in script-src.' }
      ]
    },
    {
      id: 'clickjacking',
      title: 'Clickjacking protection missing',
      category: 'Web hardening',
      exploitability: 1,
      effort: 'minutes',
      match: { rule: ['10020'], cwe: [1021], kw: [/x-frame-options/i, /clickjack/i, /anti-clickjacking/i, /frame-ancestors/i] },
      means: 'Other websites can embed your pages invisibly in a frame.',
      exploit: 'An attacker overlays your real page under a fake button ("Claim prize") so the victim unknowingly clicks "Delete account" or "Transfer" on your site.',
      impact: 'Unwanted actions performed by logged-in users.',
      fix: [
        { label: 'Send one of these headers', steps: [ '`Content-Security-Policy: frame-ancestors \'self\'` (modern)', '`X-Frame-Options: SAMEORIGIN` (legacy browsers)' ] }
      ],
      verify: [
        { check: 'Framing is restricted', cmd: 'curl -sI {url} | grep -Ei "x-frame-options|frame-ancestors"', expect: 'X-Frame-Options: SAMEORIGIN or frame-ancestors \'self\'.' }
      ]
    },
    {
      id: 'cookie-flags',
      title: 'Session cookie missing Secure / HttpOnly / SameSite',
      category: 'Web hardening',
      exploitability: 1,
      effort: 'minutes',
      match: { rule: ['10010', '10011', '10054'], cwe: [614, 1004, 1275], kw: [/cookie.*(httponly|secure flag|samesite|without secure)/i] },
      means: 'Login/session cookies are not fully protected: they may be readable by page scripts, sent over plain HTTP, or sent on cross-site requests.',
      exploit: 'Combined with XSS or a network attacker, a stolen session cookie logs the attacker in as the user — no password needed.',
      impact: 'Session hijacking.',
      fix: [
        { label: 'Set the flags', steps: [
          'Target: `Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax; Path=/`',
          'Express: `cookie: { secure: true, httpOnly: true, sameSite: "lax" }` · Django: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True` · PHP: `session.cookie_secure=1`, `session.cookie_httponly=1`, `session.cookie_samesite=Lax`' ] }
      ],
      verify: [
        { check: 'Cookies carry all three flags', cmd: 'curl -sI {url} | grep -i "^set-cookie"', expect: 'Each session cookie includes Secure; HttpOnly; SameSite=Lax (or Strict).' }
      ]
    },
    {
      id: 'version-disclosure',
      title: 'Server version / technology disclosure',
      category: 'Information exposure',
      exploitability: 1,
      effort: 'minutes',
      match: { rule: ['10036', '10037'], cwe: [200, 497], kw: [/server leaks version/i, /x-powered-by/i, /version (information|disclosure)/i, /banner/i, /server header/i] },
      means: 'The server announces exactly which software and version it runs.',
      exploit: 'It saves attackers a step: they look up exploits for that exact version. Low risk alone — but it is a 2-minute fix.',
      impact: 'Faster, targeted attacks.',
      fix: [
        { label: 'Nginx', steps: [ '`server_tokens off;`' ] },
        { label: 'Apache', steps: [ '`ServerTokens Prod` and `ServerSignature Off`' ] },
        { label: 'App frameworks', steps: [ 'Express: `app.disable("x-powered-by")` · PHP: `expose_php = Off` · IIS: remove X-Powered-By in HTTP Response Headers.' ] }
      ],
      verify: [
        { check: 'No version numbers in headers', cmd: 'curl -sI {url} | grep -Ei "^(server|x-powered-by|x-aspnet-version):"', expect: 'No version numbers (e.g. "Server: nginx" only, or nothing).' }
      ]
    },
    {
      id: 'dir-listing',
      title: 'Directory listing enabled',
      category: 'Information exposure',
      exploitability: 2,
      effort: 'minutes',
      match: { cwe: [548], kw: [/directory (listing|browsing|indexing)/i, /index of \//i] },
      means: 'Visiting a folder URL shows a list of every file in it.',
      exploit: 'Attackers browse for backups, config files, database dumps and old scripts that were never meant to be public.',
      impact: 'Exposure of sensitive files and source code.',
      fix: [
        { label: 'Turn it off', steps: [ 'Nginx: `autoindex off;`', 'Apache: `Options -Indexes`', 'IIS: Directory Browsing → Disable.', 'Then review the folder and remove anything that should not be web-accessible.' ] }
      ],
      verify: [
        { check: 'Folder URL no longer lists files', cmd: 'curl -s {url} | grep -i "index of"', expect: 'No output (expect a 403 or 404 page).' }
      ]
    },
    {
      id: 'cors',
      title: 'Overly permissive CORS policy',
      category: 'Web hardening',
      exploitability: 2,
      effort: 'hours',
      match: { rule: ['40040'], cwe: [942, 346], kw: [/\bcors\b/i, /cross-origin resource sharing/i, /access-control-allow-origin/i] },
      means: 'Your API lets any website read its responses in a user\'s browser.',
      exploit: 'If the API reflects any Origin with credentials allowed, a malicious site visited by a logged-in user can silently read their data from your API.',
      impact: 'Cross-site data theft.',
      fix: [
        { label: 'Lock it down', steps: [ 'Replace wildcard / reflected origins with an explicit allow-list of your own front-end domains.', 'Never combine `Access-Control-Allow-Credentials: true` with a reflected or `*` origin.' ] }
      ],
      verify: [
        { check: 'Foreign origin is not allowed', cmd: 'curl -sI -H "Origin: https://evil.example" {url} | grep -i access-control-allow', expect: 'No Access-Control-Allow-Origin header, or not "https://evil.example" / "*".' }
      ]
    },

    /* ───────────── Application code ───────────── */
    {
      id: 'sqli',
      title: 'SQL injection',
      category: 'Application code',
      exploitability: 3,
      effort: 'hours',
      match: { rule: ['40018', '40019', '40020', '40021', '40022', '40024', '40027', '90018'], cwe: [89, 564], kw: [/sql injection/i, /\bsqli\b/i] },
      means: 'User input is pasted straight into a database query, so a user can change what the query does.',
      exploit: 'Typing something like `\' OR 1=1--` into a form or URL can dump the whole database, bypass login, or modify data. Automated tools (sqlmap) make this point-and-click.',
      impact: 'Full database theft or tampering; sometimes server takeover.',
      fix: [
        { label: 'Fix the code', steps: [
          'Replace string-built queries with parameterized queries / prepared statements at {file}{line}.',
          'Python: `cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))` · Node: `db.query("… WHERE id = ?", [id])` · PHP PDO: `$stmt = $pdo->prepare("… WHERE id = ?"); $stmt->execute([$id]);`',
          'Give the app\'s database account least privilege (no DROP/ALTER, no access to other databases).' ] }
      ],
      verify: [
        { check: 'Injection payload is treated as data', cmd: 'curl -s "{url}" with the vulnerable parameter set to: 1\' OR \'1\'=\'1', expect: 'Same result as an invalid value — no extra rows, no SQL error.' },
        { check: 'Re-run the scanner on the endpoint', cmd: 're-scan {url}', expect: 'SQL injection alert is gone.' }
      ]
    },
    {
      id: 'xss',
      title: 'Cross-site scripting (XSS)',
      category: 'Application code',
      exploitability: 2,
      effort: 'hours',
      match: { rule: ['40012', '40014', '40016', '40017', '40026'], cwe: [79, 80], kw: [/cross[- ]site scripting/i, /\bxss\b/i] },
      means: 'The site echoes user input back into a page without neutralising it, so input can become running JavaScript.',
      exploit: 'An attacker sends a victim a link (or plants a comment) containing a script. When the victim views it, the script runs as them: steals their session, changes their email, or shows a fake login.',
      impact: 'Account takeover of anyone who views the page — including admins.',
      fix: [
        { label: 'Fix the code', steps: [
          'Output-encode at {file}{line}: use your template engine\'s auto-escaping (Jinja2, React JSX, Razor) and never bypass it (`|safe`, `dangerouslySetInnerHTML`, `innerHTML`).',
          'Use `textContent` instead of `innerHTML` in front-end code.',
          'Add a Content-Security-Policy as a second layer.' ] }
      ],
      verify: [
        { check: 'Payload is displayed, not executed', cmd: 'submit <script>alert(1)</script> to the affected parameter on {url}', expect: 'Text shows literally on the page; no alert box. View-source shows &lt;script&gt;.' },
        { check: 'Re-scan', cmd: 're-scan {url}', expect: 'XSS alert is gone.' }
      ]
    },
    {
      id: 'csrf',
      title: 'Missing anti-CSRF protection',
      category: 'Application code',
      exploitability: 2,
      effort: 'hours',
      match: { rule: ['10202', '20012'], cwe: [352], kw: [/\bcsrf\b/i, /cross[- ]site request forgery/i, /anti-csrf/i] },
      means: 'Forms that change things do not check that the request really came from your site.',
      exploit: 'A malicious page can auto-submit a hidden form to your site using the victim\'s logged-in session — changing their password or email without them knowing.',
      impact: 'Unwanted state-changing actions on behalf of users.',
      fix: [
        { label: 'Fix it', steps: [ 'Enable your framework\'s CSRF protection (Django/Rails/Laravel have it built in; Express: csrf middleware).', 'Set session cookies to `SameSite=Lax` or `Strict` as defence in depth.' ] }
      ],
      verify: [
        { check: 'Forged request is rejected', cmd: 'replay the form POST to {url} without the CSRF token', expect: 'HTTP 403 / "CSRF token missing or invalid".' }
      ]
    },
    {
      id: 'path-traversal',
      title: 'Path traversal / local file inclusion',
      category: 'Application code',
      exploitability: 3,
      effort: 'hours',
      match: { rule: ['6'], cwe: [22, 23, 35, 73, 98], cve: ['CVE-2021-41773', 'CVE-2021-42013'], kw: [/path traversal/i, /directory traversal/i, /file inclusion/i] },
      means: 'A user can make the application open files outside the folder it is supposed to use, by sending paths like ../../etc/passwd.',
      exploit: 'Attackers read config files with database passwords and API keys, or source code, and sometimes chain it into code execution.',
      impact: 'Secrets and source disclosure; potential server compromise.',
      fix: [
        { label: 'Fix the code', steps: [ 'Never build file paths from raw input at {file}{line}. Map user choices to an allow-list of IDs → filenames.', 'If paths are unavoidable, resolve them and confirm they stay inside the base directory (`realpath` / `Path.resolve()` then prefix check).', 'If this is a web server CVE ({cve}), upgrade the server package.' ] }
      ],
      verify: [
        { check: 'Traversal attempt is rejected', cmd: 'curl -s --path-as-is "{url}/../../../../etc/passwd" | grep root:', expect: 'No output (400/403/404 response).' }
      ]
    },
    {
      id: 'open-redirect',
      title: 'Open redirect',
      category: 'Application code',
      exploitability: 1,
      effort: 'hours',
      match: { rule: ['10028'], cwe: [601], kw: [/open redirect/i] },
      means: 'A link on your domain can be made to bounce visitors to any other website.',
      exploit: 'Phishers send links that start with your trusted domain but land on their fake login page.',
      impact: 'More convincing phishing; can help steal OAuth tokens.',
      fix: [
        { label: 'Fix the code', steps: [ 'Only redirect to relative paths or an allow-list of known hosts.', 'Reject values that start with `//`, `http:` or `https:` unless allow-listed.' ] }
      ],
      verify: [
        { check: 'External redirect blocked', cmd: 'curl -sI "{url}" with the redirect parameter set to https://evil.example', expect: 'No "Location: https://evil.example" header.' }
      ]
    },
    {
      id: 'hardcoded-secret',
      title: 'Hard-coded secret or credential in code',
      category: 'Secrets',
      exploitability: 3,
      effort: 'hours',
      match: { cwe: [798, 259, 321, 312], kw: [/(hard[- ]?coded|exposed|leaked).*(secret|password|key|token|credential)/i, /(aws|github|slack|stripe|private) (access )?(key|token)/i, /secret detected/i, /generic api key/i] },
      means: 'A password, API key or private key is written into the source code or image ({file}).',
      exploit: 'Anyone who can see the code — a contractor, a leaked repo, a public container image — gets the key. Bots scan public GitHub for keys within minutes of a push.',
      impact: 'Whatever the key unlocks: cloud accounts, databases, payment systems.',
      fix: [
        { label: 'In this order', steps: [
          '1. Revoke / rotate the secret at the provider now. Deleting it from code is not enough — it is in git history.',
          '2. Check the provider\'s logs for use of the old key since it was committed.',
          '3. Move the value to an environment variable or secret manager and read it at runtime.',
          '4. Add a pre-commit scanner (gitleaks, trufflehog) so it does not happen again.' ] }
      ],
      verify: [
        { check: 'Old secret no longer works', cmd: 'try an API call with the old key', expect: '401 / invalid credentials.' },
        { check: 'No secrets left in the working tree', cmd: 'gitleaks detect --no-git --source .   (or: trivy fs --scanners secret .)', expect: '"no leaks found" / 0 secrets.' }
      ]
    },
    {
      id: 'public-storage',
      title: 'Publicly accessible cloud storage',
      category: 'Cloud',
      exploitability: 3,
      effort: 'minutes',
      match: { kw: [/(bucket|blob|container|storage).*(public|anonymous|world[- ]readable)/i, /public (s3|bucket)/i, /block public access/i] },
      means: 'A cloud storage bucket or container can be read (or written) by anyone on the internet without logging in.',
      exploit: 'Researchers and criminals continuously enumerate bucket names. Exposed buckets are a leading cause of large data leaks.',
      impact: 'Data breach; if writable, malware hosting or tampering.',
      fix: [
        { label: 'AWS S3', steps: [ 'Turn on Block Public Access at the account level: `aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`', 'Serve public files through CloudFront with origin access control instead.' ] },
        { label: 'Azure / GCP', steps: [ 'Azure: Storage account → Configuration → "Allow Blob anonymous access" = Disabled.', 'GCP: enforce `storage.publicAccessPrevention` org policy.' ] }
      ],
      verify: [
        { check: 'Anonymous access denied', cmd: 'curl -sI https://<bucket>.s3.amazonaws.com/', expect: 'HTTP 403 AccessDenied.' }
      ]
    },
    {
      id: 'container-root',
      title: 'Container runs as root / insecure container config',
      category: 'Cloud',
      exploitability: 1,
      effort: 'hours',
      match: { rule: ['DS002', 'AVD-DS-0002', 'KSV001', 'KSV012', 'KSV017', 'AVD-KSV-0017'], kw: [/(running as|run as|runs as) root/i, /privileged container/i, /user directive/i] },
      means: 'The container\'s process runs with root privileges (or in privileged mode).',
      exploit: 'If the app inside is compromised, root inside the container makes escaping to the host — and every other container on it — much easier.',
      impact: 'Turns an app bug into a host compromise.',
      fix: [
        { label: 'Dockerfile / Kubernetes', steps: [ 'Add a non-root user: `RUN adduser -D app` then `USER app` in {file}.', 'Kubernetes: `securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false, privileged: false }`.' ] }
      ],
      verify: [
        { check: 'Process is not UID 0', cmd: 'docker run --rm --entrypoint id <image>', expect: 'uid is not 0.' },
        { check: 'Config scan clean', cmd: 'trivy config {file}', expect: 'No DS002 / KSV001 findings.' }
      ]
    },

    /* ───────────── Generic fallback: vulnerable dependency ───────────── */
    {
      id: 'vulnerable-package',
      title: 'Vulnerable software package',
      category: 'Vulnerable component',
      exploitability: 2,
      effort: 'hours',
      match: { kw: [] }, // selected by the matcher when a finding has a package name and CVE
      means: 'A component ({pkg} {installed}) has a published vulnerability ({cve}). Your code may or may not actually reach the vulnerable function.',
      exploit: 'Attackers scan for known-vulnerable versions; public exploit code often appears soon after disclosure. Risk depends on whether the vulnerable feature is reachable from untrusted input.',
      impact: 'Ranges from denial of service to remote code execution — see the CVE details.',
      fix: [
        { label: 'Upgrade', steps: [
          'Upgrade {pkg} to {fixed} or later.',
          'npm: `npm install {pkg}@{fixed}` · pip: `pip install "{pkg}>={fixed}"` · OS package: `apt install --only-upgrade {pkg}` · Container: rebuild on an updated base image.',
          'If no fix exists yet, check whether the vulnerable feature is used and add a compensating control (WAF rule, disable the feature).' ] }
      ],
      verify: [
        { check: 'Installed version is patched', cmd: 'npm ls {pkg} · pip show {pkg} · dpkg -l {pkg}', expect: 'Version ≥ {fixed}.' },
        { check: 'Re-scan', cmd: 'trivy image <image> (or re-run your scanner) | grep {cve}', expect: 'No output.' }
      ]
    }
  ];

  /** Fallback when nothing matches — still ends in a verifiable action. */
  const GENERIC = {
    id: 'generic',
    title: 'Security finding',
    category: 'General',
    exploitability: 2,
    effort: 'hours',
    match: {},
    means: 'Improve 2.0 has no specific playbook for this finding yet. Here is what the source tool reported.',
    exploit: 'Review the tool description below. Ask: can an unauthenticated person on the internet reach this? Does it expose data or allow code to run? Those two answers decide urgency.',
    impact: 'See the source tool description.',
    fix: [ { label: 'Suggested approach', steps: [ 'Apply the vendor/tool recommended solution (shown in "Tool says" below).', 'If unsure, restrict network access to the affected service while you investigate.' ] } ],
    verify: [ { check: 'Re-scan confirms the fix', cmd: 're-run the original scanner against {host}', expect: 'This finding no longer appears.' } ]
  };

  /**
   * CISA Known Exploited Vulnerabilities — small offline seed list.
   * The app can refresh the full catalog from cisagov/kev-data at runtime.
   */
  const KEV_SEED = [
    'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2017-0144', 'CVE-2017-0143', 'CVE-2017-0145', 'CVE-2017-0148',
    'CVE-2019-0708', 'CVE-2014-0160', 'CVE-2014-6271', 'CVE-2017-5638', 'CVE-2020-1472', 'CVE-2021-34527',
    'CVE-2021-26855', 'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2022-22965', 'CVE-2022-0847', 'CVE-2021-4034',
    'CVE-2023-4966', 'CVE-2023-34362', 'CVE-2018-13379', 'CVE-2019-11510', 'CVE-2024-3400', 'CVE-2023-44487',
    'CVE-2019-19781', 'CVE-2022-1388', 'CVE-2023-22515', 'CVE-2021-40444', 'CVE-2022-30190', 'CVE-2023-23397'
  ];

  global.ImprovePlaybooks = { PLAYBOOKS, GENERIC, KEV_SEED };
})(window);
