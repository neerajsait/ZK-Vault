# 🛡️ Security Policy & Threat Model

Welcome to the **zk-vault** Security Policy. Because this is a Zero-Knowledge Vault, maintaining a clear security boundary is essential. This document explains our security posture, supported versions, what threats are mitigated by the architecture, what threats reside under user responsibility, and how to responsibly report vulnerabilities.

---

## 📞 Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a public issue.** Instead, report it privately to ensure we can resolve the issue before details are released.

* **Email:** `security@example.com` *(Replace this with your security contact email)*
* **Expected Response Time:** We aim to acknowledge reports within 48 hours and provide a fix or status update within 7 days.
* **Disclosure Policy:** We follow responsible disclosure. We request that you do not publish details of the vulnerability until a patch has been released.

---

## 📈 Supported Versions

We actively maintain and patch security vulnerabilities for the following versions:

| Version | Supported | Notes |
|---------|-----------|-------|
| 1.0.x   | ✅ Yes    | Current Active Release |
| < 1.0.0 | ❌ No     | Pre-release / Development builds |

---

## 🧠 Threat Model & Security Boundaries

The zk-vault divides security responsibilities between the **Application Architecture** and the **User/Hosting Environment**.

### 1. What is Protected (In-Scope / Application Mitigations)

The system is designed to keep data secure even in hostile environments:

* **Full Database Compromise:**
  * **Threat:** An attacker steals a full SQL dump of the database.
  * **Mitigation:** The database holds only ciphertext blobs encrypted with AES-GCM-256 and login verifiers hashed with Argon2id. Furthermore, a server-side secret (`VERIFIER_HMAC_KEY`) is mixed into the verifier hash, preventing offline brute-force dictionary attacks even if the database is leaked.
* **Untrusted Server Administrators / Hosting Providers:**
  * **Threat:** A server operator tries to read user credentials.
  * **Mitigation:** All decryption keys (`key1`) are derived locally in browser memory and are never sent to the server. The server stores only raw ciphertext envelopes.
* **Network Eavesdropping:**
  * **Threat:** An attacker intercepts packets on public Wi-Fi or local area networks.
  * **Mitigation:** Requires SSL/TLS (HTTPS) to secure OTP tokens and login verifiers in transit. In-transit session headers are protected by server-side Redis session keys rather than client-readable cookies.
* **Cross-Site Request Forgery (CSRF):**
  * **Threat:** A malicious site tries to make requests on behalf of an authenticated user.
  * **Mitigation:** Enforced validation of anti-CSRF tokens on all POST/PUT/DELETE actions via `Flask-WTF`.
* **Cross-Site Scripting (XSS) & Injection:**
  * **Threat:** Attackers inject malicious scripts to extract keys from browser memory.
  * **Mitigation:** Secured via strict Content Security Policy (CSP) headers containing single-use cryptographic nonces (`Flask-Talisman`). Inline scripts and external CDNs are blocked by default. WebAssembly (`wasm-unsafe-eval`) is only permitted on specific authentication and vault pages that require Argon2 key derivation.

---

### 2. What is NOT Protected (Out-of-Scope / User Responsibility)

Some vectors cannot be mitigated by the web application itself. Users and hosts must ensure their clients and deployment parameters are hardened:

* **Compromised Endpoint (Client-Side Malware):**
  * **Threat:** Malware (keyloggers, screen scrapers, remote access trojans) running on the user's operating system.
  * **Mitigation:** The user must ensure their operating system is updated and free of malware. A keylogger on the endpoint can capture the master password during input.
* **Malicious Browser Extensions:**
  * **Threat:** A browser extension with broad permissions inspecting page DOM or memory.
  * **Mitigation:** The user should avoid installing untrusted or unnecessary extensions in the browser profile used to access the vault. Extensions run in a privileged context and can bypass standard web security boundaries.
* **Weak Master Passwords:**
  * **Threat:** A user chooses a simple dictionary password.
  * **Mitigation:** While Argon2id uses memory-hard parameters to slow down guessing attacks, a weak master password is still vulnerable to offline dictionary attacks if the attacker obtains the salt from a database leak.
* **Phishing Attacks:**
  * **Threat:** A user enters their Master Password on a spoofed or cloned domain (e.g., `zk-vau1t.com`).
  * **Mitigation:** The user must verify the domain name in the address bar before entering credentials.
* **Lack of HTTPS in Hosting:**
  * **Threat:** Hosting the vault on HTTP.
  * **Mitigation:** The administrator must configure SSL/TLS certificates. Running the app on standard HTTP allows attackers to sniff login verifiers and OTP codes.
