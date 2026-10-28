# ADR-0001: Corporate SSO via CDP-Driven Isolated Managed Browser Window

- **Status**: Accepted
- **Date**: 2026-10-22

## Context

Non-admin ServiceNow users in enterprise environments typically authenticate via Corporate SSO (Okta, Microsoft Entra ID, Ping) with MFA and device posture checks (Okta FastPass, Intune/Conditional Access, client certificates). Non-admins cannot create OAuth 2.0 Application Registry entries (`oauth_entity`) or provision REST API Keys (`com.glide.tokenbased_auth` requires `api_service_admin`).

Meanwhile:
1. Scraping SQLite cookie files from the user's daily-driver browser (`rookie` / Chrome `Cookies` DB) is brittle across browser updates, triggers repeated OS Keychain prompts for Chrome/Safari encryption keys, and fails when cookies are locked or partitioned.
2. Embedding a raw OS WebView (`wry` / `WKWebView`) inside an unsigned CLI binary frequently fails enterprise Conditional Access / device-trust checks that require a managed browser or browser extension (e.g., Okta Verify / Microsoft Single Sign-On extension).

## Decision

1. **Primary Interactive SSO Flow (`sncfr auth login`)**:
   - Launch the user's enterprise-managed Chromium browser (Chrome, Edge, Brave, Arc) in an isolated `--app=https://<instance>.service-now.com` window with a dedicated profile directory (`~/.local/share/sncfr/browser-profile/<instance>`) and a local loopback Chrome DevTools Protocol (CDP) port.
   - Wait for the user to complete SSO/MFA and for the ServiceNow session (`window.g_ck`) to initialize.
   - Extract all domain cookies via CDP `Network.getCookies` and the CSRF/session token (`window.g_ck`) via `Runtime.evaluate`, close the `--app` window automatically, and store the session bundle in the OS Keychain (`keyring`).
2. **Headless / Remote Fallback (`sncfr auth import`)**:
   - Support importing a session via pasted DevTools "Copy as cURL" or `Cookie` + `X-UserToken` headers, as well as API Key / Basic / OAuth tokens where available.
3. **Context-Aware Expiry Handling**:
   - In an interactive TTY, automatically launch the isolated `--app` window (which typically re-authenticates silently using IdP cookies persisted in the isolated profile) and retry.
   - In non-interactive / agent invocations (`!isatty`), fail fast with exit code `3` (`AUTH_EXPIRED`) and a structured remediation hint (`sncfr auth login`).

## Consequences

- Inherits full corporate device posture, client certificates, and password-manager/SSO extensions from the managed browser.
- Avoids touching or decrypting the user's personal browser profile SQLite databases.
- Keeps re-authentication fast because the isolated browser profile retains IdP device-trust cookies across sessions.

## Amendment (2026-10-28, release 0.2.0): CDP port lifecycle and credential storage risks

**CDP debugging port.** This describes the current behavior, not a change.

- The port is ephemeral. `sncfr` asks the OS for a free loopback port (`127.0.0.1:0`), releases it, and launches the browser with `--remote-debugging-port=<port>`. Chromium binds the debugging endpoint to loopback only by default, and `sncfr` never passes `--remote-debugging-address`.
- The port lives only for the login window. Once a verified non-guest session and `g_ck` are captured, `sncfr` sends CDP `Browser.close`, then kills the child process if it is still running. No debugging port outlives `sncfr auth login`.
- The browser profile (`~/.local/share/sncfr/browser-profile/<instance>`) is isolated from the user's daily profile, and it persists IdP cookies so later logins are fast.
- **Residual risks:**
  - CDP has no authentication. While the login window is open, any process running as the same OS user, or able to reach loopback, can attach to the port and read cookies. This is accepted because it is the same trust level as the user's own session, and the window is short-lived.
  - There is a short race between `sncfr` releasing the port and Chromium binding it. If another process takes the port, the CDP handshake fails and login aborts. It never connects to a foreign endpoint.

**`SNCFR_CREDENTIALS_FILE`.** This is the headless fallback when no OS keychain daemon exists.

- The session bundle (cookies + `g_ck`, or API key/basic/bearer material) is stored as **plaintext JSON**, protected only by file mode `0600` set on write. Risks:
  - the file is readable by root and by any process running as the user
  - it lands in backups, dotfile syncs, and container image layers if placed carelessly
  - on multi-user or shared CI hosts, a file mode is the only barrier
- **Guidance:** prefer the OS keychain. Use the file only on single-purpose hosts or ephemeral containers. Point it at a tmpfs or secret mount, never at a path inside a repository, and delete it with `sncfr auth logout` when done.
- **Organization control (0.2.0):** an Instance Pack may set `[auth] allow_credentials_file = false`.
  - Because pack safety keys are a strictest union across layers (ADR-0004), any loaded layer setting it wins.
  - With it set, every command, including each `auth` subcommand, exits 2 before opening, reading, creating, or writing the file named by `SNCFR_CREDENTIALS_FILE`.
  - To make that guarantee hold, the pack is loaded before the credential store is selected.
