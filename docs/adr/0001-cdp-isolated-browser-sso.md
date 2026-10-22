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
