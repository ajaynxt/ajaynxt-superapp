# Integration status and verification gates

## Current truthful status

The repository contains a provider catalogue and data model placeholders. **No third-party social network, advertising account, Google Business Profile, Swiggy, Zomato or other marketplace account is connected.** The Cloudflare Worker has not been deployed to the user's account, and no Firebase project credentials or real D1 ID were configured in this session.

## Integration strategy

Start with one provider after the platform owner has configured/deployed the backend. For each provider, verify the official API docs, account-type eligibility, app review requirements, available scopes, current quotas, data retention terms and publishing constraints. Never scrape or bypass an API permission requirement.

Possible catalogue, subject to official access:
- Social/content: Instagram, Facebook Pages, Threads, YouTube, LinkedIn, Pinterest, TikTok, X, Snapchat, Reddit, Bluesky and Mastodon.
- Web/business: Google Business Profile, GA4.
- Ads: Meta Ads, Google Ads.
- Communication: WhatsApp Business.
- Marketplace: Swiggy, Zomato.
- Import sources: POS exports, invoices, spreadsheets and CSV reports.

## State meanings

- Not connected: no OAuth authorization is present.
- Authorization pending: a real login/consent flow started but has not been verified.
- Connected: an authorized account was successfully queried through the expected provider API; store account identity/scopes/last success.
- Import required: there is no official API connection available for this account, so the user must import a source report.
- Error: authorization revoked, provider failure, missing permission or sync problem was detected.
- Revoked: account link has been disconnected; tokens must be revoked/deleted as appropriate.

## Verification gate per connector

1. Identify the official API and eligible account type.
2. Implement OAuth state and PKCE where appropriate; validate callbacks and required scopes.
3. Keep client secrets and tokens server-side, protect/encrypt tokens and record least-required scopes.
4. Read an actual authorized test resource.
5. Compare returned fields with the source UI and document units, attribution windows, time zone and freshness.
6. Implement token refresh, disconnect/revoke, rate limits, backoff and failure alerts.
7. Show the connection as active only after successful verification and display the last successful sync time.

## Reporting rules

- Preserve the original source and import timestamp.
- Imported values remain unverified until reconciled with the actual source report.
- Never treat missing dates as zero.
- Ads ROAS requires a defensible conversion value/attribution source; spend and clicks alone do not establish revenue or profit.
- Swiggy/Zomato sales are report imports until an authorized official API connection is proven.
- Revenue and profit are different. Revenue minus entered expenses is not net profit.
- A provider's integration status never guarantees the provider's uptime or that every metric/scope is available.
