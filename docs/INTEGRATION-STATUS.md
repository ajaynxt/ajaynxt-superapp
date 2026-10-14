# Integration status and verification gates

## Current truthful status

No third-party account is connected in the deployed product because the Cloudflare Worker, Firebase web configuration and real D1 database are not yet deployed by the owner. The repo contains an integration catalogue, official account/developer links, project-scoped status endpoints and read-only report plumbing. A status row or account-portal link does not prove that data is being read.

## Official account portals currently linked in the app

- Instagram: https://www.instagram.com/accounts/login/ — API docs: https://developers.facebook.com/docs/instagram-platform/
- Facebook Pages / Meta Business: https://www.facebook.com/login/ and https://business.facebook.com/ — Meta developer docs: https://developers.facebook.com/
- Threads: https://www.threads.com/ — API docs: https://developers.facebook.com/docs/threads/
- YouTube: https://accounts.google.com/ — API docs: https://developers.google.com/youtube/v3
- LinkedIn: https://www.linkedin.com/login — community management docs: https://learn.microsoft.com/en-us/linkedin/marketing/community-management/community-management-overview
- Pinterest: https://www.pinterest.com/login/ — developer docs: https://developers.pinterest.com/
- TikTok: https://www.tiktok.com/login — developer docs: https://developers.tiktok.com/docs/en/
- X: https://x.com/i/flow/login — developer docs: https://developer.x.com/en/docs
- Snapchat: https://accounts.snapchat.com/accounts/v2/login — developer docs: https://developers.snap.com/
- Reddit: https://www.reddit.com/login/ — API docs: https://www.reddit.com/dev/api/
- Bluesky: https://bsky.app/ — API docs: https://docs.bsky.app/
- Mastodon: https://joinmastodon.org/ — API docs: https://docs.joinmastodon.org/api/
- Meta Ads: https://business.facebook.com/adsmanager/ — Marketing API: https://developers.facebook.com/docs/marketing-api/insights/
- Google Ads: https://ads.google.com/ — API docs: https://developers.google.com/google-ads/api/docs/start
- TikTok Ads: https://ads.tiktok.com/ — API docs: https://business-api.tiktok.com/portal/docs
- LinkedIn Ads: https://www.linkedin.com/campaignmanager/ — API overview: https://learn.microsoft.com/en-us/linkedin/marketing/integrations/ads
- Google Business Profile: https://business.google.com/ — performance API: https://developers.google.com/my-business/reference/performance/rest
- Google Analytics: https://analytics.google.com/ — Data API: https://developers.google.com/analytics/devguides/reporting/data/v1
- Swiggy Restaurant Partner login: https://partner.swiggy.com/login
- Official Swiggy Partner Android app: https://play.google.com/store/apps/details?id=in.swiggy.partnerapp
- Zomato Restaurant Partner login: https://www.zomato.com/partners/
- Zomato onboarding page: https://www.zomato.com/partner-with-us
- Zomato POS developer docs: https://www.zomato.com/developer/integration/docs/overview/
- WhatsApp Business / Meta Business: https://business.facebook.com/ — WhatsApp API docs: https://developers.facebook.com/docs/whatsapp/

Account login is always on the provider's site. Logging into the provider does not connect that account to AJAYNXT. Each live connector still requires its own OAuth flow, approved scopes, provider API keys/app review if required, and a successful API test.

## Swiggy and Zomato reporting

- Swiggy's official Partner portal is linked for restaurant owners. A public, generally available third-party restaurant analytics API has not been verified for every restaurant account here. Until access is confirmed for Diamond Restaurant, import genuine Partner report exports (CSV/XLS/PDF where supported) and label them as imported/unverified.
- Zomato's published developer site describes a POS integration program (menu, outlet and order workflows), not a blanket promise that every individual restaurant can connect its analytics to a third-party dashboard. The official onboarding documentation lists eligibility prerequisites—at least 50 restaurants onboarded or 10,000 monthly orders—and the final decision is made by Zomato. For a single restaurant, do not assume this POS partner access is available. Use the partner portal and source report import unless Zomato directly confirms eligible API access.
- Official Zomato refs: https://www.zomato.com/developer/integration/docs/overview/ and https://www.zomato.com/developer/integration/docs/getting-started/prerequisites/

## Data and connection states

- Not connected: no verified provider authorization exists.
- Import required: use a real source export until an official supported API is actually available and authorized.
- Connected: only show after the authorized account has been queried successfully; preserve account identity/scopes and last successful sync time.
- Error/revoked: expose the error state, stop sync, and revoke/delete tokens appropriately.

## Connector verification gate

1. Review current official API docs, account type, approval requirements, scopes and quotas.
2. Implement provider-specific OAuth state/PKCE, callback allowlists and server-side token storage.
3. Request minimum scopes only, and provide an explicit disconnect/revoke action.
4. Read a real authorized test resource and reconcile it against the provider UI/export.
5. Document units, time zones, attribution windows, date coverage, source and freshness.
6. Implement refresh, retries/backoff, rate-limit handling, sync logs and error visibility.
7. Mark Connected only after these checks succeed.

## AI / MCP read-only access

The repository includes /mcp with OAuth authorization code + PKCE, Google sign-in, explicit workspace/project consent, a read-only scope and refresh tokens. It also supports a separate custom read-only bearer token for clients that need that option. The token screen can revoke static tokens and OAuth clients; all tools offered are read-only.

This does not mean ChatGPT, Gemini, Grok or another AI client is already configured. After deploying all D1 migrations, configure the server endpoint in each target client and run a real OAuth/tool-scan test. The OAuth registration endpoint is rate-limited by MCP_RATE_LIMIT_SALT. Hosted clients may vary in supported MCP/OAuth features. Never paste one-time tokens into a public prompt, issue or screenshot.

## Reporting rules

- Keep original source labels and import timestamps; imported data stays unverified until reconciled.
- Missing dates are never treated as zero.
- Growth comparisons require complete consecutive 14-day windows; forecasts require complete consecutive 28-day history.
- Forecasts are estimates, not promises. Ads ROAS needs a defensible conversion-value/attribution source.
- Revenue is not profit. Revenue minus recorded costs is not net profit when costs, tax, refunds, commissions, ingredients, labour or overheads are missing.
- One-year retention removes old dated metric/sales/cost rows and old generated reports/drafts/audit records. Access/workspace configuration is retained unless manually removed so the owner can keep logging in. Details are in docs/CLOUDFLARE-SETUP.md.


## Project-wise report export behaviour

- The Reports page lists one report card per project in the currently authenticated workspace.
- Open report loads only the selected project's records.
- Download JSON includes a single project's metrics, coverage, eligible comparisons/forecasts, financial reconciliation and connection metadata.
- Download CSV contains only a single project's daily metrics.
- The selected project's Print/Save PDF action also prints only the current report view.
- The server requires the same project ID in report/finance/integration requests and verifies workspace/project membership. There is no default combined report across client projects.
- In cloud mode, other project cards show Not loaded until that project has actually been fetched; they must not be interpreted as having zero metrics.

## Swiggy / Zomato practical route

Use the restaurant Partner login, not customer or delivery-rider credentials. Swiggy's official Partner app describes restaurant owner access and notes that business-metric access depends on owner access/enablement; ask the Swiggy point of contact if the account lacks metrics.

Zomato's public POS API documentation describes menu/order/outlet workflows for integrated POS vendors, with a formal onboarding process. Its prerequisites mention minimum vendor scale (50 restaurants or 10,000 monthly orders, with final eligibility decided by Zomato). This does not establish general analytics API access for a single restaurant. Therefore:
- Keep the provider labelled Import required until official account-specific API access is approved and tested.
- Prefer genuine Partner report exports, then map the real date, amount/value and currency columns in the Financials CSV importer.
- Group order-line CSVs by sum/count only where appropriate; use last-value aggregation only for an already-aggregated daily summary.
- Reconcile the imported totals with the original report before using them in client reports.
