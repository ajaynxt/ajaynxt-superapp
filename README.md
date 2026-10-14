# AJAYNXT Social Hub

Low-cost, multi-project reporting and social content workspace. The default project is Diamond Restaurant; every additional client/brand is a separate project.

## Architecture

- Responsive website and installable Progressive Web App (PWA).
- Cloudflare Workers API and D1 database; Firebase Authentication for Google sign-in.
- Server-enforced Super Admin UID, separate workspace roles, per-project authorization and audit events.
- Official account/developer portal links for social, advertising, business analytics and food-delivery platforms.
- Project-scoped metrics CSV import, with missing dates never treated as zero.
- Swiggy/Zomato Partner CSV import with manual date/value/currency column mapping and daily aggregation.
- Separate per-project reports: Open report, Download JSON, Download CSV and Print/Save PDF for the currently selected project.
- Project-scoped growth comparisons and seven-day trend estimates when the required consecutive history exists.
- Financial summaries grouped by currency. Revenue minus entered costs is not net profit.
- Read-only remote MCP reporting with OAuth authorization code + PKCE, explicit workspace/project consent, refresh and revocation.
- Scheduled 365-day cleanup for old reporting/financial observations, old drafts/reports/audit entries, expired OAuth records and old tokens.

No Supabase, Firestore, Firebase Admin SDK or Firebase Cloud Functions are required in this architecture.

## Project-by-project reports

Open Reports to see one card per project in the current authorized workspace. Each card opens or exports only that project. The JSON report includes that project's metrics, coverage, available comparisons/forecasts, financial reconciliation and integration state. The CSV contains that project's metrics records. The report currently displayed/printed on screen is also restricted to the selected project; there is no default all-clients combined report.

When signed in, opening/exporting another project fetches that project's own records through the authenticated API and its project ID. A project whose data has not been loaded is labelled as not loaded, not incorrectly shown as zero.

## Swiggy and Zomato

- Swiggy Restaurant Partner: https://partner.swiggy.com/login
- Zomato Restaurant Partner: https://www.zomato.com/partners/
- Zomato POS integration documentation: https://www.zomato.com/developer/integration/docs/overview/
- Official Swiggy Partner Android app: https://play.google.com/store/apps/details?id=in.swiggy.partnerapp

Use the restaurant owner/Partner account, not a customer or delivery-rider account. A Partner portal link is not a live AJAYNXT connection. Swiggy's account must have restaurant-owner access to the business metrics. Zomato's published POS APIs are for approved/onboarded POS integration; that does not automatically grant every restaurant a general analytics API. Until official API permission is confirmed for Diamond Restaurant, import an actual Partner report using Financials → Import Swiggy / Zomato report CSV. Imported data stays labelled unverified until reconciled with the original report.

The CSV importer requires an actual report file. It does not log in to Swiggy/Zomato, scrape dashboards or invent orders/sales. For order-line exports, use Sum or Count as appropriate; for a daily-summary export, choose Last value only when the source already contains one daily summary per date. Review the column mapping and date format before importing. Each import batch is capped at 80 daily/currency summary rows.

## Deployment status

The code is in GitHub but is not yet deployed/configured in the owner's Cloudflare account. The D1 placeholder ID in wrangler.jsonc must be replaced with the exact ID Cloudflare returns. Firebase web settings, the real Super Admin UID and the OAuth rate-limit secret must be set as encrypted Worker secrets. Apply the D1 migrations before using login, reports or cleanup.

The older Vercel preview is only the static prototype; it does not automatically run this Cloudflare Worker. Use the Cloudflare setup guide for deployment.

## Important boundaries

- A provider is not marked connected merely because its login link is available.
- Live social/ad/marketplace APIs need official permissions, app setup, token lifecycle, provider-specific implementation and a successful API test.
- MCP is read-only: it can read authorized reporting data but cannot publish, change settings or delete source data. Hosted AI client compatibility still needs a real OAuth/tool-scan test.
- Imports remain unverified until reconciled. Projections are estimates, not promises.
- One-year cleanup targets reporting records; active workspace, project, account identity and access configuration are retained so the owner can keep signing in.

## Setup and checks

1. Follow [Cloudflare deployment guide](docs/CLOUDFLARE-SETUP.md).
2. Configure Firebase Google sign-in and set AJAYNXT_SUPER_ADMIN_UID to the exact UID shown in Firebase Authentication.
3. Create D1, replace the placeholder database ID in wrangler.jsonc and apply all four migrations.
4. Set MCP_RATE_LIMIT_SALT to a long, random secret and configure the Firebase Worker secrets.
5. Deploy, sign in, and verify the worker's health route before importing client data.

Local checks:
- npm install
- npm run build
- npm run check:syntax
- npm test

Never commit .dev.vars, Firebase/private credentials, the Super Admin UID, MCP tokens, OAuth secrets or provider access tokens.
