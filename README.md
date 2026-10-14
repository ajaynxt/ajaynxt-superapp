# AJAYNXT Social Hub

Low-cost multi-project social/content and business-reporting workspace. The initial active project is Diamond Restaurant; the architecture supports additional projects and client workspaces with separate access boundaries.

## Architecture

- Frontend: responsive HTML application, installable PWA shell.
- API: Cloudflare Workers.
- Database: Cloudflare D1 with SQL migrations and tenant-scoped project membership.
- Sign-in: Firebase Authentication (Google sign-in only).
- Reports: project-scoped metrics, CSV imports, complete-window growth comparisons, conservative trend estimates, and entered sales/cost reconciliation.
- Owner controls: server-side Super Admin UID allowlist; /admin.html is the Admin Console.
- Client and staff roles: owner, admin, operator, analyst, client_viewer.

No Supabase, Firestore, Firebase Admin SDK or Firebase Cloud Functions are required in the current architecture.

## Current status — code is not deployed

Infrastructure/API code has been committed to GitHub, but it has **not** been connected to the owner's Cloudflare account or Firebase project in this session. The D1 placeholder ID still must be replaced with the actual ID from Cloudflare. The Super Admin UID and Firebase web config must be set in Cloudflare. Until these steps are completed, a live shared database and sign-in are not operational.

The previous Vercel preview is the older static prototype and does not automatically deploy these GitHub changes. Use docs/CLOUDFLARE-SETUP.md for the intended deployment path.

## Functionality included in code

- Multiple projects under an organization/workspace.
- Server-side auth token validation and project membership checks.
- Admin ID create/revoke API restricted to the configured Super Admin UID.
- Audit records for important privileged/data changes.
- Metric CSV imports (80 records per batch in current low-cost configuration), duplicate rejection and source verification flags.
- Growth comparison only when complete 14-day windows exist.
- 7-day trend estimate only when 28 consecutive days exist, with limitations shown.
- Project-specific drafts stored through the API when cloud auth is configured; drafts are not published.
- Sales/cost inputs and a currency-grouped revenue-minus-recorded-costs report that explicitly is **not net profit**.
- Installable PWA shell that does not cache API responses or admin data.
- Automated unit test, syntax-check and build scripts.

## Not yet connected or implemented

- Cloudflare account and D1 database deployment.
- Firebase project configuration and authorized domain.
- The real owner's Super Admin UID.
- Production security tests against the deployed instance and backup/restore review.
- Official OAuth connectors or live sync for Instagram, Facebook, Threads, YouTube, LinkedIn, Pinterest, TikTok, X, Google Business Profile, Meta Ads, Google Ads, WhatsApp, Swiggy or Zomato.
- Real API-based post publishing/scheduling; the schedule schema is only a foundation.
- Native iOS/Android store binaries and verified media upload pipeline.

A catalogue entry is not evidence of a connection. Only show a provider as connected after official authorization and successful provider API verification.

## Lowest-cost setup

See [Cloudflare deployment/setup guide](docs/CLOUDFLARE-SETUP.md). Cloudflare Workers + D1 and Firebase Authentication can start on free quotas. Free quotas are enforced limits, not unlimited capacity. Do not enable paid features before reviewing actual costs.

## Key docs

- [Cloudflare setup](docs/CLOUDFLARE-SETUP.md)
- [Firebase Authentication only](docs/FIREBASE-SETUP.md)
- [Product scope](docs/PRODUCT-SCOPE.md)
- [Security architecture](docs/SECURITY-ARCHITECTURE.md)
- [Reporting methodology](docs/REPORTING-METHODOLOGY.md)
- [Integration verification status](docs/INTEGRATION-STATUS.md)
- [Roadmap](docs/ROADMAP.md)

## Local checks

~~~bash
npm install
npm run build
npm run check:syntax
npm test
~~~

To develop against the Worker locally, copy .dev.vars.example to .dev.vars, configure the Firebase Web values, set a D1 database binding as required by Wrangler, and run npm run dev. Never commit .dev.vars or any admin secret.
