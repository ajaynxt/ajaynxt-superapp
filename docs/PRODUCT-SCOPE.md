# AJAYNXT Social Hub — Product Scope and Mobile App Plan

## Goal

One AJAYNXT agency workspace with multiple projects. Each project has its own business profile, social accounts, ad accounts, marketplace reports, content, permissions, analytics, projections and reports. The same secured backend serves the web app, installable mobile app and authorized AI/MCP clients.

## 1. Multi-project workspaces

- Create, rename, archive and restore projects.
- A project switcher changes the context of every screen and data request.
- Separate business details, timezone, currency, metric definitions, source connections, posts, reports and plugin permissions.
- Invite team/client members with explicit roles and project assignments.
- Optional read-only client portal for approved reports.
- Audit important changes and exports.

## 2. Agency overview

- Project health, setup readiness, last successful sync and failed connections.
- Pending approvals, upcoming posts, failed jobs and recent reports.
- Cross-project summaries only for projects the user may access.
- Do not combine metrics unless definitions and units are compatible.

## 3. Integration Hub

Social channels: Instagram Professional, Facebook Pages, Threads, YouTube, LinkedIn, Pinterest, TikTok, X, Snapchat, Reddit, Bluesky and Mastodon.

Business channels: Google Business Profile, Google Analytics 4 and WhatsApp Business Platform. Add Telegram/Discord only where an API/reporting need is verified.

Advertising: Meta Ads, Google Ads, YouTube Ads and other ad APIs where account access is verified.

Food delivery: Swiggy and Zomato, initially using actual Partner exports/CSV until direct account/API access is documented and authorized.

Every integration must show its real state: Not configured, Approval required, Connected, Syncing, Reconnect required, Error, Analytics only, Publishing supported or Import required. A catalogue entry is not proof of integration. Build and test each provider adapter independently.

## 4. Content Studio and publishing

- Project-specific media library, folders, tags, source files and usage-rights notes.
- Drafts, captions, platform-specific copy, creative briefs and alt text.
- Photo/video upload validation for type, size, duration and dimensions.
- Platform-specific previews and documented rule checks.
- Calendar, scheduling queues, approvals, publishing history, retries and errors.
- Manual publish fallback when direct posting is unsupported or not approved.
- Avoid fabricated product details, discounts, quantities or campaign claims in AI creatives.

## 5. Organic social analytics

Followers/subscribers, reach, impressions, views/watch time, engagement, link clicks and audience breakdowns only where supported and authorized. Include post/Reel performance, best/weakest content, source timestamps, metric definitions and last successful sync. Keep platform metrics separate when their definitions differ.

## 6. Meta Ads and other paid campaigns

- Campaign/ad set/ad reporting where official APIs expose it.
- Spend, reach, impressions, clicks, CTR, CPM, CPC, leads, conversions and ROAS only when accessible and tracked correctly.
- Preserve attribution window, currency, timezone, objective and source.
- Keep organic and paid results distinct.
- Begin read-only. Campaign changes and budget edits need explicit permission, safeguards and confirmation.

## 7. Swiggy and Zomato sales intelligence

- Import genuine Partner exports and review column meaning, granularity, units, timezone and how discounts, refunds and commissions are treated.
- Report orders, item performance, cancellations, reviews/ratings and revenue only if included in the source.
- Preserve order states where available: placed, accepted, prepared, cancelled, delivered and refunded.
- Log menu/photo/category changes for before/after review.
- Revenue is not profit. Profit requires actual costs, packaging, marketplace fees, discounts, refunds, taxes and ad spend.

## 8. Growth reports, projections and profit

- Daily/weekly/monthly summaries and comparable periods, with absolute and percentage change.
- Show data completeness, freshness and source attribution.
- Forecast only when history quality is sufficient; backtest against held-out real data and report error where suitable.
- Label estimates and assumptions clearly. Show uncertainty ranges only when statistically supported.
- Missing dates are not zero. Before/after movement does not prove causation.
- Show profit only when reliable cost inputs exist; otherwise report revenue and spend separately.

## 9. Reports and AI/MCP

- Weekly/monthly snapshots with source, period cutoff and last sync.
- CSV/JSON/PDF export and expiring, revocable report links.
- ChatGPT, Gemini, Claude and Grok can use API/MCP paths only where each client currently supports them and required access is configured. Consumer subscriptions do not automatically grant API access.
- Start with authenticated read-only tools: list permitted projects, retrieve a report, compare periods, list top posts, explain missing data and describe forecast methodology.
- Enforce project permissions server-side for every tool call.
- Never expose credentials. AI must not silently publish posts or change ad budgets.

## 10. Developer Hub

- Reviewed connector manifest with name, version, owner, endpoint, requested scopes, actions, data fields, documentation and status.
- Separate registration, review, enablement, authorization, connection tests and operational status.
- Use server-side adapters or vetted remote MCP endpoints instead of arbitrary executable JavaScript.
- Per-project enable/disable and least-privilege tool permissions.
- Show API quotas/costs only when verified.
- Never collect API keys through public forms or execute untrusted plugin code.

## 11. Mobile app

### Phase A: responsive website + installable PWA

- One codebase and the same secured backend as the website.
- Mobile-first project switching, analytics/reports, connection health, alerts and approval screens.
- Installable app shell; push notifications only where browser/OS support and user permission allow.
- Cache static shell assets only by default; do not cache private reports or authenticated API responses.
- Test supported iOS, Android and desktop browsers.

### Phase B: native Android/iOS app when justified

- Consider React Native/Expo once backend APIs and authorization are stable.
- Reuse the same backend and report definitions, not a second ungoverned database.
- OS secure storage, minimal local caches, biometric unlock where supported and server-side session revocation.
- App-store compliance, deep links, crash reporting and signed releases.

## 12. Recommended architecture to evaluate

Next.js + TypeScript, Supabase Auth/PostgreSQL, server-side API routes, private object storage, Vercel hosting and a trusted background worker for long/scheduled jobs. Confirm plan cost, region and existing account access before choosing. Do not reuse an unrelated production database without explicit design review. This is a proposal; the current MVP does not yet use these as a live backend.

## 13. Delivery order

1. Freeze security architecture and tenant/project model.
2. Implement authenticated backend, organization membership, RLS, audit log, private storage, import pipeline and backup/restore.
3. Establish Diamond Restaurant's baseline from actual Swiggy/Zomato reports before changing the menu.
4. Ship one verified read-only API connector based on actual account access and approvals.
5. Add organic analytics and Meta Ads Insights one provider at a time.
6. Add content media, approvals, scheduling and authorized publishing.
7. Add growth/profit reports, with backtesting and actual cost data.
8. Deploy authenticated read-only MCP tools and verify project isolation.
9. Make the website installable as a PWA on the same backend.
10. Build native apps only if proven usage and requirements justify the maintenance.
11. Add client onboarding, billing and client-facing report portals after core reliability is proven.

## 14. Launch acceptance checklist

- Projects persist across devices after sign-in.
- Unauthorized project IDs cannot be read or changed.
- Client data cannot leak across API, reports, uploads or MCP tools.
- No secrets appear in frontend code, Git history or logs.
- Each live connection has a real provider account ID, granted scopes and a last successful sync.
- Failed syncs/expired tokens are visible and recoverable.
- CSV import surfaces validation errors and never silently drops, sums or overwrites rows.
- Reports include source, units, cutoff and freshness.
- Projections are withheld for insufficient data and tested against held-out actuals.
- PWA uses the secured backend and does not cache private data.
- Backup restore, connection revocation, data export and deletion are tested.
