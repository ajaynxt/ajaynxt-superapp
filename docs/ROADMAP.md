# AJAYNXT Social Hub — Delivery Roadmap

## Phase 0 — Low-cost foundation (code committed, setup pending)

- [x] Existing responsive Social Hub interface
- [x] Cloudflare Worker API code with Firebase ID-token verification
- [x] D1 SQL schema and migration
- [x] Project/workspace access checks
- [x] Server-enforced Super Admin UID gate
- [x] Admin ID create/revoke APIs and Admin Console
- [x] Project metric import/read API with validation and duplicate protection
- [x] Reports API: 14-day complete-window comparison and 28-day forecast eligibility
- [x] Cross-device draft API (drafts only, no publishing)
- [x] Sales/cost records and revenue-minus-entered-costs reconciliation (not net profit)
- [x] PWA install shell that excludes API/admin data from caching
- [x] CI workflow for build, syntax and unit tests
- [x] Read-only MCP endpoint with OAuth authorization code + PKCE, scoped workspace/project consent and owner-managed tokens
- [x] OAuth dynamic client-registration rate limit and one-time token display
- [x] Daily 365-day reporting-data cleanup with owner-visible status/manual trigger
- [x] Official account portal and developer setup links in the integrations catalogue
- [ ] Deploy D1/Firebase configuration and validate MCP OAuth against ChatGPT or another compatible client
- [ ] Verify each provider-specific API connection separately; account portal links alone are not data integrations
- [ ] Create real Cloudflare D1 and replace placeholder DB ID
- [ ] Configure Firebase Google sign-in and authorize the deployed hostname
- [ ] Set the owner's exact Firebase UID as encrypted AJAYNXT_SUPER_ADMIN_UID
- [ ] Deploy and test server-side authorization in the real environment
- [ ] Backup/restore, quota alerts and access revocation test

## Phase 1 — Personal use on Diamond Restaurant

- Import actual social metrics and POS/marketplace CSV exports.
- Reconcile source reports and define data dictionary, currencies and metric units.
- Add repeatable import workflows and freshness/error indicators.
- Use daily/weekly reports to assess real outcomes before selling the service.

## Phase 2 — First verified provider connector

- Pick one provider with an official, currently supported API and the right account type.
- Register the app in the provider developer console.
- Implement OAuth state/PKCE, scopes, callback validation, server-side token storage/encryption and revocation.
- Read only the minimum data needed; verify against the provider's UI/API and record last-successful-sync.
- Keep connector disconnected on any missing consent or failed test.

## Phase 3 — Safe publishing and media

- Build private media upload/download and access checks before enabling upload UI.
- Create platform-specific approval status and account connection settings.
- Implement draft review, approvals, timezone-aware schedule, retry and publish-result reconciliation only for APIs that allow it.
- Never imply a post was published until the provider returns a confirmed result.

## Phase 4 — Agency operations

- Invitation workflow, Admin/client membership management and role audit.
- Client-facing read-only reports and exports.
- Separate business/client projects with least-privilege access.
- Data retention/deletion, export and restore workflows.
- Resource-usage monitoring, rate limiting and alerting.

## Phase 5 — AI/MCP clients

- Add an authenticated, scoped API for ChatGPT, Gemini, Claude and other permitted AI clients.
- Require explicit user consent, project scopes, short-lived OAuth tokens and tool-level least privilege.
- Avoid exposing D1, provider OAuth tokens or other tenants' data directly.
- Run prompt-injection, privilege escalation, data-leak and audit tests.

## Phase 6 — Native apps

- Reassess Android/iOS binaries once the PWA and backend are stable.
- Reuse the same Worker API and identity policy rather than duplicating business rules.

## Release rule

Every external data source is clearly marked disconnected, imported or verified connected. No fake metrics, orders, sales, ROAS or success claims. Growth projections require complete history and remain estimates. Revenue is not profit without complete, verified costs.
