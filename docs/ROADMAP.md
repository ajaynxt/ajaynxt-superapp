# AJAYNXT Social Hub — Delivery Roadmap

## Phase 0 — Foundation (current)

- [x] Evidence-first dashboard UI
- [x] Project switching, create and rename in browser-local state
- [x] Integration catalogue showing unconnected state honestly
- [x] CSV import with schema/date/value/duplicate checks
- [x] Source report export (CSV/JSON) and print-to-PDF
- [x] 14-day complete-window growth comparison
- [x] 28-day linear-trend projection eligibility and seven-day point estimate
- [x] Explicit MVP storage and integration limitations

## Phase 1 — Secure application core

- [ ] Freeze multi-tenant architecture and threat model (see docs/SECURITY-ARCHITECTURE.md)
- [ ] Choose hosting and dedicated database; do not silently reuse an unrelated production database
- [ ] Authentication, session revocation, organization/project membership and role policies
- [ ] Database schema, row-level security, append-only audit logs, private storage and backup/restore
- [ ] Project/tenant isolation tests for allowed and denied operations
- [ ] Encrypted provider-token storage and secure server-side secrets
- [ ] Secure import pipeline with validation report, idempotency and source provenance
- [ ] CI secret scanning, dependency checks, integration tests and preview rollout

## Phase 2 — First verified live connector

- [ ] Choose a connector based on available account/API access
- [ ] Register the official developer application and configure OAuth
- [ ] Implement read-only analytics before publishing/write scopes
- [ ] Persist source, provider account ID, sync timestamp and API status
- [ ] Test data against provider UI/export and record metric caveats

Suggested first candidates should be selected based on access to the actual account and approval feasibility, not assumed support.

## Phase 3 — Diamond Restaurant evidence baseline

- [ ] Import actual Swiggy and Zomato Partner reports with column mapping reviewed
- [ ] Record baseline period before making menu/photo changes
- [ ] Fix P1 menu/photo/category issues in controlled batches
- [ ] Keep an event log of changes and their effective dates
- [ ] Compare equivalent time windows and flag confounding factors
- [ ] Build a factual case study only after enough comparable data exists

## Phase 4 — Marketing connectors

- [ ] Instagram/Facebook organic reporting
- [ ] Meta Ads Insights
- [ ] YouTube analytics
- [ ] Additional platform connectors one-by-one after API/permission verification

## Phase 5 — Publishing

- [ ] Drafts, approval flow and media storage
- [ ] Official provider publish endpoints
- [ ] Status reconciliation, idempotency and retry rules
- [ ] Publishing limits and account eligibility messaging
- [ ] Human confirmation for risky actions

## Phase 6 — AI & MCP

- [ ] Remote MCP server over HTTPS
- [ ] Authenticated, read-only project-scoped tools first
- [ ] Report retrieval, date comparison, data-quality explanation and top-post summaries
- [ ] Explicit project authorization and tests against cross-project data leakage
- [ ] Connect to each AI client only after its current remote MCP requirements are verified

## Phase 7 — Mobile app and forecast quality

- [ ] Responsive installable PWA using the same secured backend; no sensitive API-response caching
- [ ] Install and device-coverage tests across supported browsers
- [ ] Native React Native/Expo app only if requirements justify it after PWA

- [ ] Backtest forecast methods against historical holdout periods
- [ ] Report model error and data coverage
- [ ] Add intervals only when statistically justified
- [ ] Account for seasonality and platform-specific reporting delays
- [ ] Compare against simple baselines and suppress low-quality forecasts

## Release gates

Do not label a feature production-ready until its real external dependency is configured and tested. Never represent UI prototypes, imported records, unreviewed API support, forecasts or sample fixtures as live performance.
