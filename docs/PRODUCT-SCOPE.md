# AJAYNXT Social Hub — Product Scope and Mobile App Plan

## Goal

A low-cost, multi-project workspace first used personally by the platform owner for Diamond Restaurant, then expanded to client projects. The same authenticated Worker API and D1 data model are intended to support the web/PWA and future AI clients through carefully scoped APIs.

## Current architecture

- Web/PWA: existing responsive Social Hub single-file frontend, installable manifest and static-shell service worker.
- API: Cloudflare Workers.
- Database: D1 via append-only SQL migrations.
- Authentication: Firebase Authentication for Google sign-in only.
- Owner control: secret AJAYNXT_SUPER_ADMIN_UID is the only platform Super Admin gate.
- Cost target: use free quota tiers first; inspect actual usage before any paid upgrade.

The repository has not yet been connected to the owner's cloud accounts. Deployment, D1 creation, Firebase Authorized Domains and actual owner UID are remaining setup steps.

## Tenant and role model

One owner workspace can contain multiple business/client projects. Each project can hold source metrics, drafts, sales/cost observations, reports and integration metadata, scoped by organization/project membership.

Roles: owner, admin, operator, analyst and client_viewer. Only the configured Super Admin UID can create/revoke platform Admin IDs. An existing platform Admin can be granted workspace admin access; that does not make them a Super Admin. Staff/client users must authenticate once before their records can be added through the current Admin Console.

## Working code in repository

- Worker authentication and project/workspace authorization.
- Project create/update/archive/list endpoints.
- Project metric import/read endpoints with duplicate checks and source-verification flags.
- Growth comparison based on complete 14-day windows and 7-day trend estimates requiring 28 consecutive daily observations.
- Draft create/list/archive endpoints designed for cross-device sync.
- Sales/cost entry endpoints and currency-grouped revenue-minus-recorded-costs report.
- Owner-only Admin Console UI and server APIs to create/revoke Admin IDs and add/revoke workspace members.
- Installable PWA shell and CI workflow for build, syntax and unit checks.

## Not yet implemented or verified

- Actual Cloudflare deployment and production database.
- Mobile native iOS/Android binaries.
- Social/media/ads/marketplace OAuth and official API connectors.
- Live social publishing and scheduled posting workers. Current draft feature is draft-only.
- Media upload service, malware scanning, asset access controls and encrypted OAuth-token lifecycle.
- Production hardening such as rate limiting, abuse controls, App Check/reCAPTCHA strategy as needed, incident alerts, restore drills and security audit.
- Connectors to ChatGPT/Gemini/Claude/Grok through OAuth/MCP/API. Future connectors must use the same backend, scoped permissions, per-client authorization and server-side secrets, not expose database/provider tokens directly.

## Planned integration catalogue

Social: Instagram, Facebook Pages, Threads, YouTube, LinkedIn, Pinterest, TikTok, X, Snapchat, Reddit, Bluesky, Mastodon.
Business/reporting: Google Business Profile, GA4, Meta Ads, Google Ads, WhatsApp Business.
Marketplaces: Swiggy and Zomato report imports/API if an official authorized program is available.
Other: CSV upload, POS exports, web analytics, invoices and expense data.

This is a target catalogue, not a claim of live support. Every connector needs current API permission review, client consent, successful test reads, data freshness tracking and revocation handling.

## Data truth and financial reporting

Missing observations are never filled with zero. Comparisons/forecasts show only when their complete windows exist. Projections are estimates, not guarantees. User imports remain unverified until reconciled with the source. Reported revenue is not profit. Revenue minus recorded costs is not net profit unless all expenses, taxes, commissions, refunds and adjustments are included and verified.

## Mobile approach

Ship a responsive PWA for early personal use to avoid duplicating backend or app cost. Native store binaries can be evaluated only after the real backend and account connectors have been tested in actual use.

## Privacy/security principles

- Never store tokens, private keys or admin secrets in browser storage or Git.
- Every project read/write is authorized by the server.
- Keep tenants isolated, log privileged actions and minimize data retention.
- Integrations show disconnected/pending/error until confirmed by a real provider response.
