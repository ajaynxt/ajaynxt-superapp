# AJAYNXT Social Hub — Security Architecture

## Status

This is a design specification, not proof of production security. The current deployed MVP is a static browser-side prototype with local storage. It has no authenticated backend, shared database, encrypted OAuth tokens, live social integrations or hosted MCP endpoint. Do not store sensitive client data or secrets in the preview.

## Trust boundaries

- Web/PWA/native client: UI and safe inputs only; no provider secrets, refresh tokens, service-role keys or AI provider API keys.
- Application backend: authenticated APIs, authorization, validation, OAuth callbacks, connector orchestration and report generation.
- Database: organizations, memberships, projects, connections, metric definitions, observations, posts, reports and audit events, all scoped to the authorized tenant.
- Secret store: provider credentials and encrypted OAuth tokens; use a managed secret store and KMS-backed encryption where available.
- Background workers: scheduled sync, reports and publishing jobs with retries, quota limits and idempotency.
- MCP server: authenticated, project-scoped, read-only reporting tools first.

## Multi-tenant data model

Recommended entities: users, organizations, organization memberships, projects, project memberships, integration connections, metric definitions, metric observations, sync runs/errors, media assets, content posts, publishing jobs, approval events, reports, report exports and audit events.

Resolve project/org access from authenticated memberships, not a browser-provided ID or name. Store project, provider/account, date, metric definition/unit, value, source and sync/import timestamps for each observation.

## Roles

- Owner: workspace, member access, configuration and owner-only destructive operations.
- Administrator: manage authorized projects, connections, reports and content setup.
- Operator: media, drafts and approved publishing workflow.
- Analyst: analytics and report generation.
- Client viewer: read only assigned projects and approved reports.

Verify identity and project membership in every backend route and job. Hiding a button is not authorization. Use PostgreSQL row-level security as defense in depth, not as a replacement for server-side checks.

## Authentication and sessions

Use a maintained authentication provider/library; do not invent cryptography. Support recovery, session revocation and MFA for privileged roles. Use secure HttpOnly SameSite cookies for browser sessions where appropriate and OS secure storage for native app credentials. Validate sensitive reads and all writes server-side. Protect OAuth callbacks with state validation, PKCE where supported and strict redirect allowlists. Rate-limit login, recovery and sensitive routes.

## Secrets and OAuth

- Never put secrets in frontend code, public environment variables, source control, browser storage, logs or exports.
- Store provider credentials in server-side secrets; encrypt stored tokens using managed KMS/envelope encryption.
- Request minimum OAuth scopes; begin with read-only permissions.
- Track expiry, refresh, revocation and reconnect-required state.
- Redact tokens, authorization headers and webhook signatures from logs.
- Disconnecting an account must revoke/delete credentials as applicable and create an audit event.

## Connector, plugin, webhook and import safety

- Treat external API responses, CSVs, webhooks, MCP results and plugin manifests as untrusted input.
- Prefer reviewed declarative connector manifests and server-side adapters. Never execute arbitrary uploaded plugin code in the main app.
- For custom remote endpoints, require HTTPS; restrict outbound hosts where possible; block loopback, private and link-local IPs; restrict redirects, timeouts and response sizes; defend against DNS rebinding and SSRF.
- Validate schemas, MIME types, file size and dates server-side.
- Verify webhook signatures/timestamps and reject replayed events.
- Add per-user/project/provider limits, retries, concurrency caps and circuit breakers.
- Keep publishing, deletion and advertising-budget changes disabled until separately reviewed and explicitly confirmed.

## Database, storage and web security

- Enable RLS on every exposed table and write operation-specific policies.
- Base access on server-controlled memberships, not editable user metadata.
- Never expose database service-role keys to the browser.
- Keep media private; use short-lived project-scoped signed URLs and restrict upload types/sizes.
- Add Content Security Policy, HSTS, secure headers, output escaping, CSRF protections where applicable, strict CORS and request validation.
- Pin dependencies, commit lockfiles, scan dependencies/secrets, and separate staging from production.
- PWA service worker must not cache private reports or authenticated API responses.
- Maintain backup/restore, export, retention, deletion and incident-response procedures.

## Audit and monitoring

Log sign-ins, authorization failures, role changes, provider connect/disconnect, OAuth errors, imports/exports, publish requests, approval decisions, AI/MCP report access and administrative actions. Logs must not contain secrets and should be append-only to ordinary application roles. Alert on unusual exports, repeated auth failures, token refresh failures and quota exhaustion.

## Mandatory tests before production

- Cross-organization/project allow/deny tests for every important resource.
- RLS tests for SELECT/INSERT/UPDATE/DELETE with authorized and unauthorized users.
- OAuth state/redirect/PKCE, token-refresh and revocation tests.
- CSV malformed-file, duplicate, invalid-date, rollback and large-file tests.
- Webhook signature, replay and idempotency tests.
- SSRF, XSS, CSRF, rate-limit and file-upload tests.
- MCP isolation tests proving users cannot read other projects' reports, posts or credentials.
- Publishing retry, duplicate, expired-token and provider-limit tests.
- Backup restore, disconnect, offboarding and deletion tests.

## Official references

- Next.js authentication: https://nextjs.org/docs/app/guides/authentication
- Supabase Row Level Security: https://supabase.com/docs/guides/database/postgres/row-level-security
- Supabase product security: https://supabase.com/docs/guides/security/product-security
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/

A feature is not production-ready until implementation and relevant tests pass. A deployed page, UI label or imported CSV does not prove security or provider integration.
