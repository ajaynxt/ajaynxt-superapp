# AJAYNXT Social Hub — Security Architecture

## Deployment status

This document describes committed Cloudflare Worker + D1 code and required controls. It is not proof of a production security audit. The code has not yet been deployed into the owner's Cloudflare account or configured with the real Firebase project, D1 database ID or Super Admin UID.

## Security boundaries

- Identity: Firebase Authentication Google sign-in. Worker verifies Firebase ID tokens server-side against issuer, audience and Google's Secure Token signing keys.
- API/data: Cloudflare Worker routes use D1 binding on the server. The browser never connects directly to D1.
- Tenant isolation: users gain access to an organization through an active org_members row. Project routes validate that the project belongs to the requested organization before reading or writing.
- Super Admin: platform privileges are restricted to an exact AJAYNXT_SUPER_ADMIN_UID Worker secret. A browser flag, email address, localStorage value or Admin ID string alone cannot confer Super Admin privileges.
- Admin IDs: only the configured Super Admin UID can create/revoke platform Admin IDs. Revoking Admin access also revokes workspace memberships with role admin. All such events are written to the audit log.
- Secrets: Worker secret values remain server-side. The Firebase Web config exposed from /api/config is public client configuration, not an admin credential.
- Browser: service worker only handles safe static shell assets; it bypasses API paths and the Admin Console. Authentication state or report responses are not cached by the service worker.
- Imports: request size, record count, dates, metric names and values are validated. Duplicate observations are rejected rather than overwritten. Imported records are marked unverified by default.
- Finance: source records are not assumed to be verified. Report labels explicitly distinguish revenue minus entered costs from net profit.
- Errors: API responses do not expose stacks or database error details.

## Roles

- owner: workspace owner. Only the configured platform Super Admin UID has platform-wide Super Admin powers.
- admin: workspace project management. Must already have a platform Admin ID. Cannot create/revoke other platform Admin IDs.
- operator: content/data operations.
- analyst: read/report access.
- client_viewer: read-only access.

## Data model

D1 migration 0001 includes users, organizations, org_members, projects, metrics, platform_admins, audit_events, content_drafts, scheduled_posts, integration_connections, sales_observations, business_costs and reports. Project data carries organization and project scope; tenant checks are implemented server-side.

## Owner onboarding

1. Owner deploys Worker and D1 under their own Cloudflare account.
2. Owner signs in via Google once, so their Firebase UID is recorded.
3. Owner copies the exact Firebase UID from Authentication > Users and stores it in the AJAYNXT_SUPER_ADMIN_UID Worker secret.
4. Workspace initialization and platform admin routes remain unavailable until the matching UID is configured.
5. Every privileged request rechecks that server-side allowlist.
6. A platform Admin ID can be issued only to a user who has already authenticated with Google once.

## Release gates before storing sensitive client data

- Run automated tests and verify the deployed Worker build and D1 migration.
- Confirm missing/invalid ID tokens return 401 and wrong-org/project requests are denied.
- Confirm an unapproved UID cannot create/revoke Admin IDs, and cannot add an Admin workspace role.
- Revoke a test Admin and prove that all admin project membership is removed.
- Test requests against another workspace's IDs; no result or write must leak across tenants.
- Review CSRF/origin policy, rate limiting, abuse controls and provider OAuth state/PKCE when implementing social connections.
- Add controlled invite/onboarding rather than relying solely on a user's first sign-in.
- Review backups, restore tests, export/delete workflows and audit-event retention.
- Review Cloudflare quota monitoring. Free-tier limits can stop requests once exhausted.
- Review third-party scopes and token encryption before storing provider tokens. No provider OAuth token store has been implemented yet.
- Do not claim integration, social publishing, ad ROAS or marketplace data unless the provider authorization and API response are real and tested.
