# Firebase Backend Setup (Supabase-free)

This project uses Firebase Authentication and Cloud Firestore for identity and data, with serverless API routes on Vercel. It intentionally does not use Supabase.

## Current status

The secure API scaffolding is committed, but a Firebase project has not been connected to this deployment. Until the required environment variables are configured:
- GET /api/health reports backendConfigured: false.
- GET /api/config returns a setup-required response.
- Authenticated data APIs cannot access a database.
- No social, advertising, Swiggy or Zomato account is connected.

Do not add credentials to GitHub files or paste them into chat.

## 1. Create a Firebase project

1. Open https://console.firebase.google.com/ and create/select a dedicated project for AJAYNXT Social Hub. Do not reuse a production project until its data, roles and billing are reviewed.
2. In Project settings, add a Web app and save its public web configuration.
3. In Authentication > Sign-in method, enable Google sign-in (or the chosen sign-in provider) and set the authorized domains for the actual deployment.
4. Create a Cloud Firestore database in production mode. Do not enable public read/write.
5. Storage is intentionally denied by default. Enable it only when private media upload/download endpoints are implemented.
6. Check the current Firebase plan and billing details before enabling paid products.

Official docs:
- Web setup: https://firebase.google.com/docs/web/setup
- Google sign-in: https://firebase.google.com/docs/auth/web/google-signin
- Firestore security rules: https://firebase.google.com/docs/firestore/security/get-started

## 2. Configure server credentials securely

Create a dedicated service account for the application backend using the least privilege needed to access the project's Firestore database and verify user tokens. Prefer managed identity or short-lived credentials when the hosting provider supports it.

For the current Vercel serverless implementation, the Admin SDK accepts service-account JSON through an encrypted server-side environment variable named FIREBASE_SERVICE_ACCOUNT_JSON. This secret must never appear in GitHub, the frontend, a public .env.example, reports, browser localStorage or logs.

In the Vercel project settings, configure these variables:
- FIREBASE_SERVICE_ACCOUNT_JSON — full service-account JSON, stored as a sensitive server environment variable.
- FIREBASE_API_KEY — public Firebase Web config value.
- FIREBASE_AUTH_DOMAIN — public Firebase Web config value.
- FIREBASE_PROJECT_ID — public Firebase Web config value; should match the server service account project.
- FIREBASE_APP_ID — public Firebase Web config value.
- FIREBASE_STORAGE_BUCKET and FIREBASE_MESSAGING_SENDER_ID — optional public config values if provided by Firebase.
- APP_ORIGIN — optional exact origin allowlist if cross-origin access is introduced. Prefer same-origin frontend/API deployment.

Redeploy the project after environment changes. Only public web config is returned by /api/config; the service-account JSON must never be returned.

## 3. Deploy database rules

With Firebase CLI installed and the correct project explicitly selected:

~~~bash
npm install -g firebase-tools
firebase login
firebase projects:list
firebase use YOUR_FIREBASE_PROJECT_ID
firebase deploy --only firestore:rules,firestore:indexes,storage
~~~

The current Firestore and Storage rules deny direct client data access. All database requests must go through the API routes, where Firebase ID tokens and project membership are verified. Firebase Admin SDK bypasses Firestore Rules, so server-side authorization and the service account IAM permissions are critical.

Official note about Admin SDK and rules: https://firebase.google.com/docs/firestore/security/rules-conditions

## 4. First sign-in / workspace bootstrap

The API creates an initial agency workspace after an authenticated user calls POST /api/workspaces. That workspace contains a Diamond Restaurant project. A second attempt for the same identity is rejected rather than silently creating a duplicate workspace.

The front end must obtain a Firebase ID token through the Firebase client SDK and send it as:
Authorization: Bearer <Firebase ID token>

Do not send passwords, provider tokens or service account JSON to these endpoints.

## 5. API endpoints

- GET /api/health — non-sensitive process/config readiness.
- GET /api/config — public Firebase Web configuration, or setup-required status.
- GET /api/workspaces — authenticated workspaces for the signed-in user.
- POST /api/workspaces — creates the user's initial agency workspace and Diamond Restaurant project.
- GET /api/projects?organizationId=... — list projects after membership validation.
- POST /api/projects?organizationId=... — create a project (owner/admin only).
- PATCH /api/projects/<projectId>?organizationId=... — rename/update project (owner/admin only).
- DELETE /api/projects/<projectId>?organizationId=... — soft-archive project (owner/admin only).
- GET /api/projects/<projectId>/metrics?organizationId=...&limit=... — authorized metrics read.
- POST /api/projects/<projectId>/imports — validated imports, max 300 observations per request; duplicates are rejected, not overwritten.
- GET /api/projects/<projectId>/reports?organizationId=... — data-coverage, 7-day comparisons and forecasts where complete history exists.

All handlers must return 503 setup status instead of pretending Firebase is connected when server credentials are absent.

## 6. Local checks

From the repository root:

~~~bash
npm install
npm test
npm run check:syntax
~~~

A syntax check does not prove that Firebase, auth, database access or production security is configured. Those require a real Firebase project and authorized sign-in tests.

## 7. Security checks before production

- Test unauthorized/no-token requests (401), wrong organization (404/403), and read-only roles attempting write operations (403).
- Verify Firestore direct client access is denied.
- Test that one user cannot read another user's project or metrics even if they guess IDs.
- Confirm service-account JSON never appears in frontend bundles, Git history, logs or report exports.
- Review project IAM, API quotas, Auth authorized domains, App Check strategy, data retention, backups and restore.
- Do not mark a platform integration connected until an actual official OAuth/API test has succeeded.
