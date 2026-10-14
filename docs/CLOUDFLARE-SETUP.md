# AJAYNXT Social Hub — lowest-cost setup

## Architecture and cost target

The current codebase uses Cloudflare Workers + D1 database for the API and shared project data, and Firebase Authentication only for Google sign-in. It does not use Supabase, Firestore or Firebase Cloud Functions.

It can start at ₹0 while usage remains within the providers' free quotas. The currently published Cloudflare Workers Free plan includes up to 100,000 requests per day; D1 Free includes 5 million rows read/day, 100,000 rows written/day and up to 5 GB total D1 storage across databases, with a 500 MB maximum database size. These are enforceable limits, not unlimited capacity. Confirm current terms and quotas before deployment:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/d1/platform/pricing/
- https://firebase.google.com/docs/projects/billing/firebase-pricing-plans

Vercel Hobby is currently defined for personal, non-commercial use, so the older Vercel preview should not be the production hosting plan for a future client/agency service:
- https://vercel.com/legal/terms

Do not activate paid add-ons until the exact cost and need are known.

## What is in the repository

- Cloudflare Worker API with Firebase ID-token verification.
- D1 schema for organizations, memberships, multiple projects, metrics, draft content, sales, costs, integrations metadata, scheduled-post placeholders and audit events.
- Project-level authorization on API routes.
- Super Admin gate enforced by the server using the configured Firebase UID. Only that UID can create/revoke platform Admin IDs.
- Private Admin Console at /admin.html.
- Project-specific CSV imports, duplicate protection, growth reports and cautious trend estimates.
- Financial data entry/reconciliation that labels revenue minus entered costs as NOT net profit.
- Installable PWA shell. Native iOS/Android app binaries are not built yet.

This code is committed to GitHub, but has NOT been connected to the user's Cloudflare account or Firebase project from this session. No real social, ads, Swiggy or Zomato connection is active. Those integrations need their own official permissions and successful tests.

## 1. Create Firebase Authentication

1. Go to https://console.firebase.google.com/ and create/select a dedicated AJAYNXT Social Hub project.
2. Keep it on the no-cost Spark plan while only using no-cost features. Do not enable paid Firebase products just to make the app sign in.
3. In Project settings, create a Web app. Copy the exact Firebase Web App values: Project ID, API key, Auth domain and App ID.
4. In Authentication > Sign-in method, enable Google sign-in.
5. Authorized domains will be updated after the first Cloudflare deployment.
6. Keep this Firebase Project ID identical to the issuer project ID expected by the Worker.

Official guide: https://firebase.google.com/docs/auth/web/google-signin

## 2. Clone and install on the MacBook

Open Terminal and run:

~~~bash
git clone https://github.com/ajaynxt/ajaynxt-superapp.git
cd ajaynxt-superapp
npm install
cp .dev.vars.example .dev.vars
~~~

Edit .dev.vars with the actual Firebase web configuration for local development. This file is ignored by Git. Do not commit it or send it in a screenshot.

Run the build and test suite:

~~~bash
npm run build
npm run check:syntax
npm test
~~~

## 3. Create the Cloudflare database

1. Create/sign in to a Cloudflare account at https://dash.cloudflare.com/.
2. From the project folder, install/login through Wrangler:

~~~bash
npx wrangler login
npx wrangler whoami
npx wrangler d1 create ajaynxt-social-hub
~~~

3. Wrangler prints a real database ID. Replace the placeholder value in wrangler.jsonc under d1_databases with that exact ID. Never guess or reuse a made-up ID.
4. Apply the schema:

~~~bash
npm run db:migrate:remote
~~~

Wrangler tracks the migrations it has applied. Do not apply the same migration manually a second time.

## 4. Configure Worker environment values

For development, edit the ignored .dev.vars file. For remote deployment, set the values using Cloudflare's encrypted Worker secrets:

~~~bash
npx wrangler secret put FIREBASE_PROJECT_ID
npx wrangler secret put FIREBASE_API_KEY
npx wrangler secret put FIREBASE_AUTH_DOMAIN
npx wrangler secret put FIREBASE_APP_ID
~~~

Use the exact values copied from the Firebase Web app. Optional values can also be set if Firebase provided them:

~~~bash
npx wrangler secret put FIREBASE_STORAGE_BUCKET
npx wrangler secret put FIREBASE_MESSAGING_SENDER_ID
~~~

Do not configure a Firebase service-account private key. This architecture does not need Firebase Admin SDK credentials. Public Firebase web config is returned by /api/config to initialise the browser SDK; it is not an admin credential.

APP_ORIGIN is optional. If you set it, use the exact browser origin that should call the API, including scheme, and keep local development and production origins distinct.

## 5. Deploy, allow the domain, then set the Super Admin

Deploy only after inserting the actual D1 ID and configuring the Firebase values:

~~~bash
npm run deploy
~~~

Wrangler prints the deployed Worker URL, normally under workers.dev. Copy its hostname.

1. In Firebase Console > Authentication > Settings > Authorized domains, add the exact deployed hostname.
2. Open the site on that hostname and click Sign in to sync. Sign in with your own Google account. On the first pass, the API will record the signed-in user but will refuse workspace creation until the owner UID allowlist is set. This is an intentional fail-closed security step.
3. In Firebase Console > Authentication > Users, copy the exact UID of your own account.
4. Back in Terminal, run:

~~~bash
npx wrangler secret put AJAYNXT_SUPER_ADMIN_UID
~~~

Paste your exact Firebase UID when prompted. Do not use your email, display name, another person's UID or a guessed value.
5. Reload the app, click sign in/sync again, and check /api/health. ownerAccessConfigured should be true.
6. Open /admin.html and verify that the console identifies you as the owner and displays your workspace. The first successful workspace initialization creates the default Diamond Restaurant project.

There is no client-side Super Admin bypass. If you deliberately change the owner account later, update the secret through an authorized Cloudflare deployment session.

## 6. Admin IDs and staff/client access

Each person who will be added must first sign in to Social Hub once using Google, so their Firebase identity is present in the app user directory.

From /admin.html, while signed in with the configured owner account:
- Create Admin ID: enter the registered user's email. The API creates an AJN-ADM-XXXXXXXX identifier.
- Revoke: disable the selected Admin ID. Their organisation Admin memberships are revoked by the backend as well.
- Workspace Members: grant an existing user client_viewer, analyst, operator or admin access. The admin role is permitted only if a platform Admin ID already exists.

Only AJAYNXT_SUPER_ADMIN_UID can create/revoke platform Admin IDs. Admins cannot add or promote other Admins. Owner privilege is checked by the Worker on every privileged request, not by hiding a button in the page. The IDs are access records, not passwords; Google sign-in remains the authentication method.

## 7. Important routes and truthfulness rules

- /api/health: deployment/configuration health; not proof of third-party connections.
- /api/config: public Firebase Web App configuration only.
- /api/workspaces: authenticated workspace list.
- /api/projects: project CRUD with workspace membership enforcement.
- /api/projects/:id/imports and /api/projects/:id/metrics: project-scoped observations, duplicate rejection and reads.
- /api/projects/:id/reports: comparison/forecast only when the needed consecutive history exists.
- /api/projects/:id/drafts: cross-device saved draft notes, not published posts.
- /api/projects/:id/sales and /api/projects/:id/costs: actual manual/imported finance records.
- /api/projects/:id/financial-report: revenue less recorded costs, NOT net profit.
- /api/admin/admins: owner-only platform Admin ID operations.
- /api/admin/members: owner-only workspace role operations.

No social platform, ad account, Swiggy or Zomato account should be marked connected until an official OAuth flow is implemented, authorization succeeds, and a test reads the expected provider resource. Current integration cards are a catalogue, not a live connection.

## 8. PWA install

Once deployed over HTTPS, Android users can open the site in Chrome and use Install app/Add to Home Screen. iPhone/iPad users can open the site in Safari and use Share > Add to Home Screen. This provides an installable web app, not a native App Store/Play Store binary.

The service worker does not cache API responses, reports, account credentials or the Admin Console. When offline, a fresh API read/write will not work.

## 9. Production safety checklist

Before uploading sensitive client data:
- Run npm test, npm run check:syntax and npm run build in CI.
- Verify no-token requests return 401.
- Verify an unapproved Google account cannot create/revoke Admin IDs (403).
- Revoke a test membership and confirm cross-project reads immediately fail.
- Check that D1 project foreign keys, unique indexes and migration state match expectations.
- Review backups/restore, user deletion and audit retention.
- Monitor Worker and D1 quota usage. Free quotas can halt operations at their limits.
- Treat manual CSVs and financial entries as unverified until reconciled with original reports/invoices.
- Implement actual OAuth connectors and scheduled publication only after each provider's current API permissions/terms are verified.
