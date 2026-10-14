# AJAYNXT Social Hub — low-cost deployment

## Architecture

The app uses Cloudflare Workers for APIs, Cloudflare D1 for shared data, and Firebase Authentication only for Google sign-in. No Supabase, Firebase Firestore, Firebase Admin SDK or Firebase Cloud Functions are required.

This can start at ₹0 while use remains inside free quotas. Current published limits include up to 100,000 Workers requests/day and D1 Free limits of 5 million rows read/day, 100,000 rows written/day and 5 GB total D1 storage, with a 500 MB maximum per free database. These are real limits, not unlimited scale. Check official pricing/limits before launch:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/d1/platform/pricing/
- https://firebase.google.com/docs/projects/billing/firebase-pricing-plans

Vercel Hobby is currently for personal, non-commercial use, so the older Vercel preview is not the production target for a future client/agency service:
- https://vercel.com/legal/terms

Do not enable paid services until their price and need are clear.

## Included in this repository

- Cloudflare Worker API with Firebase ID token validation.
- D1 database schema for organizations, memberships, projects, metric imports, draft content, sales, costs, integrations metadata, scheduled-post placeholders, reports and audit events.
- Project-scoped API authorization.
- Server-side Super Admin UID enforcement; only this UID can create or revoke platform Admin IDs.
- Admin Console at /admin.html.
- Financial reconciliation labelled revenue minus entered costs, NOT net profit.
- Installable PWA shell. Native app-store binaries are not built yet.

This is committed code, not a connected production deployment. No Cloudflare account or Firebase project was configured during this coding session. Social media, ads, Swiggy and Zomato are not connected; they need their own official permission flow and successful API test.

## 1. Firebase Google sign-in

1. Open https://console.firebase.google.com/ and create/select a dedicated AJAYNXT Social Hub project.
2. Use the no-cost Spark plan while relying only on free features; do not enable paid services just for sign-in.
3. Project settings > create a Web app. Copy the exact Project ID, API key, Auth domain and App ID.
4. Authentication > Sign-in method: enable Google.
5. Add the actual Cloudflare hostname to Authorized domains after deployment.
6. The Firebase Project ID configured in the Worker must match the project issuing your ID tokens.

Official guide: https://firebase.google.com/docs/auth/web/google-signin

## 2. Clone and install on the MacBook

Open Terminal:

~~~bash
git clone https://github.com/ajaynxt/ajaynxt-superapp.git
cd ajaynxt-superapp
npm install
cp .dev.vars.example .dev.vars
~~~

Edit .dev.vars with the actual Firebase Web app settings. The file is ignored by Git; never commit or share it.

Run checks:

~~~bash
npm run build
npm run check:syntax
npm test
~~~

## 3. Create D1

In the project directory:

~~~bash
npx wrangler login
npx wrangler whoami
npx wrangler d1 create ajaynxt-social-hub
~~~

Cloudflare returns a real database ID. Replace the all-zero placeholder in wrangler.jsonc with the exact returned ID. Never guess this value.

Apply the schema:

~~~bash
npm run db:migrate:remote
~~~

Wrangler records which migrations have run. Do not manually reapply an already applied migration.

## 4. Configure remote Worker secrets

Set these exact Firebase Web values as encrypted Cloudflare Worker secrets:

~~~bash
npx wrangler secret put FIREBASE_PROJECT_ID
npx wrangler secret put FIREBASE_API_KEY
npx wrangler secret put FIREBASE_AUTH_DOMAIN
npx wrangler secret put FIREBASE_APP_ID
~~~

Optionally set FIREBASE_STORAGE_BUCKET and FIREBASE_MESSAGING_SENDER_ID if Firebase provides them. The current app does not use a Firebase service-account private key.

For local testing, put the same values in the ignored .dev.vars file. Do not add the owner UID until you have copied it from Firebase Authentication.

## 5. Deploy and configure the sole Super Admin

~~~bash
npm run deploy
~~~

Wrangler prints the site hostname under workers.dev.

1. Copy the deployed hostname into Firebase Console > Authentication > Settings > Authorized domains.
2. Open the site and use Sign in to sync with your own Google account. At first, workspace creation is blocked because no Super Admin UID has been configured yet. This is intentional.
3. Open Firebase Console > Authentication > Users and copy the exact UID for your personal owner account.
4. In Terminal run:

~~~bash
npx wrangler secret put AJAYNXT_SUPER_ADMIN_UID
~~~

Paste that exact UID when prompted. Never use an email, display name, guessed ID or another user's UID.
5. Reload the deployed app and sign in/sync again. Visit /api/health; ownerAccessConfigured should be true.
6. Open /admin.html. The first valid owner initialization creates your workspace and the default Diamond Restaurant project.

Super Admin status is checked by server-side UID on every privileged request; it is not merely a hidden UI button. There is no client-side owner bypass.

## 6. Create/revoke Admin IDs

Each staff/client user must sign into the app once using Google first. Then, in /admin.html as the configured owner:
- Enter a registered user's email in Platform Admin IDs to create an AJN-ADM-XXXXXXXX identifier.
- Revoke Admin access using the Revoke control. The API also revokes their workspace memberships with role admin.
- Use Workspace Members to assign client_viewer, analyst, operator or admin.
- The admin workspace role is only available to someone with an active platform Admin ID.

Only the configured Super Admin UID can create/revoke platform Admin IDs. Other Admins cannot promote themselves or create another Admin ID. These IDs are access records, not passwords; Google sign-in is still required.

## 7. Current routes and data rules

- /api/health reports service/config health, not external account connection.
- /api/config returns only public Firebase Web settings.
- /api/workspaces and /api/projects list and manage the user's authorized workspace/projects.
- /api/projects/:id/imports and /api/projects/:id/metrics import/read project metrics with duplicate protection.
- /api/projects/:id/reports creates comparisons only with 14 complete consecutive days and trend estimates only with 28 complete consecutive days.
- /api/projects/:id/drafts syncs draft content across devices. It does not publish posts.
- /api/projects/:id/sales, /costs and /financial-report store/reconcile actual financial inputs. Revenue minus recorded costs is not net profit.

No social/ad/marketplace integration should show Connected until official OAuth approval, account authorization and a real provider API test all succeed. The current integrations catalogue is not an active integration.

## 8. Install the PWA

After HTTPS deployment:
- Android: open in Chrome and choose Install app/Add to Home Screen.
- iPhone: open in Safari > Share > Add to Home Screen.

This installs the web app shell, not an App Store or Play Store binary. The service worker does not cache API responses, reports, auth or Admin Console data.

## 9. Before using client data

Run build, syntax and unit tests. Verify no-token requests return 401; unapproved users cannot create/revoke Admin IDs (403); revoked users lose access; and cross-workspace IDs cannot read data. Check backups, retention and delete/restore workflows. Free quotas can stop requests at their limit. Treat user-imported data as unverified until it is reconciled with source reports/invoices.
