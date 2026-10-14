# Firebase Authentication configuration

Firebase is used only for Google sign-in in the current Cloudflare Workers + D1 architecture. The application does not use Firebase Firestore, Firebase Admin SDK or Firebase Cloud Functions.

Follow docs/CLOUDFLARE-SETUP.md for end-to-end setup and deployment. Never commit configuration secrets to this repository.

After the owner's first Google sign-in, configure AJAYNXT_SUPER_ADMIN_UID as an encrypted Cloudflare Worker secret using the exact UID from Firebase Authentication. Only that server-side UID is allowed to create or revoke platform Admin IDs.

Official Google sign-in guide:
https://firebase.google.com/docs/auth/web/google-signin
