# D1 migrations

Apply local migrations with `npm run db:migrate:local` and remote migrations with `npm run db:migrate:remote` after replacing the placeholder database ID in `wrangler.jsonc`.

Migrations are append-only after they have been applied remotely. Add a new numbered SQL file rather than editing a migration already deployed.
