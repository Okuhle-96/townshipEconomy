# Township Economy

Township Economy is a member-only community directory for local members, jobs, job seekers, and service providers. It uses a same-origin Node.js API and PostgreSQL for shared accounts and listings. The browser does not connect directly to PostgreSQL.

## Run locally

Requirements: Node.js 20+ and a PostgreSQL database.

1. Install packages with `npm install`.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL` to your PostgreSQL connection string and replace `SESSION_SECRET` with a random value of at least 32 characters. Keep `.env` private; never publish the database password.
4. If your PostgreSQL host requires TLS, set `PGSSL=true` and make sure Node trusts the host certificate.
5. Start the website with `npm start`, then open `http://localhost:3000`.

To enable password resets, create a Resend API key, verify the sender domain in Resend, and set `RESEND_API_KEY` and `RESEND_FROM_EMAIL` in `.env`. Set `APP_ORIGIN` to the exact origin used to open the site (for example `http://localhost:3000` locally or your HTTPS origin in production). Reset links expire after 30 minutes and work only once. The request response does not reveal whether an account exists; delivery/configuration failures are written to the server log.

### Windows local setup helper

If PostgreSQL 18 is installed locally, run `.\setup-local.ps1` in PowerShell from the project folder. It prompts for the local PostgreSQL `postgres` password without displaying it, creates a dedicated app role and database, and writes a private `.env` with a generated session secret. Then run `npm start` and open `http://localhost:3000`. If you already have a `.env`, the helper will not overwrite it.

The server creates the required tables from `schema.sql` on startup. It does not insert example listings. Members can create an account, sign in, browse the directory, and create, close/reopen, or delete their own listings. Old records saved by the previous file-only version are not deleted, but they are not automatically copied into PostgreSQL.

## Before public deployment

- Use HTTPS and set `NODE_ENV=production`, `APP_ORIGIN` to the exact HTTPS origin, and `COOKIE_SECURE=true`.
- Use a private PostgreSQL connection string and a database user with only the permissions the app needs.
- Configure backups and database monitoring.
- Add email verification before accepting public registrations. Email verification requires an email delivery provider and is not configured here.
- The in-memory sign-in rate limiter is intended for a single server process. Use a shared rate-limit store if deploying multiple instances.

## Checks

- `npm test` runs validation tests.
- `npm run check` checks the server JavaScript syntax.
