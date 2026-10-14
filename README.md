# AJAYNXT Social Hub

Project-based social media, advertising and marketplace reporting foundation for AJAYNXT.

## Current build status

This repository currently contains a **browser-only MVP foundation**, not a production SaaS product. The index.html interface includes:

- Project workspaces, beginning with **Diamond Restaurant**
- Local project switching, create and rename
- Integration catalogue for social networks, ads, Google Business/Analytics, Swiggy and Zomato
- CSV import for real user-provided daily metric observations
- Data coverage and source reports
- Seven-day period growth comparisons when the required consecutive history exists
- Seven-day linear-trend point estimates when 28 consecutive daily observations exist
- CSV/JSON exports, print-to-PDF, project-local content drafts and developer connector notes

## Strict data integrity rules

- No demo sales values, fake account connections or synthetic growth percentages are included.
- Integrations are **not connected** until the official OAuth/API connector exists and a real connection test succeeds.
- Swiggy/Zomato figures must come from actual Partner reports/exports unless verified direct access is implemented later.
- Uploaded CSV records are user-provided and are **not independently verified** by this front-end.
- Missing dates are not assumed to be zero.
- Comparisons and projections display only when the required data coverage exists.
- A trend projection is an estimate, not a guarantee and not proof that a change caused growth.

## Run locally

This is a static single-page app; no package installation is required for the interface.

~~~bash
python3 -m http.server 8080
~~~

Open http://localhost:8080.

## Import CSV format

Required columns:

~~~csv
date,project,platform,metric,value,source
~~~

One row per date + project + platform + metric. Use dates in YYYY-MM-DD format, non-negative numeric values, and project names that match a workspace exactly. The source column is optional; include it to identify the actual report/export source.

Examples of metric names include orders, revenue_inr, impressions, views, clicks, followers. Use consistent definitions and units throughout each series. Do not rename metrics in ways that change their meaning.

## Forecast methodology

See [Reporting Methodology](docs/REPORTING-METHODOLOGY.md). The current projection is a simple linear-trend point estimate from 28 consecutive daily observations. It is not seasonally adjusted, does not compute a confidence interval, and must not be presented as guaranteed future performance.

## Integration reality

See [Integration Status](docs/INTEGRATION-STATUS.md). This MVP does **not** implement social OAuth, API sync, ad account sync, direct Swiggy/Zomato access, real publishing, central database/authentication or remote MCP hosting.

## Production prerequisites

Before using real client data in a hosted production service, build and test:
1. Authenticated backend and server-side project isolation.
2. Database, row-level security, audit logs and backup/restore.
3. Encrypted server-side OAuth token storage and refresh.
4. Official API connectors, verified scopes, platform app reviews and rate-limit handling.
5. Source sync jobs, last-sync/error states and data validation.
6. Real post scheduling/publishing with retries and status reconciliation.
7. Secure read-only MCP tools, user authentication and project-level authorization.

Never commit API keys, OAuth tokens, secrets, customer personal data, or provider credentials to this repository or browser storage.


## Product and security specifications

- [Full product scope, reporting, plugins and mobile app plan](docs/PRODUCT-SCOPE.md)
- [Security architecture and launch gates](docs/SECURITY-ARCHITECTURE.md)
