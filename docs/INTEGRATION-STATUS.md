# Integration Status and Verification Gates

## Current live status in this repository

**No external platform is connected.** The integration page is a catalogue, not proof of OAuth or API access. All integrations are labelled not connected or import required. A button in this MVP does not establish a connection.

| Provider / channel | Current MVP behavior | Verification required before live support |
|---|---|---|
| Instagram Professional | Catalogue only | Official API product, account type, scopes, app review, supported insights and publishing formats |
| Facebook Pages | Catalogue only | Page authorization, Graph API permissions, supported insights and publishing features |
| Threads | Catalogue only | Official API scopes, insights, publishing capabilities and account eligibility |
| YouTube | Catalogue only | Google OAuth, YouTube Data/Analytics API enablement and owner authorization |
| LinkedIn | Catalogue only | API product approval, organization permissions, analytics and publishing access |
| Pinterest | Catalogue only | App access, business-account authorization, endpoint permissions and quota |
| TikTok | Catalogue only | Product access, account eligibility, posting/analytics API scopes and any applicable audit/review |
| X | Catalogue only | Current API access tier, price/limits, account scopes and allowed data use |
| Snapchat | Catalogue only | Relevant Public Profile/Ads product access and supported reporting data |
| Reddit | Catalogue only | OAuth/API access, approved use case, current data limits and content policy |
| Bluesky | Catalogue only | App-password/OAuth model, API behavior and reporting availability |
| Mastodon | Catalogue only | Instance-specific server capabilities, auth and available metrics |
| Meta Ads | Catalogue only | Meta app configuration, ad-account authorization, required permissions, Insights fields, attribution windows and rate limits |
| Google Ads | Catalogue only | Google Ads API access, OAuth, developer-token approval, customer access and field compatibility |
| TikTok Ads | Catalogue only | Business API access, advertiser authorization and reports endpoints |
| LinkedIn Ads | Catalogue only | Marketing API access, campaign permissions and reporting endpoints |
| Pinterest Ads | Catalogue only | Business API approval, advertiser access and reporting endpoints |
| Google Business Profile | Catalogue only | Eligible verified profile, OAuth, API enablement and supported performance metrics |
| Google Analytics 4 | Catalogue only | OAuth, Analytics property access, metric metadata and reporting scope |
| Swiggy | Manual/CSV import path only | Obtain actual Partner exports or written/official API access; confirm data grain, definitions and access terms |
| Zomato | Manual/CSV import path only | Obtain actual Partner exports or written/official API access; confirm data grain, definitions and access terms |
| WhatsApp Business | Catalogue only | Business Platform app setup, phone-number authorization, webhooks and metrics availability |

## Implementation rule

For each connector:
1. Cite the current official developer documentation in the implementation ticket.
2. Confirm the product/endpoint, exact OAuth scopes and terms for intended use.
3. Verify app review requirements, quotas, billing and data-retention rules.
4. Request least-privilege permissions and use server-side OAuth/token management.
5. Implement a read-only connection and fetch real account data first.
6. Record a last-sync time, provider response status and data provenance.
7. Add publishing/write capabilities only after separate review and explicit authorization.
8. Mark the connector live only after end-to-end tests with an actually authorized account succeed.

## References for initial API review

- YouTube Analytics API: https://developers.google.com/youtube/analytics/reference
- Google Analytics Data API: https://developers.google.com/analytics/devguides/reporting/data/v1/rest
- Meta Marketing API Insights: https://developers.facebook.com/docs/marketing-api/insights/
- Instagram Platform: https://developers.facebook.com/docs/instagram-platform/
- Threads API: https://developers.facebook.com/docs/threads/
- Pinterest API: https://developers.pinterest.com/docs/api/v5/
- TikTok for Developers: https://developers.tiktok.com/
- X API: https://docs.x.com/
- LinkedIn Developers: https://learn.microsoft.com/en-us/linkedin/
