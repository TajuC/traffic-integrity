# Google Ads operations

These settings live in Google Ads, not in the code. Menu names below were checked against Google's help pages in October 2026; Google reorganizes the interface from time to time, so search the help center for the quoted label if a path has moved.

## What the website cannot do

Google records and bills an ad click before the browser reaches your server. Blocking or challenging the visitor afterwards does not undo the charge. The application can only make abuse harder, keep fake leads out of your conversion data, and give you the evidence for exclusions and invalid traffic investigations. Credits for invalid clicks come from Google's own systems or from an investigation you request.

## Keep click identifiers intact

1. Confirm auto-tagging is on: Admin, Account settings, Auto-tagging, "Tag the URL that people click through from my ad". It is on by default for new accounts.
2. Google appends `gclid`, and on iOS traffic `gbraid` or `wbraid`, plus the aggregate parameters `gad_source` and `gad_campaignid`, to the final URL before any `#` fragment. Every redirect between the ad and the landing page, including `http` to `https`, `example.com` to `www.example.com` and language redirects, must keep the full query string.
3. Test by clicking one of your own ads and checking that the landing URL still carries the parameters and that the application logged a `paid_visit` event with the campaign id.

## Optimize on qualified leads only

Smart Bidding learns from the conversion actions marked as primary. If a form submit or a page view is primary, anyone who can submit forms can teach the bidding to buy more of their traffic.

1. Create a conversion action for imported conversions from clicks and name it exactly like `CONVERSION_ACTION_NAME` (default `Qualified lead`). Make it the primary action for the campaigns' goal.
2. Keep any website tag action (for example the one fired by `TrafficIntegrity.protectForm`) as secondary, so it is reported but not used for bidding. The form helper only fires it for server-trusted leads and sends the server conversion id as `transaction_id`, which Google uses to deduplicate.
3. Schedule the import: Goals, Conversions, Uploads, Schedules. Choose HTTPS as the source, enter `https://your-domain/_ti/admin/conversions.csv` with `EXPORT_USERNAME` and `EXPORT_PASSWORD`, and a daily frequency. The file follows the "Conversions from clicks" layout with a `Parameters:TimeZone` row, includes only qualified conversions that have a `gclid`, and uses the conversion id as Order ID, so repeated imports do not double count.
4. If you enable enhanced conversions for leads, scheduled uploads must contain pre-hashed email and phone values in the enhanced template. `/_ti/admin/conversions.json` provides SHA-256 values normalized the way Google requires (lowercase, trimmed, dots and plus suffixes removed for gmail.com and googlemail.com, phones in E.164 when `PHONE_COUNTRY_CODE` is set). Download the matching template from Uploads, View templates, rather than guessing its columns. The JSON export also lists `gbraid` and `wbraid` conversions, which can be uploaded through the Google Ads API.
5. Use the "All conv. (by conv. time)" column to confirm that imports arrive.
6. Wait until the primary action has a steady volume of qualified conversions (Google's own lead generation guidance mentions at least 15 in 30 days for value-based bidding) before switching to Maximize conversions or a target CPA.

Leads in `review` status are not exported. Qualify or disqualify them through `/_ti/admin/conversions/<id>/qualify` or `/disqualify`, or from your CRM. When a conversion that was already exported is disqualified, the response says `requiresAdjustment: true`; retract it in Google Ads with a conversion adjustment.

## Targeting choices that reduce wasted clicks

Location options: for a local business choose "Presence: People in or regularly in your included locations" instead of the default "Presence or interest". Leads from outside the service area are a common symptom of the broader setting.

Networks: Search campaigns can include Google search partners and the Display Network. If the summary report shows suspicious traffic concentrated in partner placements, compare performance with segmentation by network and consider unchecking "Include Google search partners" and "Include Google Display Network".

## Invalid traffic

1. Add the "Invalid clicks" column to the campaigns table. These are clicks Google already filtered and did not charge.
2. Clicks found invalid after billing are credited on later invoices. Report editor, Template gallery, "Invalid activity credit report: Search and Performance Max" shows credited clicks and amounts.
3. If you believe abuse was not filtered, submit the Click Quality Form for the affected period, within the last 60 days. Include your 10-digit customer id, exact dates and campaigns, and the evidence this system collects: `/_ti/admin/exclusions.json`, `/_ti/admin/campaigns.json`, `/_ti/admin/sessions.json`, `/_ti/admin/evidence/<uuid>.json`, the `paid_visit` and `temporary_restriction` events, and hashed click identifiers rather than raw `gclid` values in exported bundles. Evidence bundles state that they do not prove Google billed a click and cannot reverse a charge.

Campaign pause or throttle recommendations from `/_ti/admin/campaigns.json` are never applied automatically. `GOOGLE_ADS_APPLY_CHANGES` stays false unless an operator has authorized a control-plane integration. Spend-at-risk figures are estimates from `GOOGLE_ADS_CPC_USD` times suspicious visit counts.

## IP exclusions

Campaigns, select the campaign, Settings, Additional settings, IP exclusions. Each campaign accepts up to 500 entries. An entry is a single address or a block with an asterisk replacing the last part, such as `203.0.113.*`. IP exclusions are not available for every campaign type (for example video and app campaigns).

`/_ti/admin/exclusions.json` lists addresses and networks with repeated suspicious paid visits and a `googleAds` field already in that syntax. Exclude sparingly: residential and mobile addresses change hands, the 500 entry limit fills quickly, and an exclusion also hides your ads from the next legitimate person on that address. Datacenter addresses and networks that keep reappearing are the best candidates.

## Ongoing monitoring

Each week compare the number of qualified, review and disqualified conversions, the share of paid arrivals that were challenged (from `/_ti/admin/summary.json`), the campaigns with the highest suspicious share, and Google's invalid click column. A sudden rise in leads that never answer the phone, or in conversions from one network or campaign, should be investigated before Smart Bidding adapts to it.
