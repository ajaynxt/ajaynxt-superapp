# Reporting, Growth Comparisons and Projections

## 1. Source of truth

The current UI can report only on rows imported by the user. Each report must preserve:

- Project
- Platform/source label
- Metric name
- Metric value and unit
- Observation date
- Source label (when supplied)
- Import timestamp in the local application state

The CSV is not independently verified against the provider. Reports must say **user-imported / not independently verified** until a future official API connector provides verifiable provenance and sync metadata.

## 2. Normalized import contract

Required columns: **date, project, platform, metric, value**.

Optional column: **source**.

Use one observation per **project + date + platform + metric**. Duplicate observations are rejected rather than automatically summed or overwritten. This avoids silently double-counting uncertain exports. If a Partner export contains multiple rows for the same daily metric, map/aggregate them only after confirming the source's grain and units.

Dates must be real calendar dates in ISO YYYY-MM-DD form. Values must be numeric and non-negative. Each project field must match an existing project's name. Keep units and metric definitions consistent over time.

## 3. Seven-day growth comparison

A comparison is available only when the same project/platform/metric has **14 consecutive daily observations**.

- The earlier window is the first 7 days.
- The latest window is the subsequent 7 days.
- For flow/activity metrics (for example orders, revenue, clicks, views or impressions), compare daily averages across both 7-day windows.
- For snapshot-style metrics whose names identify followers/subscribers/member counts, compare the first available value in the earlier window with the final value in the latest window.
- Percentage change is undefined when the comparison baseline is zero; show N/A instead.
- If any date in the 14-day window is missing, do not show the comparison.

A positive result means that the imported metric moved upward between the two windows. It does not establish that the website, campaign or any specific change caused that movement. Changes in seasonality, availability, offers, platform algorithms and reporting definitions may affect the outcome.

## 4. Seven-day projection

A projection is available only when the same project/platform/metric contains **28 consecutive daily observations**.

Method in the current MVP:
1. Take the latest 28 consecutive observations.
2. Fit an ordinary least-squares linear trend against day index.
3. Extrapolate seven additional daily point estimates.
4. Clamp negative forecast values to zero because the imported metric contract is non-negative.
5. Show the average of those seven point estimates and compare it with the average of the latest seven actual daily values, if the latter is non-zero.

This is a deliberately simple baseline model. It does **not** model seasonality, weekdays, promotions, holidays, stock-outs, price changes, platform ranking, uncertainty intervals or causal effects. No confidence interval is calculated. Forecasts must be labelled estimates and should not be represented as guaranteed sales, reach or profit.

## 5. Profit reporting

Revenue is not profit. A future profitability report should be enabled only when source records provide clearly defined costs and adjustments, such as ingredients/COGS, packaging, marketplace commission, discounts, refunds, advertising spend, taxes and other operating costs. Never infer costs from sales amounts.

## 6. Data-quality guardrails

- Missing is not zero.
- Keep platform-specific metric definitions separate; do not sum unlike metrics into a single score.
- Display source label, date coverage and last sync/import time.
- Detect duplicate daily observations and inconsistent units.
- Do not combine organic and paid results unless the report labels them separately and the underlying metrics have compatible definitions.
- Do not call imported rows verified merely because the app successfully parsed them.
- Preserve original source exports for audit/reconciliation.

## 7. Future production improvements

Before calling the forecast analytics-grade, add backtesting, error metrics (such as MAE/WAPE where appropriate), interval estimates, seasonality/weekday checks, outlier handling and a source-specific metric registry. Choose or withhold a model based on actual out-of-sample performance rather than promising an arbitrary accuracy level.
