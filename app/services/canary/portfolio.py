"""Executive portfolio decoy — static HTML, identical for every request (OpSec)."""

PORTFOLIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Executive Summary — Draft</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1f2933;
      background: #f4f5f7;
      line-height: 1.55;
      font-size: 15px;
    }
    .banner {
      background: #fff8e6;
      border-bottom: 1px solid #f0d78c;
      color: #7a5c00;
      padding: 0.65rem 1.25rem;
      font-size: 0.8rem;
      text-align: center;
    }
    .wrap {
      max-width: 52rem;
      margin: 0 auto;
      padding: 2rem 1.25rem 3rem;
    }
    .doc {
      background: #fff;
      border: 1px solid #dde1e6;
      border-radius: 4px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.06);
      padding: 2.25rem 2rem 2.5rem;
    }
    h1 {
      font-size: 1.45rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      margin-bottom: 0.35rem;
    }
    .subtitle {
      color: #52606d;
      font-size: 0.92rem;
      margin-bottom: 1.75rem;
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 1.25rem;
      font-size: 0.8rem;
      color: #616e7c;
      padding-bottom: 1.25rem;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid #e4e7eb;
    }
    h2 {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #7b8794;
      margin: 1.75rem 0 0.75rem;
      font-weight: 600;
    }
    p { margin-bottom: 0.85rem; color: #323f4b; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
      margin-top: 0.5rem;
    }
    th, td {
      text-align: left;
      padding: 0.55rem 0.65rem;
      border-bottom: 1px solid #e4e7eb;
    }
    th {
      font-weight: 600;
      color: #52606d;
      background: #f9fafb;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    td.num { font-variant-numeric: tabular-nums; }
    .delta { color: #0e7c3a; font-weight: 500; }
    .project {
      padding: 1rem 0;
      border-bottom: 1px solid #e4e7eb;
    }
    .project:last-child { border-bottom: none; }
    .project-title { font-weight: 600; margin-bottom: 0.25rem; }
    .project-meta { font-size: 0.82rem; color: #7b8794; margin-bottom: 0.5rem; }
    .redact {
      display: inline-block;
      background: #cbd2d9;
      color: transparent;
      border-radius: 2px;
      user-select: none;
      vertical-align: baseline;
    }
    .note {
      margin-top: 1.75rem;
      padding: 0.85rem 1rem;
      background: #f9fafb;
      border-left: 3px solid #cbd2d9;
      font-size: 0.82rem;
      color: #52606d;
    }
    footer {
      text-align: center;
      padding: 1.5rem;
      font-size: 0.75rem;
      color: #9aa5b1;
    }
  </style>
</head>
<body>
  <div class="banner">
    Draft — confidential. Internal evaluation only. Do not forward or distribute.
  </div>
  <div class="wrap">
    <article class="doc">
      <h1>Executive Summary — Platform &amp; Data Architecture</h1>
      <p class="subtitle">Retained search supporting materials · unredacted working draft</p>
      <div class="meta">
        <span>Prepared by: Frank <span class="redact">████████</span></span>
        <span>Scope: Enterprise data platform · 2022–2025</span>
        <span>Version: 0.9 (pre-compliance review)</span>
      </div>

      <p>
        Summary of outcomes from recent architectural reviews and delivery leadership
        across multi-region data pipelines, billing reconciliation, and platform
        reliability programmes. Figures below are taken directly from post-implementation
        reviews and executive steering packs.
      </p>

      <h2>Quantified outcomes</h2>
      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th>Baseline</th>
            <th>Post-change</th>
            <th>Impact</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Pipeline P99 latency (ingest → warehouse)</td>
            <td class="num">840 ms</td>
            <td class="num">118 ms</td>
            <td class="num delta">−86%</td>
          </tr>
          <tr>
            <td>Platform uptime (rolling 90d)</td>
            <td class="num">99.21%</td>
            <td class="num">99.97%</td>
            <td class="num delta">+0.76 pp</td>
          </tr>
          <tr>
            <td>Revenue attribution accuracy</td>
            <td class="num">81.4%</td>
            <td class="num">96.1%</td>
            <td class="num delta">+14.7 pp</td>
          </tr>
          <tr>
            <td>B2B invoice reconciliation cycle</td>
            <td class="num">11.2 days</td>
            <td class="num">2.4 days</td>
            <td class="num delta">−79%</td>
          </tr>
          <tr>
            <td>Incident MTTR (Sev-1/2)</td>
            <td class="num">4h 20m</td>
            <td class="num">47m</td>
            <td class="num delta">−82%</td>
          </tr>
        </tbody>
      </table>

      <h2>Selected engagements</h2>
      <div class="project">
        <div class="project-title">Real-time metering &amp; usage pipeline</div>
        <div class="project-meta">Lead architect · <span class="redact">████████████</span> (B2B SaaS)</div>
        <p>
          Replaced batch ETL with event-driven ingestion (Kafka → stream processing →
          warehouse). Delivered measurable latency reduction and enabled same-day
          usage-based billing for enterprise accounts.
        </p>
      </div>
      <div class="project">
        <div class="project-title">Multi-tenant billing reconciliation</div>
        <div class="project-meta">Technical lead · confidential B2B structures retained below</div>
        <p>
          Unified contract tiers, credit pools, and regional tax rules into a single
          reconciliation service. Reduced manual finance touchpoints; sensitive tariff
          schedules remain in appendix <span class="redact">██</span> (not yet redacted).
        </p>
      </div>
      <div class="project">
        <div class="project-title">Platform reliability programme</div>
        <div class="project-meta">Engagement principal · infrastructure &amp; SRE alignment</div>
        <p>
          Introduced SLOs, error budgets, and automated failover for critical path
          services. Uptime and MTTR improvements reflected in table above.
        </p>
      </div>

      <div class="note">
        This draft still contains unfiltered personal identifiers and client-specific
        billing constructs pending legal review. Please restrict access to retained-search
        evaluators only.
      </div>
    </article>
  </div>
  <footer>Last updated · working draft</footer>
</body>
</html>"""
