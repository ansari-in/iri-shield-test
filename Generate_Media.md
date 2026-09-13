# Iri-Shield Media Generation Brief

This file describes the figures, screenshots, animations, and videos needed for the `iri-test` home page. The current page intentionally leaves placeholder blocks for these assets.

## Visual Direction

Use a clean academic project-site style inspired by modern research pages:

- White or warm off-white background.
- Cobalt blue as the primary research accent.
- Amber for suspicious/risk signals.
- Red only for blocked or critical events.
- Use crisp diagrams, thin borders, readable labels, and minimal decoration.
- Prefer real dashboard screenshots and real benchmark charts where possible.
- Keep all labels short enough to remain legible on mobile.

Recommended export sizes:

- Hero teaser: 1920x1080 MP4/WebM, 20-45 seconds.
- Inline diagrams: 1600x1000 PNG or SVG.
- Dashboard screenshots: 1600x1000 PNG.
- Chart images: 1400x900 PNG or SVG.
- Short loop animations: 1200x800 MP4/WebM or GIF.

## Home Page Asset Slots

### Hero Media Slot - End-to-End Pipeline Teaser

Location: top hero section on `/`.

Create a 20-30 second looping video or animation showing:

1. A normal API request entering an Express.js app.
2. Iri-Shield middleware intercepting the request.
3. Identity, static rules, behavior, and correlation layers lighting up.
4. A malicious payload such as `GET /api/search?q=' or 1=1`.
5. Risk score increasing with explainable reasons.
6. The request being blocked or flagged.
7. A response path where sensitive fields are redacted before logging.
8. The dashboard receiving the final event.

Style notes:

- Dark terminal/dashboard surface with bright but restrained accents.
- Use real terminology from the package: `riskScore`, `action`, `redaction`, `clientId`, `blocked`.
- Do not make it look like a generic stock cybersecurity animation.

Suggested filename:

```text
public/media/iri-shield-hero-pipeline.mp4
```

### Figure A - Overall System Architecture

Location: Figures and media section.

Create a clean architecture diagram showing:

- Client / API Request.
- Express.js application.
- Iri-Shield middleware.
- Protected route handler.
- Response redaction layer.
- Storage abstraction.
- Dashboard.
- Storage branches: Memory, SQLite, MongoDB.

Key message:

Iri-Shield sits inside the Express.js request lifecycle and connects runtime protection with dashboard observability.

Suggested filename:

```text
public/media/fig-overall-system-architecture.png
```

### Figure B - Seven-Layer Request Processing Flow

Location: Figures and media section.

Create a horizontal or vertical flowchart with these stages:

1. HTTP transport security hardening.
2. Multi-signal client identity continuity.
3. Static multi-vector threat detection.
4. Behavioral anomaly monitoring.
5. Stateful attack sequence correlation.
6. Explainable risk scoring and mitigation.
7. Recursive response redaction.

Show the risk score accumulating as the request moves through the stages. Use small callouts such as `+30 SQL injection`, `+12 sequence correlation`, and `block threshold reached`.

Suggested filename:

```text
public/media/fig-seven-layer-flow.png
```

### Figure C - Stateful Attack Sequence Correlation

Location: Figures and media section.

Create a timeline figure with request cards from the same client:

- Failed login attempt.
- Endpoint enumeration.
- SQL injection attempt.
- Secret probe such as `/.env`.
- Final mitigation event.

The visual should communicate that individual events become stronger evidence when viewed as a sequence.

Suggested filename:

```text
public/media/fig-attack-sequence-correlation.png
```

### Figure D - Dashboard Overview Screenshot

Location: Figures and media section.

Capture the real `/iri-shield` dashboard after replaying the dataset.

The screenshot should include:

- Total requests.
- Threats detected.
- Active blocked IPs.
- Active alerts.
- Threat distribution chart.
- Top endpoints.
- Alerts or recent events visible if possible.

Before capturing, run a dataset replay or manually call the demo attack routes so the dashboard is populated.

Suggested filename:

```text
public/media/dashboard-overview.png
```

## Results Section Charts

### Chart 1 - Threat Detection By Category

Use the research result data from the `iri-shield` package output files, especially:

```text
../iri-shield/final-results/security.csv
../iri-shield/final-results/charts/threat-detection-by-category.svg
```

The chart should show category-wise detection rates. Highlight:

- Overall isolated detection: 214 / 220.
- Overall detection rate: 97.3%.
- Categories with 100% detection.
- Any category where attacks were missed.

Suggested filename:

```text
public/media/chart-threat-detection-by-category.svg
```

### Chart 2 - False Positive Rate

Use:

```text
../iri-shield/final-results/false_positives.csv
../iri-shield/final-results/charts/false-positive-rate.svg
```

Show that the observed false-positive block rate was 0.00% for the evaluated legitimate datasets. Include a small note that this result applies to the evaluated controlled dataset, not all possible production traffic.

Suggested filename:

```text
public/media/chart-false-positive-rate.svg
```

### Chart 3 - Identity Continuity Accuracy

Use:

```text
../iri-shield/final-results/identity.csv
../iri-shield/final-results/charts/identity-accuracy.svg
```

Show accuracy for identity states such as stable identity, IP drift, user-agent drift, fingerprint drift, or combined drift depending on the exact CSV labels.

Suggested filename:

```text
public/media/chart-identity-continuity.svg
```

### Chart 4 - Redaction Accuracy

Use:

```text
../iri-shield/final-results/redaction.csv
../iri-shield/final-results/charts/redaction-accuracy.svg
```

Show successful redactions, missed sensitive values, and over-masked decoy values. The intended message is that structured JSON redaction protected 100% of tested sensitive fields without observed overmasking.

Suggested filename:

```text
public/media/chart-redaction-accuracy.svg
```

### Chart 5 - Throughput and Latency Trade-Off

Use:

```text
../iri-shield/final-results/performance.csv
../iri-shield/final-results/charts/throughput-comparison.svg
../iri-shield/final-results/charts/latency-comparison.svg
../iri-shield/final-results/charts/p95-latency.svg
```

Create either a combined figure or three separate figures:

- Baseline Express.js throughput vs shielded throughput.
- Average latency comparison.
- p95 latency under increasing concurrency.

The caption should be honest: the middleware improves security coverage but introduces measurable processing overhead.

Suggested filenames:

```text
public/media/chart-throughput-comparison.svg
public/media/chart-latency-comparison.svg
public/media/chart-p95-latency.svg
```

## Video Concepts

### Video 1 - Product Demo

Length: 30-45 seconds.

Storyboard:

1. Open the home page.
2. Click "Open dashboard".
3. Sign in.
4. Send `/api/public` and show normal telemetry.
5. Send `/api/search?q=' or 1=1`.
6. Show alert/event creation.
7. Open event details and zoom into explainable risk score.
8. Show blocked IP or mitigation state.
9. Call `/api/private` with sensitive fields and show redaction.

Suggested filename:

```text
public/media/video-product-demo.mp4
```

### Video 2 - Research Evaluation Walkthrough

Length: 60-90 seconds.

Storyboard:

1. Introduce the research question: can a lightweight in-process middleware combine detection, identity continuity, correlation, mitigation, and redaction?
2. Show the seven-layer method figure.
3. Show the attack category chart.
4. Show false-positive chart.
5. Show identity continuity chart.
6. Show redaction chart.
7. Show performance trade-off chart.
8. End with Vercel deployment note: use MongoDB for persistent dashboard history.

Suggested filename:

```text
public/media/video-research-walkthrough.mp4
```

## Login Page Optional Media

The dashboard login page includes a small placeholder for an optional loop.

Create a subtle 8-12 second animation showing:

- Alert cards entering a dashboard queue.
- Risk scores changing from low to high.
- A sensitive token becoming `[REDACTED]`.
- A final "blocked" or "alerted" state.

Suggested filename:

```text
public/media/login-security-loop.mp4
```

## Suggested Implementation After Media Generation

When the assets exist:

1. Add static serving for a `public/` directory in `server.js`.
2. Replace placeholder cards with `<img>` or `<video>` tags.
3. Add `poster` images for videos.
4. Use `loading="lazy"` on images below the first viewport.
5. Keep the hero video muted, looped, and inline:

```html
<video autoplay muted loop playsinline poster="/media/iri-shield-hero-pipeline-poster.png">
  <source src="/media/iri-shield-hero-pipeline.mp4" type="video/mp4">
</video>
```

## Research Claims To Use Carefully

Use these claims only with wording that makes the controlled evaluation context clear:

- 214 of 220 controlled attack requests detected and mitigated.
- 97.3% isolated detection rate.
- 0.00% observed false-positive block rate on evaluated legitimate traffic.
- 100.0% identity-continuity accuracy across 500 controlled identity scenarios.
- 100.0% required sensitive-data redaction success across 500 structured payloads.
- The middleware introduces measurable latency and throughput overhead compared with vanilla Express.js.

