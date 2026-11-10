# Client reports

Send `quality-report-client.html` when the reader is a customer, manager, or
other non-developer stakeholder. It contains the same findings as the
technical report, but with a shorter layout and no local development links.

## What the recipient sees

- Summary.
- How to read.
- Fix now.
- Quality Score.
- Action Plan.
- The finding list.
- OWASP, when the scan produced any OWASP findings.

## What is intentionally omitted

- Risk Overview.
- Baseline Delta.
- Top Rules.
- Checker-by-checker table.
- Methodology appendix.
- Local absolute paths and clickable editor links.

These omissions change presentation only. They do not reduce the findings.

## Send checklist

1. Run the scan with `--format=html --client`.
2. Open `quality-report-client.html` from the output directory.
3. Check that the brand and project name are correct.
4. Send only the client file unless the recipient asks for the technical file.

## Branding

Set the brand and project in the published configuration:

```php
'html' => [
    'client_brand' => 'RAMPART', // Your company or product name.
    'client_project' => null,    // Defaults to the scanned directory name.
],
```

For the developer-facing files and command variants, see
[HTML reports](reports.md).
