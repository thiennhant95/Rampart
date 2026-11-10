# HTML reports

One scan can produce three HTML presentations. These options do not remove
findings, change severity counts, change the Quality Score, or change the
pass/fail gate. They only change how much fix guidance and engineering detail
the HTML page shows. JSON and SARIF always contain the complete machine data.

## Choose the file for the reader

| If the reader will ... | Add this flag | Open or send this file |
|---|---|---|
| Fix the issues | None; this is the default | `quality-report.html` |
| Review the same technical report without fix boxes | `--no-remediation` | `quality-report-findings.html` |
| Read a simplified external summary | `--client` | `quality-report-client.html` |
| Compare or archive every presentation | `--all-variants` | All three files |

The same flags work for both entry points:

```bash
php artisan quality:check --format=html
php artisan quality:check --format=html --no-remediation
php artisan quality:check --format=html --client
php bin/quality-check /path/to/project --format=html --all-variants
```

## What is different in each file?

- **Full technical report:** all technical sections available for that run,
  fix boxes, code snippets, and clickable file links.
- **Findings-only report:** the same technical report and findings, but fix
  boxes are hidden. The run writes both the historical `quality-report.html`
  filename and the clearer `quality-report-findings.html` copy; send the
  latter.
- **Client report:** the same findings in a shorter external layout. It keeps
  Summary, How to read, Fix now, Quality Score, Action Plan, the finding
  list, and OWASP when the scan produced any. It omits Risk Overview,
  baseline Delta, Top Rules, the checker-by-checker table, and Appendix. File
  paths are relative, there are no editor links, and the header shows the
  brand/project instead of tool metadata.
- `--no-remediation` also hides fix guidance in console and Markdown reports.

## Fix-guidance default

Fix guidance is on by default. Use `--no-remediation` for one findings-only
run, or make findings-only the default for every run with:

```php
'remediation' => false,
```

The default is `true`. A command-line flag overrides the config for that run
only.

For an external handoff, continue to [Client reports](client-reports.md).
