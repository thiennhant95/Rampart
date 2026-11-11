---
layout: default
title: Rampart Quality Checker — English
description: Full English documentation for the Laravel quality gate.
---

# Rampart Quality Checker — English

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

A comprehensive quality gate for **Laravel 9–13** on **PHP 8.1+**. One Artisan
command runs the whole pipeline and returns a CI-ready exit code.

## The Rampart family

| Project | Focus | Repository | Documentation |
|---|---|---|---|
| **Rampart** | Laravel Artisan quality gate | [GitHub](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | Plain PHP + frameworks, PHP 7.4+ | [GitHub](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress plugins/themes | [GitHub](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## Install

```bash
composer require rampart/quality-checker --dev
php artisan vendor:publish --tag=quality-checker-config
```

The service provider is auto-discovered. Publishing the config is optional but
recommended when you change paths, tiers, tools or enable Trivy.

## Quick start

```bash
# Safest first run: security tier, no optional tools required
php artisan quality:check --tier=security --only=custom,composer_audit

# Full local gate
php artisan quality:check

# All reports
php artisan quality:check --format=all --output=reports/quality-checker
```

Exit codes: `0` pass · `1` findings above `--fail-on` · `2` bad invocation ·
`3` internal error.

## What it checks

Wrapped tools: `phpcs` (PSR-12), `phpstan` (level 6 by default), `phpunit`
(JUnit + Clover coverage gate), `composer audit`, `npm audit`, optional `trivy`.

50 custom rules:

- **OWASP Top 10 2021:** broken access control, IDOR/ownership, path traversal,
  Blade XSS, SSTI, command injection, misconfiguration, XXE, open redirect,
  SSRF, dynamic include.
- **Security:** SQL injection, eval, hardcoded secrets, mass assignment,
  deserialization, weak hash/cookie/session/password policy, CSRF exemptions,
  taint engine (opt-in).
- **Laravel quality:** migration reversibility, destructive `up()`, route
  validation.
- **Test coverage:** missing controller/service/repository/model/unit/feature
  tests, tests without assertions (opt-in).
- **Frontend:** JS/CSS syntax, Blade `@push`/`@stack` mismatches.
- **Ops/forensics:** world-writable paths, EOL Laravel/PHP, rogue PHP in
  `public/`, obfuscated PHP.
- **Conventions (opt-in):** dead code, naming, TODO/FIXME, `env()` outside
  config, `dd()`/`dump()`, `sleep()` in tests.

Full table: [README](https://github.com/thiennhant95/Rampart#custom-analyzer-rules).

## Confidence and tiers

Every finding carries severity (`critical` → `info`) and confidence
(`high`/`medium`/`low`). `--tier=security` fails only on high-confidence
security findings; `--tier=quality` adds phpcs/phpstan/phpunit errors.
`--min-confidence` and `--min-severity` filter what is reported; `--fail-on`
controls the gate independently.

## Reports

`console`, `json`, `html`, `md`, `sarif`. The HTML report is self-contained,
searchable, dark-mode ready and includes fix guidance, code snippets, severity
and top-rule charts, OWASP drill-down and an action plan.

Three HTML presentations: `quality-report.html` (developer),
`quality-report-findings.html` (`--no-remediation`), and
`quality-report-client.html` (`--client`). See [reports.html]({{ site.baseurl }}/reports.html).

## CI

```yaml
- run: composer install --prefer-dist --no-progress
- run: php artisan quality:check --ci
- uses: actions/upload-artifact@v4
  with:
    name: quality-report
    path: reports/quality-checker/quality-report.json
```

For GitHub code scanning, run `--format=sarif` and upload
`quality-report.sarif`. Add `--only=custom` when installing with `--no-dev`.

## Baseline workflow

```bash
php artisan quality:check --format=all --fail-on=none   # review
php artisan quality:check --baseline-generate           # accept
php artisan quality:check --ci --baseline-file=baseline.json
```

Only new findings fail after that. Inline suppression:
`// quality-checker-ignore RULE` or `// quality-checker-ignore-next-line RULE`.

## Upgrading

Read [UPGRADE.md](https://github.com/thiennhant95/Rampart/blob/main/UPGRADE.md)
before re-baselining; behavioural changes move findings. The
[CHANGELOG](https://github.com/thiennhant95/Rampart/blob/main/CHANGELOG.md) has
the full history.

## Docs map

- [Overview]({{ site.baseurl }}/overview.html)
- [Reports]({{ site.baseurl }}/reports.html) · [Client reports]({{ site.baseurl }}/client-reports.html)
- [Baseline]({{ site.baseurl }}/baseline.html)
- [False positives]({{ site.baseurl }}/false-positives.html)
- [Comparison with Enlightn]({{ site.baseurl }}/comparison-enlightn.html)

## License

MIT © 2026 Rampart.
