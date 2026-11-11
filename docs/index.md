---
layout: default
title: Rampart Quality Checker
description: Laravel quality gate with security, tests and convention analyzers.
---

# Rampart Quality Checker

**One Artisan command for the whole Laravel quality gate.**

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

Rampart wraps `phpcs`, `phpstan`, `phpunit`, `composer audit` and `trivy` into
`php artisan quality:check`, and adds 50 PHP-Parser rules for security,
missing tests and code conventions. Reports: console, JSON, HTML, Markdown and
SARIF.

```bash
composer require rampart/quality-checker --dev
php artisan vendor:publish --tag=quality-checker-config
php artisan quality:check --tier=security --only=custom,composer_audit
```

## The Rampart family

| Project | Focus | Repository | Documentation |
|---|---|---|---|
| **Rampart** | Laravel Artisan quality gate | [thiennhant95/Rampart](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | Plain PHP + frameworks, PHP 7.4+ | [thiennhant95/Rampart-PHP](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress plugins/themes | [thiennhant95/Rampart-Wordpress](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## Start here

- [English documentation]({{ site.baseurl }}/en/) — install, rules, reports, CI.
- [日本語ドキュメント]({{ site.baseurl }}/ja/)
- [Tài liệu tiếng Việt]({{ site.baseurl }}/vi/)

## Repository guides

- [Overview](overview.html) — what the package does and how it is put together.
- [Reports](reports.html) — HTML variants and machine formats.
- [Baseline](baseline.html) — accept existing findings, fail only on new ones.
- [False positives](false-positives.html) — triage and inline suppression.
- [Client reports](client-reports.html) — hand a report to a non-developer.
- [Comparison with Enlightn](comparison-enlightn.html) — static vs dynamic analysis.

MIT © 2026 Rampart.
