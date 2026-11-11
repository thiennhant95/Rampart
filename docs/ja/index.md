---
layout: default
title: Rampart Quality Checker — 日本語
description: Laravel 向け品質ゲートの日本語ドキュメント。
---

# Rampart Quality Checker — 日本語

[English]({{ site.baseurl }}/en/) · [日本語]({{ site.baseurl }}/ja/) · [Tiếng Việt]({{ site.baseurl }}/vi/)

**Laravel 9–13** / **PHP 8.1+** 向けの総合品質ゲート。1 つの Artisan コマンドで
phpcs、phpstan、phpunit、composer audit、trivy を実行し、50 個の PHP-Parser
ルールでセキュリティ・テスト不足・規約を検査します。

## Rampart ファミリー

| プロジェクト | 対象 | リポジトリ | ドキュメント |
|---|---|---|---|
| **Rampart** | Laravel Artisan 品質ゲート | [GitHub](https://github.com/thiennhant95/Rampart) | [Pages](https://thiennhant95.github.io/Rampart/) |
| **Rampart PHP** | プレーン PHP + 各フレームワーク、PHP 7.4+ | [GitHub](https://github.com/thiennhant95/Rampart-PHP) | [Pages](https://thiennhant95.github.io/Rampart-PHP/) |
| **Rampart WP** | WordPress プラグイン/テーマ | [GitHub](https://github.com/thiennhant95/Rampart-Wordpress) | [Pages](https://thiennhant95.github.io/Rampart-Wordpress/) |

## インストール

```bash
composer require rampart/quality-checker --dev
php artisan vendor:publish --tag=quality-checker-config
```

サービスプロバイダは自動検出されます。設定の公開は任意ですが、パス・ティア・
ツール設定・Trivy を変更する場合に推奨します。

## クイックスタート

```bash
# 最初の安全な実行
php artisan quality:check --tier=security --only=custom,composer_audit

# フルゲート
php artisan quality:check

# 全レポート
php artisan quality:check --format=all --output=reports/quality-checker
```

終了コード: `0` 合格 · `1` しきい値超過 · `2` 不正な引数 · `3` 内部エラー。

## 検査内容

- **ラップするツール:** phpcs（PSR-12）、phpstan（既定 level 6）、phpunit
  （JUnit + Clover カバレッジ）、composer audit、npm audit、任意の trivy。
- **OWASP Top 10 2021:** アクセス制御、IDOR、パストラバーサル、Blade XSS、
  SSTI、コマンドインジェクション、設定不備、XXE、オープンリダイレクト、SSRF。
- **セキュリティ:** SQLi、eval、秘密情報、マスアサインメント、デシリアライズ、
  弱いハッシュ/Cookie/セッション/パスワード、CSRF、テイントエンジン（任意）。
- **Laravel:** マイグレーションの可逆性、破壊的 `up()`、ルートバリデーション。
- **テスト:** controller/service/repository/model/unit/feature のテスト不足、
  アサーションなしテスト（任意）。
- **フロントエンド:** JS/CSS 構文、Blade `@push`/`@stack`。
- **運用/フォレンジック:** 権限、EOL、`public/` の不審 PHP、難読化 PHP。
- **規約（任意）:** デッドコード、命名、TODO/FIXME、`env()`、`dd()`、`sleep()`。

完全な一覧: [README](https://github.com/thiennhant95/Rampart#custom-analyzer-rules)

## レポート

`console` / `json` / `html` / `md` / `sarif`。HTML は自己完結・検索可能・
ダークモード対応で、修正ガイド、コードスニペット、重大度/ルール別チャート、
OWASP ドリルダウン、アクションプランを含みます。

3 種類の HTML: `quality-report.html`（開発者）、
`quality-report-findings.html`（`--no-remediation`）、
`quality-report-client.html`（`--client`）。

## CI

```yaml
- run: composer install --prefer-dist --no-progress
- run: php artisan quality:check --ci
```

`--format=sarif` で GitHub コードスキャンに連携できます。`--no-dev` の場合は
`--only=custom` を併用してください。

## ベースライン

```bash
php artisan quality:check --format=all --fail-on=none
php artisan quality:check --baseline-generate
php artisan quality:check --ci --baseline-file=baseline.json
```

以降は新規の指摘のみが失敗します。インライン抑制:
`// quality-checker-ignore RULE` または
`// quality-checker-ignore-next-line RULE`。

## アップグレード

再ベースライン化の前に
[UPGRADE.md](https://github.com/thiennhant95/Rampart/blob/main/UPGRADE.md) を
読んでください。履歴は
[CHANGELOG](https://github.com/thiennhant95/Rampart/blob/main/CHANGELOG.md) に
あります。

## ドキュメント

- [概要]({{ site.baseurl }}/overview.html)
- [レポート]({{ site.baseurl }}/reports.html) · [クライアント向け]({{ site.baseurl }}/client-reports.html)
- [ベースライン]({{ site.baseurl }}/baseline.html)
- [誤検知]({{ site.baseurl }}/false-positives.html)
- [Enlightn との比較]({{ site.baseurl }}/comparison-enlightn.html)

## ライセンス

MIT © 2026 Rampart.
