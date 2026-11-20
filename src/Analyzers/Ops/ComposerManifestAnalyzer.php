<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Missing or unparseable `composer.json`.
 *
 * This is deliberately separate from EOL_COMPONENT: "the manifest is absent /
 * broken" is a different problem from "the pinned version is unsupported",
 * and conflating them made EOL_COMPONENT fire on every sub-directory a runner
 * happened to point at.
 *
 * To stay quiet in monorepos and fixture trees, the rule only fires when the
 * scan root actually looks like a Laravel application (at least two of the
 * signals a real project always ships). A lone `app/` fixture, a vendored
 * skeleton, or a package sub-directory never reports.
 */
final class ComposerManifestAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE_MISSING = 'MISSING_COMPOSER';

    private const RULE_INVALID = 'INVALID_CONSTRAINT';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null || !$this->looksLikeLaravel($root)) {
            return [];
        }

        $composer = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composer)) {
            return [new Issue(
                self::RULE_MISSING,
                'composer.json is missing from a Laravel project — dependencies are not reproducible.',
                $composer,
                1,
                Severity::Warning,
                'custom',
                ['path' => $composer, 'reason' => 'missing_composer'],
                Confidence::High
            )];
        }

        $code = $this->sharedSource($composer);
        if ($code === '') {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json is empty or unreadable — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::Error,
                'custom',
                ['path' => $composer, 'reason' => 'unreadable'],
                Confidence::High
            )];
        }

        $data = json_decode($code, true);
        if (!is_array($data)) {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json is not valid JSON — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_json'],
                Confidence::High
            )];
        }

        $requires = $data['require'] ?? null;
        if ($requires !== null && !is_array($requires)) {
            return [new Issue(
                self::RULE_INVALID,
                'composer.json "require" is not an object — dependency constraints cannot be checked.',
                $composer,
                1,
                Severity::Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_require'],
                Confidence::High
            )];
        }

        if (!is_array($requires)) {
            return [];
        }

        $issues = [];
        foreach (['php', 'laravel/framework'] as $package) {
            if (!array_key_exists($package, $requires)) {
                continue;
            }
            $constraint = $requires[$package];
            if (is_string($constraint) && trim($constraint) !== '') {
                continue;
            }
            $issues[] = new Issue(
                self::RULE_INVALID,
                sprintf('composer.json constraint for %s is not a version string.', $package),
                $composer,
                1,
                Severity::Error,
                'custom',
                ['path' => $composer, 'reason' => 'invalid_constraint', 'package' => $package],
                Confidence::High
            );
        }

        return $issues;
    }

    /**
     * A real Laravel root ships several of these. Requiring at least two
     * keeps the rule from firing on a bare `app/` fixture or an arbitrary
     * package folder while still catching a project whose composer.json was
     * deleted or mangled.
     */
    private function looksLikeLaravel(string $root): bool
    {
        $signals = [
            is_file($root . DIRECTORY_SEPARATOR . 'artisan'),
            is_dir($root . DIRECTORY_SEPARATOR . 'app'),
            is_dir($root . DIRECTORY_SEPARATOR . 'database' . DIRECTORY_SEPARATOR . 'migrations'),
            is_dir($root . DIRECTORY_SEPARATOR . 'bootstrap'),
            is_dir($root . DIRECTORY_SEPARATOR . 'routes'),
            is_dir($root . DIRECTORY_SEPARATOR . 'config'),
            is_file($root . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'index.php'),
        ];

        return count(array_filter($signals)) >= 2;
    }
}
