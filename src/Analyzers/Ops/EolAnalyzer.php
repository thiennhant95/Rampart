<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class EolAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'EOL_COMPONENT';

    /**
     * Security-support end dates (EOL) per major line.
     *
     * Sources: laravel.com/docs/releases (bug/security fix windows) and
     * php.net/supported-versions.php (security-support end = EOL).
     * Refresh when a new major ships; unknown majors never fire.
     *
     * @var array<int, string>
     */
    private const LARAVEL_EOL = [
        9 => '2024-02-06',
        10 => '2025-02-04',
        11 => '2026-03-12',
        12 => '2027-02-24',
        13 => '2028-03-17',
    ];

    /**
     * @var array<string, string> minor line => EOL date
     */
    private const PHP_EOL = [
        '8.0' => '2023-11-26',
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $composer = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composer)) {
            return [];
        }
        $code = $this->sharedSource($composer);
        if ($code === '') {
            return [];
        }
        $data = json_decode($code, true);
        if (!is_array($data)) {
            return [];
        }
        $requires = $data['require'] ?? [];
        if (!is_array($requires)) {
            return [];
        }
        $issues = [];
        $laravel = $requires['laravel/framework'] ?? null;
        if (is_string($laravel)) {
            $laravelFloor = min(array_keys(self::LARAVEL_EOL));
            foreach ($this->eolLaravelMajors($laravel) as $major => $eol) {
                $issues[] = new Issue(
                    self::RULE,
                    $eol === ''
                        ? sprintf('laravel/framework %s is end-of-life (older than %d.x) — upgrade.', $laravel, $laravelFloor)
                        : sprintf('laravel/framework %s is end-of-life since %s — upgrade.', $laravel, $eol),
                    $composer,
                    1,
                    Severity::Warning,
                    'custom',
                    ['package' => 'laravel/framework', 'constraint' => $laravel, 'major' => $major, 'eol' => $eol === '' ? null : $eol, 'below_supported' => $eol === ''],
                    Confidence::Medium
                );
            }
        }
        $php = $requires['php'] ?? null;
        if (is_string($php)) {
            $phpFloor = min(array_keys(self::PHP_EOL));
            foreach ($this->eolPhpLines($php) as $line => $eol) {
                $issues[] = new Issue(
                    self::RULE,
                    $eol === ''
                        ? sprintf('php %s is end-of-life (older than %s) — upgrade.', $php, $phpFloor)
                        : sprintf('php %s is end-of-life since %s — upgrade.', $php, $eol),
                    $composer,
                    1,
                    Severity::Warning,
                    'custom',
                    ['package' => 'php', 'constraint' => $php, 'line' => $line, 'eol' => $eol === '' ? null : $eol, 'below_supported' => $eol === ''],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    /**
     * Laravel majors pinned by the constraint whose security support ended.
     *
     * A constraint allowing ANY supported major (e.g. `^11.0|^12.0`) does not
     * fire: the project can resolve to a live line. Only fire when every
     * major mentioned is EOL (single-major pins like `^11.0` are the norm).
     * Majors older than the lowest tracked line (Laravel 8 and below) are EOL
     * too, but without a reliable date — they are reported with a generic
     * "older than X.x" message (empty date sentinel). Majors newer than the
     * highest tracked line are treated as supported (unknown, not EOL).
     *
     * @return array<int, string> major => eol date ('' when below the tracked map)
     */
    private function eolLaravelMajors(string $constraint): array
    {
        if (preg_match('/>=/', $constraint)) {
            // Open floor (`>=9.0`, `>=8.1`) allows any newer (supported)
            // line, so the project is not pinned to an EOL major.
            return [];
        }
        preg_match_all('/\b(\d{1,2})(?:\.\d+){0,2}\b/', $constraint, $m);
        $majors = [];
        foreach ($m[1] as $raw) {
            $major = (int) $raw;
            if ($major >= 1) {
                $majors[$major] = true;
            }
        }
        if ($majors === []) {
            return [];
        }
        $now = time();
        $floor = min(array_keys(self::LARAVEL_EOL));
        $ceiling = max(array_keys(self::LARAVEL_EOL));
        $eol = [];
        foreach (array_keys($majors) as $major) {
            if ($major > $ceiling) {
                // Future release: treat as supported rather than guess.
                return [];
            }
            $date = self::LARAVEL_EOL[$major] ?? null;
            if ($date === null) {
                if ($major < $floor) {
                    $eol[$major] = '';
                    continue;
                }

                // A gap inside the tracked range is unknown, not EOL.
                return [];
            }
            if (strtotime($date) >= $now) {
                // At least one supported line allowed: not EOL.
                return [];
            }
            $eol[$major] = $date;
        }

        return $eol;
    }

    /**
     * PHP minor lines pinned by the constraint whose support ended.
     *
     * Same any-supported-wins rule as Laravel. `>=8.1` style open ranges
     * mention a floor but allow newer lines, so they never fire — only
     * exact pins (`8.1.*`, `~8.1.0`, `^8.1`) and closed sets of EOL lines do.
     * Lines older than the lowest tracked line (PHP 7.x and below) are EOL
     * with a generic message; lines newer than the highest tracked line are
     * treated as supported.
     *
     * @return array<string, string> line => eol date ('' when below the tracked map)
     */
    private function eolPhpLines(string $constraint): array
    {
        if (preg_match('/>=/', $constraint)) {
            return [];
        }
        preg_match_all('/\b(\d+\.\d+)\b/', $constraint, $m);
        $lines = array_unique($m[1]);
        if ($lines === []) {
            return [];
        }
        $now = time();
        $floor = min(array_keys(self::PHP_EOL));
        $ceiling = max(array_keys(self::PHP_EOL));
        $eol = [];
        foreach ($lines as $line) {
            if (version_compare($line, $ceiling, '>')) {
                // Future line: treat as supported rather than guess.
                return [];
            }
            $date = self::PHP_EOL[$line] ?? null;
            if ($date === null) {
                if (version_compare($line, $floor, '<')) {
                    $eol[$line] = '';
                    continue;
                }

                // A gap inside the tracked range is unknown, not EOL.
                return [];
            }
            if (strtotime($date) >= $now) {
                return [];
            }
            $eol[$line] = $date;
        }

        return $eol;
    }
}
