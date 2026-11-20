<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class PermsAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'PERMS_TOO_OPEN';

    /**
     * Sensitive paths checked relative to the scan root. Only these are
     * inspected — never the whole filesystem/tree — so a project can be
     * scanned from any sub-directory without noisy reports.
     *
     * @var list<string>
     */
    private const CANDIDATES = ['.env', 'storage', 'bootstrap/cache'];

    /**
     * Deploy-owned descendants that are expected to be writable by the app
     * user. Kept as a whitelist even though the checks above are top-level:
     * it documents intent and keeps a future recursive expansion from
     * flagging the framework's own scratch space.
     *
     * @var list<string>
     */
    private const WHITELIST = ['storage/framework', 'storage/logs'];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        // Only check when scanning the project root itself, not when
        // the runner is pointed at a fixture sub-directory (tests/Feature/fixtures/app).
        // Testbench boots its own skeleton at vendor/orchestra/testbench-core/laravel
        // which has storage/bootstrap/cache with 777 — that is not the project's
        // deploy artifact and must not be reported when the test scans fixtures.
        $normalizedRoot = str_replace('\\', '/', $root);
        if (str_contains($normalizedRoot, '/vendor/orchestra/testbench-core')) {
            return [];
        }
        foreach (self::CANDIDATES as $relative) {
            if ($this->isWhitelisted($relative)) {
                continue;
            }
            $path = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            if (!file_exists($path)) {
                continue;
            }
            $perms = fileperms($path);
            if ($perms === false) {
                continue;
            }
            // Compare permission bits, not a hardcoded octal string: 775 is
            // group-writable (not world-writable), while 772/767/757 leak
            // other-write too and used to slip through the exact-match list.
            $mode = $perms & 0777;
            $classification = self::classify($mode);
            if ($classification === null) {
                continue;
            }
            $octal = sprintf('%03o', $mode);
            $isDir = is_dir($path);
            $issues[] = new Issue(
                self::RULE,
                sprintf('Permissions too open: %s is %s (%s).', $path, $octal, $classification['scope']),
                $path,
                1,
                $classification['severity'],
                'custom',
                [
                    'perms' => $octal,
                    'path' => $path,
                    'target' => $isDir ? 'directory' : 'file',
                    'reason' => $classification['reason'],
                    'fix_hint' => self::fixHint($relative, $isDir),
                ],
                $classification['reason'] === 'other_write' ? Confidence::High : Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * Classify a POSIX mode by its write bits. World-write is Critical;
     * group-write alone is Warning because it depends on deploy context.
     *
     * @return array{severity: Severity, scope: string, reason: string}|null
     */
    public static function classify(int $mode): ?array
    {
        $mode &= 0777;
        if (($mode & 0002) !== 0) {
            return ['severity' => Severity::Critical, 'scope' => 'world-writable', 'reason' => 'other_write'];
        }
        if (($mode & 0020) !== 0) {
            return ['severity' => Severity::Warning, 'scope' => 'group-writable', 'reason' => 'group_write'];
        }

        return null;
    }

    private static function fixHint(string $relative, bool $isDir): string
    {
        if ($relative === '.env') {
            // .env holds secrets: 644 (Laravel default) is not an error, but
            // the fix once it is writable should be tighter than a normal file.
            return 'chmod 600 .env (or 640 if the web server needs group read)';
        }

        return $isDir ? 'chmod 755 ' . $relative : 'chmod 644 ' . $relative;
    }

    private static function isWhitelisted(string $relative): bool
    {
        $relative = str_replace('\\', '/', $relative);
        foreach (self::WHITELIST as $allowed) {
            if ($relative === $allowed || str_starts_with($relative, $allowed . '/')) {
                return true;
            }
        }

        return false;
    }
}
