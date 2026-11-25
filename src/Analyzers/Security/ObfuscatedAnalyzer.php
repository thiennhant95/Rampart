<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class ObfuscatedAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'OBFUSCATED_PHP';

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            $code = $this->sharedSource($file);
            if ($code === '') {
                continue;
            }
            // Pattern names inside docs, remediation text or this analyzer's
            // own labels are not backdoors (self-scan used to flag
            // OBFUSCATED_PHP on its own source); the shared detector strips
            // strings/comments before matching.
            $match = PhpPayloadPatterns::obfuscation($code);
            if ($match === null) {
                continue;
            }
            $issues[] = new Issue(
                self::RULE,
                sprintf('Obfuscated PHP detected: %s.', $match['label']),
                $file,
                $match['line'],
                Severity::Critical,
                'custom',
                ['pattern' => $match['pattern']],
                Confidence::Medium
            );
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }
}
