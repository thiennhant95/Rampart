<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Frontend\JsSyntaxAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\ComposerManifestAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\EolAnalyzer;
use Rampart\QualityChecker\Analyzers\Ops\PermsAnalyzer;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContext;

final class OpsAnalyzerTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-ops-' . uniqid('', true);
        @mkdir($this->tmp, 0777, true);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->tmp, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $item) {
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($this->tmp);
        }
    }

    /** @param array<string, string> $require */
    private function eolWith(array $require): EolAnalyzer
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', json_encode(['require' => $require]));
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    private function permsWith(string $root): PermsAnalyzer
    {
        $analyzer = new PermsAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($root);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    public function testEolFiresOnLaravel11(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^11.0', 'php' => '^8.3'])->analyze([]);
        $rules = array_map(static fn ($i) => $i->rule, $issues);
        self::assertContains('EOL_COMPONENT', $rules);
        self::assertCount(1, $issues);
    }

    public function testEolSilentOnLaravel12And13(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^12.0'])->analyze([]));
        self::assertSame([], $this->eolWith(['laravel/framework' => '^13.0'])->analyze([]));
    }

    public function testEolSilentWhenAnySupportedMajorAllowed(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^11.0|^12.0'])->analyze([]));
    }

    public function testEolFiresOnPhp81Pin(): void
    {
        $issues = $this->eolWith(['php' => '^8.1'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('EOL_COMPONENT', $issues[0]->rule);
    }

    public function testEolSilentOnPhp82AndOpenRange(): void
    {
        self::assertSame([], $this->eolWith(['php' => '^8.2'])->analyze([]));
        self::assertSame([], $this->eolWith(['php' => '>=8.1'])->analyze([]));
    }

    public function testEolSilentWithoutComposerJson(): void
    {
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testEolSilentOnInvalidJson(): void
    {
        file_put_contents($this->tmp . DIRECTORY_SEPARATOR . 'composer.json', '{not json');
        $analyzer = new EolAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($this->tmp);
        $analyzer->setScanContext($ctx);
        self::assertSame([], $analyzer->analyze([]));
    }

    public function testPermsSilentWhenNoSensitivePaths(): void
    {
        self::assertSame([], $this->permsWith($this->tmp)->analyze([]));
    }

    public function testPermsSkipsTestbenchSkeleton(): void
    {
        $fake = $this->tmp . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'orchestra'
            . DIRECTORY_SEPARATOR . 'testbench-core' . DIRECTORY_SEPARATOR . 'laravel';
        @mkdir($fake, 0777, true);
        self::assertSame([], $this->permsWith($fake)->analyze([]));
    }

    public function testPermsClassifyWorldWriteIsCritical(): void
    {
        foreach ([0777, 0776, 0772, 0767, 0757, 0773, 0666, 0662] as $mode) {
            $classification = PermsAnalyzer::classify($mode);
            self::assertNotNull($classification, sprintf('%03o must be flagged', $mode));
            self::assertSame(Severity::Critical, $classification['severity'], sprintf('%03o', $mode));
            self::assertSame('world-writable', $classification['scope'], sprintf('%03o', $mode));
        }
    }

    public function testPermsClassifyGroupWriteIsWarningNotWorldWritable(): void
    {
        foreach ([0775, 0774, 0770, 0670, 0664, 0660] as $mode) {
            $classification = PermsAnalyzer::classify($mode);
            self::assertNotNull($classification, sprintf('%03o must be flagged', $mode));
            self::assertSame(Severity::Warning, $classification['severity'], sprintf('%03o', $mode));
            self::assertSame('group-writable', $classification['scope'], sprintf('%03o', $mode));
        }
    }

    public function testPermsClassifySilentOnSafeModes(): void
    {
        foreach ([0755, 0750, 0700, 0644, 0640, 0600] as $mode) {
            self::assertNull(PermsAnalyzer::classify($mode), sprintf('%03o must stay silent', $mode));
        }
    }

    public function testPermsFlagsOpenEnvAndStorageWithContextualFixHints(): void
    {
        $env = $this->tmp . DIRECTORY_SEPARATOR . '.env';
        file_put_contents($env, "APP_KEY=secret\n");
        @chmod($env, 0666);

        $storage = $this->tmp . DIRECTORY_SEPARATOR . 'storage';
        @mkdir($storage, 0777, true);
        @chmod($storage, 0777);

        $issues = $this->permsWith($this->tmp)->analyze([]);
        self::assertNotSame([], $issues);

        $byPath = [];
        foreach ($issues as $issue) {
            $byPath[$issue->metadata['path']] = $issue;
        }

        self::assertArrayHasKey($env, $byPath);
        self::assertSame('file', $byPath[$env]->metadata['target']);
        self::assertStringContainsString('600', $byPath[$env]->metadata['fix_hint']);

        self::assertArrayHasKey($storage, $byPath);
        self::assertSame('directory', $byPath[$storage]->metadata['target']);
        self::assertStringContainsString('755', $byPath[$storage]->metadata['fix_hint']);
        self::assertSame(Severity::Critical, $byPath[$storage]->severity);
    }

    public function testEolFiresOnLaravelBelowTrackedMapWithGenericMessage(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^8.0'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertTrue($issues[0]->metadata['below_supported']);
        self::assertNull($issues[0]->metadata['eol']);
        self::assertStringContainsString('older than 9.x', $issues[0]->message);
    }

    public function testEolFiresOnPhpBelowTrackedMapWithGenericMessage(): void
    {
        $issues = $this->eolWith(['php' => '^7.4'])->analyze([]);
        self::assertCount(1, $issues);
        self::assertTrue($issues[0]->metadata['below_supported']);
        self::assertNull($issues[0]->metadata['eol']);
        self::assertStringContainsString('older than 8.0', $issues[0]->message);
    }

    public function testEolFiresOnOldLaravelAndPhpTogether(): void
    {
        $issues = $this->eolWith(['laravel/framework' => '^7.0', 'php' => '^7.2'])->analyze([]);
        self::assertCount(2, $issues);
    }

    public function testEolSilentOnFutureLinesAndUnparseableConstraints(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '^14.0'])->analyze([]));
        self::assertSame([], $this->eolWith(['php' => '^8.6'])->analyze([]));
        self::assertSame([], $this->eolWith(['laravel/framework' => 'dev-main', 'php' => 'dev-main'])->analyze([]));
    }

    public function testEolSilentOnOpenRangeThatAllowsSupportedLines(): void
    {
        self::assertSame([], $this->eolWith(['laravel/framework' => '>=9.0'])->analyze([]));
        self::assertSame([], $this->eolWith(['laravel/framework' => '>=8.0'])->analyze([]));
    }

    public function testComposerSilentWithoutLaravelSignals(): void
    {
        self::assertSame([], $this->composerWith($this->tmp)->analyze([]));
    }

    public function testComposerMissingFiresOnLaravelRoot(): void
    {
        $this->makeLaravelRoot();
        $issues = $this->composerWith($this->tmp)->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('MISSING_COMPOSER', $issues[0]->rule);
        self::assertSame(Severity::Warning, $issues[0]->severity);
    }

    public function testComposerInvalidJsonFires(): void
    {
        $this->makeLaravelRoot();
        $issues = $this->composerWith($this->tmp, '{not json')->analyze([]);
        self::assertCount(1, $issues);
        self::assertSame('INVALID_CONSTRAINT', $issues[0]->rule);
        self::assertSame(Severity::Error, $issues[0]->severity);
    }

    public function testComposerInvalidConstraintFires(): void
    {
        $this->makeLaravelRoot();
        $issues = $this->composerWith(
            $this->tmp,
            json_encode(['require' => ['php' => ['8.1'], 'laravel/framework' => true]])
        )->analyze([]);
        self::assertCount(2, $issues);
        foreach ($issues as $issue) {
            self::assertSame('INVALID_CONSTRAINT', $issue->rule);
        }
    }

    public function testComposerSilentOnValidManifest(): void
    {
        $this->makeLaravelRoot();
        $issues = $this->composerWith(
            $this->tmp,
            json_encode(['require' => ['php' => '^8.3', 'laravel/framework' => '^12.0']])
        )->analyze([]);
        self::assertSame([], $issues);
    }

    private function makeLaravelRoot(): void
    {
        @mkdir($this->tmp . DIRECTORY_SEPARATOR . 'app', 0777, true);
        @mkdir($this->tmp . DIRECTORY_SEPARATOR . 'config', 0777, true);
    }

    private function composerWith(string $root, ?string $json = null): ComposerManifestAnalyzer
    {
        if ($json !== null) {
            file_put_contents($root . DIRECTORY_SEPARATOR . 'composer.json', $json);
        }
        $analyzer = new ComposerManifestAnalyzer();
        $ctx = new ScanContext();
        $ctx->setBasePath($root);
        $analyzer->setScanContext($ctx);

        return $analyzer;
    }

    public function testJsCollectorParityMinifiedExcluded(): void
    {
        // collectJsFiles() mirrors supports(): minified bundles never scan.
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/js/app.min.js'));
        self::assertFalse((new JsSyntaxAnalyzer())->supports('public/build/assets/app-abc123.min.js'));
        self::assertTrue((new JsSyntaxAnalyzer())->supports('resources/js/app.js'));
    }
}
