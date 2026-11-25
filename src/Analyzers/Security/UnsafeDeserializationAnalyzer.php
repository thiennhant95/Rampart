<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class UnsafeDeserializationAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'UNSAFE_UNSERIALIZE';

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    public function analyzeFile(string $file): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();

        $calls = $finder->findInstanceOf($ast, Node\Expr\FuncCall::class);
        foreach ($calls as $call) {
            $target = $this->resolveFunctionName($call, $finder, $ast);
            if ($target === null) {
                continue;
            }
            $functionName = $target['name'];
            $dataIndex = $target['data_index'];

            if ($functionName === 'unserialize') {
                $arg = $call->args[$dataIndex] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if ($this->isLiteralOrConstant($arg->value)) {
                    continue;
                }
                if ($this->disallowsClasses($call, $dataIndex)) {
                    continue;
                }
                $issues[] = new Issue(
                    self::RULE,
                    'unserialize() is called with a non-literal (potentially untrusted) argument.',
                    $file,
                    $call->getStartLine(),
                    Severity::Critical,
                    'custom',
                    ['function' => 'unserialize']
                );
            }

            if (in_array($functionName, ['yaml_parse', 'yaml_parse_file', 'yaml_parse_url'], true)) {
                $arg = $call->args[$dataIndex] ?? null;
                if (!$arg instanceof Node\Arg) {
                    continue;
                }
                if ($this->isLiteralOrConstant($arg->value)) {
                    continue;
                }
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('%s() is called with a non-literal (potentially untrusted) argument; YAML tags can instantiate PHP objects.', $functionName),
                    $file,
                    $call->getStartLine(),
                    Severity::Critical,
                    'custom',
                    ['function' => $functionName]
                );
            }

            if ($functionName === 'ini_set' || $functionName === 'set_error_handler') {
                $arg = $call->args[$dataIndex] ?? null;
                $arg2 = $call->args[$dataIndex + 1] ?? null;
                $argName = $arg instanceof Node\Arg ? $this->argLiteralString($arg->value) : null;
                if ($argName !== null && strtolower($argName) === 'unserialize_callback_func') {
                    if (!$arg2 instanceof Node\Arg || $this->isLiteralOrConstant($arg2->value)) {
                        continue;
                    }
                    $issues[] = new Issue(
                        self::RULE,
                        'unserialize_callback_func is set to a non-literal callback, allowing arbitrary code execution on unserialize.',
                        $file,
                        $call->getStartLine(),
                        Severity::Critical,
                        'custom',
                        ['function' => 'unserialize_callback_func']
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * Direct calls, simple `$f = 'unserialize'; $f(...)` calls, and
     * call_user_func('unserialize', ...) wrappers all resolve to the same
     * normalized function name. data_index points at the first argument the
     * target function treats as data.
     *
     * @param list<Node> $nodes
     * @return array{name: string, data_index: int}|null
     */
    private function resolveFunctionName(
        Node\Expr\FuncCall $call,
        CountingNodeFinder $finder,
        array $nodes
    ): ?array {
        if ($call->name instanceof Node\Name) {
            $name = strtolower($call->name->toString());
            if ($name === 'call_user_func' && isset($call->args[0]) && $call->args[0] instanceof Node\Arg) {
                $first = $call->args[0];
                $resolved = LocalStringResolver::resolve($first->value, $call, $finder, $nodes);

                return $resolved !== null
                    ? ['name' => strtolower($resolved), 'data_index' => 1]
                    : ['name' => $name, 'data_index' => 0];
            }

            return ['name' => $name, 'data_index' => 0];
        }
        if (!$call->name instanceof Node\Expr\Variable) {
            return null;
        }
        $resolved = LocalStringResolver::resolve($call->name, $call, $finder, $nodes);
        if ($resolved === null) {
            return null;
        }

        return ['name' => strtolower($resolved), 'data_index' => 0];
    }

    private function isLiteralOrConstant(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Scalar
            || $expr instanceof Node\Expr\ClassConstFetch
            || $expr instanceof Node\Expr\ConstFetch;
    }

    /**
     * unserialize($data, ['allowed_classes' => false]) cannot instantiate
     * objects — the object-injection vector is closed.
     */
    private function disallowsClasses(Node\Expr\FuncCall $call, int $dataIndex = 0): bool
    {
        $options = $call->args[$dataIndex + 1] ?? null;
        if (!$options instanceof Node\Arg || !$options->value instanceof Node\Expr\Array_) {
            return false;
        }

        foreach ($options->value->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                continue;
            }
            if (strtolower($item->key->value) !== 'allowed_classes') {
                continue;
            }
            $value = $item->value;
            if ($value instanceof Node\Expr\ConstFetch && $value->name instanceof Node\Name) {
                return strtolower($value->name->toString()) === 'false';
            }

            return false;
        }

        return false;
    }

    private function argLiteralString(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }

        return null;
    }
}
