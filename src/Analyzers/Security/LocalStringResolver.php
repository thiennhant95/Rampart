<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Resolves a callable/function name when it is either a literal string or a
 * local variable assigned exactly one literal string in the enclosing
 * function. Anything with a non-literal or conflicting assignment stays
 * unresolved so callers keep their conservative behaviour.
 */
final class LocalStringResolver
{
    public static function literal(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }
        if ($expr instanceof Node\Scalar\LNumber) {
            return (string) $expr->value;
        }

        return null;
    }

    /**
     * @param list<Node> $nodes
     */
    public static function resolve(
        Node\Expr $expr,
        Node $call,
        NodeFinder $finder,
        array $nodes
    ): ?string {
        $literal = self::literal($expr);
        if ($literal !== null) {
            return $literal;
        }
        if (!$expr instanceof Node\Expr\Variable || !is_string($expr->name)) {
            return null;
        }

        $func = self::enclosingFunction($call, $finder, $nodes);
        $scope = $func ?? $nodes;
        $topLevelOnly = $func === null;

        $name = $expr->name;
        $callLine = $call->getStartLine();
        $value = null;
        $assignments = $finder->find($scope, static function (Node $node) use ($name): bool {
            return $node instanceof Node\Expr\Assign
                && $node->var instanceof Node\Expr\Variable
                && $node->var->name === $name;
        });

        foreach ($assignments as $assignment) {
            if (!$assignment instanceof Node\Expr\Assign) {
                continue;
            }
            if ($topLevelOnly && !self::isTopLevel($assignment)) {
                continue;
            }
            if ($assignment->getStartLine() > $callLine) {
                continue;
            }
            $resolved = self::literal($assignment->expr);
            if ($resolved === null) {
                return null;
            }
            if ($value !== null && $value !== $resolved) {
                return null;
            }
            $value = $resolved;
        }

        return $value;
    }

    private static function isTopLevel(Node $node): bool
    {
        $parent = $node->getAttribute('parent');
        while ($parent instanceof Node) {
            if (
                $parent instanceof Node\Stmt\ClassMethod
                || $parent instanceof Node\Stmt\Function_
                || $parent instanceof Node\Expr\Closure
                || $parent instanceof Node\Expr\ArrowFunction
            ) {
                return false;
            }
            $parent = $parent->getAttribute('parent');
        }

        return true;
    }

    /**
     * @param list<Node> $nodes
     */
    private static function enclosingFunction(
        Node $call,
        NodeFinder $finder,
        array $nodes
    ): Node\Stmt\ClassMethod|Node\Stmt\Function_|null {
        $target = spl_object_id($call);
        $functions = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_;
        });

        foreach ($functions as $function) {
            if (!$function instanceof Node\Stmt\ClassMethod && !$function instanceof Node\Stmt\Function_) {
                continue;
            }
            $found = $finder->find($function, static function (Node $node) use ($target): bool {
                return spl_object_id($node) === $target;
            });
            if ($found !== []) {
                return $function;
            }
        }

        return null;
    }
}
