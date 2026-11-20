<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

/**
 * Shared, token-aware detection of PHP backdoor payloads.
 *
 * Both `ObfuscatedAnalyzer` (responsible for `OBFUSCATED_PHP`) and
 * `RoguePhpAnalyzer` (`ROGUE_PHP`) need to answer "does this file hide an
 * executable payload?". Keeping the patterns and the string/comment stripping
 * in one place stops the two rules from drifting apart — the rogue rule only
 * raises severity to Critical when the same evidence the obfuscation rule uses
 * is present, instead of inventing a second, looser regex.
 *
 * Detection is conservative on purpose: pattern names inside documentation,
 * comments or string literals must not trip it (the self-scan used to flag
 * this package's own remediation text).
 */
final class PhpPayloadPatterns
{
    /** @var array<string, string> regex => human label */
    private const OBFUSCATION = [
        '/eval\s*\(\s*base64_decode\s*\(/i' => 'eval(base64_decode(...))',
        '/gzinflate\s*\(\s*base64_decode\s*\(/i' => 'gzinflate(base64_decode(...))',
        '/str_rot13\s*\(/i' => 'str_rot13(...)',
        '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(/i' => 'chr() concatenation',
    ];

    private const HEX_PATTERN = '/\\\\x[0-9a-f]{2}/i';

    /**
     * Code-execution sinks that must never appear in a file served straight
     * out of `public/`. Matched against stripped source so the names inside
     * docs/comments/strings stay silent.
     */
    private const DANGEROUS_CALL = '/\b(eval|assert|create_function|shell_exec|system|exec|passthru|popen|proc_open)\s*\(/i';

    /**
     * First obfuscation signal in the source, with the regex that matched.
     *
     * @return array{label: string, pattern: string}|null
     */
    public static function obfuscation(string $code): ?array
    {
        $stripped = self::stripStringsAndComments($code);
        foreach (self::OBFUSCATION as $pattern => $label) {
            if (preg_match($pattern, $stripped) === 1) {
                return ['label' => $label, 'pattern' => $pattern];
            }
        }

        // Hex escapes live inside string literals by definition, so stripping
        // would blind this check. Require density instead: real payloads carry
        // runs of escapes; short legit runs (BOM `\xEF\xBB\xBF`, newlines) stay
        // silent below 4.
        if (preg_match_all(self::HEX_PATTERN, $code) >= 4) {
            return ['label' => 'hex-encoded string', 'pattern' => self::HEX_PATTERN];
        }

        return null;
    }

    /**
     * Obfuscation OR a code-execution sink. Used by the rogue-file rule to
     * decide whether an unexpected `public/*.php` is a probable webshell
     * (Critical) or merely a convention violation (Warning).
     *
     * @return array{label: string, pattern: string}|null
     */
    public static function dangerous(string $code): ?array
    {
        $obfuscated = self::obfuscation($code);
        if ($obfuscated !== null) {
            return $obfuscated;
        }

        if (preg_match(self::DANGEROUS_CALL, self::stripStringsAndComments($code)) === 1) {
            return ['label' => 'dangerous function call', 'pattern' => self::DANGEROUS_CALL];
        }

        return null;
    }

    /**
     * Code with string literals, comments and HTML dropped, tokenized with the
     * native lexer (no extra dependency). Snippets without an open tag lex as
     * inline HTML, so a synthetic tag is prepended.
     */
    public static function stripStringsAndComments(string $code): string
    {
        if (!str_contains($code, '<?')) {
            $code = '<?php ' . $code;
        }
        $out = '';
        foreach (token_get_all($code) as $token) {
            if (is_string($token)) {
                $out .= $token . ' ';
                continue;
            }
            [$id, $text] = $token;
            if (in_array($id, [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML], true)) {
                $out .= ' ';
                continue;
            }
            $out .= $text . ' ';
        }

        return $out;
    }
}
