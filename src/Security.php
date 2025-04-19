<?php

declare(strict_types=1);

namespace Rancoud\Security;

/**
 * Class Security.
 */
class Security
{
    /**
     * @var array|null Array of supported charsets by PHP.<br>
     *                 It will be populate on the first usage.
     */
    protected static ?array $supportedCharsets = null;

    /**
     * Populate supported charsets.<br>
     * It will keep only supported encodings and aliases that are in the shortlist
     * and available on the current PHP installation.<br>
     * Current shortlist are:
     * - BIG5
     * - BIG5-HKSCS
     * - CP866
     * - CP932
     * - CP1251
     * - CP1252
     * - EUC-JP
     * - eucJP-win
     * - GB2312
     * - ISO-8859-1
     * - ISO-8859-5
     * - ISO-8859-15
     * - KOI8-R
     * - MacRoman
     * - Shift_JIS
     * - SJIS
     * - SJIS-win
     * - UTF-8
     * - Windows-1251
     * - Windows-1252.
     */
    protected static function generateSupportedCharsets(): array
    {
        $shortlistSupportedCharsets = [
            'ISO-8859-1', 'ISO-8859-5', 'ISO-8859-15', 'UTF-8', 'CP866', 'CP1251', 'Windows-1251', 'CP1252',
            'Windows-1252', 'KOI8-R', 'BIG5', 'GB2312', 'BIG5-HKSCS', 'Shift_JIS', 'SJIS', 'SJIS-win', 'EUC-JP',
            'eucJP-win', 'CP932', 'MacRoman'
        ];

        $charsets = \array_intersect(\mb_list_encodings(), $shortlistSupportedCharsets);

        $callbackAliases = static function (string $charset) {
            return \mb_encoding_aliases($charset);
        };

        $aliases = \array_map($callbackAliases, $charsets);

        return \array_combine($charsets, $aliases);
    }

    /** Checks if charset is supported. */
    public static function isSupportedCharset(string $charset): bool
    {
        if (static::$supportedCharsets === null) {
            static::$supportedCharsets = static::generateSupportedCharsets();
        }

        if (isset(static::$supportedCharsets[$charset])) {
            return true;
        }

        foreach (static::$supportedCharsets as $aliases) {
            if (\in_array($charset, $aliases, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Throws Security Exception if charset is not supported.
     *
     * @throws SecurityException
     */
    protected static function throwExceptionIfCharsetIsUnsupported(string $charset): void
    {
        if (!static::isSupportedCharset($charset)) {
            throw new SecurityException(\sprintf("Charset '%s' is not supported", $charset));
        }
    }

    /**
     * Converts string from any charset to UTF-8.
     *
     * @throws SecurityException
     */
    protected static function convertStringToUTF8($string, string $charset = 'UTF-8'): string
    {
        static::throwExceptionIfCharsetIsUnsupported($charset);

        $string = (string) $string;

        if (!\mb_check_encoding($string, $charset)) {
            throw new SecurityException('String to convert is not valid for the specified charset');
        }

        if ($charset !== 'UTF-8') {
            $string = \mb_convert_encoding($string, 'UTF-8', $charset);
        }

        // @codeCoverageIgnoreStart
        // I don't know how to reach this statement
        if ($string !== '' && \preg_match('/^./su', $string) !== 1) {
            throw new SecurityException('After conversion string is not a valid UTF-8 sequence');
        }
        // @codeCoverageIgnoreEnd

        return $string;
    }

    /**
     * Converts string from UTF-8 to any charset.
     */
    protected static function convertStringFromUTF8($string, string $charset = 'UTF-8'): string
    {
        $string = (string) $string;

        if ($charset === 'UTF-8') {
            return $string;
        }

        return \mb_convert_encoding($string, $charset, 'UTF-8');
    }

    /**
     * Escapes text for HTML output.
     *
     * @throws SecurityException
     */
    public static function escHTML($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \htmlspecialchars($text, \ENT_QUOTES | \ENT_SUBSTITUTE);
        $text = \str_replace('/', '&#47;', $text);

        return static::convertStringFromUTF8($text, $charset);
    }

    /**
     * Escapes text for HTML attribute output.
     *
     * @throws SecurityException
     */
    public static function escAttr($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \preg_replace_callback('/[^a-z0-9,.\-_]/iSu', static function ($matches) {
            $chr = $matches[0];
            $ord = \ord($chr);

            if (($ord <= 0x1F && $chr !== "\t" && $chr !== "\n" && $chr !== "\r")
                || ($ord >= 0x7F && $ord <= 0x9F)
            ) {
                return '&#xFFFD;';
            }

            static $entityMap = [
                34 => '&quot;',
                38 => '&amp;',
                60 => '&lt;',
                62 => '&gt;'
            ];

            if (\strlen($chr) === 1) {
                return $entityMap[$ord] ?? \sprintf('&#x%02X;', $ord);
            }

            $chr = \mb_convert_encoding($chr, 'UTF-32BE', 'UTF-8');

            $hex = \bin2hex($chr);
            $ord = \hexdec($hex);

            return $entityMap[$ord] ?? \sprintf('&#x%04X;', $ord);
        }, $text);

        return static::convertStringFromUTF8($text, $charset);
    }

    /**
     * Escapes text for JS output.
     *
     * @throws SecurityException
     */
    public static function escJS($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \preg_replace_callback('/[^a-z0-9,._]/iSu', static function ($matches) {
            $chr = $matches[0];

            static $controlMap = [
                '\\'   => '\\\\',
                '/'    => '\\/',
                "\x08" => '\b',
                "\x0C" => '\f',
                "\x0A" => '\n',
                "\x0D" => '\r',
                "\x09" => '\t',
            ];

            if (isset($controlMap[$chr])) {
                return $controlMap[$chr];
            }

            if (\strlen($chr) === 1) {
                return \sprintf('\\x%02X', \ord($chr));
            }

            $chr = \mb_convert_encoding($chr, 'UTF-16BE', 'UTF-8');
            $hex = \strtoupper(\bin2hex($chr));
            if (\strlen($hex) <= 4) {
                return \sprintf('\\u%04s', $hex);
            }

            $highSurrogate = \substr($hex, 0, 4);
            $lowSurrogate = \substr($hex, 4, 4);

            return \sprintf('\\u%04s\\u%04s', $highSurrogate, $lowSurrogate);
        }, $text);

        return static::convertStringFromUTF8($text, $charset);
    }

    /**
     * Escapes text for URL output.
     *
     * @throws SecurityException
     */
    public static function escURL($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \rawurlencode($text);

        return static::convertStringFromUTF8($text, $charset);
    }

    /**
     * Escapes text for CSS output.
     *
     * @throws SecurityException
     */
    public static function escCSS($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \preg_replace_callback('/[^a-z0-9]/iSu', static function ($matches) {
            $chr = $matches[0];

            if (\strlen($chr) === 1) {
                $ord = \ord($chr);
            } else {
                $chr = \mb_convert_encoding($chr, 'UTF-32BE', 'UTF-8');
                $ord = \hexdec(\bin2hex($chr));
            }

            return \sprintf('\\%X ', $ord);
        }, $text);

        return static::convertStringFromUTF8($text, $charset);
    }
}
