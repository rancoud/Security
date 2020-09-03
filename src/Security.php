<?php

declare(strict_types=1);

namespace Rancoud\Security;

/**
 * Class Security.
 */
class Security
{
    /**
     * Array of charsets supported by PHP. It will be generated when first used.
     *
     * @var array|null
     */
    protected static ?array $supportedCharsets = null;

    /**
     * @return array
     */
    protected static function generateSupportedCharsets(): array
    {
        $maxSupportedCharsets = [
            'ISO-8859-1', 'ISO-8859-5', 'ISO-8859-15', 'UTF-8', 'CP866', 'CP1251', 'Windows-1251', 'CP1252',
            'Windows-1252', 'KOI8-R', 'BIG5', 'GB2312', 'BIG5-HKSCS', 'Shift_JIS', 'SJIS', 'SJIS-win', 'EUC-JP',
            'eucJP-win', 'CP932', 'MacRoman'
        ];

        $charsets = \array_intersect(\mb_list_encodings(), $maxSupportedCharsets);

        $callbackAliases = static function (string $charset) {
            return \mb_encoding_aliases($charset);
        };

        $aliases = \array_map($callbackAliases, $charsets);

        return \array_combine($charsets, $aliases);
    }

    /**
     * @param string $charset
     *
     * @return bool
     */
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
     * @param string $charset
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
     * @param mixed  $string
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
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

        /* @codeCoverageIgnoreStart */
        if ($string !== '' && \preg_match('/^./su', $string) !== 1) {
            throw new SecurityException('After conversion string is not a valid UTF-8 sequence');
        }
        /* @codeCoverageIgnoreEnd */

        return $string;
    }

    /**
     * @param mixed  $string
     * @param string $charset
     *
     * @return string
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
     * @param mixed  $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    public static function escHTML($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $text = \str_replace('/', '&#47;', $text);

        return static::convertStringFromUTF8($text, $charset);
    }

    /**
     * @param mixed  $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    public static function escAttr($text, string $charset = 'UTF-8'): string
    {
        $text = static::convertStringToUTF8($text, $charset);

        $text = \preg_replace_callback('/[^a-z0-9,.\-_]/iSu', static function ($matches) {
            $chr = $matches[0];
            $ord = \ord($chr);

            if (($ord <= 0x1f && $chr !== "\t" && $chr !== "\n" && $chr !== "\r")
                || ($ord >= 0x7f && $ord <= 0x9f)
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
     * @param mixed  $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
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
}
