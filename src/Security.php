<?php

declare(strict_types=1);

namespace Rancoud\Security;

/**
 * Class Security.
 */
class Security
{
    protected static array $supportedCharsets = [
        'ISO-8859-1'  => true, // Western European, Latin-1
        'ISO-8859-5'  => true, // Little used cyrillic charset (Latin/Cyrillic)
        'ISO-8859-15' => true, // Western European, Latin-9
        'UTF-8'       => true, // ASCII compatible multi-byte 8-bit Unicode
        'cp866'       => true, // DOS-specific Cyrillic charset
        'cp1251'      => true, // Windows-specific Cyrillic charset
        'cp1252'      => true, // Windows specific charset for Western European
        'KOI8-R'      => true, // Russian
        'BIG5'        => true, // Traditional Chinese, mainly used in Taiwan
        'GB2312'      => true, // Simplified Chinese, national standard character set
        'BIG5-HKSCS'  => true, // Big5 with Hong Kong extensions, Traditional Chinese
        'Shift_JIS'   => true, // Japanese
        'EUC-JP'      => true, // Japanese
        'MacRoman'    => true  // Charset that was used by Mac OS
    ];

    /**
     * @param $string
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    protected static function convertStringToUtf8($string, $charset = 'UTF-8'): string
    {
        $string = (string) $string;

        if ($charset !== 'UTF-8') {
            $string = \mb_convert_encoding($string, 'UTF-8', $charset);
        }

        if ($string !== '' && \preg_match('/^./su', $string) !== 1) {
            throw new SecurityException('After conversion string is not a valid UTF-8 sequence');
        }

        return $string;
    }

    /**
     * @param $string
     * @param string $charset
     *
     * @return string
     */
    protected static function convertStringFromUtf8($string, $charset = 'UTF-8'): string
    {
        $string = (string) $string;

        if ($charset === 'UTF-8') {
            return $string;
        }

        $string = \mb_convert_encoding($string, $charset, 'UTF-8');

        return $string;
    }

    /**
     * @param string $charset
     *
     * @return bool
     */
    public static function isCharsetSupported(string $charset): bool
    {
        return isset(static::$supportedCharsets[$charset]);
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    public static function escHtml($text, string $charset = 'UTF-8'): string
    {
        if (!static::isCharsetSupported($charset)) {
            throw new SecurityException(\sprintf("Charset '%s' is not supported", $charset));
        }

        $text = static::convertStringToUtf8($text, $charset);

        $text = \htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, $charset);
        $text = \str_replace('/', '&#47;', $text);

        $text = static::convertStringFromUtf8($text, $charset);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    public static function escAttr($text, string $charset = 'UTF-8'): string
    {
        if (!static::isCharsetSupported($charset)) {
            throw new SecurityException(\sprintf("Charset '%s' is not supported", $charset));
        }

        $text = static::convertStringToUtf8($text, $charset);

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

        $text = static::convertStringFromUtf8($text, $charset);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    public static function escJs($text, string $charset = 'UTF-8'): string
    {
        if (!static::isCharsetSupported($charset)) {
            throw new SecurityException(\sprintf("Charset '%s' is not supported", $charset));
        }

        $text = static::convertStringToUtf8($text, $charset);

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

        $text = static::convertStringFromUtf8($text, $charset);

        return $text;
    }
}
