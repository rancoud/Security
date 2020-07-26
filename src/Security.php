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
    private static ?array $supportedCharsets = null;

    /**
     * @return array
     */
    private static function generateSupportedCharsets(): array
    {
        $charsets = \array_map('\strtolower', \mb_list_encodings());

        $callbackAliases = static function (string $charset) {
            return \array_map('\strtolower', \mb_encoding_aliases($charset));
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
        if (self::$supportedCharsets === null) {
            self::$supportedCharsets = self::generateSupportedCharsets();
        }

        $lowerCharset = \strtolower($charset);

        if (isset(self::$supportedCharsets[$lowerCharset])) {
            return true;
        }

        foreach (self::$supportedCharsets as $aliases) {
            if (\in_array($lowerCharset, $aliases, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $charset
     *
     * @throw SecurityException
     */
    protected static function throwExceptionIfCharsetIsUnsupported(string $charset): void
    {
        if (!static::isSupportedCharset($charset)) {
            // should we encode charset?
            throw new SecurityException(\sprintf("Charset '%s' is not supported", $charset));
        }
    }

    /**
     * @param string $charset1
     * @param string $charset2
     *
     * @throws SecurityException
     *
     * @return bool
     */
    public static function areCharsetAliases(string $charset1, string $charset2): bool
    {
        static::throwExceptionIfCharsetIsUnsupported($charset1);
        static::throwExceptionIfCharsetIsUnsupported($charset2);

        $lowerCharset1 = \strtolower($charset1);
        $lowerCharset2 = \strtolower($charset2);

        if ($lowerCharset1 === $lowerCharset2) {
            return true;
        }

        if (isset(self::$supportedCharsets[$lowerCharset1])) {
            return \in_array($lowerCharset2, self::$supportedCharsets[$lowerCharset1], true);
        }

        if (isset(self::$supportedCharsets[$lowerCharset2])) {
            return \in_array($lowerCharset1, self::$supportedCharsets[$lowerCharset2], true);
        }

        foreach (self::$supportedCharsets as $aliases) {
            $isAlias1 = \in_array($lowerCharset1, $aliases, true);
            $isAlias2 = \in_array($lowerCharset2, $aliases, true);

            if ($isAlias1 || $isAlias2) {
                return $isAlias1 && $isAlias2;
            }
        }

        return false;
    }

    /**
     * @param string $charset
     *
     * @return bool
     */
    public static function isUTF8Alias(string $charset): bool
    {
        $lowerCharset = \strtolower($charset);

        return \strtolower($charset) === 'utf-8'
            || \in_array($lowerCharset, self::$supportedCharsets['utf-8'], true);
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

        if (!static::isUTF8Alias($charset)) {
            $string = \mb_convert_encoding($string, 'UTF-8', $charset);
        }

        if ($string !== '' && \preg_match('/^./su', $string) !== 1) {
            throw new SecurityException('After conversion string is not a valid UTF-8 sequence');
        }

        return $string;
    }

    /**
     * @param mixed  $string
     * @param string $charset
     *
     * @throws SecurityException
     *
     * @return string
     */
    protected static function convertStringFromUTF8($string, string $charset = 'UTF-8'): string
    {
        // static::throwExceptionIfCharsetIsUnsupported($charset); // useless

        $string = (string) $string;

        if (static::isUTF8Alias($charset)) {
            return $string;
        }

        $string = \mb_convert_encoding($string, $charset, 'UTF-8');

        return $string;
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

        $text = static::convertStringFromUTF8($text, $charset);

        return $text;
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

        $text = static::convertStringFromUTF8($text, $charset);

        return $text;
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

        $text = static::convertStringFromUTF8($text, $charset);

        return $text;
    }
}
