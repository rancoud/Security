<?php

declare(strict_types=1);

namespace Rancoud\Security;

/**
 * Class Security.
 */
class Security
{
    /**
     * @param        $string
     * @param string $charset
     *
     * @return string
     */
    public static function sanitizeUtf8Text($string, string $charset = 'UTF-8'): string
    {
        $string = (string) $string;

        if ($string === '') {
            return '';
        }

        if ($charset !== 'UTF-8') {
            return $string;
        }

        static $utf8Pcre = null;
        if (!isset($utf8Pcre)) {
            $utf8Pcre = \preg_match('/^./u', 'a');
        }

        if (!$utf8Pcre) {
            return $string;
        }

        if (\preg_match('/^./us', $string) === 1) {
            return $string;
        }

        return '';
    }

    /**
     * @param        $string
     * @param int    $quote
     * @param string $charset
     *
     * @return string
     */
    public static function htmlspecialchars($string, int $quote = ENT_NOQUOTES, string $charset = 'UTF-8'): string
    {
        $string = (string) $string;

        if ($string === '') {
            return '';
        }

        if (!\in_array($quote, [ENT_NOQUOTES, ENT_COMPAT, ENT_QUOTES], true)) {
            $quote = ENT_QUOTES;
        }

        if ($charset !== 'UTF-8') {
            $string = \mb_convert_encoding($string, 'UTF-8', $charset);
        }

        return \htmlspecialchars($string, $quote | ENT_SUBSTITUTE, $charset);
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escAttr($text, string $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text, $charset);

        $text = \preg_replace_callback('#[^a-zA-Z0-9,.\-_]#Su', static function ($matches) {
            $chr = $matches[0];
            $ord = \mb_ord($chr);

            if (($ord <= 0x1f && "\t" !== $chr && "\n" !== $chr && "\r" !== $chr) || ($ord >= 0x7f && $ord <= 0x9f)) {
                return '&#xFFFD;';
            }

            if (\mb_strlen($chr) === 1) {
                static $entityMap = [
                    34 => '&quot;',
                    38 => '&amp;',
                    60 => '&lt;',
                    62 => '&gt;'
                ];

                return $entityMap[$ord] ?? \sprintf('&#x%02X;', $ord);
            }

            return \sprintf('&#x%04X;', \mb_ord($chr, 'UTF-8'));
        }, $text);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escHtml($text, string $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text, $charset);
        $text = static::htmlspecialchars($text, ENT_QUOTES, $charset);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escJs($text, string $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text, $charset);
        $text = static::htmlspecialchars($text, ENT_COMPAT, $charset);
        $text = \preg_replace('/&#(x)?0*(?(1)27|39);?/i', "'", \stripslashes($text));
        $text = \str_replace("\r", '', $text);
        $text = \str_replace("\n", '\\n', \addslashes($text));

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escTextarea($text, string $charset = 'UTF-8'): string
    {
        return \htmlspecialchars($text, ENT_QUOTES, $charset);
    }
}
