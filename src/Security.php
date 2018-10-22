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

        if (mb_strlen($string) === 0) {
            return '';
        }

        if ($charset !== 'UTF-8') {
            return $string;
        }

        static $utf8Pcre = null;
        if (!isset($utf8Pcre)) {
            $utf8Pcre = preg_match('/^./u', 'a');
        }

        if (!$utf8Pcre) {
            return $string;
        }

        if (preg_match('/^./us', $string) === 1) {
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
    public static function htmlspecialchars($string, int $quote = ENT_NOQUOTES, string $charset = 'UTF-8')
    {
        $string = (string) $string;

        if (mb_strlen($string) === 0) {
            return '';
        }

        if (!\in_array($quote, [ENT_NOQUOTES, ENT_COMPAT, ENT_QUOTES], true)) {
            $quote = ENT_QUOTES;
        }

        if ($charset !== 'UTF-8') {
            $string = mb_convert_encoding($string, 'UTF-8', $charset);
        }

        return htmlspecialchars($string, $quote | ENT_SUBSTITUTE, $charset);
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escAttr($text, $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text);

        $text = preg_replace_callback('#[^a-zA-Z0-9,\.\-_]#Su', function ($matches) {
            $chr = $matches[0];
            $ord = ord($chr);

            if (($ord <= 0x1f && "\t" != $chr && "\n" != $chr && "\r" != $chr) || ($ord >= 0x7f && $ord <= 0x9f)) {
                return '&#xFFFD;';
            }

            if (mb_strlen($chr) === 1) {
                static $entityMap = [
                    34 => '&quot;',
                    38 => '&amp;',
                    60 => '&lt;',
                    62 => '&gt;'
                ];
                if (isset($entityMap[$ord])) {
                    return $entityMap[$ord];
                }
                return sprintf('&#x%02X;', $ord);
            }

            return sprintf('&#x%04X;', mb_ord($chr, 'UTF-8'));
        }, $text);

        //$text = static::htmlspecialchars($text, ENT_QUOTES, $charset);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escHtml($text, $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text);
        $text = static::htmlspecialchars($text, ENT_QUOTES, $charset);

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escJs($text, $charset = 'UTF-8'): string
    {
        $text = static::sanitizeUtf8Text($text);
        $text = static::htmlspecialchars($text, ENT_COMPAT, $charset);
        $text = preg_replace('/&#(x)?0*(?(1)27|39);?/i', "'", stripslashes($text));
        $text = str_replace("\r", '', $text);
        $text = str_replace("\n", '\\n', addslashes($text));

        return $text;
    }

    /**
     * @param        $text
     * @param string $charset
     *
     * @return string
     */
    public static function escTextarea($text, $charset = 'UTF-8'): string
    {
        return htmlspecialchars($text, ENT_QUOTES, $charset);
    }

    /*public static function esc_url($url, $protocols = null, $_context = 'display')
    {
        if ('' == $url) {
            return $url;
        }

        $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);
        if (0 !== stripos($url, 'mailto:')) {
            $strip = ['%0d', '%0a', '%0D', '%0A'];
            $url = static::deepReplace($strip, $url);
        }
        $url = str_replace(';//', '://', $url);

        if (strpos($url, ':') === false && !in_array($url[0], ['/', '#', '?']) && !preg_match('/^[a-z0-9-]+?\.php/i', $url)) {
            $url = 'http://' . $url;
        }

        // Replace ampersands and single quotes only when displaying.
        if ('display' == $_context) {
            $url = wp_kses_normalize_entities($url);
            $url = str_replace('&amp;', '&#038;', $url);
            $url = str_replace("'", '&#039;', $url);
        }

        if ('/' === $url[0]) {
            $good_protocol_url = $url;
        } else {
            if (!is_array($protocols)) {
                $protocols = ['http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'gopher', 'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'svn', 'tel', 'fax', 'xmpp', 'webcal'];
            }
            $good_protocol_url = wp_kses_bad_protocol($url, $protocols);
            if (strtolower($good_protocol_url) != strtolower($url)) {
                return '';
            }
        }

        return $good_protocol_url;
    }*/

    /*public static function escUrlRaw($url, $protocols = null)
    {
        return esc_url($url, $protocols, 'db');
    }*/

    /*
     * @param $email
     *
     * @return bool
     */
    /*public static function isValidEmail($email): bool
    {
        if (mb_strlen($email) < 3) {
            return false;
        }

        if (mb_strpos($email, '@', 1) === false) {
            return false;
        }

        return true;
    }*/

    /*
     * @param $search
     * @param $subject
     *
     * @return mixed|string
     */
    /*public static function deepReplace($search, $subject)
    {
        $subject = (string) $subject;

        $count = 1;
        while ($count) {
            $subject = str_replace($search, '', $subject, $count);
        }

        return $subject;
    }*/
}
