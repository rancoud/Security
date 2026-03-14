<?php

declare(strict_types=1);

namespace tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Rancoud\Security\Security;
use Rancoud\Security\SecurityException;

/**
 * @internal
 */
class SecurityTest extends TestCase
{
    public static function provideEscHTMLDataCases(): iterable
    {
        yield 'backtick'                      => ['`', '`'];

        yield 'single quote'                  => ["'", '&#039;'];

        yield 'double quote'                  => ['"', '&quot;'];

        yield 'open tag'                      => ['<', '&lt;'];

        yield 'close tag'                     => ['>', '&gt;'];

        yield 'ampersand'                     => ['&', '&amp;'];

        yield 'emoji'                         => ['😀', '😀'];

        yield 'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", "\xF0\x90\x80\x80"];

        yield 'comma'                         => [',', ','];

        yield 'period'                        => ['.', '.'];

        yield 'dash'                          => ['-', '-'];

        yield 'underscore'                    => ['_', '_'];

        yield 'a'                             => ['a', 'a'];

        yield 'A'                             => ['A', 'A'];

        yield 'z'                             => ['z', 'z'];

        yield 'Z'                             => ['Z', 'Z'];

        yield '0'                             => ['0', '0'];

        yield '9'                             => ['9', '9'];

        yield 'return carriage'               => ["\r", "\r"];

        yield 'new line'                      => ["\n", "\n"];

        yield 'tabulation'                    => ["\t", "\t"];

        yield 'backspace'                     => ["\x08", ''];

        yield 'form feed'                     => ["\f", \chr(0xC)];

        yield 'null'                          => ["\0", "\0"];

        yield 'space'                         => [' ', ' '];

        yield 'slash'                         => ['/', '&#47;'];

        yield 'antislash'                     => ['\\', '\\'];

        yield 'chinese'                       => ['你好', '你好'];

        yield 'hindi'                         => ['नमस्ते', 'नमस्ते'];

        yield 'japanese'                      => ['こんにちは', 'こんにちは'];

        yield 'russian'                       => ['привет', 'привет'];

        yield 'arabic'                        => ['صباح الخير', 'صباح الخير'];

        yield 'cypriot'                       => ['𐠀', '𐠀'];

        yield 'ideo'                          => ['嶲', '嶲'];

        yield 'ideo2'                         => ['金', '金'];

        yield 'ideo3'                         => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜'];

        yield 'empty'                         => ['', ''];
    }

    /** @throws SecurityException */
    #[DataProvider('provideEscHTMLDataCases')]
    public function testEscHTML(string $input, string $expected): void
    {
        static::assertSame($expected, Security::escHTML($input));
    }

    public static function provideEscAttrDataCases(): iterable
    {
        yield 'backtick'                      => ['`', '&#x60;'];

        yield 'single quote'                  => ['\'', '&#x27;'];

        yield 'double quote'                  => ['"', '&quot;'];

        yield 'open tag'                      => ['<', '&lt;'];

        yield 'close tag'                     => ['>', '&gt;'];

        yield 'ampersand'                     => ['&', '&amp;'];

        yield 'characters beyond value 255'   => ['Ā', '&#x0100;'];

        yield 'emoji'                         => ['😀', '&#x1F600;'];

        yield 'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", '&#x10000;'];

        yield 'comma'                         => [',', ','];

        yield 'period'                        => ['.', '.'];

        yield 'dash'                          => ['-', '-'];

        yield 'underscore'                    => ['_', '_'];

        yield 'a'                             => ['a', 'a'];

        yield 'A'                             => ['A', 'A'];

        yield 'z'                             => ['z', 'z'];

        yield 'Z'                             => ['Z', 'Z'];

        yield '0'                             => ['0', '0'];

        yield '9'                             => ['9', '9'];

        yield 'return carriage'               => ["\r", '&#x0D;'];

        yield 'new line'                      => ["\n", '&#x0A;'];

        yield 'tabulation'                    => ["\t", '&#x09;'];

        yield 'backspace'                     => ["\x08", '&#xFFFD;'];

        yield 'form feed'                     => ["\f", '&#xFFFD;'];

        yield 'null'                          => ["\0", '&#xFFFD;'];

        yield 'space'                         => [' ', '&#x20;'];

        yield 'slash'                         => ['/', '&#x2F;'];

        yield 'antislash'                     => ['\\', '&#x5C;'];

        yield 'chinese'                       => ['你好', '&#x4F60;&#x597D;'];

        yield 'hindi'                         => ['नमस्ते', '&#x0928;&#x092E;&#x0938;&#x094D;&#x0924;&#x0947;'];

        yield 'japanese'                      => ['こんにちは', '&#x3053;&#x3093;&#x306B;&#x3061;&#x306F;'];

        yield 'russian'                       => ['привет', '&#x043F;&#x0440;&#x0438;&#x0432;&#x0435;&#x0442;'];

        yield 'arabic'                        => ['صباح الخير', '&#x0635;&#x0628;&#x0627;&#x062D;&#x20;&#x0627;&#x0644;&#x062E;&#x064A;&#x0631;'];

        yield 'cypriot'                       => ['𐠀', '&#x10800;'];

        yield 'ideo'                          => ['嶲', '&#x2F9F4;'];

        yield 'ideo2'                         => ['金', '&#x91D1;'];

        yield 'ideo3'                         => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '&#xC20D;&#x8A0A;&#x6631;&#x7A7F;&#x5237;&#x5944;&#x5254;&#x33C6;&#x7A7D;&#x4F98;&#x320A;&#xC11E;&#x660C;&#x4F84;&#x5F9E;&#xC49C;'];

        yield 'empty'                         => ['', ''];
    }

    /** @throws SecurityException */
    #[DataProvider('provideEscAttrDataCases')]
    public function testEscAttr(string $input, string $expected): void
    {
        static::assertSame($expected, Security::escAttr($input));
    }

    public static function provideEscJSDataCases(): iterable
    {
        yield 'backtick'                      => ['`', '\\x60'];

        yield 'single quote'                  => ['\'', '\\x27'];

        yield 'double quote'                  => ['"', '\\x22'];

        yield 'open tag'                      => ['<', '\\x3C'];

        yield 'close tag'                     => ['>', '\\x3E'];

        yield 'ampersand'                     => ['&', '\\x26'];

        yield 'characters beyond value 255'   => ['Ā', '\\u0100'];

        yield 'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", '\\uD800\\uDC00'];

        yield 'comma'                         => [',', ','];

        yield 'period'                        => ['.', '.'];

        yield 'dash'                          => ['-', '\\x2D'];

        yield 'underscore'                    => ['_', '_'];

        yield 'a'                             => ['a', 'a'];

        yield 'A'                             => ['A', 'A'];

        yield 'z'                             => ['z', 'z'];

        yield 'Z'                             => ['Z', 'Z'];

        yield '0'                             => ['0', '0'];

        yield '9'                             => ['9', '9'];

        yield 'return carriage'               => ["\r", '\\r'];

        yield 'new line'                      => ["\n", '\\n'];

        yield 'tabulation'                    => ["\t", '\\t'];

        yield 'backspace'                     => ["\x08", '\\b'];

        yield 'form feed'                     => ["\f", '\\f'];

        yield 'null'                          => ["\0", '\\x00'];

        yield 'space'                         => [' ', '\\x20'];

        yield 'slash'                         => ['/', '\\/'];

        yield 'antislash'                     => ['\\', '\\\\'];

        yield 'chinese'                       => ['你好', '\\u4F60\\u597D'];

        yield 'hindi'                         => ['नमस्ते', '\\u0928\\u092E\\u0938\\u094D\\u0924\\u0947'];

        yield 'japanese'                      => ['こんにちは', '\\u3053\\u3093\\u306B\\u3061\\u306F'];

        yield 'russian'                       => ['привет', '\\u043F\\u0440\\u0438\\u0432\\u0435\\u0442'];

        yield 'arabic'                        => ['صباح الخير', '\\u0635\\u0628\\u0627\\u062D\\x20\\u0627\\u0644\\u062E\\u064A\\u0631'];

        yield 'cypriot'                       => ['𐠀', '\\uD802\\uDC00'];

        yield 'ideo'                          => ['嶲', '\\uD87E\\uDDF4'];

        yield 'ideo2'                         => ['金', '\\u91D1'];

        yield 'ideo3'                         => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '\\uC20D\\u8A0A\\u6631\\u7A7F\\u5237\\u5944\\u5254\\u33C6\\u7A7D\\u4F98\\u320A\\uC11E\\u660C\\u4F84\\u5F9E\\uC49C'];

        yield 'empty'                         => ['', ''];
    }

    /** @throws SecurityException */
    #[DataProvider('provideEscJSDataCases')]
    public function testEscJS(string $input, string $expected): void
    {
        static::assertSame($expected, Security::escJS($input));
    }

    public static function provideEscURLDataCases(): iterable
    {
        yield '<'  => ['<', '%3C'];

        yield '>'  => ['>', '%3E'];

        yield '\'' => ['\'', '%27'];

        yield '"'  => ['"', '%22'];

        yield '&'  => ['&', '%26'];

        yield 'Ā'  => ['Ā', '%C4%80'];

        yield ','  => [',', '%2C'];

        yield '.'  => ['.', '.'];

        yield '_'  => ['_', '_'];

        yield '-'  => ['-', '-'];

        yield ':'  => [':', '%3A'];

        yield ';'  => [';', '%3B'];

        yield '!'  => ['!', '%21'];

        yield 'a'  => ['a', 'a'];

        yield 'A'  => ['A', 'A'];

        yield 'z'  => ['z', 'z'];

        yield 'Z'  => ['Z', 'Z'];

        yield '0'  => ['0', '0'];

        yield '9'  => ['9', '9'];

        yield "\r" => ["\r", '%0D'];

        yield "\n" => ["\n", '%0A'];

        yield "\t" => ["\t", '%09'];

        yield "\0" => ["\0", '%00'];

        yield ' '  => [' ', '%20'];

        yield '~'  => ['~', '~'];

        yield '+'  => ['+', '%2B'];
    }

    /** @throws SecurityException */
    #[DataProvider('provideEscURLDataCases')]
    public function testEscURL(string $input, string $expected): void
    {
        static::assertSame($expected, Security::escURL($input));
    }

    public static function provideEscCSSDataCases(): iterable
    {
        yield '<'                => ['<', '\\3C '];

        yield '>'                => ['>', '\\3E '];

        yield '\''               => ['\'', '\\27 '];

        yield '"'                => ['"', '\\22 '];

        yield '&'                => ['&', '\\26 '];

        yield 'Ā'                => ['Ā', '\\100 '];

        yield "\xF0\x90\x80\x80" => ["\xF0\x90\x80\x80", '\\10000 '];

        yield ','                => [',', '\\2C '];

        yield '.'                => ['.', '\\2E '];

        yield '_'                => ['_', '\\5F '];

        yield 'a'                => ['a', 'a'];

        yield 'A'                => ['A', 'A'];

        yield 'z'                => ['z', 'z'];

        yield 'Z'                => ['Z', 'Z'];

        yield '0'                => ['0', '0'];

        yield '9'                => ['9', '9'];

        yield "\r"               => ["\r", '\\D '];

        yield "\n"               => ["\n", '\\A '];

        yield "\t"               => ["\t", '\\9 '];

        yield "\0"               => ["\0", '\\0 '];

        yield ' '                => [' ', '\\20 '];
    }

    /** @throws SecurityException */
    #[DataProvider('provideEscCSSDataCases')]
    public function testEscCSS(string $input, string $expected): void
    {
        static::assertSame($expected, Security::escCSS($input));
    }

    public function testCharsetNotSupportedException(): void
    {
        $countThrownExceptions = 0;

        try {
            Security::escHTML('a', 'nope');
        } catch (SecurityException $e) {
            static::assertSame("Charset 'nope' is not supported", $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escAttr('a', 'nope');
        } catch (SecurityException $e) {
            static::assertSame("Charset 'nope' is not supported", $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escJS('a', 'nope');
        } catch (SecurityException $e) {
            static::assertSame("Charset 'nope' is not supported", $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escURL('a', 'nope');
        } catch (SecurityException $e) {
            static::assertSame("Charset 'nope' is not supported", $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escCSS('a', 'nope');
        } catch (SecurityException $e) {
            static::assertSame("Charset 'nope' is not supported", $e->getMessage());
            ++$countThrownExceptions;
        }

        static::assertSame(5, $countThrownExceptions);
    }

    public function testInvalidCharacter(): void
    {
        $invalidChar = \chr(99999999);
        $countThrownExceptions = 0;

        try {
            Security::escHTML($invalidChar);
        } catch (SecurityException $e) {
            static::assertSame('String to convert is not valid for the specified charset', $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escAttr($invalidChar);
        } catch (SecurityException $e) {
            static::assertSame('String to convert is not valid for the specified charset', $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escJS($invalidChar);
        } catch (SecurityException $e) {
            static::assertSame('String to convert is not valid for the specified charset', $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escURL($invalidChar);
        } catch (SecurityException $e) {
            static::assertSame('String to convert is not valid for the specified charset', $e->getMessage());
            ++$countThrownExceptions;
        }

        try {
            Security::escCSS($invalidChar);
        } catch (SecurityException $e) {
            static::assertSame('String to convert is not valid for the specified charset', $e->getMessage());
            ++$countThrownExceptions;
        }

        static::assertSame(5, $countThrownExceptions);
    }

    /** @throws SecurityException */
    public function testLatin1Encoding(): void
    {
        static::assertSame('été', Security::escHTML('été', 'latin1'));
        static::assertSame('&#x00C3;&#x00A9;t&#x00C3;&#x00A9;', Security::escAttr('été', 'latin1'));
        static::assertSame("\u00C3\u00A9t\u00C3\u00A9", Security::escJS('été', 'latin1'));
    }
}
