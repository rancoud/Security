<?php

declare(strict_types=1);

namespace Rancoud\Security\Test;

use PHPUnit\Framework\TestCase;
use Rancoud\Security\Security;
use Rancoud\Security\SecurityException;

/**
 * Class SecurityTest.
 */
class SecurityTest extends TestCase
{
    public function dataHTML(): array
    {
        return [
            'backtick' => ['`', '`'],
            'single quote' => ["'", '&#039;'],
            'double quote' => ['"', '&quot;'],
            'open tag' => ['<', '&lt;'],
            'close tag' => ['>', '&gt;'],
            'ampersand' => ['&', '&amp;'],
            'emoji' => ['😀', '😀'],
            'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", "\xF0\x90\x80\x80"],
            'comma' => [',', ','],
            'period' => ['.', '.'],
            'dash' => ['-', '-'],
            'underscore' => ['_', '_'],
            'a' => ['a', 'a'],
            'A' => ['A', 'A'],
            'z' => ['z', 'z'],
            'Z' => ['Z', 'Z'],
            '0' => ['0', '0'],
            '9' => ['9', '9'],
            'return carriage' => ["\r", "\r"],
            'new line' => ["\n", "\n"],
            'tabulation' => ["\t", "\t"],
            'backspace' => ["\x08", ''],
            'form feed' => ["\f", ''],
            'null' => ["\0", "\0"],
            'space' => [' ', ' '],
            'slash' => ['/', '&#47;'],
            'antislash' => ['\\', '\\'],
            'chinese' => ['你好', '你好'],
            'hindi' => ['नमस्ते', 'नमस्ते'],
            'japanese' => ['こんにちは', 'こんにちは'],
            'russian' => ['привет', 'привет'],
            'arabic' => ['صباح الخير', 'صباح الخير'],
            'cypriot' => ['𐠀', '𐠀'],
            'ideo' => ['嶲', '嶲'],
            'ideo2' => ['金', '金'],
            'ideo3' => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜'],
            'empty' => ['', '']
        ];
    }

    public function dataAttr(): array
    {
        return [
            'backtick' => ["`", '&#x60;'],
            'single quote' => ['\'', '&#x27;'],
            'double quote' => ['"', '&quot;'],
            'open tag' => ['<', '&lt;'],
            'close tag' => ['>', '&gt;'],
            'ampersand' => ['&', '&amp;'],
            'characters beyond value 255' => ['Ā', '&#x0100;'],
            'emoji' => ['😀', '&#x1F600;'],
            'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", '&#x10000;'],
            'comma' => [',', ','],
            'period' => ['.', '.'],
            'dash' => ['-', '-'],
            'underscore' => ['_', '_'],
            'a' => ['a', 'a'],
            'A' => ['A', 'A'],
            'z' => ['z', 'z'],
            'Z' => ['Z', 'Z'],
            '0' => ['0', '0'],
            '9' => ['9', '9'],
            'return carriage' => ["\r", '&#x0D;'],
            'new line' => ["\n", '&#x0A;'],
            'tabulation' => ["\t", '&#x09;'],
            'backspace' => ["\x08", '&#xFFFD;'],
            'form feed' => ["\f", '&#xFFFD;'],
            'null' => ["\0", '&#xFFFD;'],
            'space' => [' ' ,'&#x20;'],
            'slash' => ['/', '&#x2F;'],
            'antislash' => ['\\', '&#x5C;'],
            'chinese' => ['你好', '&#x4F60;&#x597D;'],
            'hindi' => ['नमस्ते', '&#x0928;&#x092E;&#x0938;&#x094D;&#x0924;&#x0947;'],
            'japanese' => ['こんにちは', '&#x3053;&#x3093;&#x306B;&#x3061;&#x306F;'],
            'russian' => ['привет', '&#x043F;&#x0440;&#x0438;&#x0432;&#x0435;&#x0442;'],
            'arabic' => ['صباح الخير', '&#x0635;&#x0628;&#x0627;&#x062D;&#x20;&#x0627;&#x0644;&#x062E;&#x064A;&#x0631;'],
            'cypriot' => ['𐠀', '&#x10800;'],
            'ideo' => ['嶲', '&#x2F9F4;'],
            'ideo2' => ['金', '&#x91D1;'],
            'ideo3' => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '&#xC20D;&#x8A0A;&#x6631;&#x7A7F;&#x5237;&#x5944;&#x5254;&#x33C6;&#x7A7D;&#x4F98;&#x320A;&#xC11E;&#x660C;&#x4F84;&#x5F9E;&#xC49C;'],
            'empty' => ['', '']
        ];
    }

    public function dataJS(): array
    {
        return [
            'backtick' => ["`", '\\x60'],
            'single quote' => ['\'', '\\x27'],
            'double quote' => ['"', '\\x22'],
            'open tag' => ['<', '\\x3C'],
            'close tag' => ['>', '\\x3E'],
            'ampersand' => ['&', '\\x26'],
            'characters beyond value 255' => ['Ā', '\\u0100'],
            'characters beyond unicode BMP' => ["\xF0\x90\x80\x80", '\\uD800\\uDC00'],
            'comma' => [',', ','],
            'period' => ['.', '.'],
            'dash' => ['-', '\\x2D'],
            'underscore' => ['_', '_'],
            'a' => ['a', 'a'],
            'A' => ['A', 'A'],
            'z' => ['z', 'z'],
            'Z' => ['Z', 'Z'],
            '0' => ['0', '0'],
            '9' => ['9', '9'],
            'return carriage' => ["\r", '\\r'],
            'new line' => ["\n", '\\n'],
            'tabulation' => ["\t", '\\t'],
            'backspace' => ["\x08", '\\b'],
            'form feed' => ["\f", '\\f'],
            'null' => ["\0", '\\x00'],
            'space' => [' ', '\\x20'],
            'slash' => ['/', '\\/'],
            'antislash' => ['\\', '\\\\'],
            'chinese' => ['你好', '\\u4F60\\u597D'],
            'hindi' => ['नमस्ते', '\\u0928\\u092E\\u0938\\u094D\\u0924\\u0947'],
            'japanese' => ['こんにちは', '\\u3053\\u3093\\u306B\\u3061\\u306F'],
            'russian' => ['привет', '\\u043F\\u0440\\u0438\\u0432\\u0435\\u0442'],
            'arabic' => ['صباح الخير', '\\u0635\\u0628\\u0627\\u062D\\x20\\u0627\\u0644\\u062E\\u064A\\u0631'],
            'cypriot' => ['𐠀', '\\uD802\\uDC00'],
            'ideo' => ['嶲', '\\uD87E\\uDDF4'],
            'ideo2' => ['金', '\\u91D1'],
            'ideo3' => ['숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', '\\uC20D\\u8A0A\\u6631\\u7A7F\\u5237\\u5944\\u5254\\u33C6\\u7A7D\\u4F98\\u320A\\uC11E\\u660C\\u4F84\\u5F9E\\uC49C'],
            'empty' => ['', '']
        ];
    }

    /**
     * @dataProvider dataHTML
     * @param string $input
     * @param string $expected
     * @throws SecurityException
     */
    public function testEscHtml(string $input, string $expected): void
    {
        self::assertSame($expected, Security::escHtml($input));
    }

    /**
     * @dataProvider dataAttr
     * @param string $input
     * @param string $expected
     * @throws SecurityException
     */
    public function testEscAttr(string $input, string $expected): void
    {
        self::assertSame($expected, Security::escAttr($input));
    }

    /**
     * @dataProvider dataJS
     * @param string $input
     * @param string $expected
     * @throws SecurityException
     */
    public function testEscJS(string $input, string $expected): void
    {
        self::assertSame($expected, Security::escJs($input));
    }

    public function testUnicodeEncodingXSS(): void
    {
        $this->expectException(SecurityException::class);

        self::assertSame('숝訊昱穿刷奄剔㝆穽侘㈊섞昌侄從쒜', Security::escHtml('숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', 'cp1252'));
        self::assertSame('&#x00EC;&#x02C6;&#xFFFD;&#x00E8;&#x00A8;&#x0160;&#x00E6;&#x02DC;&#x00B1;&#x00E7;&#x00A9;&#x00BF;&#x00E5;&#x02C6;&#x00B7;&#x00E5;&#x00A5;&#x201E;&#x00E5;&#x2030;&#x201D;&#x00E3;&#xFFFD;&#x2020;&#x00E7;&#x00A9;&#x00BD;&#x00E4;&#x00BE;&#x02DC;&#x00E3;&#x02C6;&#x0160;&#x00EC;&#x201E;&#x017E;&#x00E6;&#x02DC;&#x0152;&#x00E4;&#x00BE;&#x201E;&#x00E5;&#x00BE;&#x017E;&#x00EC;&#x2019;&#x0153;', Security::escAttr('숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', 'cp1252'));
        self::assertSame('\u00EC\u02C6\uFFFD\u00E8\u00A8\u0160\u00E6\u02DC\u00B1\u00E7\u00A9\u00BF\u00E5\u02C6\u00B7\u00E5\u00A5\u201E\u00E5\u2030\u201D\u00E3\uFFFD\u2020\u00E7\u00A9\u00BD\u00E4\u00BE\u02DC\u00E3\u02C6\u0160\u00EC\u201E\u017E\u00E6\u02DC\u0152\u00E4\u00BE\u201E\u00E5\u00BE\u017E\u00EC\u2019\u0153', Security::escJs('숍訊昱穿刷奄剔㏆穽侘㈊섞昌侄從쒜', 'cp1252'));
    }

    public function testCharsetNotSupportedException(): void
    {
        $countThrownExceptions = 0;

        try {
            Security::escHTML('a', 'nope');
        } catch (SecurityException $e) {
            self::assertSame("Charset 'nope' is not supported", $e->getMessage());
            $countThrownExceptions++;
        }

        try {
            Security::escAttr('a', 'nope');
        } catch (SecurityException $e) {
            self::assertSame("Charset 'nope' is not supported", $e->getMessage());
            $countThrownExceptions++;
        }

        try {
            Security::escJS('a', 'nope');
        } catch (SecurityException $e) {
            self::assertSame("Charset 'nope' is not supported", $e->getMessage());
            $countThrownExceptions++;
        }

        self::assertSame(3, $countThrownExceptions);
    }

    public function testInvalidCharacter(): void
    {
        $invalidChar = \chr(99999999);
        $countThrownExceptions = 0;

        try {
            Security::escHTML($invalidChar);
        } catch (SecurityException $e) {
            self::assertSame("String to convert is not valid for the specified charset", $e->getMessage());
            $countThrownExceptions++;
        }

        try {
            Security::escAttr($invalidChar);
        } catch (SecurityException $e) {
            self::assertSame("String to convert is not valid for the specified charset", $e->getMessage());
            $countThrownExceptions++;
        }

        try {
            Security::escJS($invalidChar);
        } catch (SecurityException $e) {
            self::assertSame("String to convert is not valid for the specified charset", $e->getMessage());
            $countThrownExceptions++;
        }

        self::assertSame(3, $countThrownExceptions);
    }
}
