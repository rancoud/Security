<?php

declare(strict_types=1);

namespace Rancoud\Security\Test;

use PHPUnit\Framework\TestCase;
use Rancoud\Security\Security;

/**
 * Class SecurityTest.
 */
class SecurityTest extends TestCase
{
    public function data(): array
    {
        return [
            'lambda' => ['name', 'name', 'UTF-8'],
            'empty' => ['', '', 'UTF-8'],
            //'special_1' => ['\'', '&#039;', 'UTF-8'],
            'special_2' => ['"', '&quot;', 'UTF-8'],
            'special_3' => ['<', '&lt;', 'UTF-8'],
            'special_4' => ['>', '&gt;', 'UTF-8'],
            'special_5' => ['&', '&amp;', 'UTF-8'],
            'xss' => ['<script>alert(1);</script>', '&lt;script&gt;alert(1);&lt;/script&gt;', 'UTF-8'],
            'html comment' => ['<!--...NEVER PUT UNTRUSTED DATA HERE...-->', '&lt;!--...NEVER PUT UNTRUSTED DATA HERE...--&gt;', 'UTF-8'],
            'div attr' => ['<div ...NEVER PUT UNTRUSTED DATA HERE...=test />', '&lt;div ...NEVER PUT UNTRUSTED DATA HERE...=test /&gt;', 'UTF-8'],
            'tag' => ['<NEVER PUT UNTRUSTED DATA HERE... href="/test" />', '&lt;NEVER PUT UNTRUSTED DATA HERE... href=&quot;/test&quot; /&gt;', 'UTF-8'],
            'css' => ['<style>...NEVER PUT UNTRUSTED DATA HERE...</style>', '&lt;style&gt;...NEVER PUT UNTRUSTED DATA HERE...&lt;/style&gt;', 'UTF-8'],
        ];
    }

    public function dataAttr(): array
    {
        return [
            'lambda' => ['name', 'name', 'UTF-8'],
            'empty' => ['', '', 'UTF-8'],
            //'special_1' => ['\'', '&#039;', 'UTF-8'],
            'special_2' => ['"', '&quot;', 'UTF-8'],
            'special_3' => ['<', '&lt;', 'UTF-8'],
            'special_4' => ['>', '&gt;', 'UTF-8'],
            'special_5' => ['&', '&amp;', 'UTF-8'],
            'xss' => ['<script>alert(1);</script>', '&lt;script&gt;alert&#x28;1&#x29;&#x3B;&lt;&#x2F;script&gt;', 'UTF-8'],
            'html comment' => ['<!--...NEVER PUT UNTRUSTED DATA HERE...-->', '&lt;&#x21;--...NEVER&#x20;PUT&#x20;UNTRUSTED&#x20;DATA&#x20;HERE...--&gt;', 'UTF-8'],
            'div attr' => ['<div ...NEVER PUT UNTRUSTED DATA HERE...=test />', '&lt;div&#x20;...NEVER&#x20;PUT&#x20;UNTRUSTED&#x20;DATA&#x20;HERE...&#x3D;test&#x20;&#x2F;&gt;', 'UTF-8'],
            'tag' => ['<NEVER PUT UNTRUSTED DATA HERE... href="/test" />', '&lt;NEVER&#x20;PUT&#x20;UNTRUSTED&#x20;DATA&#x20;HERE...&#x20;href&#x3D;&quot;&#x2F;test&quot;&#x20;&#x2F;&gt;', 'UTF-8'],
            'css' => ['<style>...NEVER PUT UNTRUSTED DATA HERE...</style>', '&lt;style&gt;...NEVER&#x20;PUT&#x20;UNTRUSTED&#x20;DATA&#x20;HERE...&lt;&#x2F;style&gt;', 'UTF-8'],
        ];
    }
    
    /**
     * @dataProvider dataAttr
     */
    public function testEscAttr($input, $expected, $charset): void
    {
        self::assertSame($expected, Security::escAttr($input, $charset));
    }
    /**
     * @dataProvider data
     */
    public function testEscHtml($input, $expected, $charset): void
    {
        self::assertSame($expected, Security::escHtml($input, $charset));
    }

    /**
     * @dataProvider data
     */
    public function testEscJs($input, $expected, $charset): void
    {
        self::assertSame($expected, Security::escJs($input, $charset));
    }

    /**
     * @dataProvider data
     */
    public function testTextarea($input, $expected, $charset): void
    {
        self::assertSame($expected, Security::escTextarea($input, $charset));
    }
}
