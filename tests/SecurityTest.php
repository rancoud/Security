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
    public function data()
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

    /**
     * @dataProvider data
     */
    public function testEscAttr($input, $expected, $charset)
    {
        self::assertSame($expected, Security::escAttr($input, $charset));
    }
    /**
     * @dataProvider data
     */
    public function testEscHtml($input, $expected, $charset)
    {
        self::assertSame($expected, Security::escHtml($input, $charset));
    }

    /**
     * @dataProvider data
     */
    public function testEscJs($input, $expected, $charset)
    {
        self::assertSame($expected, Security::escJs($input, $charset));
    }

    /**
     * @dataProvider data
     */
    public function testTextarea($input, $expected, $charset)
    {
        self::assertSame($expected, Security::escTextarea($input, $charset));
    }
}
