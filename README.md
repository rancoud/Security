# Security Package

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/rancoud/security)
[![Packagist Version](https://img.shields.io/packagist/v/rancoud/security)](https://packagist.org/packages/rancoud/security)
[![Packagist Downloads](https://img.shields.io/packagist/dt/rancoud/security)](https://packagist.org/packages/rancoud/security)
[![Composer dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/rancoud/Security/blob/master/composer.json)
[![Test workflow](https://img.shields.io/github/actions/workflow/status/rancoud/security/test.yml?branch=master)](https://github.com/rancoud/security/actions/workflows/test.yml)
[![Codecov](https://img.shields.io/codecov/c/github/rancoud/security?logo=codecov)](https://codecov.io/gh/rancoud/security)

Escape string to output HTML (and JS).

## Installation
```php
composer require rancoud/security
```

## How to use it?
```php
use Rancoud\Security\Security;

// When you want to escape string for HTML output.
echo '<p>' . Security::escHTML('<script>alert("test");</script>') . '<p>';
// -> <p>&lt;script&gt;alert(&quot;test&quot;);&lt;&#47;script&gt;<p>

// When you want to escape string for HTML attribute output.
echo '<div data-attr="' . Security::escAttr('my-data"><script>alert("test");</script><div hidden="') . '">';
// -> <div data-attr="my-data&quot;&gt;&lt;script&gt;alert&#x28;&quot;test&quot;&#x29;&#x3B;&lt;&#x2F;script&gt;&lt;div&#x20;hidden&#x3D;&quot;"></div>

// When you want to escape string for JS output.
echo 'const value = "' . Security::escJS('";alert("test");let a="') . '";';
// -> const value = "\x22\x3Balert\x28\x22test\x22\x29\x3Blet\x20a\x3D\x22";

// When you want to escape string for URL output.
echo Security::escURL('https://example.com');
// -> https%3A%2F%2Fexample.com

// When you want to escape string for CSS output.
echo 'body { background-color: ' . Security::escCSS('red;} body {background-image: url("https://example.com");') . '}';echo "\n";
// -> body { background-color: red\3B \7D \20 body\20 \7B background\2D image\3A \20 url\28 \22 https\3A \2F \2F example\2E com\22 \29 \3B }

// Checks if charset is supported.
echo Security::isSupportedCharset('ISO-8859-15');
// -> true
echo Security::isSupportedCharset('foo');
// -> false
```

## Security
### Main functions
Escapes string for HTML output.
```php
public static function escHTML($text, string $charset = 'UTF-8'): string
```

Escapes string for HTML attribute output.
```php
public static function escAttr($text, string $charset = 'UTF-8'): string
```

Escapes string for JS output.
```php
public static function escJS($text, string $charset = 'UTF-8'): string
```

Escapes string for URL output.
```php
public static function escURL($text, string $charset = 'UTF-8'): string
```

Escapes string for CSS output.
```php
public static function escCSS($text, string $charset = 'UTF-8'): string
```

Checks if charset is supported.
```php
public static function isSupportedCharset(string $charset): bool
```

## Supported Charsets
Charsets supported are only charsets shortlisted (see list below) which are also supported by mbstring extension.  
[More info at PHP documentation](https://www.php.net/manual/en/mbstring.encodings.php) [and at the PHP libmbfl README](https://github.com/php/php-src/tree/master/ext/mbstring/libmbfl)

Charsets shortlisted:
* BIG5
* BIG5-HKSCS
* CP866
* CP932
* CP1251
* CP1252
* EUC-JP
* eucJP-win
* GB2312
* ISO-8859-1
* ISO-8859-5
* ISO-8859-15
* KOI8-R
* MacRoman
* Shift_JIS
* SJIS
* SJIS-win
* UTF-8
* Windows-1251
* Windows-1252

## How to Dev
`composer ci` for php-cs-fixer and phpunit and coverage  
`composer lint` for php-cs-fixer  
`composer test` for phpunit and coverage
