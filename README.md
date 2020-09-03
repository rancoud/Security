# Security Package

![Packagist PHP Version Support](https://img.shields.io/packagist/php-v/rancoud/security)
[![Packagist Version](https://img.shields.io/packagist/v/rancoud/security)](https://packagist.org/packages/rancoud/security)
[![Packagist Downloads](https://img.shields.io/packagist/dt/rancoud/security)](https://packagist.org/packages/rancoud/security)
[![Composer dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/rancoud/Security/blob/master/composer.json)
[![Test workflow](https://img.shields.io/github/workflow/status/rancoud/security/test?label=test&logo=github)](https://github.com/rancoud/security/actions?workflow=test)
[![Codecov](https://img.shields.io/codecov/c/github/rancoud/security?logo=codecov)](https://codecov.io/gh/rancoud/security)
[![composer.lock](https://poser.pugx.org/rancoud/security/composerlock)](https://packagist.org/packages/rancoud/security)

Escape string to output HTML (and JS).

## Installation
```php
composer require rancoud/security
```

## How to use it?
```php
Security::escAttr('string');

Security::escHTML('string');

Security::escJS('string');

Security::isSupportedCharset('string');
```

## Supported Charsets
All charset supported by mbstring extension inside charsets list.  
[More info at PHP documentation](https://www.php.net/manual/en/mbstring.encodings.php)  
[And at the PHP libmbfl README](https://github.com/php/php-src/tree/master/ext/mbstring/libmbfl)  

Maximum supported charset below:
* ISO-8859-1
* ISO-8859-5
* ISO-8859-15
* UTF-8
* cp866
* cp1251
* cp1252
* KOI8-R
* BIG5
* GB2312
* BIG5-HKSCS
* Shift_JIS
* EUC-JP
* MacRoman

## Security Methods
### General Static Methods
* isSupportedCharset(charset: string): bool
* areCharsetAliases(charsetToCheck: string, charsetReference: string): bool
* escHTML(text: mixed, [charset: string = 'UTF-8']): string
* escAttr(text: mixed, [charset: string = 'UTF-8']): string
* escJS(text: mixed, [charset: string = 'UTF-8']): string

## How to Dev
`composer ci` for php-cs-fixer and phpunit and coverage  
`composer lint` for php-cs-fixer  
`composer test` for phpunit and coverage  
