# Security Package

[![Build Status](https://travis-ci.org/rancoud/Security.svg?branch=master)](https://travis-ci.org/rancoud/Security) [![Coverage Status](https://coveralls.io/repos/github/rancoud/Security/badge.svg?branch=master)](https://coveralls.io/github/rancoud/Security?branch=master)

Security.  

## Installation
```php
composer require rancoud/security
```

## How to use it?
```php
Security::escAttr('string');

Security::escHtml('string');

Security::escJs('string');

Security::isCharsetSupported('string');
```

## Supported Charsets
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
### General Static Commands  
* sanitizeUtf8Text(string: mixed, [charset: string = 'UTF-8']): string  
* htmlspecialchars(string: mixed, [quote: int = ENT_NOQUOTES], [charset: string = 'UTF-8']): string  
* escAttr(text: mixed, [charset: string = 'UTF-8']): string  
* escHtml(text: mixed, [charset: string = 'UTF-8']): string  
* escJs(text: mixed, [charset: string = 'UTF-8']): string  
* isCharsetSupported(charset: string): bool  

## How to Dev
`./run_all_commands.sh` for php-cs-fixer and phpunit and coverage  
`./run_php_unit_coverage.sh` for phpunit and coverage  