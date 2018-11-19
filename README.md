# Security Package

[![Build Status](https://travis-ci.org/rancoud/Security.svg?branch=master)](https://travis-ci.org/rancoud/Security) [![Coverage Status](https://coveralls.io/repos/github/rancoud/Security/badge.svg?branch=master)](https://coveralls.io/github/rancoud/Security?branch=master)

Security.  

## Installation
```php
composer require rancoud/security
```

## How to use it?
```php
Security::sanitizeUtf8Text('string');

Security::htmlspecialchars('string');

Security::escAttr('string');

Security::escHtml('string');

Security::escJs('string');

Security::escTextarea('string');
```

## Security Methods
### General Static Commands  
* sanitizeUtf8Text(string: mixed, [charset: string = 'UTF-8']): string  
* htmlspecialchars(string: mixed, [quote: int = ENT_NOQUOTES], [charset: string = 'UTF-8']): string  
* escAttr(text: mixed, [charset: string = 'UTF-8']): string  
* escHtml(text: mixed, [charset: string = 'UTF-8']): string  
* escJs(text: mixed, [charset: string = 'UTF-8']): string  
* escTextarea(text: mixed, [charset: string = 'UTF-8']): string  

## How to Dev
`./run_all_commands.sh` for php-cs-fixer and phpunit and coverage  
`./run_php_unit_coverage.sh` for phpunit and coverage  