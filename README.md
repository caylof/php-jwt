# 基于 lcobucci/jwt 库的二次封装

## Install

```shell
composer require caylof/jwt
```

## Example

### Symmetric algorithm (HMAC using SHA256)

```php
use Caylof\Jwt\JwtAlgo;
use Caylof\Jwt\JwtIssuer;
use Caylof\Jwt\JwtParser;
use Caylof\Jwt\JwtSigner;
use Caylof\Jwt\JwtValidator;

/// issue tokens
$jwtSigner = new JwtSigner(JwtAlgo::HS256, random_bytes(32));
$jwtIssuer = new JwtIssuer(
    issuer: 'user-srv',
    subject: 'auth-tkn',
    audiences: ['mbr'],
    claims: [
        'uid' => 1,
        'name' => 'cctv',
    ]
);
$jwtIssuer->setExpires(0, 1);
$token = $jwtIssuer->issue($jwtSigner);
$jwtStr = $token->toString();


/// parse token
$jwtParser = new JwtParser();
$token = $jwtParser->parse($jwtStr);


/// validate token
$jwtValidator = new JwtValidator(
    issuer: 'user-srv',
    subject: 'auth-tkn',
    audience: 'mbr',
);
$validateResult = $jwtValidator->validate($token, $jwtSigner);
$claims = $token->claims()->all();


print_r(compact('jwtStr', 'validateResult', 'claims'));

```

### Asymmetric algorithm (RSA using SHA256)

```php
use Caylof\Jwt\JwtAlgo;
use Caylof\Jwt\JwtIssuer;
use Caylof\Jwt\JwtParser;
use Caylof\Jwt\JwtSigner;
use Caylof\Jwt\JwtValidator;

/// issue tokens
$issueSigner = new JwtSigner(JwtAlgo::RS256, file_get_contents(runtime_path('jwt.private.key')));
$jwtIssuer = new JwtIssuer(
    issuer: 'user-srv',
    subject: 'auth-tkn',
    audiences: ['mbr'],
    claims: [
        'uid' => 1,
        'name' => 'cctv',
    ]
);
$jwtIssuer->setExpires(0, 1);
$token = $jwtIssuer->issue($issueSigner);
$jwtStr = $token->toString();


/// parse token
$jwtParser = new JwtParser();
$token = $jwtParser->parse($jwtStr);


/// validate token
$validateSigner = new JwtSigner(JwtAlgo::RS256, file_get_contents(runtime_path('jwt.public.key')));
$jwtValidator = new JwtValidator(
    issuer: 'user-srv',
    subject: 'auth-tkn',
    audience: 'mbr',
);
$validateResult = $jwtValidator->validate($token, $validateSigner);
$claims = $token->claims()->all();


print_r(compact('jwtStr', 'validateResult', 'claims'));

```