<?php

namespace Caylof\Jwt;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Rsa;

enum JwtAlgo {
    case HS256;
    case HS384;
    case HS512;
    case ES256;
    case ES384;
    case ES512;
    case RS256;
    case RS384;
    case RS512;

    public function verifySignerKeyLength(int $length): bool
    {
        [$mustEqual, $minLength] = match($this) {
            self::HS256 => [false, 32],
            self::ES256 => [true, 32],
            self::HS384 => [false, 48],
            self::ES384 => [true, 48],
            self::HS512 => [false, 64],
            self::ES512 => [true, 64],
            self::RS256, self::RS384, self::RS512 => [false, 256],
        };

        if ($mustEqual) {
            return $length === $minLength;
        }
        return $length >= $minLength;
    }

    public function getSigner(): Signer
    {
        return match ($this) {
            self::HS256 => new Hmac\Sha256(),
            self::HS384 => new Hmac\Sha384(),
            self::HS512 => new Hmac\Sha512(),
            self::ES256 => new Ecdsa\Sha256(),
            self::ES384 => new Ecdsa\Sha384(),
            self::ES512 => new Ecdsa\Sha512(),
            self::RS256 => new Rsa\Sha512(),
            self::RS384 => new Rsa\Sha384(),
            self::RS512 => new Rsa\Sha512(),
        };
    }
}
