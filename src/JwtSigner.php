<?php

namespace Caylof\Jwt;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;

class JwtSigner
{
    private Signer $signer;
    private Key $signerKey;

    public function __construct(JwtAlgo $algo, string $signContent, string $passphrase = '')
    {
        if (! $algo->verifySignerKeyLength(strlen($signContent))) {
            throw new \InvalidArgumentException($algo->name . ' required key length error, see: https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/');
        }
        $this->signer = $algo->getSigner();
        $this->signerKey = InMemory::plainText($signContent, $passphrase);
    }

    public function getSigner(): Signer
    {
        return $this->signer;
    }

    public function getSignerKey(): Key
    {
        return $this->signerKey;
    }
}