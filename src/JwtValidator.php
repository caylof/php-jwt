<?php

namespace Caylof\Jwt;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;

class JwtValidator
{
    private string $timezone = 'Asia/Shanghai';
    private int $leewaySec = 60;

    public function __construct(
        private readonly ?string $issuer,
        private readonly ?string $subject,
        private readonly ?string $audience,
        private readonly array $claims = [],
    ){}

    public function setTimezone(string $timezone): void
    {
        $this->timezone = $timezone;
    }

    public function setLeewaySec(int $leewaySec): void
    {
        $this->leewaySec = $leewaySec;
    }

    public function validate(Token $token, JwtSigner $jwtSigner) : bool
    {
        $constraints = [];
        if (! empty($this->issuer)) {
            $constraints[] = new IssuedBy($this->issuer);
        }
        if (! empty($this->subject)) {
            $constraints[] = new RelatedTo($this->subject);
        }
        if (! empty($this->audience)) {
            $constraints[] = new PermittedFor($this->audience);
        }
        foreach ($this->claims as $claim => $expectedValue) {
            $constraints[] = new HasClaimWithValue($claim, $expectedValue);
        }
        $constraints = [
            ...$constraints,
            new StrictValidAt(new SystemClock(new \DateTimeZone($this->timezone)), new \DateInterval(sprintf('PT%dS', $this->leewaySec))),
            new SignedWith($jwtSigner->getSigner(), $jwtSigner->getSignerKey()),
        ];

        $validator = new Validator();
        return $validator->validate($token, ...$constraints);
    }
}