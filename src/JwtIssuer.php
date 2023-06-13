<?php

namespace Caylof\Jwt;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Plain;

class JwtIssuer
{
    private int $expireDays = 0;
    private int $expireHours = 0;
    private int $expireMinutes = 5;

    public function __construct(
        private readonly string $issuer,
        private readonly string $subject,
        private readonly array $audiences,
        private readonly array $claims = [],
    ){}

    public function setExpires(int ...$dayHourMinute): void
    {
        if (count($dayHourMinute) < 3) {
            $dayHourMinute = array_pad($dayHourMinute, 3, 0);
        }
        [$this->expireDays, $this->expireHours, $this->expireMinutes] = $dayHourMinute;
    }

    public function issue(JwtSigner $jwtSigner) : Plain
    {
        $now = new \DateTimeImmutable();
        $tokenBuilder = new Builder(new JoseEncoder(), ChainedFormatter::default());
        $tokenBuilder
            ->issuedBy($this->issuer)
            ->relatedTo($this->subject)
            ->permittedFor(...$this->audiences)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify(sprintf('+%d day +%d hour +%d minute', $this->expireDays, $this->expireHours, $this->expireMinutes)));
        foreach ($this->claims as $name => $value) {
            $tokenBuilder->withClaim($name, $value);
        }
        return $tokenBuilder->getToken($jwtSigner->getSigner(), $jwtSigner->getSignerKey());
    }
}
