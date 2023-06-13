<?php

namespace Caylof\Jwt;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;

class JwtParser
{
    private readonly Parser $parser;

    public function __construct()
    {
        $this->parser = new Parser(new JoseEncoder());
    }

    public function parse(string $jwtStr) : Token
    {
        return $this->parser->parse($jwtStr);
    }
}
