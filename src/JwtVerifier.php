<?php

namespace CognitoJwtVerifier;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use RuntimeException;

class JwtVerifier
{
    /**
     * @var string
     */
    private $cognitoRegion;

    /**
     * @var string
     */
    private $cognitoUserPoolId;

    /**
     * @param string $cognitoRegion
     * @param string $cognitoUserPoolId
     */
    public function __construct(string $cognitoRegion, string $cognitoUserPoolId)
    {
        $this->cognitoRegion = $cognitoRegion;
        $this->cognitoUserPoolId = $cognitoUserPoolId;
    }

    /**
     * @param string $jwt
     * @return object|null
     */
    public function decode(string $jwt)
    {
        $tks = explode('.', $jwt);
        if (count($tks) !== 3) {
            return null;
        }
        list($headb64, $_, $_) = $tks;

        $jwks = $this->fetchJWKs();
        try {
            $kid = $this->getKid($headb64);
            $jwk = $this->getJWK($jwks, $kid);
            $alg = $this->getAlg($jwks, $kid);
            return JWT::decode($jwt, $jwk, [$alg]);
        } catch (RuntimeException $exception) {
            return null;
        }
    }

    /**
     * @param string $headb64
     * @return mixed
     */
    private function getKid(string $headb64)
    {
        $headb64 = json_decode(JWT::urlsafeB64Decode($headb64), true);
        if (array_key_exists('kid', $headb64)) {
            return $headb64['kid'];
        }
        throw new RuntimeException();
    }

    /**
     * @param array $jwks
     * @param string $kid
     * @return mixed
     */
    private function getJWK(array $jwks, string $kid)
    {
        $keys = JWK::parseKeySet($jwks);
        if (array_key_exists($kid, $keys)) {
            return $keys[$kid];
        }
        throw new RuntimeException();
    }

    /**
     * @param array $jwks
     * @param string $kid
     * @return mixed
     */
    private function getAlg(array $jwks, string $kid)
    {
        if (!array_key_exists('keys', $jwks)) {
            throw new RuntimeException();
        }

        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $kid && array_key_exists('alg', $key)) {
                return $key['alg'];
            }
        }
        throw new RuntimeException();
    }

    /**
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function fetchJWKs(): array
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->cognitoRegion,
            $this->cognitoUserPoolId
        );
        $response = (new Client())->get($url);
        return json_decode($response->getBody()->getContents(), true) ?: [];
    }
}
