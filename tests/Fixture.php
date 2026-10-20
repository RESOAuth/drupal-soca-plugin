<?php
declare(strict_types=1);
namespace RESOAuth\Soca\Tests;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use RESOAuth\Soca\{Client, Failure, HttpInterface, Json, Keys};

/** Synthetic provider; validates client assertion, PKCE and single-use code. */
final class Fixture implements HttpInterface {
    public array $discovery;
    public array $overrides = [];
    public array $header = [];
    public ?array $userinfo = null;
    public bool $userinfoOutage = false;
    public bool $consumed = false;
    public bool $badMetadata = false;
    public bool $badJwks = false;
    public Client $client;
    public array $transaction;
    public Keys $provider;
    public function __construct(string $algorithm = 'ES256') {
        $options = $algorithm === 'RS256' ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048] : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => match($algorithm) { 'ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1' }];
        openssl_pkey_export(openssl_pkey_new($options), $pem);
        $this->provider = new Keys($pem, $algorithm, 'provider-key');
        $this->discovery = ['issuer' => 'https://issuer.example.com', 'authorization_endpoint' => 'https://issuer.example.com/authorize',
            'token_endpoint' => 'https://issuer.example.com/token', 'jwks_uri' => 'https://issuer.example.com/keys',
            'userinfo_endpoint' => 'https://issuer.example.com/userinfo', 'response_types_supported' => ['code'],
            'code_challenge_methods_supported' => ['S256'], 'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
            'token_endpoint_auth_signing_alg_values_supported' => [$algorithm], 'id_token_signing_alg_values_supported' => [$algorithm],
            'subject_types_supported' => ['pairwise'], 'client_id_metadata_document_supported' => true,
            'authorization_response_iss_parameter_supported' => true];
    }
    public function request(string $url, ?array $form = null, ?string $bearer = null): array {
        if (str_ends_with($url, '/.well-known/openid-configuration')) { return $this->discovery; }
        if ($url === $this->client->clientId()) { $doc = $this->client->metadata(); if ($this->badMetadata) { $doc['client_name'] = 'Changed'; } return $doc; }
        if ($url === 'https://app.example.com/soca/jwks') { return $this->badJwks ? ['keys' => []] : $this->client->jwks(); }
        if ($url === $this->discovery['jwks_uri']) { return ['keys' => [$this->provider->jwk()]]; }
        if ($url === $this->discovery['userinfo_endpoint']) {
            Failure::require(!$this->userinfoOutage, 'https_request_failed');
            Failure::require($bearer === 'synthetic-access', 'fixture_bearer');
            return $this->userinfo ?? ['sub' => 'stable-subject'];
        }
        Failure::require($url === $this->discovery['token_endpoint'] && !$this->consumed, 'fixture_code_replay');
        $this->consumed = true;
        Failure::require(($form['code'] ?? '') === 'synthetic-code' && ($form['code_verifier'] ?? '') === $this->transaction['verifier'] && $form['redirect_uri'] === $this->transaction['redirect_uri'], 'fixture_pkce');
        $assertion = (array)JWT::decode($form['client_assertion'], JWK::parseKey($this->client->jwks()['keys'][0]));
        Failure::require($assertion['iss'] === $this->client->clientId() && $assertion['sub'] === $assertion['iss'] && $assertion['aud'] === $this->discovery['token_endpoint'] && $assertion['exp'] - $assertion['iat'] === 60 && strlen($assertion['jti']) >= 43, 'fixture_assertion');
        $now = time();
        $claims = array_replace(['iss' => $this->discovery['issuer'], 'sub' => 'stable-subject', 'aud' => $this->client->clientId(),
            'iat' => $now, 'exp' => $now + 120, 'nonce' => $this->transaction['nonce'],
            'email' => 'person@example.com', 'email_verified' => true], $this->overrides);
        $jwt = $this->provider->sign($claims);
        if ($this->header) {
            [$head, $body, $signature] = explode('.', $jwt);
            $jwt = Json::b64(Json::canonical($this->header + Json::decode(Json::unb64($head)))) . '.' . $body . '.' . $signature;
        }
        return ['id_token' => $jwt, 'access_token' => 'synthetic-access', 'token_type' => 'Bearer'];
    }
    public function begin(Client $client): array {
        $this->client = $client; $this->transaction = $client->start()['transaction'];
        return $this->transaction;
    }
    public function query(): array { return ['code' => 'synthetic-code', 'state' => $this->transaction['state'], 'iss' => $this->discovery['issuer']]; }
}
