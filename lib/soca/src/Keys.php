<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

use Firebase\JWT\JWT;

final class Keys {
    private \OpenSSLAsymmetricKey $key;
    private array $public;
    public readonly string $kid;
    public function __construct(private string $pem, public readonly string $algorithm = 'ES256', ?string $kid = null) {
        Failure::require(in_array($algorithm, ['ES256', 'ES384', 'RS256'], true), 'unsupported_assertion_algorithm');
        $key = openssl_pkey_get_private($pem);
        Failure::require($key instanceof \OpenSSLAsymmetricKey, 'private_key_required');
        $this->key = $key; $details = openssl_pkey_get_details($key);
        if ($algorithm === 'RS256') {
            Failure::require($details['type'] === OPENSSL_KEYTYPE_RSA && $details['bits'] >= 2048, 'strong_rsa_key_required');
            $this->public = ['e' => Json::b64($details['rsa']['e']), 'kty' => 'RSA', 'n' => Json::b64($details['rsa']['n'])];
        } else {
            [$curve, $name, $length] = match ($algorithm) { 'ES256' => ['prime256v1', 'P-256', 32], 'ES384' => ['secp384r1', 'P-384', 48], 'ES512' => ['secp521r1', 'P-521', 66] };
            Failure::require($details['type'] === OPENSSL_KEYTYPE_EC && ($details['ec']['curve_name'] ?? '') === $curve, 'ec_curve_mismatch');
            $this->public = ['crv' => $name, 'kty' => 'EC', 'x' => Json::b64(str_pad($details['ec']['x'], $length, "\0", STR_PAD_LEFT)), 'y' => Json::b64(str_pad($details['ec']['y'], $length, "\0", STR_PAD_LEFT))];
        }
        $this->kid = $kid ?? Json::b64(hash('sha256', Json::canonical($this->public), true));
        Failure::require((bool)preg_match('/^[A-Za-z0-9._-]{1,200}$/D', $this->kid), 'invalid_key_id');
    }
    public function jwk(): array { return $this->public + ['kid' => $this->kid, 'alg' => $this->algorithm, 'use' => 'sig']; }
    public function sign(array $claims): string { return JWT::encode($claims, $this->pem, $this->algorithm, $this->kid); }
}
