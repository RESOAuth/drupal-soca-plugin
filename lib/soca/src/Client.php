<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/** Protocol only. Host adapters own browser binding, replay state and accounts. */
final class Client {
    private array $config;
    private HttpInterface $http;
    private Keys $keys;
    private array $publicMetadata;
    private string $client;
    public function __construct(array $config, ?HttpInterface $http = null) {
        $this->config = $config + [
            'issuer' => 'https://auth.resoauth.cloud', 'metadata_mode' => 'hosted',
            'proxy_template' => 'https://dynamic-cimd.resoauth.cloud/cimd/%s',
            'assertion_alg' => 'ES256', 'id_token_alg' => 'ES256', 'assertion_audience' => 'token_endpoint',
            'client_name' => 'SOCA application', 'userinfo' => 'optional', 'max_age' => null,
            'required_acr' => [], 'required_amr' => [], 'scopes' => 'openid email profile',
        ];
        $c = $this->config;
        foreach (['issuer', 'redirect_uri', 'metadata_uri', 'jwks_uri'] as $name) {
            Failure::require(is_string($c[$name] ?? null), 'missing_' . $name); Http::url($c[$name]);
        }
        Failure::require(!str_contains($c['issuer'], '?') && !str_contains($c['issuer'], '#'), 'issuer_url');
        Failure::require(in_array($c['metadata_mode'], ['hosted', 'proxy'], true), 'metadata_mode');
        Failure::require(in_array($c['id_token_alg'], ['ES256', 'ES384', 'RS256'], true), 'unsupported_id_token_algorithm');
        Failure::require(in_array($c['assertion_audience'], ['issuer', 'token_endpoint'], true), 'assertion_audience');
        Failure::require(in_array($c['userinfo'], ['disabled', 'optional', 'required'], true), 'userinfo_mode');
        Failure::require(is_string($c['scopes']) && (bool)preg_match('/^openid(?: (?:email|profile))*$/D', $c['scopes']), 'scopes');
        Failure::require($c['max_age'] === null || (is_int($c['max_age']) && $c['max_age'] >= 0 && $c['max_age'] <= 86400), 'max_age');
        foreach (['required_acr', 'required_amr'] as $field) {
            Failure::require(is_array($c[$field]) && array_is_list($c[$field]) && count($c[$field]) <= 20, 'assurance_configuration');
            foreach ($c[$field] as $item) { Failure::require(is_string($item) && strlen($item) > 0 && strlen($item) <= 200 && !preg_match('/[\x00-\x20\x7f]/', $item), 'assurance_configuration'); }
        }
        Policy::validate($c);
        Failure::require(is_string($c['private_key_pem'] ?? null), 'private_key_required');
        $this->keys = new Keys($c['private_key_pem'], $c['assertion_alg'], $c['key_id'] ?? null);
        $this->http = $http ?? new Http();
        $m = ['client_name' => $c['client_name'], 'redirect_uris' => [$c['redirect_uri']],
            'response_types' => ['code'], 'grant_types' => ['authorization_code'],
            'token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_signing_alg' => $c['assertion_alg'],
            'id_token_signed_response_alg' => $c['id_token_alg']];
        Failure::require(is_string($c['client_name']) && strlen($c['client_name']) > 0 && strlen($c['client_name']) <= 200 && !preg_match('/[\x00-\x1f\x7f]/', $c['client_name']), 'client_name');
        foreach (['client_uri', 'logo_uri', 'policy_uri', 'tos_uri'] as $field) {
            if (isset($c[$field]) && $c[$field] !== '') { Failure::require(is_string($c[$field]), 'metadata_url'); Http::url($c[$field]); $m[$field] = $c[$field]; }
        }
        $keyMode = $c['metadata_jwks_mode'] ?? ($c['metadata_mode'] === 'proxy' ? 'inline' : 'uri');
        Failure::require(in_array($keyMode, ['inline', 'uri'], true), 'metadata_jwks_mode');
        if ($keyMode === 'inline') { $m['jwks'] = $this->jwks(); } else { $m['jwks_uri'] = $c['jwks_uri']; }
        $this->publicMetadata = $m;
        if ($c['metadata_mode'] === 'proxy') {
            $template = $c['proxy_template'];
            Failure::require(is_string($template) && substr_count($template, '%s') === 1, 'proxy_placeholder');
            $p = Http::url(str_replace('%s', 'placeholder', $template));
            Failure::require(str_contains(parse_url($template, PHP_URL_PATH) ?? '', '%s') && !isset($p['query']), 'proxy_path_template');
            $payload = Json::canonical($m);
            Failure::require(strlen($payload) <= 6144, 'proxy_payload_size');
            $this->client = str_replace('%s', Json::b64($payload), $template);
            Failure::require(strlen($this->client) <= 8192, 'proxy_url_size');
        } else { $this->client = $c['metadata_uri']; }
    }
    public function jwks(): array { return ['keys' => [$this->keys->jwk()]]; }
    public function clientId(): string { return $this->client; }
    public function metadata(): array { return ['client_id' => $this->client] + $this->publicMetadata; }
    public function revision(): string {
        $c = $this->config; unset($c['private_key_pem']);
        // Includes admission and key identity, without retaining private material.
        return hash('sha256', Json::canonical(['config' => $c, 'metadata' => $this->metadata(), 'keys' => $this->jwks()]));
    }
    public function discovery(): array {
        $c = $this->config;
        $d = $this->http->request(rtrim($c['issuer'], '/') . '/.well-known/openid-configuration');
        Failure::require(($d['issuer'] ?? null) === $c['issuer'], 'discovery_issuer');
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            Failure::require(is_string($d[$field] ?? null), 'discovery_endpoint'); Http::url($d[$field]);
        }
        if (isset($d['userinfo_endpoint'])) { Failure::require(is_string($d['userinfo_endpoint']), 'userinfo_endpoint'); Http::url($d['userinfo_endpoint']); }
        foreach (['response_types_supported' => 'code', 'code_challenge_methods_supported' => 'S256',
            'token_endpoint_auth_methods_supported' => 'private_key_jwt',
            'token_endpoint_auth_signing_alg_values_supported' => $c['assertion_alg'],
            'id_token_signing_alg_values_supported' => $c['id_token_alg']] as $field => $wanted) {
            Failure::require(is_array($d[$field] ?? null) && in_array($wanted, $d[$field], true), 'provider_capability_' . $field);
        }
        Failure::require(is_array($d['subject_types_supported'] ?? null) && count(array_intersect(['public', 'pairwise'], $d['subject_types_supported'])) > 0, 'provider_subject_types');
        Failure::require(!array_key_exists('client_id_metadata_document_supported', $d) || $d['client_id_metadata_document_supported'] === true, 'provider_cimd_unsupported');
        Failure::require(!isset($d['authorization_response_iss_parameter_supported']) || is_bool($d['authorization_response_iss_parameter_supported']), 'response_issuer_support');
        foreach (['response_modes_supported' => ['query'], 'grant_types_supported' => ['authorization_code'], 'scopes_supported' => explode(' ', $c['scopes'])] as $field => $wanted) {
            Failure::require(!isset($d[$field]) || (is_array($d[$field]) && !array_diff($wanted, $d[$field])), 'provider_capability_' . $field);
        }
        parse_str(parse_url($d['authorization_endpoint'], PHP_URL_QUERY) ?? '', $query);
        Failure::require(!array_intersect(array_keys($query), ['response_type', 'response_mode', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'prompt', 'max_age', 'acr_values']), 'reserved_authorisation_query');
        return $d;
    }
    public function checkDocuments(): array {
        $d = $this->discovery();
        $remote = $this->http->request($this->clientId());
        Failure::require(Json::canonical($remote) === Json::canonical($this->metadata()), 'public_metadata_mismatch');
        if (isset($this->publicMetadata['jwks_uri'])) {
            Failure::require(Json::canonical($this->http->request($this->publicMetadata['jwks_uri'])) === Json::canonical($this->jwks()), 'public_jwks_mismatch');
        }
        return ['revision' => $this->revision(), 'checked_at' => time(), 'documents' => true,
            'cimd_advertised' => ($d['client_id_metadata_document_supported'] ?? null) === true,
            'real_login' => false];
    }
    public function start(): array {
        $this->emergency();
        $d = $this->discovery();
        $tx = ['state' => Json::b64(random_bytes(32)), 'nonce' => Json::b64(random_bytes(32)),
            'verifier' => Json::b64(random_bytes(48)), 'started' => time(), 'issuer' => $this->config['issuer'],
            'client_id' => $this->clientId(), 'redirect_uri' => $this->config['redirect_uri'],
            'revision' => $this->revision(), 'discovery' => $d];
        $p = ['response_type' => 'code', 'response_mode' => 'query', 'client_id' => $tx['client_id'],
            'redirect_uri' => $tx['redirect_uri'], 'scope' => $this->config['scopes'], 'state' => $tx['state'],
            'nonce' => $tx['nonce'], 'code_challenge' => Json::b64(hash('sha256', $tx['verifier'], true)), 'code_challenge_method' => 'S256'];
        if ($this->config['max_age'] !== null) { $p['max_age'] = $this->config['max_age']; if ($p['max_age'] === 0) { $p['prompt'] = 'login'; } }
        if ($this->config['required_acr']) { $p['acr_values'] = implode(' ', $this->config['required_acr']); }
        return ['url' => $d['authorization_endpoint'] . (str_contains($d['authorization_endpoint'], '?') ? '&' : '?') . http_build_query($p, '', '&', PHP_QUERY_RFC3986), 'state' => $tx['state'], 'transaction' => $tx];
    }
    public function complete(array $tx, array $query): array {
        $this->emergency();
        foreach (['state', 'nonce', 'verifier', 'issuer', 'client_id', 'redirect_uri', 'revision'] as $key) { Failure::require(is_string($tx[$key] ?? null) && $tx[$key] !== '', 'invalid_transaction'); }
        Failure::require(is_int($tx['started'] ?? null) && $tx['started'] <= time() && $tx['started'] >= time() - 300, 'transaction_expired');
        Failure::require(hash_equals($this->revision(), $tx['revision']) && $tx['issuer'] === $this->config['issuer'] && $tx['client_id'] === $this->clientId() && $tx['redirect_uri'] === $this->config['redirect_uri'], 'transaction_configuration_changed');
        Failure::require(is_string($query['state'] ?? null) && hash_equals($tx['state'], $query['state']), 'callback_state');
        Failure::require(!isset($query['error']), 'provider_cancelled');
        // Require RFC 9207 issuer identification even when discovery omits the flag.
        Failure::require(($query['iss'] ?? null) === $tx['issuer'], 'callback_issuer');
        Failure::require(is_string($query['code'] ?? null) && strlen($query['code']) > 0 && strlen($query['code']) <= 4096 && !preg_match('/[\x00-\x20\x7f]/', $query['code']), 'callback_code');
        $d = $tx['discovery']; $now = time();
        $assertion = $this->keys->sign(['iss' => $tx['client_id'], 'sub' => $tx['client_id'],
            'aud' => $this->config['assertion_audience'] === 'issuer' ? $tx['issuer'] : $d['token_endpoint'],
            'iat' => $now, 'exp' => $now + 60, 'jti' => Json::b64(random_bytes(32))]);
        $tokens = $this->http->request($d['token_endpoint'], ['grant_type' => 'authorization_code',
            'client_id' => $tx['client_id'], 'redirect_uri' => $tx['redirect_uri'], 'code' => $query['code'],
            'code_verifier' => $tx['verifier'], 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion' => $assertion]);
        Failure::require(is_string($tokens['id_token'] ?? null), 'id_token_missing');
        $access = $tokens['access_token'] ?? '';
        Failure::require(is_string($access) && strlen($access) <= 16384, 'invalid_access_token');
        if ($access !== '') { Failure::require(is_string($tokens['token_type'] ?? null) && strcasecmp($tokens['token_type'], 'Bearer') === 0, 'token_type'); }
        $claims = $this->verify($tokens['id_token'], $tx, $access, $query['code']);
        if ($this->config['userinfo'] !== 'disabled') {
            if (isset($d['userinfo_endpoint']) && $access !== '') {
                try { $info = $this->http->request($d['userinfo_endpoint'], null, $access); }
                catch (Failure $e) { if ($this->config['userinfo'] === 'required') { throw $e; } $info = null; }
                if ($info !== null) {
                    Failure::require(($info['sub'] ?? null) === $claims['sub'], 'userinfo_subject_conflict');
                    foreach (['email', 'email_verified', 'preferred_username'] as $key) {
                        Failure::require(!array_key_exists($key, $info) || !array_key_exists($key, $claims) || $info[$key] === $claims[$key], 'userinfo_identity_conflict');
                    }
                    foreach (['email', 'email_verified', 'given_name', 'family_name', 'name', 'preferred_username'] as $key) {
                        if (!array_key_exists($key, $claims) && array_key_exists($key, $info)) { $claims[$key] = $info[$key]; }
                    }
                }
            } else { Failure::require($this->config['userinfo'] !== 'required', 'userinfo_unavailable'); }
        }
        return $claims;
    }
    private function verify(string $token, array $tx, string $access, string $code): array {
        Failure::require(strlen($token) <= 32768 && count(explode('.', $token)) === 3, 'jwt_format');
        [$h, $p] = explode('.', $token);
        $header = Json::decode(Json::unb64($h)); $claims = Json::decode(Json::unb64($p)); $alg = $this->config['id_token_alg'];
        Failure::require(($header['alg'] ?? null) === $alg && is_string($header['kid'] ?? null) && strlen($header['kid']) > 0 && strlen($header['kid']) <= 200, 'jwt_algorithm_or_kid');
        foreach (['crit', 'jku', 'jwk', 'x5u', 'b64'] as $key) { Failure::require(!array_key_exists($key, $header), 'untrusted_jose_header'); }
        Failure::require(!isset($header['typ']) || $header['typ'] === 'JWT', 'jwt_type');
        foreach (['exp', 'iat'] as $key) { Failure::require(is_int($claims[$key] ?? null), 'jwt_time_type'); }
        foreach (['nbf', 'auth_time'] as $key) { Failure::require(!array_key_exists($key, $claims) || is_int($claims[$key]), 'jwt_time_type'); }
        $jwks = $this->http->request($tx['discovery']['jwks_uri']);
        Failure::require(is_array($jwks['keys'] ?? null) && array_is_list($jwks['keys']) && count($jwks['keys']) > 0 && count($jwks['keys']) <= 50, 'provider_jwks');
        $matches = array_values(array_filter($jwks['keys'], static fn($key) => is_array($key) && ($key['kid'] ?? null) === $header['kid']));
        Failure::require(count($matches) === 1, 'ambiguous_provider_key'); $key = $matches[0];
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $field) { Failure::require(!array_key_exists($field, $key), 'private_provider_key'); }
        Failure::require(($key['alg'] ?? $alg) === $alg && ($key['use'] ?? 'sig') === 'sig' && (!isset($key['key_ops']) || (is_array($key['key_ops']) && in_array('verify', $key['key_ops'], true))), 'provider_key_purpose');
        $curve = match ($alg) { 'ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521', default => null };
        Failure::require(($key['kty'] ?? null) === ($curve === null ? 'RSA' : 'EC') && ($curve === null || ($key['crv'] ?? null) === $curve), 'provider_key_type');
        if ($curve === null) { Failure::require(is_string($key['n'] ?? null) && strlen(Json::unb64($key['n'])) >= 256, 'weak_provider_key'); }
        $leeway = JWT::$leeway; $timestamp = JWT::$timestamp;
        try {
            JWT::$leeway = 60; JWT::$timestamp = null;
            JWT::decode($token, JWK::parseKey($key, $alg));
        } catch (\Throwable $e) { throw new Failure('id_token_validation'); }
        finally { JWT::$leeway = $leeway; JWT::$timestamp = $timestamp; }
        $now = time();
        Failure::require(($claims['iss'] ?? null) === $tx['issuer'], 'id_token_issuer');
        Failure::require(is_string($claims['sub'] ?? null) && (bool)preg_match('/^[\x20-\x7e]{1,255}$/D', $claims['sub']), 'id_token_subject');
        $aud = $claims['aud'] ?? null; if (is_string($aud)) { $aud = [$aud]; }
        Failure::require(is_array($aud) && array_is_list($aud) && count($aud) > 0 && count(array_filter($aud, 'is_string')) === count($aud) && in_array($tx['client_id'], $aud, true), 'id_token_audience');
        Failure::require((count($aud) === 1 || isset($claims['azp'])) && (!isset($claims['azp']) || $claims['azp'] === $tx['client_id']), 'id_token_azp');
        Failure::require(is_string($claims['nonce'] ?? null) && hash_equals($tx['nonce'], $claims['nonce']), 'id_token_nonce');
        Failure::require($claims['exp'] > $now - 60 && $claims['iat'] <= $now + 60 && $claims['iat'] >= $tx['started'] - 60 && $claims['exp'] > $claims['iat'] && $claims['exp'] - $claims['iat'] <= 86400, 'id_token_time');
        Failure::require(!isset($claims['nbf']) || ($claims['nbf'] <= $now + 60 && $claims['nbf'] < $claims['exp']), 'id_token_not_before');
        Failure::require(!isset($claims['auth_time']) || ($claims['auth_time'] > 0 && $claims['auth_time'] <= min($now, $claims['iat']) + 60), 'id_token_auth_time');
        if ($this->config['max_age'] !== null) { Failure::require(isset($claims['auth_time']) && $claims['auth_time'] >= $tx['started'] - $this->config['max_age'] - 60, 'authentication_age'); }
        Failure::require(!isset($claims['acr']) || is_string($claims['acr']), 'acr_type');
        Failure::require(!isset($claims['amr']) || (is_array($claims['amr']) && array_is_list($claims['amr']) && count(array_filter($claims['amr'], 'is_string')) === count($claims['amr'])), 'amr_type');
        if ($this->config['required_acr']) { Failure::require(in_array($claims['acr'] ?? null, $this->config['required_acr'], true), 'assurance_acr'); }
        if ($this->config['required_amr']) { Failure::require(!array_diff($this->config['required_amr'], $claims['amr'] ?? []), 'assurance_amr'); }
        foreach (['at_hash' => $access, 'c_hash' => $code] as $field => $value) {
            if (isset($claims[$field])) {
                $bits = $alg === 'RS256' ? 256 : (int)substr($alg, 2);
                $digest = hash('sha' . ($bits === 512 ? 512 : $bits), $value, true);
                Failure::require($value !== '' && is_string($claims[$field]) && hash_equals(Json::b64(substr($digest, 0, intdiv(strlen($digest), 2))), $claims[$field]), 'token_hash');
            }
        }
        return $claims;
    }
    private function emergency(): void {
        Failure::require(!in_array(strtolower((string)getenv('SOCA_EMERGENCY_DISABLE')), ['1', 'true', 'yes'], true), 'emergency_disabled');
    }
}
