<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Fixture.php';

use RESOAuth\Soca\{Client, Failure, Http, Json, Keys, Policy};
use RESOAuth\Soca\Tests\Fixture;

$tests = 0;
function check(bool $condition, string $name): void {
    global $tests; $tests++;
    if (!$condition) { throw new \RuntimeException('FAILED: ' . $name); }
}
function rejects(callable $function, string $name): void {
    try { $function(); } catch (Failure $e) { check(true, $name); return; }
    check(false, $name);
}
function config(array $overrides = [], string $algorithm = 'ES256'): array {
    $options = $algorithm === 'RS256' ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048] : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => match($algorithm) { 'ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1' }];
    openssl_pkey_export(openssl_pkey_new($options), $pem);
    return $overrides + ['issuer' => 'https://issuer.example.com', 'redirect_uri' => 'https://app.example.com/soca/callback',
        'metadata_uri' => 'https://app.example.com/soca/metadata', 'jwks_uri' => 'https://app.example.com/soca/jwks',
        'client_name' => 'Example wiki', 'client_uri' => 'https://app.example.com', 'private_key_pem' => $pem,
        'assertion_alg' => $algorithm, 'id_token_alg' => $algorithm, 'allowed_domains' => ['example.com']];
}
foreach (['ES256', 'ES384', 'RS256'] as $algorithm) {
    foreach (['hosted', 'proxy'] as $mode) {
        $fixture = new Fixture($algorithm); $client = new Client(config(['metadata_mode' => $mode], $algorithm), $fixture);
        $tx = $fixture->begin($client); $url = $client->start()['url']; parse_str(parse_url($url, PHP_URL_QUERY), $params);
        check($params['code_challenge_method'] === 'S256' && $params['scope'] === 'openid email profile', 'PKCE request');
        $fixture->transaction = $tx;
        $result = $client->complete($tx, $fixture->query()); Policy::assertAllowed($result, config());
        check($result['sub'] === 'stable-subject', "$algorithm/$mode signed roundtrip");
        check(!str_contains(Json::canonical($client->metadata()), 'PRIVATE KEY'), 'public keys only');
        check($client->checkDocuments()['real_login'] === false, 'document evidence distinct');
        rejects(fn() => $client->complete($tx, $fixture->query()), 'provider code single use');
    }
}
foreach (['iss' => 'https://attacker.example.com', 'sub' => '', 'aud' => 'wrong-client', 'nonce' => 'wrong-nonce',
    'iat' => '1', 'exp' => time() - 120, 'auth_time' => '123', 'nbf' => time() + 600,
    'azp' => 'wrong-client', 'at_hash' => 'wrong-hash', 'c_hash' => 'wrong-hash', 'amr' => 'mfa'] as $field => $value) {
    $fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client); $fixture->overrides = [$field => $value];
    rejects(fn() => $client->complete($tx, $fixture->query()), 'reject claim ' . $field);
}
foreach (['alg' => 'none', 'jku' => 'https://attacker.example.com/keys', 'crit' => ['x'], 'kid' => 'unknown'] as $field => $value) {
    $fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client); $fixture->header = [$field => $value];
    rejects(fn() => $client->complete($tx, $fixture->query()), 'reject header ' . $field);
}
foreach (['state' => 'wrong', 'iss' => 'https://attacker.example.com', 'code' => '', 'error' => 'access_denied'] as $field => $value) {
    $fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client);
    rejects(fn() => $client->complete($tx, array_replace($fixture->query(), [$field => $value])), 'reject query ' . $field);
}
$fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client);
rejects(fn() => $client->complete(array_replace($tx, ['started' => time() - 301]), $fixture->query()), 'expired transaction');
rejects(fn() => $client->complete(array_replace($tx, ['revision' => 'changed']), $fixture->query()), 'revision changed');
putenv('SOCA_EMERGENCY_DISABLE=1');
rejects(fn() => $client->start(), 'emergency begin'); rejects(fn() => $client->complete($tx, $fixture->query()), 'emergency callback'); putenv('SOCA_EMERGENCY_DISABLE');
foreach (['sub' => 'conflict', 'email' => 'different@example.com', 'email_verified' => false, 'preferred_username' => 'different'] as $field => $value) {
    $fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client);
    if ($field === 'preferred_username') { $fixture->overrides = [$field => 'original']; }
    $fixture->userinfo = [$field => $value] + ['sub' => 'stable-subject'];
    rejects(fn() => $client->complete($tx, $fixture->query()), 'userinfo conflict ' . $field);
}
$fixture = new Fixture(); $client = new Client(config(), $fixture); $tx = $fixture->begin($client); $fixture->userinfoOutage = true;
check($client->complete($tx, $fixture->query())['sub'] === 'stable-subject', 'optional userinfo outage');
$fixture = new Fixture(); $client = new Client(config(['userinfo' => 'required']), $fixture); $tx = $fixture->begin($client); $fixture->userinfoOutage = true;
rejects(fn() => $client->complete($tx, $fixture->query()), 'required userinfo outage');
foreach ([['max_age' => 0], ['required_acr' => ['urn:example:mfa']], ['required_amr' => ['mfa']]] as $assurance) {
    $fixture = new Fixture(); $client = new Client(config($assurance), $fixture); $tx = $fixture->begin($client);
    rejects(fn() => $client->complete($tx, $fixture->query()), 'assurance enforced');
}
$fixture = new Fixture(); $client = new Client(config(['max_age' => 0, 'required_acr' => ['urn:example:mfa'], 'required_amr' => ['mfa']]), $fixture);
$tx = $fixture->begin($client); $fixture->overrides = ['auth_time' => time(), 'acr' => 'urn:example:mfa', 'amr' => ['pwd', 'mfa']];
check($client->complete($tx, $fixture->query())['sub'] === 'stable-subject', 'explicit assurance');
foreach ([['issuer' => 'https://other.example.com'], ['client_id_metadata_document_supported' => false], ['code_challenge_methods_supported' => ['plain']], ['token_endpoint_auth_methods_supported' => ['client_secret_basic']], ['id_token_signing_alg_values_supported' => ['RS256']]] as $override) {
    $fixture = new Fixture(); $client = new Client(config(), $fixture); $fixture->client = $client; $fixture->discovery = array_replace($fixture->discovery, $override);
    rejects(fn() => $client->start(), 'discovery incompatible');
}
$fixture = new Fixture(); $client = new Client(config(), $fixture); $fixture->client = $client; unset($fixture->discovery['client_id_metadata_document_supported']);
check($client->checkDocuments()['cimd_advertised'] === false, 'missing CIMD unconfirmed');
$fixture->badMetadata = true; rejects(fn() => $client->checkDocuments(), 'wrong public metadata');
$fixture->badMetadata = false; $fixture->badJwks = true; rejects(fn() => $client->checkDocuments(), 'wrong public keys');
foreach (['*.example.com' => ['a.example.com', 'a.b.example.com'], 'example.com' => ['example.com']] as $rule => $domains) {
    foreach ($domains as $domain) { Policy::assertAllowed(['email' => 'person@' . $domain, 'email_verified' => true], ['allowed_domains' => [$rule]]); check(true, 'domain admitted'); }
}
foreach (['example.com', 'badexample.com'] as $domain) {
    rejects(fn() => Policy::assertAllowed(['email' => 'person@' . $domain, 'email_verified' => true], ['allowed_domains' => ['*.example.com']]), 'wildcard label boundary');
}
foreach (['*example.com', 'a.*.example.com', '*.*.example.com', 'example', 'https://example.com', 'person@example.com', 'a..example.com', '-a.example.com', '*.com'] as $domain) {
    rejects(fn() => Policy::validate(['allowed_domains' => [$domain]]), 'invalid domain ' . $domain);
}
foreach ([[], ['allowed_domains' => ['example.com'], 'denied_domains' => ['example.com']]] as $policy) {
    rejects(fn() => Policy::assertAllowed(['email' => 'person@example.com', 'email_verified' => true], $policy), 'deny default and precedence');
}
foreach ([false, 'true', 1, null] as $verified) {
    rejects(fn() => Policy::assertAllowed(['email' => 'person@example.com', 'email_verified' => $verified], ['allowed_domains' => ['example.com']]), 'boolean verified');
}
Policy::assertAllowed(['email' => 'PERSON@EXAMPLE.COM', 'email_verified' => true], ['allowed_emails' => ['person@example.com']]); check(true, 'email case');
foreach (['http://example.com', 'https://localhost/x', 'https://127.0.0.1/x', 'https://user@example.com/x', 'https://example.com/#x', 'https://example.com/a/../b', 'https://example.com/%2e%2e/x', "https://example.com/\n"] as $url) { rejects(fn() => Http::url($url), 'unsafe url'); }
foreach (['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '192.0.2.1', '198.18.0.1', '224.0.0.1', '::1', 'fe80::1', 'fc00::1', '::ffff:8.8.8.8', '2001:db8::1', '2002:0808:0808::1'] as $ip) { check(!Http::publicIp($ip), 'private/reserved address'); }
foreach (['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'] as $ip) { check(Http::publicIp($ip), 'public address'); }
foreach (['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":1,"\\u0061":2}'] as $json) { rejects(fn() => Json::decode($json), 'duplicate JSON'); }
check(Json::decode('{"array":[{},[],"text"],"a":true}')["a"] === true, "nested JSON");
$config = config(['metadata_mode' => 'proxy', 'logo_uri' => 'https://app.example.com/logo.png', 'policy_uri' => 'https://app.example.com/privacy', 'tos_uri' => 'https://app.example.com/terms']);
$client = new Client($config); $payload = Json::decode(Json::unb64(basename($client->clientId())));
check(!isset($payload['client_id']) && $payload['policy_uri'] === $config['policy_uri'], 'proxy public metadata encoding');
check($client->clientId() === (new Client($config))->clientId(), 'deterministic client ID');
foreach (['https://proxy.example.com/no-placeholder', 'https://proxy.example.com/%s/%s', 'https://%s.proxy.example.com/path', 'https://%s.proxy.example.com/placeholder', 'https://proxy.example.com/path?x=%s', 'http://proxy.example.com/%s'] as $template) { rejects(fn() => new Client(config(['metadata_mode' => 'proxy', 'proxy_template' => $template])), 'unsafe proxy'); }
echo "SOCA core: $tests assertions passed (synthetic provider, no live-provider claim).\n";
