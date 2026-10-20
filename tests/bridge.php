<?php

declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/Fixture.php';

use RESOAuth\Soca\Bridge\Flow;
use RESOAuth\Soca\Client;
use RESOAuth\Soca\Tests\Fixture;

final class MemoryFlow extends Flow {
    public array $config;
    public array $transactions = [];
    public array $proof = [];
    public int $admin = 7;
    public Fixture $fixture;
    private Client $protocol;
    public function __construct() {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($key, $pem);
        $this->config = ['origin' => 'https://app.example.com', 'issuer' => 'https://issuer.example.com',
            'allowed_domains' => ['example.com'], 'enabled' => false];
        $this->fixture = new Fixture();
        $this->protocol = new Client($this->configuration() + ['private_key_pem' => $pem], $this->fixture);
        $this->fixture->client = $this->protocol;
    }
    protected function settings(): array { return $this->config; }
    protected function paths(): array { return ['redirect_uri' => '/soca/callback', 'metadata_uri' => '/soca/metadata', 'jwks_uri' => '/soca/jwks']; }
    protected function siteName(): string { return 'Test application'; }
    public function operator(): int { return $this->admin; }
    public function client(): Client { return $this->protocol; }
    protected function putTransaction(string $state, array $transaction): void { $this->transactions[$state] = $transaction; $this->fixture->transaction = $transaction; $this->fixture->consumed = false; }
    protected function takeTransaction(string $state): array {
        if (!isset($this->transactions[$state])) { throw new RuntimeException('No matching browser transaction.'); }
        $transaction = $this->transactions[$state]; unset($this->transactions[$state]); return $transaction;
    }
    protected function evidence(string $kind): ?string { return $this->proof[$kind] ?? null; }
    protected function saveEvidence(string $kind, string $revision): void { $this->proof[$kind] = $revision; }
    public function invalidate(): void { $this->transactions = []; }
}
$count = 0;
function test(bool $condition, string $name): void { global $count; $count++; if (!$condition) { throw new RuntimeException($name); } }
function fails(callable $action, string $name): void { try { $action(); } catch (Throwable $e) { test(true, $name); return; } test(false, $name); }
$flow = new MemoryFlow();
fails(fn() => $flow->begin(), 'Disabled ordinary login fails');
$flow->checkDocuments();
test($flow->status()['documents_checked'] && !$flow->status()['test_login_passed'], 'Document checks do not establish real login evidence');
$flow->begin(true);
$query = $flow->fixture->query();
test($flow->finish($query) === null, 'Operator tests return no account claims');
test($flow->status()['test_login_passed'], 'Operator test evidence bound to revision');
fails(fn() => $flow->finish($query), 'Callback replay rejected');
$revision = $flow->revision(); $flow->config['enabled'] = true;
test($flow->revision() === $revision, 'Activation alone preserves candidate evidence');
$flow->begin(); $query = $flow->fixture->query();
test($flow->finish($query)['sub'] === 'stable-subject', 'Approved ordinary login returns validated identity');
$flow->begin(true); $query = $flow->fixture->query(); $flow->admin = 8;
fails(fn() => $flow->finish($query), 'Test callback cannot transfer operators');
$flow->admin = 7; $flow->begin(true); $query = $flow->fixture->query();
$flow->config['denied_domains'] = ['example.com'];
fails(fn() => $flow->finish($query), 'Policy changes invalidate in-flight login');
test(!$flow->status()['test_login_passed'], 'Policy changes invalidate activation evidence');
$flow->config['denied_domains'] = []; $flow->begin(true);
putenv('SOCA_EMERGENCY_DISABLE=1');
fails(fn() => $flow->finish($flow->fixture->query()), 'Emergency disable blocks test callback');
test(!$flow->transactions, 'Emergency disable invalidates pending state');
putenv('SOCA_EMERGENCY_DISABLE');
test(Flow::identity(['iss' => 'https://one.example', 'sub' => 'same']) !== Flow::identity(['iss' => 'https://two.example', 'sub' => 'same']), 'Identity binds issuer and subject');
fails(fn() => Flow::identity(['iss' => 'https://one.example', 'sub' => '']), 'Empty subject denied');
fails(fn() => Flow::profile(['iss' => 'https://one.example', 'sub' => 'x', 'email' => 'a@example.com', 'email_verified' => 'true']), 'String email verification denied');
fails(fn() => Flow::profile(['iss' => 'https://one.example', 'sub' => 'x', 'email' => 'a@example.com', 'email_verified' => true, 'given_name' => "Bad\nName"]), 'Profile controls denied');
$path = tempnam(sys_get_temp_dir(), 'soca-config-');
file_put_contents($path, '{"enabled":false,"origin":"https://locked.example.com"}');
putenv('SOCA_CONFIG_FILE=' . $path);
test($flow->configuration()['origin'] === 'https://locked.example.com', 'Deployment overrides database configuration');
file_put_contents($path, '{"private_key_pem":"forbidden"}');
fails(fn() => $flow->configuration(), 'Private material excluded from deployment JSON');
putenv('SOCA_CONFIG_FILE'); unlink($path);
echo "SOCA host bridge: $count assertions passed (simulated host storage).\n";
