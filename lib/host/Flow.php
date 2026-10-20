<?php

declare(strict_types=1);

namespace RESOAuth\Soca\Bridge;

use RESOAuth\Soca\Client;
use RESOAuth\Soca\Policy;
use RuntimeException;

/** Native adapters own sessions, atomic replay rows, administration and accounts. */
abstract class Flow
{
    abstract protected function settings(): array;
    /** Routes are fixed paths, including any installation prefix, never request Host data. */
    abstract protected function paths(): array;
    abstract protected function siteName(): string;
    abstract public function operator(): int;
    abstract protected function putTransaction(string $state, array $transaction): void;
    abstract protected function takeTransaction(string $state): array;
    abstract protected function evidence(string $kind): ?string;
    abstract protected function saveEvidence(string $kind, string $revision): void;
    abstract public function invalidate(): void;

    public static function defaults(): array
    {
        return [
            'enabled' => false, 'provisioning' => false,
            'issuer' => 'https://auth.resoauth.cloud', 'origin' => '',
            'metadata_mode' => 'hosted',
            'proxy_template' => 'https://dynamic-cimd.resoauth.cloud/cimd/%s',
            'allowed_emails' => [], 'allowed_domains' => [],
            'denied_emails' => [], 'denied_domains' => [],
        ];
    }

    public static function deployment(): array
    {
        $path = getenv('SOCA_CONFIG_FILE');
        if ($path === false || $path === '') {
            return [];
        }
        if (!str_starts_with($path, '/') || !is_readable($path)) {
            throw new RuntimeException('SOCA_CONFIG_FILE must reference a readable absolute JSON file.');
        }
        $contents = file_get_contents($path);
        if ($contents === false || strlen($contents) > 65536) {
            throw new RuntimeException('SOCA deployment configuration is unreadable or too large.');
        }
        $config = json_decode($contents, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($config) || array_is_list($config)) {
            throw new RuntimeException('SOCA configuration must be a JSON object.');
        }
        if (isset($config['private_key_pem'])) {
            throw new RuntimeException('Use SOCA_PRIVATE_KEY_FILE, never configuration, for private keys.');
        }
        return $config;
    }

    public function configuration(): array
    {
        $config = array_replace(self::defaults(), $this->settings(), self::deployment());
        foreach (['enabled', 'provisioning'] as $boolean) {
            if (!is_bool($config[$boolean])) {
                throw new RuntimeException('SOCA enabled and provisioning must be JSON booleans.');
            }
        }
        $origin = $config['origin'];
        if (!is_string($origin) || !str_starts_with($origin, 'https://') ||
            str_contains($origin, '?') || str_contains($origin, '#') ||
            parse_url($origin, PHP_URL_USER) !== null || parse_url($origin, PHP_URL_PATH) !== null || rtrim($origin, '/') !== $origin) {
            throw new RuntimeException('Configure the canonical HTTPS origin without a trailing slash, query or credentials.');
        }
        foreach ($this->paths() as $name => $path) {
            $config[$name] = $origin . $path;
        }
        $config['client_name'] = $config['client_name'] ?? $this->siteName();
        $config['client_uri'] = $config['client_uri'] ?? $origin . '/';
        Policy::validate($config);
        return $config;
    }

    public function client(): Client
    {
        $config = $this->configuration();
        $path = getenv('SOCA_PRIVATE_KEY_FILE');
        if ($path === false || !str_starts_with($path, '/') || !is_readable($path)) {
            throw new RuntimeException('Mount a persistent P-256 private key and set SOCA_PRIVATE_KEY_FILE.');
        }
        $key = file_get_contents($path);
        if ($key === false || strlen($key) > 32768) {
            throw new RuntimeException('The SOCA signing key is unreadable or too large.');
        }
        $config['private_key_pem'] = $key;
        unset($config['enabled']);
        return new Client($config);
    }

    public function revision(): string
    {
        $config = $this->configuration();
        unset($config['enabled']);
        return hash('sha256', $this->client()->revision() . json_encode($config, JSON_THROW_ON_ERROR)
            . (getenv('SOCA_SECURITY_EPOCH') ?: '1'));
    }

    public function disabled(): bool
    {
        return !in_array(strtolower((string) getenv('SOCA_EMERGENCY_DISABLE')), ['', '0', 'false'], true);
    }

    public function status(): array
    {
        $revision = $this->revision();
        return [
            'revision' => $revision, 'emergency_disabled' => $this->disabled(),
            'enabled' => $this->configuration()['enabled'],
            'documents_checked' => hash_equals($revision, $this->evidence('documents') ?? ''),
            'test_login_passed' => hash_equals($revision, $this->evidence('login') ?? ''),
            'client_id' => $this->client()->clientId(),
            'deployment_locked_fields' => array_keys(self::deployment()),
        ];
    }

    public function checkDocuments(): array
    {
        $this->requireAvailable();
        $result = $this->client()->checkDocuments();
        $this->saveEvidence('documents', $this->revision());
        return $result;
    }

    public function begin(bool $test = false): string
    {
        $this->requireAvailable();
        $revision = $this->revision();
        if ($test) {
            if ($this->operator() < 1) {
                throw new RuntimeException('An authenticated local administrator must start a test login.');
            }
        } elseif (!$this->configuration()['enabled'] ||
            !hash_equals($revision, $this->evidence('documents') ?? '') ||
            !hash_equals($revision, $this->evidence('login') ?? '')) {
            throw new RuntimeException('SOCA is disabled or this configuration has not passed document and operator login checks.');
        }
        $start = $this->client()->start();
        $transaction = $start['transaction'];
        $transaction['_revision'] = $revision;
        $transaction['_test_operator'] = $test ? $this->operator() : 0;
        $this->putTransaction($start['state'], $transaction);
        return $start['url'];
    }

    /** Return null for a side-effect-free operator test; verified claims otherwise. */
    public function finish(array $query): ?array
    {
        $this->requireAvailable();
        $state = $query['state'] ?? null;
        if (!is_string($state) || strlen($state) > 256 || strlen($state) < 16) {
            throw new RuntimeException('Invalid or missing SOCA transaction.');
        }
        // Host atomically deletes the shared replay row before any token request.
        $transaction = $this->takeTransaction($state);
        if (!hash_equals($this->revision(), $transaction['_revision'] ?? '')) {
            throw new RuntimeException('SOCA configuration changed. Start a new login.');
        }
        $operator = (int) ($transaction['_test_operator'] ?? 0);
        if ($operator && $operator !== $this->operator()) {
            throw new RuntimeException('The initiating administrator session is required.');
        }
        if (!$operator && !$this->configuration()['enabled']) {
            throw new RuntimeException('SOCA has been disabled.');
        }
        $claims = $this->client()->complete($transaction, $query);
        Policy::assertAllowed($claims, $this->configuration());
        if ($operator) {
            $this->saveEvidence('login', $this->revision());
            return null;
        }
        return $claims;
    }

    protected function requireAvailable(): void
    {
        if ($this->disabled()) {
            $this->invalidate();
            throw new RuntimeException('SOCA is disabled by deployment policy. Use local login.');
        }
    }

    /** Stable identity key; email and mutable profile values never select an account. */
    public static function identity(array $claims): string
    {
        if (!is_string($claims['iss'] ?? null) || !is_string($claims['sub'] ?? null) ||
            $claims['iss'] === '' || $claims['sub'] === '' || strlen($claims['sub']) > 255) {
            throw new RuntimeException('A validated issuer and subject are required.');
        }
        return hash('sha256', json_encode([$claims['iss'], $claims['sub']], JSON_THROW_ON_ERROR));
    }

    public static function profile(array $claims): array
    {
        if (($claims['email_verified'] ?? null) !== true || !is_string($claims['email'] ?? null) ||
            !filter_var($claims['email'], FILTER_VALIDATE_EMAIL) || strlen($claims['email']) > 100) {
            throw new RuntimeException('Provisioning requires a verified, valid email address.');
        }
        $given = $claims['given_name'] ?? 'SOCA';
        $family = $claims['family_name'] ?? 'User';
        foreach ([$given, $family] as $name) {
            if (!is_string($name) || strlen($name) > 100 || preg_match('/[\x00-\x1F\x7F]/', $name)) {
                throw new RuntimeException('Profile names must be bounded text.');
            }
        }
        return ['email' => $claims['email'], 'given_name' => $given, 'family_name' => $family,
            'username' => 'soca_' . substr(self::identity($claims), 0, 40)];
    }
}
