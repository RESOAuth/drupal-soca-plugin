<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

final class Policy {
    public static function validate(array $config): void {
        foreach (['allowed_domains', 'denied_domains'] as $name) {
            Failure::require(is_array($config[$name] ?? []), 'domain_rules_array');
            foreach ($config[$name] ?? [] as $domain) {
                Failure::require(is_string($domain), 'invalid_domain_rule');
                $host = str_starts_with($domain, '*.') ? substr($domain, 2) : $domain;
                Failure::require(strlen($host) <= 253 && (bool)preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/iD', $host), 'invalid_domain_rule');
            }
        }
        foreach (['allowed_emails', 'denied_emails'] as $name) {
            Failure::require(is_array($config[$name] ?? []), 'email_rules_array');
            foreach ($config[$name] ?? [] as $email) { Failure::require(is_string($email) && strlen($email) <= 254 && (bool)filter_var($email, FILTER_VALIDATE_EMAIL), 'invalid_email_rule'); }
        }
    }
    public static function matchesDomain(string $domain, string $rule): bool {
        $domain = strtolower($domain); $rule = strtolower($rule);
        return str_starts_with($rule, '*.') ? str_ends_with($domain, substr($rule, 1)) && strlen($domain) > strlen($rule) - 1 : $domain === $rule;
    }
    public static function assertAllowed(array $claims, array $config): void {
        self::validate($config);
        $email = $claims['email'] ?? null;
        Failure::require(is_string($email) && strlen($email) <= 254 && (bool)filter_var($email, FILTER_VALIDATE_EMAIL) && ($claims['email_verified'] ?? null) === true, 'verified_email_required');
        $email = strtolower($email); $domain = substr(strrchr($email, '@'), 1);
        $matches = static function (string $prefix) use ($email, $domain, $config): bool {
            foreach ($config[$prefix . '_emails'] ?? [] as $rule) { if ($email === strtolower($rule)) { return true; } }
            foreach ($config[$prefix . '_domains'] ?? [] as $rule) { if (self::matchesDomain($domain, $rule)) { return true; } }
            return false;
        };
        Failure::require(!$matches('denied') && $matches('allowed'), 'admission_denied');
    }
}
