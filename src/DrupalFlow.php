<?php

declare(strict_types=1);

namespace Drupal\soca;

use RESOAuth\Soca\Bridge\Flow;
use RuntimeException;

final class DrupalFlow extends Flow
{
    protected function settings(): array {
        return \Drupal::config('soca.settings')->get('profile') ?? [];
    }
    protected function paths(): array {
        $base = \Drupal::request()->getBasePath();
        return ['redirect_uri' => $base . '/soca/callback', 'metadata_uri' => $base . '/soca/client.json',
            'jwks_uri' => $base . '/soca/jwks.json'];
    }
    protected function siteName(): string { return \Drupal::config('system.site')->get('name') ?: 'Drupal'; }
    public function operator(): int {
        $account = \Drupal::currentUser();
        return $account->hasPermission('administer soca') ? (int) $account->id() : 0;
    }
    protected function putTransaction(string $state, array $transaction): void {
        $session = \Drupal::request()->getSession();
        $pending = $session->get('soca.transactions', []);
        $pending = array_filter($pending, fn($t) => ($t['started'] ?? 0) >= time() - 300);
        if (count($pending) >= 5) { throw new RuntimeException('Too many outstanding sign-in attempts. Wait five minutes.'); }
        \Drupal::database()->delete('soca_transactions')->condition('expires', time(), '<')->execute();
        $hash = hash('sha256', $state);
        \Drupal::database()->insert('soca_transactions')->fields(['statehash' => $hash, 'expires' => time() + 300])->execute();
        $pending[$hash] = $transaction;
        $session->set('soca.transactions', $pending);
    }
    protected function takeTransaction(string $state): array {
        $session = \Drupal::request()->getSession();
        $pending = $session->get('soca.transactions', []);
        $hash = hash('sha256', $state);
        $transaction = $pending[$hash] ?? null;
        if (!$transaction) { throw new RuntimeException('This browser has no matching sign-in attempt.'); }
        unset($pending[$hash]);
        $session->set('soca.transactions', $pending);
        $consumed = \Drupal::database()->delete('soca_transactions')->condition('statehash', $hash)
            ->condition('expires', time(), '>=')->execute();
        if ($consumed !== 1) { throw new RuntimeException('Sign-in attempt expired or was already used.'); }
        return $transaction;
    }
    protected function evidence(string $kind): ?string { return \Drupal::state()->get('soca.' . $kind); }
    protected function saveEvidence(string $kind, string $revision): void { \Drupal::state()->set('soca.' . $kind, $revision); }
    public function invalidate(): void {
        \Drupal::database()->delete('soca_transactions')->execute();
        \Drupal::request()->getSession()->remove('soca.transactions');
    }
    public function account(array $claims): \Drupal\user\UserInterface {
        $identity = self::identity($claims);
        $connection = \Drupal::database();
        $tx = $connection->startTransaction();
        try {
            $uid = $connection->select('soca_links', 'l')->fields('l', ['uid'])->condition('identity', $identity)->execute()->fetchField();
            if ($uid) {
                $account = \Drupal\user\Entity\User::load($uid);
            } else {
                if (!$this->configuration()['provisioning']) { throw new RuntimeException('This identity needs an approved local account link.'); }
                $profile = self::profile($claims);
                // Existing emails are a conflict, never a candidate account selection.
                if (\Drupal::entityTypeManager()->getStorage('user')->loadByProperties(['mail' => $profile['email']])) {
                    throw new RuntimeException('Provisioning needs administrator review.');
                }
                $account = \Drupal\user\Entity\User::create(['name' => $profile['username'], 'mail' => $profile['email'],
                    'status' => 1, 'pass' => bin2hex(random_bytes(48))]);
                $account->save();
                $connection->insert('soca_links')->fields(['identity' => $identity, 'uid' => $account->id(), 'created' => time()])->execute();
            }
            if (!$account || !$account->isActive() || (int) $account->id() === 1 ||
                $account->hasPermission('administer users') || $account->hasPermission('administer permissions')) {
                throw new RuntimeException('This local account is not eligible for SOCA sign-in.');
            }
            unset($tx);
            return $account;
        } catch (\Throwable $error) {
            $tx->rollBack();
            throw $error;
        }
    }
    public function link(string $issuer, string $subject, int $uid): void {
        if (!$this->operator()) { throw new RuntimeException('Administrator approval is required.'); }
        $account = \Drupal\user\Entity\User::load($uid);
        if (!$account || !$account->isActive() || $uid === 1 || $account->hasPermission('administer users')) {
            throw new RuntimeException('The selected account is not eligible.');
        }
        if ($issuer !== $this->configuration()['issuer']) { throw new RuntimeException('Issuer must match the trusted profile.'); }
        \Drupal::database()->insert('soca_links')->fields(['identity' => self::identity(['iss' => $issuer, 'sub' => $subject]),
            'uid' => $uid, 'created' => time()])->execute();
        \Drupal::logger('soca')->notice('Administrator @operator approved an identity link for local account @uid.',
            ['@operator' => $this->operator(), '@uid' => $uid]);
    }
}
