<?php
/** Run only against a disposable installed Drupal site. */
declare(strict_types=1);

use Drupal\Core\DrupalKernel;
use Drupal\soca\DrupalFlow;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

$root = getenv('DRUPAL_ROOT') ?: '/var/www/html';
chdir($root);
$loader = require dirname($root) . '/vendor/autoload.php';
$request = Request::create('https://app.example.com/');
$kernel = DrupalKernel::createFromRequest($request, $loader, 'prod');
$kernel->boot(); $kernel->preHandle($request);
\Drupal::service('module_installer')->install(['soca']);
$request->setSession(new Session(new MockArraySessionStorage()));
\Drupal::configFactory()->getEditable('soca.settings')->set('profile', ['origin' => 'https://app.example.com',
    'issuer' => 'https://issuer.example.com', 'allowed_domains' => ['example.com'], 'provisioning' => true])->save();
$flow = new DrupalFlow();
$count = 0;
function verify(bool $value, string $label): void { global $count; $count++; if (!$value) { throw new RuntimeException($label); } }
function denied(callable $callback, string $label): void { try { $callback(); } catch (Throwable $e) { verify(true, $label); return; } verify(false, $label); }
$claims = ['iss' => 'https://issuer.example.com', 'sub' => 'test-' . bin2hex(random_bytes(8)),
    'email' => bin2hex(random_bytes(8)) . '@example.com', 'email_verified' => true];
$user = $flow->account($claims);
verify($user->id() > 1 && $user->isActive(), 'Native account provisioning');
verify($flow->account($claims)->id() === $user->id(), 'Stable issuer/subject returns linked account');
$before = \Drupal::database()->select('users', 'u')->countQuery()->execute()->fetchField();
denied(fn() => $flow->account(array_replace($claims, ['sub' => 'other-subject'])), 'Existing email cannot silently link');
verify(\Drupal::database()->select('users', 'u')->countQuery()->execute()->fetchField() === $before, 'Failed provision creates no orphan');
$user->block()->save();
denied(fn() => $flow->account($claims), 'Disabled account remains disabled');
$user->activate()->save();
\Drupal::configFactory()->getEditable('soca.settings')->set('profile.provisioning', false)->save();
denied(fn() => $flow->account(array_replace($claims, ['sub' => 'unlinked', 'email' => 'new@example.com'])), 'Provisioning opt-in enforced');
$put = new ReflectionMethod($flow, 'putTransaction');
$take = new ReflectionMethod($flow, 'takeTransaction');
$state = bin2hex(random_bytes(32));
$put->invoke($flow, $state, ['started' => time(), 'verifier' => 'confidential-server-session']);
$original = $request->getSession();
$request->setSession(new Session(new MockArraySessionStorage()));
denied(fn() => $take->invoke($flow, $state), 'Copied callback has no browser-bound transaction');
$request->setSession($original);
verify($take->invoke($flow, $state)['verifier'] === 'confidential-server-session', 'Native server session transaction consumed');
denied(fn() => $take->invoke($flow, $state), 'Native database replay rejected');
verify(!\Drupal::database()->select('soca_transactions', 't')->countQuery()->execute()->fetchField(), 'Consumed replay rows cleaned');
\Drupal::getContainer()->set('session', $original);
$original->start(); $old = $original->getId();
if (class_exists(\Drupal\user\LoginFinalizer::class)) { \Drupal::service(\Drupal\user\LoginFinalizer::class)->finalizeLogin($user); }
else { user_login_finalize($user); }
verify((int) \Drupal::currentUser()->id() === (int) $user->id(), 'Native Drupal authenticated account');
verify($old !== $original->getId(), 'Native session rotates at authentication');
echo "Drupal native host: $count assertions passed.\n";
