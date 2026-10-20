<?php

declare(strict_types=1);

namespace Drupal\soca\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\soca\DrupalFlow;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

final class LoginController extends ControllerBase
{
    public function login(): Response { return $this->run(fn($flow) => new \Drupal\Core\Routing\TrustedRedirectResponse($flow->begin())); }
    public function callback(): Response {
        return $this->run(function ($flow) {
            $claims = $flow->finish(\Drupal::request()->query->all());
            if ($claims === null) { return new RedirectResponse(\Drupal\Core\Url::fromRoute('soca.settings')->toString()); }
            $account = $flow->account($claims);
            if (class_exists(\Drupal\user\LoginFinalizer::class)) {
                \Drupal::service(\Drupal\user\LoginFinalizer::class)->finalizeLogin($account);
            } else { user_login_finalize($account); }
            return new RedirectResponse(\Drupal\Core\Url::fromRoute('<front>')->toString());
        });
    }
    public function metadata(): Response { return $this->run(fn($f) => new JsonResponse($f->client()->metadata(), 200,
        ['Cache-Control' => 'public, max-age=300'])); }
    public function jwks(): Response { return $this->run(fn($f) => new JsonResponse($f->client()->jwks(), 200,
        ['Cache-Control' => 'public, max-age=300'])); }
    private function run(callable $action): Response {
        try { return $action(new DrupalFlow()); }
        catch (\Throwable $error) {
            $reference = bin2hex(random_bytes(6));
            \Drupal::logger('soca')->warning('SOCA request failed. Reference @reference, category @category.',
                ['@reference' => $reference, '@category' => get_class($error)]);
            return new Response('SOCA sign-in unavailable. Use local /user/login or contact an administrator. Reference ' . $reference,
                400, ['Cache-Control' => 'no-store', 'Content-Type' => 'text/plain; charset=utf-8']);
        }
    }
}
