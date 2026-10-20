<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

interface HttpInterface {
    /** Return the JSON object itself, not an HTTP response envelope. */
    public function request(string $url, ?array $form = null, ?string $bearer = null): array;
}
