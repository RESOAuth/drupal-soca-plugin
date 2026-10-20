<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

/** Safe reason codes only: do not append tokens, claims or callback parameters. */
final class Failure extends \RuntimeException {
    public function __construct(public readonly string $reason, string $message = '') {
        parent::__construct($message !== '' ? $message : 'SOCA validation failed: ' . $reason);
    }
    public static function require(bool $condition, string $reason): void {
        if (!$condition) { throw new self($reason); }
    }
}
