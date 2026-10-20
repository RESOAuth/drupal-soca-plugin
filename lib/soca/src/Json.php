<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

/** Strict JSON decoding rejects duplicate names at every nesting level. */
final class Json {
    public static function decode(string $json): array {
        Failure::require(strlen($json) <= 262144, 'json_size');
        try {
            $decoded = json_decode($json, false, 32, JSON_THROW_ON_ERROR);
            Failure::require($decoded instanceof \stdClass, 'json_object');
            $offset = 0;
            self::scan($json, $offset, 0);
            return json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) { throw new Failure('invalid_json'); }
    }
    private static function space(string $s, int &$i): void {
        $i += strspn($s, " \t\n\r", $i);
    }
    private static function string(string $s, int &$i): string {
        $start = $i++;
        while ($i < strlen($s)) {
            if ($s[$i] === '\\') { $i += 2; continue; }
            if ($s[$i++] === '"') { return json_decode(substr($s, $start, $i - $start), true, 32, JSON_THROW_ON_ERROR); }
        }
        throw new Failure('invalid_json');
    }
    private static function scan(string $s, int &$i, int $depth): void {
        Failure::require($depth <= 32, 'json_depth');
        self::space($s, $i);
        if ($s[$i] === '"') { self::string($s, $i); return; }
        if ($s[$i] === '{' || $s[$i] === '[') {
            $object = $s[$i++] === '{';
            $end = $object ? '}' : ']'; $keys = [];
            self::space($s, $i);
            if ($s[$i] === $end) { $i++; return; }
            do {
                self::space($s, $i);
                if ($object) {
                    $key = self::string($s, $i);
                    Failure::require(!array_key_exists($key, $keys), 'duplicate_json_member');
                    $keys[$key] = true; self::space($s, $i); $i++;
                }
                self::scan($s, $i, $depth + 1); self::space($s, $i);
                $delimiter = $s[$i++];
            } while ($delimiter === ',');
            return;
        }
        while ($i < strlen($s) && !str_contains(",]} \t\n\r", $s[$i])) { $i++; }
    }
    public static function canonical(array $value): string {
        $sort = static function ($item) use (&$sort) {
            if (!is_array($item)) { return $item; }
            if (!array_is_list($item)) { ksort($item, SORT_STRING); }
            foreach ($item as &$child) { $child = $sort($child); }
            return $item;
        };
        return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }
    public static function b64(string $value): string { return rtrim(strtr(base64_encode($value), '+/', '-_'), '='); }
    public static function unb64(string $value): string {
        Failure::require((bool)preg_match('/^[A-Za-z0-9_-]+$/D', $value), 'base64url');
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        Failure::require($decoded !== false && self::b64($decoded) === $value, 'base64url');
        return $decoded;
    }
}
