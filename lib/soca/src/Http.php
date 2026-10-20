<?php
declare(strict_types=1);
namespace RESOAuth\Soca;

/** HTTPS transport: validates every DNS answer and pins the connection address. */
final class Http implements HttpInterface {
    public static function url(string $url): array {
        Failure::require(strlen($url) <= 16384 && !preg_match('/[^\x21-\x7e]|\\\\/', $url), 'invalid_url');
        $p = parse_url($url);
        Failure::require(is_array($p) && ($p['scheme'] ?? '') === 'https' && !isset($p['user'], $p['pass']) && !isset($p['user']) && !isset($p['pass']) && !isset($p['fragment']) && !str_contains($url, '#'), 'https_required');
        Failure::require((bool)preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/D', $p['host'] ?? '') && strlen($p['host']) <= 253, 'public_hostname_required');
        Failure::require(!preg_match('/%(?![a-fA-F0-9]{2})/', $url), 'url_encoding');
        foreach (explode('/', rawurldecode($p['path'] ?? '/')) as $part) { Failure::require($part !== '.' && $part !== '..', 'url_dot_path'); }
        Failure::require(!isset($p['port']) || $p['port'] > 0, 'url_port');
        return $p;
    }
    public static function publicIp(string $ip): bool {
        if (str_contains($ip, ':')) {
            $bin = @inet_pton($ip);
            return $bin !== false && strlen($bin) === 16 && (ord($bin[0]) & 0xe0) === 0x20 &&
                !(ord($bin[0]) === 0x20 && ord($bin[1]) === 0x01 && ord($bin[2]) === 0x0d && ord($bin[3]) === 0xb8) &&
                !str_starts_with(strtolower($ip), '2002:') &&
                !(ord($bin[0]) === 0x20 && ord($bin[1]) === 0x01 && ord($bin[2]) < 2) &&
                !(ord($bin[0]) === 0x3f && ord($bin[1]) === 0xff && (ord($bin[2]) & 0xf0) === 0);
        }
        return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) &&
            !preg_match('/^(?:100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|192\.0\.[02]\.|198\.(?:18|19)\.|192\.88\.99\.|198\.51\.100\.|203\.0\.113\.|(?:22[4-9]|23[0-9]|24[0-9]|25[0-5])\.)/', $ip);
    }
    public function request(string $url, ?array $form = null, ?string $bearer = null): array {
        $p = self::url($url); $host = strtolower($p['host']); $port = $p['port'] ?? 443;
        Failure::require(extension_loaded('curl'), 'curl_required');
        $ips = gethostbynamel($host) ?: [];
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $r) { if (isset($r['ipv6'])) { $ips[] = $r['ipv6']; } }
        $ips = array_values(array_unique($ips));
        Failure::require(count($ips) > 0, 'dns_failed');
        foreach ($ips as $ip) { Failure::require(self::publicIp($ip), 'nonpublic_address'); }
        $address = str_contains($ips[0], ':') ? '[' . $ips[0] . ']' : $ips[0];
        $headers = ['Accept: application/json', 'Accept-Encoding: identity'];
        if ($bearer !== null) {
            Failure::require(strlen($bearer) <= 16384 && (bool)preg_match('/^[A-Za-z0-9._~+\/-]+=*$/D', $bearer), 'invalid_bearer');
            $headers[] = 'Authorization: Bearer ' . $bearer;
        }
        $body = ''; $headerSize = 0; $responseHeaders = [];
        $handle = curl_init($url);
        $options = [CURLOPT_RESOLVE => ["$host:$port:$address"], CURLOPT_PROXY => '', CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 12, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_HTTPHEADER => $headers,
            CURLOPT_USERAGENT => 'RESOAuth-SOCA/0.1.0',
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > 262144) { return 0; }
                $body .= $chunk; return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headerSize, &$responseHeaders): int {
                $headerSize += strlen($line); if ($headerSize > 32768) { return 0; }
                if (str_contains($line, ':')) { [$key, $value] = explode(':', $line, 2); $responseHeaders[strtolower(trim($key))] = trim($value); }
                return strlen($line);
            }];
        if ($form !== null) {
            $options[CURLOPT_POST] = true; $options[CURLOPT_POSTFIELDS] = http_build_query($form, '', '&', PHP_QUERY_RFC3986);
            $options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
        }
        try {
            Failure::require(curl_setopt_array($handle, $options) && curl_exec($handle) !== false, 'https_request_failed');
            Failure::require(curl_getinfo($handle, CURLINFO_RESPONSE_CODE) === 200, 'http_status');
            Failure::require((bool)preg_match('~^application/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)~i', $responseHeaders['content-type'] ?? ''), 'json_content_type');
            Failure::require(strtolower($responseHeaders['content-encoding'] ?? 'identity') === 'identity', 'encoded_response');
            return Json::decode($body);
        } finally { curl_close($handle); }
    }
}
