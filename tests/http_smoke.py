#!/usr/bin/env python3
"""Public-route smoke against a disposable host with SSO explicitly disabled."""
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
product = Path(__file__).resolve().parents[1].name.removesuffix('-soca-plugin')
profile = {
    'drupal': (18081, '/user/login', '/soca/login', '/soca/client.json', '/soca/jwks.json', '/soca/callback'),
    'moodle': (18082, '/login/index.php', '/auth/soca/login.php', '/auth/soca/metadata.php', '/auth/soca/jwks.php', '/auth/soca/callback.php'),
    'joomla': (18083, '/index.php?option=com_users&view=login', '/index.php?soca=login', '/index.php?soca=metadata', '/index.php?soca=jwks', '/index.php?soca=callback'),
}[product]
port, login, start, metadata, jwks, callback = profile
base = f'http://127.0.0.1:{port}'
for attempt in range(50):
    try:
        with urllib.request.urlopen(base + metadata, timeout=5) as response:
            document = json.load(response)
        break
    except urllib.error.URLError:
        if attempt == 49: raise
        time.sleep(.2)
assert document['client_id'] == 'https://app.example.com' + metadata
assert document['redirect_uris'] == ['https://app.example.com' + callback]
assert document['token_endpoint_auth_method'] == 'private_key_jwt'
assert document['token_endpoint_auth_signing_alg'] == 'ES256'
assert document['id_token_signed_response_alg'] == 'ES256'
with urllib.request.urlopen(base + jwks, timeout=5) as response:
    keys = json.load(response)['keys']
assert len(keys) == 1 and keys[0]['kty'] == 'EC' and keys[0]['crv'] == 'P-256'
assert all(secret not in keys[0] for secret in ['d', 'p', 'q', 'k'])
with urllib.request.urlopen(base + login, timeout=10) as response:
    page = response.read().decode()
assert 'SOCA' in page and start.replace('&', '&amp;') in page
print(f'{product.capitalize()} HTTP smoke: 8 assertions passed (native login, correct public CIMD/JWKS, public-key boundary).')
