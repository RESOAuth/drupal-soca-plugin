#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
runtime="$root/demo/.runtime"
engine=${CONTAINER_ENGINE:-docker}
identity=()
if [[ "$engine" == *docker ]]; then identity=(--user "$(id -u):$(id -g)"); fi
image='docker.io/library/wordpress@sha256:607e9f6829f9e4f3001bc91c98426aaa742d164af030aa7a8073932798e2af6b'
composer='docker.io/library/composer@sha256:af98f42dfff7c68ba8d53c2164fd9fde1087b7d449514baa38c418b1f6bc4bac'
mkdir -p "$runtime"
"$engine" run --rm "${identity[@]}" -e COMPOSER_HOME=/tmp/soca-composer "$composer" cat /usr/bin/composer > "$runtime/composer"
run() { "$engine" run --rm "${identity[@]}" -e COMPOSER_HOME=/tmp/soca-composer --network host -e DRUPAL_ROOT=/demo/site/web -v "$root:/plugin" -v "$runtime:/demo" -w /demo/site/web "$image" "$@"; }
"$engine" run --rm "${identity[@]}" -e COMPOSER_HOME=/tmp/soca-composer --network host -v "$root:/app" -w /app "$composer" install --no-interaction --no-progress --ignore-platform-req=ext-curl
if [[ ! -f "$runtime/site/composer.json" ]]; then
  "$engine" run --rm "${identity[@]}" -e COMPOSER_HOME=/tmp/soca-composer --network host -v "$runtime:/demo" -w /demo "$image" php /demo/composer create-project drupal/recommended-project:11.4.10 site --no-interaction --no-progress > "$runtime/install-source.log" 2>&1
fi
mkdir -p "$runtime/site/web/modules/custom"
[[ -L "$runtime/site/web/modules/custom/soca" ]] || ln -s /plugin "$runtime/site/web/modules/custom/soca"
[[ -L "$runtime/site/web/vendor" ]] || ln -s ../vendor "$runtime/site/web/vendor"
if [[ ! -f "$runtime/site/web/sites/default/settings.php" ]]; then
  run php core/scripts/drupal install minimal --site-name='SOCA Drupal demo' --password='Demo-Only-Replace-Me-2841' --no-interaction > "$runtime/install.log" 2>&1
fi
run php /plugin/tests/host.php

# Public documents are checked locally without weakening production HTTPS rules.
run php -r '$key=openssl_pkey_new(["private_key_type"=>OPENSSL_KEYTYPE_EC,"curve_name"=>"prime256v1"]);openssl_pkey_export($key,$pem);file_put_contents("/demo/http-key.pem",$pem);'
printf '%s' '{"enabled":false,"origin":"https://app.example.com","allowed_domains":["example.com"]}' > "$runtime/http-profile.json"
"$engine" run -d --stop-signal SIGTERM --stop-timeout 1 --name drupal-soca-smoke --network host "${identity[@]}" -e SOCA_CONFIG_FILE=/demo/http-profile.json -e SOCA_PRIVATE_KEY_FILE=/demo/http-key.pem -v "$root:/plugin" -v "$runtime:/demo" -w /demo/site/web "$image" php -d max_input_vars=5000 -S 127.0.0.1:18081 -t /demo/site/web /demo/site/web/.ht.router.php > /dev/null
trap '"$engine" rm -f drupal-soca-smoke > /dev/null 2>&1 || true' EXIT
python3 tests/http_smoke.py
"$engine" kill drupal-soca-smoke > /dev/null
"$engine" rm -f drupal-soca-smoke > /dev/null
trap - EXIT

if [[ ${1:-test} == serve ]]; then
  printf 'Local demo: http://127.0.0.1:18081/user/login (admin / Demo-Only-Replace-Me-2841)\n'
  run php -S 127.0.0.1:18081 -t /demo/site/web /demo/site/web/.ht.router.php
fi
