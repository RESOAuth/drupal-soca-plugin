#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
runtime="$root/demo/.runtime"
engine=${CONTAINER_ENGINE:-docker}
image='docker.io/library/wordpress@sha256:607e9f6829f9e4f3001bc91c98426aaa742d164af030aa7a8073932798e2af6b'
composer='docker.io/library/composer@sha256:af98f42dfff7c68ba8d53c2164fd9fde1087b7d449514baa38c418b1f6bc4bac'
mkdir -p "$runtime"
"$engine" run --rm "$composer" cat /usr/bin/composer > "$runtime/composer"
run() { "$engine" run --rm --network host -e DRUPAL_ROOT=/demo/site/web -v "$root:/plugin" -v "$runtime:/demo" -w /demo/site/web "$image" "$@"; }
"$engine" run --rm --network host -v "$root:/app" -w /app "$composer" install --no-interaction --no-progress --ignore-platform-req=ext-curl
if [[ ! -f "$runtime/site/composer.json" ]]; then
  "$engine" run --rm --network host -v "$runtime:/demo" -w /demo "$image" php /demo/composer create-project drupal/recommended-project:11.4.10 site --no-interaction --no-progress > "$runtime/install-source.log" 2>&1
fi
mkdir -p "$runtime/site/web/modules/custom"
[[ -L "$runtime/site/web/modules/custom/soca" ]] || ln -s /plugin "$runtime/site/web/modules/custom/soca"
[[ -L "$runtime/site/web/vendor" ]] || ln -s ../vendor "$runtime/site/web/vendor"
if [[ ! -f "$runtime/site/web/sites/default/settings.php" ]]; then
  run php core/scripts/drupal install minimal --site-name='SOCA Drupal demo' --password='Demo-Only-Replace-Me-2841' --no-interaction > "$runtime/install.log" 2>&1
fi
run php /plugin/tests/host.php
if [[ ${1:-test} == serve ]]; then
  printf 'Local demo: http://127.0.0.1:18081/user/login (admin / Demo-Only-Replace-Me-2841)\n'
  run php -S 127.0.0.1:18081 -t /demo/site/web /demo/site/web/.ht.router.php
fi
