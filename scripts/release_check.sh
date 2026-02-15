#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[release] checking required files"
for f in README.md package.xml composer.json; do
  [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
done

echo "[release] validating composer.json"
php -n -r '$j=json_decode(file_get_contents("composer.json"), true); if(!is_array($j)){fwrite(STDERR,"invalid composer.json\n"); exit(1);} echo "composer.json ok\n";'

echo "[release] validating package.xml"
php -n -r '$x=simplexml_load_file("package.xml"); if($x===false){fwrite(STDERR,"invalid package.xml\n"); exit(1);} echo "package.xml ok\n";'

if [[ -f "example.php" ]]; then
  echo "[release] linting example.php"
  php -n -l example.php >/dev/null
fi

echo "[release] checking version metadata"
php -n -r '$x=simplexml_load_file("package.xml"); $rel=(string)$x->version->release; $api=(string)$x->version->api; if($rel===""||$api===""){fwrite(STDERR,"missing package.xml version\n"); exit(1);} echo "package.xml version: $rel / $api\n";'

echo "[release] release checks passed"
