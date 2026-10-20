#!/usr/bin/env python3
"""Build an installable ZIP and CycloneDX dependency inventory from the lockfile."""
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import hashlib
import json
root = Path(__file__).resolve().parents[1]
product = root.name.removesuffix('-soca-plugin')
build = root / 'build'
build.mkdir(exist_ok=True)
files = []
for directory in ['lib', 'vendor', 'src', 'classes', 'db', 'lang', 'cli']:
    files.extend(p for p in (root / directory).rglob('*') if p.is_file())
files.extend(p for p in root.iterdir() if p.is_file() and (p.suffix in ['.php', '.yml', '.module', '.install'] or p.name in ['README.md', 'LICENSE', 'composer.json', 'composer.lock']))
package = build / f'{product}-soca-0.1.0.zip'
with ZipFile(package, 'w', ZIP_DEFLATED) as archive:
    for path in sorted(set(files)):
        info = ZipInfo('soca/' + str(path.relative_to(root)), (1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, path.read_bytes())
lock = json.loads((root / 'composer.lock').read_text())
components = []
for dep in lock['packages']:
    component = {'type': 'library', 'name': dep['name'], 'version': dep['version'], 'purl': f"pkg:composer/{dep['name']}@{dep['version']}"}
    if dep.get('license'): component['licenses'] = [{'license': {'id': name}} for name in dep['license']]
    components.append(component)
(build / 'bom.cdx.json').write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1, 'components': components}, indent=2) + '\n')
(build / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in [package, build / 'bom.cdx.json']))
print(package)
