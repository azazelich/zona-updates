#!/usr/bin/env python3
"""Read-only, reproducible static audit. Does not execute APK code."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path

# Reuses the verified DEX scanner already in the project's build script.
from zona_build import method_location, manifest_info

TARGETS = {
    'stream_cookie_interceptor': ('Lvd/d;', 'b', '(LI9/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;'),
    'original_cookie_builder': ('Lid/a;', 'a', '(JLjava/lang/Object;)Ljava/lang/String;'),
    'freezona_cookie_builder': ('Lmobi/zona/utils/zona;', 'Cookie', '(JLandroid/content/Context;)Ljava/lang/String;'),
    'freezona_native_replacement': ('Lmobi/zona/utils/zona;', 'checkTimeNative123', '(Landroid/content/Context;JLjava/lang/String;)Ljava/lang/String;'),
}
EXPECTED = {
    'official': 'bd6b8eb66a9f2c45e6b95a372f1b7c0891bba898eb0ca7cb33c5102690561b8c',
    'reference': 'aa3c36ab5faa1770104b1f3347d52ad72270ec377b5f7684acc2323df70ba021',
}

def pool(data):
    count, _, flags, start, _ = struct.unpack_from('<IIIII', data, 16)
    offsets = struct.unpack_from('<' + 'I' * count, data, 36)
    def read_len(p, utf):
        if utf:
            n = data[p]; p += 1
            if n & 128:
                n = ((n & 127) << 8) | data[p]; p += 1
        else:
            n = struct.unpack_from('<H', data, p)[0]; p += 2
            if n & 32768:
                n = ((n & 32767) << 16) | struct.unpack_from('<H', data, p)[0]; p += 2
        return n, p
    names = []
    for off in offsets:
        p = 8 + start + off
        if flags & 256:
            _, p = read_len(p, True)
            n, p = read_len(p, True)
            names.append(data[p:p+n].decode('utf-8', 'replace'))
        else:
            n, p = read_len(p, False)
            names.append(data[p:p+2*n].decode('utf-16le', 'replace'))
    return names

def analyze(path, role):
    raw = Path(path).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != EXPECTED[role]:
        raise ValueError('Unexpected ' + role + ' APK SHA256: ' + sha)
    with zipfile.ZipFile(path) as z:
        if z.testzip():
            raise ValueError('Corrupted APK')
        manifest_strings = pool(z.read('AndroidManifest.xml'))
        permissions = sorted(set(s for s in manifest_strings if s.startswith('android.permission.')))
        libs = sorted(s for s in z.namelist() if s.startswith('lib/') and s.endswith('.so'))
        methods = {}
        for f in z.namelist():
            if f.startswith('classes') and f.endswith('.dex'):
                dex = z.read(f)
                for label, target in TARGETS.items():
                    # Scanner checks exact class + method + prototype.
                    matches, _ = method_location(dex, target)
                    if matches:
                        if len(matches) != 1 or label in methods:
                            raise ValueError('Unexpected duplicate method ' + label)
                        offset, size, registers, code = matches[0]
                        methods[label] = {
                            'dex': f, 'code_units': size,
                            'code_sha256': hashlib.sha256(code).hexdigest(),
                        }
        info = manifest_info(path)
    return {
        'sha256': sha, 'package': info.get('package'), 'version': info.get('versionName'),
        'permissions': permissions, 'native_libraries': libs, 'target_methods': methods,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('official_apk')
    ap.add_argument('freezona_apk')
    ap.add_argument('--out', default='audit-report.json')
    args = ap.parse_args()
    original = analyze(args.official_apk, 'official')
    reference = analyze(args.freezona_apk, 'reference')
    op, rp = set(original['permissions']), set(reference['permissions'])
    ol, rl = set(original['native_libraries']), set(reference['native_libraries'])
    report = {
        'official': original, 'freezona': reference,
        'added_permissions': sorted(rp - op), 'removed_permissions': sorted(op - rp),
        'added_native_libraries': sorted(rl - ol),
        'removed_native_libraries': sorted(ol - rl),
        'warning': 'STATIC AUDIT ONLY. No Android runtime or network inspection; no safety guarantee.',
    }
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('Report:', args.out)
    print('Additional permissions:', len(report['added_permissions']))
    print('Removed permissions:', len(report['removed_permissions']))
    print('Targeted methods:', len(original['target_methods']), len(reference['target_methods']))

if __name__ == '__main__':
    main()
