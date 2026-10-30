#!/usr/bin/env python3
"""Verified one-method Zona NoVAST patch. Refuse unknown layouts / identities."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile
import zlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding

OFFICIAL_SIGNER = 'e85c1eb707f4c7987e51886a8b8eee159c4256aabfcca179626cd04aac4aa989'
CUSTOM_SIGNER = '1ae0e98bbf5c2206fa537593f15170d614419be68e7029c70cac7d18754ae8b1'
AD_METHOD = ('Lmobi/zona/data/model/response/VastResponse;', 'getVast', '()Ljava/lang/String;')
EXPECTED_CODE = bytes.fromhex('5410414c1100')
NEW_CODE = bytes.fromhex('1a0000001100')


def uleb(data, pos):
    result = 0
    shift = 0
    while True:
        value = data[pos]
        pos += 1
        result |= (value & 0x7f) << shift
        if value < 128:
            return result, pos
        shift += 7


def method_location(data):
    u16 = lambda p: struct.unpack_from('<H', data, p)[0]
    u32 = lambda p: struct.unpack_from('<I', data, p)[0]
    n, off = struct.unpack_from('<II', data, 56)
    names = []
    for i in range(n):
        p = u32(off + 4 * i)
        _, p = uleb(data, p)
        names.append(data[p:data.index(b'\0', p)].decode('utf-8', 'replace'))
    n, off = struct.unpack_from('<II', data, 64)
    types = [names[u32(off + 4 * i)] for i in range(n)]
    n, off = struct.unpack_from('<II', data, 72)
    protos = []
    for i in range(n):
        _, ret, po = struct.unpack_from('<III', data, off + i * 12)
        n_params = u32(po) if po else 0
        param_types = ''.join(types[u16(po + 4 + j * 2)] for j in range(n_params))
        protos.append('(' + param_types + ')' + types[ret])
    n, off = struct.unpack_from('<II', data, 88)
    methods = []
    for i in range(n):
        cl, pro, name = struct.unpack_from('<HHI', data, off + i * 8)
        methods.append((types[cl], names[name], protos[pro]))
    n, off = struct.unpack_from('<II', data, 96)
    found = []
    for i in range(n):
        _, _, _, _, _, _, cd, _ = struct.unpack_from('<8I', data, off + i * 32)
        if not cd:
            continue
        p = cd
        ns, p = uleb(data, p)
        ni, p = uleb(data, p)
        nd, p = uleb(data, p)
        nv, p = uleb(data, p)
        for _ in range(ns + ni):
            _, p = uleb(data, p)
            _, p = uleb(data, p)
        for z in range(nd + nv):
            if z in (0, nd):
                mid = 0
            delta, p = uleb(data, p)
            mid += delta
            _, p = uleb(data, p)
            co, p = uleb(data, p)
            if co and methods[mid] == AD_METHOD:
                regs, ins, outs, tries, debug, size = struct.unpack_from('<HHHHII', data, co)
                code = data[co + 16:co + 16 + size * 2]
                found.append((co, size, regs, code))
    return found, names[0]


def lp(data):
    return struct.pack('<I', len(data)) + data


def take(data, pos):
    n = struct.unpack_from('<I', data, pos)[0]
    return data[pos + 4:pos + 4 + n], pos + 4 + n


def signing_certificate_digest(path):
    data = Path(path).read_bytes()
    eo = data.rfind(b'PK\x05\x06')
    if eo < 0:
        raise ValueError('ZIP End of Central Directory not found')
    cd = struct.unpack_from('<I', data, eo + 16)[0]
    if data[cd - 16:cd] != b'APK Sig Block 42':
        raise ValueError('Original has no recognized APK v2 signature')
    size = struct.unpack_from('<Q', data, cd - 24)[0]
    pos = cd - size
    while pos < cd - 24:
        length = struct.unpack_from('<Q', data, pos)[0]
        signature_id = struct.unpack_from('<I', data, pos + 8)[0]
        if signature_id == 0x7109871a:
            signers, _ = take(data[pos + 12:pos + 8 + length], 0)
            signer, _ = take(signers, 0)
            signed_data, _ = take(signer, 0)
            _, p = take(signed_data, 0)
            certificates, _ = take(signed_data, p)
            cert, _ = take(certificates, 0)
            return hashlib.sha256(cert).hexdigest()
        pos += length + 8
    raise ValueError('No APK v2 signer')


def manifest_info(path):
    with zipfile.ZipFile(path) as archive:
        data = archive.read('AndroidManifest.xml')
    assert data[:4] == b'\x03\x00\x08\x00'
    count, _, flags, start, _ = struct.unpack_from('<IIIII', data, 16)
    offsets = struct.unpack_from('<' + str(count) + 'I', data, 36)

    def length(p, utf8):
        if utf8:
            n = data[p]; p += 1
            if n & 128:
                n = ((n & 127) << 8) | data[p]; p += 1
            return n, p
        n = struct.unpack_from('<H', data, p)[0]; p += 2
        if n & 32768:
            n = ((n & 32767) << 16) | struct.unpack_from('<H', data, p)[0]; p += 2
        return n, p

    strings = []
    for offset in offsets:
        p = 8 + start + offset
        if flags & 256:
            _, p = length(p, True)
            n, p = length(p, True)
            strings.append(data[p:p + n].decode('utf-8'))
        else:
            n, p = length(p, False)
            strings.append(data[p:p + n * 2].decode('utf-16le'))
    p = 8
    while p < len(data):
        ty, _, size = struct.unpack_from('<HHI', data, p)
        if ty == 0x102:
            _, name, attr_start, attr_size, attrs, *_ = struct.unpack_from('<IIHHHHHH', data, p + 16)
            if strings[name] == 'manifest':
                result = {}
                for i in range(attrs):
                    a = p + 16 + attr_start + i * attr_size
                    _, idx, raw, _, _, dt, value = struct.unpack_from('<IIIHBBI', data, a)
                    result[strings[idx]] = strings[raw] if raw != 0xffffffff else (strings[value] if dt == 3 else value)
                return result
        p += size
    raise ValueError('Missing manifest')


def digest_apk(parts):
    chunks = []
    for part in parts:
        for i in range(0, len(part), 1024 * 1024):
            chunk = part[i:i + 1024 * 1024]
            chunks.append(hashlib.sha256(b'\xa5' + struct.pack('<I', len(chunk)) + chunk).digest())
    return hashlib.sha256(b'\x5a' + struct.pack('<I', len(chunks)) + b''.join(chunks)).digest()


def signed_v2_data(data, cert_der, key):
    eo = data.rfind(b'PK\x05\x06')
    if eo < 0 or eo + 22 != len(data):
        raise ValueError('Unexpected ZIP structure')
    cd = struct.unpack_from('<I', data, eo + 16)[0]
    if data[cd:cd+4] != b'PK\x01\x02':
        raise ValueError('No central directory')
    digest = digest_apk([data[:cd], data[cd:eo], data[eo:]])
    alg = 0x0103
    signed = lp(lp(struct.pack('<I', alg) + lp(digest))) + lp(lp(cert_der)) + lp(b'')
    sig = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed) + lp(lp(struct.pack('<I', alg) + lp(sig))) + lp(pub)
    val = lp(lp(signer))
    pair = struct.pack('<Q', 4 + len(val)) + struct.pack('<I', 0x7109871a) + val
    block_size = len(pair) + 24
    block = struct.pack('<Q', block_size) + pair + struct.pack('<Q', block_size) + b'APK Sig Block 42'
    eo2 = bytearray(data[eo:])
    struct.pack_into('<I', eo2, 16, cd + len(block))
    out = data[:cd] + block + data[cd:eo] + eo2
    final_eo = out.rfind(b'PK\x05\x06')
    final_cd = struct.unpack_from('<I', out, final_eo + 16)[0]
    old_eo = bytearray(out[final_eo:])
    struct.pack_into('<I', old_eo, 16, cd)
    assert digest_apk([out[:cd], out[final_cd:final_eo], old_eo]) == digest
    return out


def android_tool(name):
    """Find Android build tools; never publish a ZIP that was not aligned."""
    override = os.environ.get('ZONA_' + name.upper())
    if override:
        return override
    direct = shutil.which(name)
    if direct:
        return direct
    for root in (os.environ.get('ANDROID_HOME'), os.environ.get('ANDROID_SDK_ROOT')):
        if root:
            matches = sorted((Path(root) / 'build-tools').glob('*/' + name))
            if matches:
                return str(matches[-1])
    raise ValueError(name + ' missing: install Android SDK build-tools before signing')


def build(original, output, keyfile, password, restore_original=False):
    info = manifest_info(original)
    if info.get('package') != 'mobi.zona':
        raise ValueError('Unexpected package name')
    if signing_certificate_digest(original) != OFFICIAL_SIGNER:
        raise ValueError('Official source signature mismatch')
    key, cert, _ = pkcs12.load_key_and_certificates(Path(keyfile).read_bytes(), password.encode())
    if not key or not cert:
        raise ValueError('Missing signing certificate')
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(cert_der).hexdigest() != CUSTOM_SIGNER:
        raise ValueError('Signer differs from our previously installed Zona')
    with tempfile.TemporaryDirectory() as tmp:
        unsigned = Path(tmp, 'unsigned.apk')
        v1 = Path(tmp, 'v1.apk')
        aligned = Path(tmp, 'aligned.apk')
        patch_count = 0
        patched = None
        with zipfile.ZipFile(original) as zin, zipfile.ZipFile(unsigned, 'w') as zout:
            for item in zin.infolist():
                name = item.filename
                if name.startswith('META-INF/') and (name.upper() == 'META-INF/MANIFEST.MF' or name.upper().endswith(('.SF', '.RSA', '.DSA', '.EC')) or name.upper().split('/')[-1].startswith('SIG-')):
                    continue
                raw = zin.read(name)
                if not restore_original and name.startswith('classes') and name.endswith('.dex'):
                    positions, first_string = method_location(raw)
                    if positions:
                        if len(positions) != 1 or first_string != '':
                            raise ValueError('Unsafe or ambiguous ad method location')
                        offset, size, regs, bytecode = positions[0]
                        if size != 3 or regs < 1 or bytecode != EXPECTED_CODE:
                            raise ValueError('Advertising method changed; patch refused')
                        new = bytearray(raw)
                        new[offset + 16:offset + 22] = NEW_CODE
                        new[12:32] = hashlib.sha1(new[32:]).digest()
                        struct.pack_into('<I', new, 8, zlib.adler32(new[12:]) & 0xffffffff)
                        raw = bytes(new)
                        patch_count += 1
                        patched = name
                zout.writestr(item, raw)
        if patch_count != (0 if restore_original else 1):
            raise ValueError('Unexpected patch count ' + str(patch_count))
        alias = 'zona no-vast local test'
        cmd = ['jarsigner', '-keystore', str(keyfile), '-storetype', 'PKCS12',
               '-storepass:env', 'ZONA_KEY_PASSWORD', '-keypass:env', 'ZONA_KEY_PASSWORD',
               '-sigalg', 'SHA256withRSA', '-digestalg', 'SHA-256', '-signedjar', str(v1), str(unsigned), alias]
        env = os.environ.copy()
        env['ZONA_KEY_PASSWORD'] = password
        subprocess.run(cmd, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['jarsigner', '-verify', str(v1)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        zipalign = android_tool('zipalign')
        subprocess.run([zipalign, '-f', '4', str(v1), str(aligned)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run([zipalign, '-c', '4', str(aligned)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # v2 signing must happen AFTER zipalign; otherwise ZIP changes invalidate v2.
        Path(output).write_bytes(signed_v2_data(aligned.read_bytes(), cert_der, key))
    subprocess.run(['jarsigner', '-verify', str(output)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run([android_tool('apksigner'), 'verify', '--verbose', str(output)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run([android_tool('zipalign'), '-c', '4', str(output)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if signing_certificate_digest(output) != CUSTOM_SIGNER:
        raise ValueError('Output certificate mismatch')
    with zipfile.ZipFile(original) as src, zipfile.ZipFile(output) as dest:
        if dest.testzip():
            raise ValueError('ZIP CRC mismatch')
        changed = [n for n in src.namelist() if n not in ('META-INF/CERT.RSA', 'META-INF/CERT.SF', 'META-INF/MANIFEST.MF') and src.read(n) != dest.read(n)]
        expected_changes = [] if restore_original else [patched]
        if changed != expected_changes:
            raise ValueError('Unexpected modifications: ' + repr(changed))
    return dict(package=info['package'], versionCode=info['versionCode'], versionName=info['versionName'],
                mode='original-recovery-with-ads' if restore_original else 'experimental-no-vast',
                modified=patched, sha256=hashlib.sha256(Path(output).read_bytes()).hexdigest(),
                signingCertificate=CUSTOM_SIGNER, checks='v1+v2 signature via apksigner, zipalign, ZIP, code-diff, package OK',
                runtimeTested=False, updateClientWired=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('original')
    ap.add_argument('--key', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--restore-original', action='store_true', help='Sign unmodified original app code to recover playback without clearing data')
    args = ap.parse_args()
    password = os.getenv('ZONA_KEY_PASSWORD')
    if not password:
        ap.error('Missing ZONA_KEY_PASSWORD')
    results = build(args.original, args.out, args.key, password, restore_original=args.restore_original)
    Path(args.out + '.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
