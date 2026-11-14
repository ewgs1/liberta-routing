#!/usr/bin/env python3
"""Extract hostname candidates from an APK, without executing or redistributing it."""
import argparse, hashlib, ipaddress, json, re, struct, subprocess, zipfile
from pathlib import Path
from urllib.parse import urlsplit

HOST = re.compile(r'(?<![a-z0-9_.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:ru|su|com|net|org|io|app|tech|cloud|online|me|cc|link|by|kz|yandex|dev|pro|tv|one|aero)(?![a-z0-9_.-])', re.I)

def uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data): raise ValueError('invalid DEX string')
        byte = data[offset]; offset += 1; value |= (byte & 127) << shift
        if byte < 128: return value, offset
    raise ValueError('invalid DEX length')

def dex_strings(data):
    if len(data) < 112 or not data.startswith(b'dex\n'): return []
    count, offset = struct.unpack_from('<II', data, 56)
    if count > 2_000_000 or offset + 4 * count > len(data): raise ValueError('invalid DEX table')
    result = []
    for index in range(count):
        pos = struct.unpack_from('<I', data, offset + index * 4)[0]
        _, pos = uleb(data, pos)
        end = data.find(b'\0', pos, min(len(data), pos + 65536))
        if end >= pos: result.append(data[pos:end].decode('utf-8', 'ignore'))
    return result

def strings(data, name):
    if name.endswith('.dex'): return dex_strings(data)
    # Android resource pools contain UTF-8/UTF-16 strings; .so constants are ASCII.
    result = [s.decode('utf-8', 'ignore') for s in re.findall(rb'[\x20-\x7e]{5,65536}', data)]
    result += [s.decode('utf-16le', 'ignore') for s in re.findall(rb'(?:[\x20-\x7e]\x00){5,65536}', data)]
    return result

def inspect(path):
    candidates = {}
    with zipfile.ZipFile(path) as archive:
        items = archive.infolist()
        if len(items) > 30000 or sum(x.file_size for x in items) > 1_500_000_000: raise ValueError('APK exceeds inspection budget')
        for item in items:
            if item.file_size > 120_000_000 or item.flag_bits & 1: raise ValueError('unsupported APK entry')
            if not (item.filename.endswith(('.dex','.xml','.json','.txt','.html','.js','.so','.arsc','.properties'))): continue
            for value in strings(archive.read(item), item.filename):
                names=[match.group() for match in HOST.finditer(value)]
                for match in re.finditer(r'(?:https?|wss?)://[^\s\x00<>"\x27]+',value,re.I):
                    try:
                        host=urlsplit(match.group()).hostname
                        if host: names.append(host.encode('idna').decode())
                    except (ValueError,UnicodeError): pass
                for name in names:
                    host=name.lower().rstrip('.')
                    if len(host.split('.'))<2 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in host.split('.')): continue
                    if host.split('.')[-1] in ['local','lan','internal','invalid','test','example','localhost']: continue
                    try: ipaddress.ip_address(host); continue
                    except ValueError: pass
                    if len(host) <= 253: candidates.setdefault(host, set()).add('dex' if item.filename.endswith('.dex') else 'resources-or-native')
    return [{'domain': host, 'locations': sorted(locations), 'status': 'candidate-only'} for host, locations in sorted(candidates.items())]

def verify(path, expected=None):
    try: result = subprocess.run(['apksigner','verify','--verbose','--print-certs',str(path)],capture_output=True,text=True,timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired): raise ValueError('apksigner unavailable or timed out')
    if result.returncode: raise ValueError('APK signature verification failed')
    certs = sorted(set(re.findall(r'certificate SHA-256 digest:\s*([a-fA-F0-9]{64})',result.stdout)))
    if not certs: raise ValueError('APK signer certificate unavailable')
    certs = [value.lower() for value in certs]
    if expected and expected.lower().replace(':','') not in certs: raise ValueError('publisher certificate does not match expected pin')
    return {'integrity': 'verified', 'publisher': 'certificate-pinned' if expected else 'not-pinned', 'certificatesSha256': certs}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--apk',required=True);parser.add_argument('--out',required=True);parser.add_argument('--certificate-sha256');options=parser.parse_args()
    root=Path('.private').resolve();root.mkdir(mode=0o700,exist_ok=True)
    target=Path(options.out).resolve()
    if not target.is_relative_to(root) or target == root or target == Path(options.apk).resolve(): raise ValueError('output must be a separate file under .private')
    if Path(options.apk).stat().st_size > 350_000_000: raise ValueError('APK too large')
    signature=verify(options.apk,options.certificate_sha256)
    report={'schemaVersion':1,'artifactSha256':hashlib.file_digest(open(options.apk,'rb'),'sha256').hexdigest(),'signature':signature,'routesModified':False,'applicationExecuted':False,'candidates':inspect(options.apk)}
    target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with target.open('x') as handle: handle.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    target.chmod(0o600);print(json.dumps({'candidates':len(report['candidates']),'signature':signature['publisher'],'routesModified':False}))
if __name__ == '__main__':
    try: main()
    except Exception as error: raise SystemExit(str(error) if isinstance(error,ValueError) else 'APK inspection failed')
