#!/usr/bin/env python3
"""Assemble the guest root: the Android tree as the running system sees it, with every arm64
ELF file replaced by its precompiled, signed image.

    build_rootfs.py <extracted fs dir> <out root> [--platform ios|macos] [--sign IDENTITY]
                    [--only PREFIX ...] [-j N]

<extracted fs dir> is what extract_image.py + fsck.erofs + extract_apex.sh produced:
system/ (the system-as-root partition), system_ext/, vendor/, product/, apex/<name>/.
Other files are hard-linked, so the root costs no extra space beyond the images. Re-running
only redoes files whose source is newer than their output.
"""
import argparse, os, shutil, subprocess, sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
import amc  # noqa: E402

# (source under the fs dir, destination under the root)
LAYOUT = [
    ('system', ''),
    ('system_ext', 'system_ext'),
    ('vendor', 'vendor'),
    ('product', 'product'),
    ('apex', 'apex'),
]


def walk(src_root, dst_root):
    for src_rel, dst_rel in LAYOUT:
        base = os.path.join(src_root, src_rel)
        if not os.path.isdir(base):
            continue
        for dp, dns, fns in os.walk(base):
            rel = os.path.relpath(dp, base)
            out_dir = os.path.normpath(os.path.join(dst_root, dst_rel, rel))
            # The system partition carries empty mount points for the others; skip their contents.
            if src_rel == 'system' and rel == '.':
                dns[:] = [d for d in dns if d not in ('system_ext', 'vendor', 'product', 'apex')]
            yield out_dir, None, None
            for n in dns + fns:
                yield out_dir, os.path.join(dp, n), os.path.join(out_dir, n)


def is_elf(path):
    try:
        with open(path, 'rb') as f:
            return amc.is_arm64_elf(f.read(64))
    except OSError:
        return False


def compile_one(job):
    src, dst, platform, sign = job
    try:
        stats = amc.compile_file(src, dst, platform)
        os.chmod(dst, os.stat(src).st_mode & 0o7777)
        if sign:
            subprocess.run(['codesign', '-s', sign, '-f', '--timestamp=none', dst], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return dst, stats, None
    except Exception as e:  # report and carry on; one odd file should not stop the build
        return dst, None, str(e)


def pb_fields(b):
    """The top-level varint and string fields of a protobuf message: {field: value}."""
    out, i = {}, 0
    def varint():
        nonlocal i
        v = shift = 0
        while True:
            c = b[i]; i += 1
            v |= (c & 0x7F) << shift; shift += 7
            if c < 0x80:
                return v
    while i < len(b):
        key = varint()
        field, wt = key >> 3, key & 7
        if wt == 0:
            out[field] = varint()
        elif wt == 2:
            n = varint(); out[field] = b[i:i + n]; i += n
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            break
    return out


def write_apex_info(src_root, dst_root):
    """/apex/apex-info-list.xml, which apexd writes at boot and linkerconfig reads. The APEXes
    are unpacked at build time, so the list is written here."""
    rows = []
    apex_dir = os.path.join(src_root, 'apex')
    for name in sorted(os.listdir(apex_dir)):
        try:
            with open(os.path.join(apex_dir, name, 'apex_manifest.pb'), 'rb') as f:
                m = pb_fields(f.read())
        except OSError:
            continue
        version = m.get(2, 1)
        original = name.replace('com.android.', 'com.google.android.')
        for cand in (name, original):
            path = '/system/apex/%s.apex' % cand
            if os.path.exists(os.path.join(src_root, 'system/system/apex', cand + '.apex')):
                break
        rows.append('    <apex-info moduleName="%s" modulePath="%s" preinstalledModulePath="%s" '
                    'versionCode="%d" versionName="" isFactory="true" isActive="true" '
                    'lastUpdateMillis="0" provideSharedApexLibs="false" partition="SYSTEM"/>'
                    % (name, path, path, version))
    with open(os.path.join(dst_root, 'apex', 'apex-info-list.xml'), 'w') as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<apex-info-list>\n%s\n</apex-info-list>\n' % '\n'.join(rows))
    return len(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src')
    ap.add_argument('dst')
    ap.add_argument('--platform', default='macos', choices=['ios', 'macos'])
    ap.add_argument('--sign', default='-', help="codesign identity ('-' = ad hoc, '' = unsigned)")
    ap.add_argument('--only', action='append', default=[], help='guest path prefixes to include')
    ap.add_argument('-j', type=int, default=os.cpu_count())
    a = ap.parse_args()

    jobs, linked = [], 0
    for out_dir, src, dst in walk(a.src, a.dst):
        if src is None:
            os.makedirs(out_dir, exist_ok=True)
            continue
        guest = '/' + os.path.relpath(dst, a.dst)
        if a.only and not any(guest.startswith(p) or p.startswith(guest + '/') for p in a.only):
            continue
        if os.path.islink(src):
            if os.path.lexists(dst):
                os.unlink(dst)
            os.symlink(os.readlink(src), dst)
        elif os.path.isdir(src):
            os.makedirs(dst, exist_ok=True)
        elif os.path.exists(dst) and os.path.getmtime(dst) >= os.path.getmtime(src):
            continue
        elif is_elf(src):
            jobs.append((src, dst, a.platform, a.sign))
        else:
            if os.path.lexists(dst):
                os.unlink(dst)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)
            linked += 1

    totals, failed = {}, []
    with ProcessPoolExecutor(a.j) as ex:
        for dst, stats, err in ex.map(compile_one, jobs, chunksize=8):
            if err:
                failed.append((dst, err))
                continue
            for k, v in stats.items():
                totals[k] = totals.get(k, 0) + v
    print(f'{len(jobs)} images, {linked} files linked, rewritten: {totals}')
    print(f'apex-info-list.xml: {write_apex_info(a.src, a.dst)} APEXes')
    for dst, err in failed:
        print(f'  failed: {dst}: {err}', file=sys.stderr)


if __name__ == '__main__':
    main()
