#!/usr/bin/env python3
"""Pull the logical partitions (system, vendor, ...) out of an Android emulator system.img.

The SDK image is a GPT disk whose `super` partition holds the dynamic-partition metadata
(liblp format). Each logical partition is written out as <out>/<name>.img.

    extract_image.py <system.img> <out-dir>
"""
import os, struct, sys

SECTOR = 512
LP_METADATA_GEOMETRY_MAGIC = 0x616C4467
LP_METADATA_HEADER_MAGIC = 0x414C5030
LP_PARTITION_RESERVED_BYTES = 4096


def gpt_partitions(f):
    f.seek(SECTOR)
    hdr = f.read(92)
    assert hdr[:8] == b'EFI PART', 'not a GPT disk'
    lba, count, size = struct.unpack_from('<QII', hdr, 72)
    f.seek(lba * SECTOR)
    parts = {}
    for _ in range(count):
        e = f.read(size)
        if e[:16] == b'\0' * 16:
            continue
        first, last = struct.unpack_from('<QQ', e, 32)
        name = e[56:128].decode('utf-16le').rstrip('\0')
        parts[name] = (first * SECTOR, (last - first + 1) * SECTOR)
    return parts


def lp_unpack(f, base, out):
    f.seek(base + LP_PARTITION_RESERVED_BYTES)
    geo = f.read(52)
    magic, _, _, max_meta, slots, _ = struct.unpack_from('<II32sIII', geo)
    assert magic == LP_METADATA_GEOMETRY_MAGIC, 'no liblp geometry'
    meta_off = base + LP_PARTITION_RESERVED_BYTES + 2 * 4096  # primary metadata, slot 0
    f.seek(meta_off)
    h = f.read(256)
    magic, major, minor, hsize = struct.unpack_from('<IHHI', h)
    assert magic == LP_METADATA_HEADER_MAGIC, 'no liblp header'
    tables_size = struct.unpack_from('<I', h, 44)[0]
    # four table descriptors (offset, num_entries, entry_size) after the checksums
    descs = [struct.unpack_from('<III', h, 80 + 12 * i) for i in range(4)]
    f.seek(meta_off + hsize)
    tables = f.read(tables_size)

    def table(i):
        off, n, sz = descs[i]
        return [tables[off + k * sz: off + (k + 1) * sz] for k in range(n)]

    parts, extents = table(0), table(1)
    os.makedirs(out, exist_ok=True)
    for p in parts:
        name = p[:36].rstrip(b'\0').decode()
        _, first_ext, n_ext, _ = struct.unpack_from('<IIII', p, 36)
        path = os.path.join(out, name + '.img')
        total = 0
        with open(path, 'wb') as o:
            for e in extents[first_ext:first_ext + n_ext]:
                n_sectors, target_type, target_data, _ = struct.unpack_from('<QIQI', e)
                if target_type == 0:  # LINEAR
                    f.seek(base + target_data * SECTOR)
                    left = n_sectors * SECTOR
                    while left:
                        chunk = f.read(min(left, 1 << 24))
                        o.write(chunk)
                        left -= len(chunk)
                else:  # ZERO
                    o.seek(n_sectors * SECTOR, 1)
                total += n_sectors * SECTOR
            o.truncate(total)
        print(f'{name}: {total} bytes -> {path}')


def main():
    img, out = sys.argv[1], sys.argv[2]
    with open(img, 'rb') as f:
        parts = gpt_partitions(f)
        base, _ = parts['super']
        lp_unpack(f, base, out)


if __name__ == '__main__':
    main()
