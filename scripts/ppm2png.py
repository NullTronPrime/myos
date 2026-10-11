#!/usr/bin/env python3
"""Convert a binary P6 PPM screenshot to PNG using only the stdlib.

Usage: ppm2png.py in.ppm [out.png]
"""
import struct
import sys
import zlib


def read_ppm(path):
    with open(path, "rb") as f:
        magic = f.readline().strip()
        if magic != b"P6":
            raise ValueError("not a P6 PPM")
        dims = []
        while len(dims) < 3:
            line = f.readline()
            if line.startswith(b"#"):
                continue
            dims.extend(int(x) for x in line.split())
        w, h, maxval = dims
        if maxval != 255:
            raise ValueError("only maxval 255 supported")
        px = f.read(w * h * 3)
        if len(px) < w * h * 3:
            raise ValueError("truncated pixels")
        return w, h, px


def write_png(path, w, h, px):
    row = w * 3
    raw = b"".join(b"\x00" + px[y * row:(y + 1) * row] for y in range(h))

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


def main():
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src.rsplit(".", 1)[0] + ".png"
    w, h, px = read_ppm(src)
    write_png(dst, w, h, px)
    print(f"{dst}: {w}x{h}")


if __name__ == "__main__":
    main()
