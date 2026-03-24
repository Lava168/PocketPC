"""Generate simple PNG icons for the PWA."""
import struct
import zlib
import os

def create_png(width, height, color_bg=(10, 10, 26), color_fg=(108, 92, 231)):
    """Create a minimal PNG icon with a simple remote-control design."""

    def px(r, g, b, a=255):
        return bytes([r, g, b, a])

    raw_data = bytearray()
    cx, cy = width // 2, height // 2
    r_outer = int(width * 0.38)
    r_inner = int(width * 0.12)

    for y in range(height):
        raw_data.append(0)  # filter: none
        for x in range(width):
            dx, dy = x - cx, y - cy
            dist = (dx*dx + dy*dy) ** 0.5

            if dist <= r_outer and dist >= r_outer - max(3, width // 32):
                raw_data.extend(px(*color_fg))
            elif dist <= r_inner:
                raw_data.extend(px(*color_fg))
            elif abs(dx) <= max(2, width//64) and -r_outer < dy < -r_inner:
                raw_data.extend(px(*color_fg))
            elif abs(dx) <= max(2, width//64) and r_inner < dy < r_outer:
                raw_data.extend(px(*color_fg))
            elif abs(dy) <= max(2, width//64) and -r_outer < dx < -r_inner:
                raw_data.extend(px(*color_fg))
            elif abs(dy) <= max(2, width//64) and r_inner < dx < r_outer:
                raw_data.extend(px(*color_fg))
            else:
                raw_data.extend(px(*color_bg))

    def make_chunk(chunk_type, data):
        c = chunk_type + data
        crc = zlib.crc32(c) & 0xffffffff
        return struct.pack('>I', len(data)) + c + struct.pack('>I', crc)

    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    compressed = zlib.compress(bytes(raw_data))

    png = b'\x89PNG\r\n\x1a\n'
    png += make_chunk(b'IHDR', ihdr)
    png += make_chunk(b'IDAT', compressed)
    png += make_chunk(b'IEND', b'')
    return png


icons_dir = os.path.join(os.path.dirname(__file__), 'static', 'icons')
os.makedirs(icons_dir, exist_ok=True)

for size in [192, 512]:
    data = create_png(size, size)
    path = os.path.join(icons_dir, f'icon-{size}.png')
    with open(path, 'wb') as f:
        f.write(data)
    print(f'Created {path} ({len(data)} bytes)')

print('Done!')
