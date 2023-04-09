import os
import struct
import sys

def parse_header(header_data: bytes) -> dict:
    magic, segment_count, flash_mode, flash_config, entry = struct.unpack('<BBBBI', header_data)
    return {
        'magic': magic,
        'segment_count': segment_count,
        'flash_mode': flash_mode,
        'flash_config': flash_config,
        'entry': entry
    }

def hexdump(data: bytes, start_addr: int):
    addr = start_addr
    ff_count = 0

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]

        if all(b == 0xFF for b in chunk):
            ff_count += len(chunk)
            addr += len(chunk)
            continue

        if ff_count > 0:
            print(f"    {addr - ff_count:#010x}: {ff_count} byte(s) of 0xFF")
            ff_count = 0

        hex_line = ' '.join(f"{b:02x}" for b in chunk)
        ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        print(f"    {addr:#010x}: {hex_line:<48} {ascii_line}")

        addr += len(chunk)

    if ff_count > 0:
        print(f"    {addr - ff_count:#010x}: {ff_count} byte(s) of 0xFF")

def firmware_image_dump(firmware_file: str):
    with open(firmware_file, "rb") as f:
        file_size = os.path.getsize(firmware_file)
        parsed_size = 0

        header_data = f.read(8)
        header = parse_header(header_data)

        parsed_size += 8

        print("Firmware header:")
        print(f"Magic: {header['magic']:#04x}")
        print(f"Segment count: {header['segment_count']}")
        print(f"Flash mode: {header['flash_mode']:#04x}")
        print(f"Flash config: {header['flash_config']:#04x}")
        print(f"Entry point: {header['entry']:#010x}")

        for segment_index in range(header['segment_count']):
            segment_data = f.read(8)
            addr, size = struct.unpack('<II', segment_data)
            parsed_size += 8

            print(f"Segment {segment_index}:")
            print(f"  Address: {addr:#010x}")
            print(f"  Size: {size}")

            segment_content = f.read(size)
            parsed_size += size

            hexdump(segment_content, addr)

        if parsed_size < file_size:
            print(f"\nRemaining data (not part of segments):")
            remaining_data = f.read()
            hexdump(remaining_data, parsed_size)

        if parsed_size != file_size:
            print(f"\nSize mismatch detected! Parsed: {parsed_size} bytes, Actual file size: {file_size} bytes")
        else:
            print("\nFile size matches the parsed data")

def main():
    if len(sys.argv) != 2:
        print("Usage: python espfwdump.py <firmware_file>")
        sys.exit(1)

    firmware_file = sys.argv[1]
    firmware_image_dump(firmware_file)

if __name__ == '__main__':
    main()
