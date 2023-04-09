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

def hexdump(data, start_address, compact_repeats=True):
    length = len(data)
    addr = start_address
    i = 0
    while i < length:
        compacted = False
        if compact_repeats:
            repeat_char = data[i]
            repeat_len = 1
            for j in range(i+1, length):
                if data[j] == repeat_char:
                    repeat_len += 1
                else:
                    break
            if repeat_len >= 16:
                compacted = True
                print(f"  0x{addr:08x}: {'..' * 48} [0x{repeat_char:02x}] x {repeat_len}")
                addr += repeat_len
                i += repeat_len
        if not compacted:
            line = ' '.join(f"{data[i+j]:02x}" for j in range(16) if i+j < length)
            ascii_repr = ''.join(chr(data[i+j]) if 32 <= data[i+j] <= 126 else '.' for j in range(16) if i+j < length)
            print(f"  0x{addr:08x}: {line:<48} {ascii_repr}")
            addr += 16
            i += 16

def strings_dump(data, start_address):
    strings_list = []
    current_string = ""
    current_address = start_address

    for byte in data:
        if 32 <= byte <= 126:
            current_string += chr(byte)
            if len(current_string) == 1:
                current_address = start_address
        else:
            if len(current_string) >= 4:
                strings_list.append((current_address, current_string))
            current_string = ""
        start_address += 1

    if len(current_string) >= 4:
        strings_list.append((current_address, current_string))

    for address, string in strings_list:
        print(f"  0x{address:08x}: {string}")

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
            strings_dump(segment_content, addr)

        if parsed_size < file_size:
            print(f"\nRemaining data (not part of segments):")
            remaining_data = f.read()
            hexdump(remaining_data, parsed_size)
            print("\nRemaining data strings:")
            strings_dump(remaining_data, parsed_size)

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

