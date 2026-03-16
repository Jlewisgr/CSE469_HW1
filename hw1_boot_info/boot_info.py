#!/usr/bin/env python3
# Generative AI Used: GitHub Copilot (GitHub/OpenAI)
# Purpose: Copilot was used during development to generate suggestions for bug fixes
# and to provide some structural suggestions while writing parts of the code.

import argparse
import hashlib
import os
import struct
import sys
import csv

SECTOR_SIZE = 512

VERBOSE = False

def vprint(*args):
    if VERBOSE:
        print("[VERBOSE]", *args, file=sys.stderr)


def load_partition_types():
    built_in = {
        "00": "Empty",
        "01": "FAT12",
        "02": "XENIX root",
        "03": "XENIX usr",
        "04": "FAT16 <32M",
        "05": "Extended",
        "06": "FAT16",
        "07": "HPFS/NTFS/exFAT",
        "82": "Linux swap / Solaris",
        "83": "Linux",
        "a9": "NetBSD",
        "ee": "GPT",
        "ef": "EFI",
    }

    if os.path.exists("partition_types.csv"):
        try:
            mapping = {}
            with open("partition_types.csv") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 3:
                        key = row[1].lower()
                        value = row[2]
                        mapping[key] = value
            if mapping:
                return mapping
        except:
            pass

    return built_in


PARTITION_TYPES = load_partition_types()


def compute_hashes(file_path):

    vprint("Computing hashes...")

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    name = os.path.basename(file_path).replace(".raw", "")

    with open(f"MD5-{name}.txt", "w") as f:
        f.write(md5.hexdigest())

    with open(f"SHA-256-{name}.txt", "w") as f:
        f.write(sha256.hexdigest())

    with open(f"SHA-512-{name}.txt", "w") as f:
        f.write(sha512.hexdigest())


def bytes_to_hex(data):
    return " ".join(f"{b:02x}" for b in data)


def format_ascii(data):
    chars = []
    for b in data:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    return "  ".join(chars)


def guid_bytes_to_string_raw(guid_bytes):
    return guid_bytes[::-1].hex()


def detect_partition_scheme(f):

    vprint("Detecting partition scheme")

    f.seek(0)
    mbr = f.read(SECTOR_SIZE)

    for i in range(4):
        entry = mbr[446 + i * 16:446 + (i + 1) * 16]
        if entry[4] == 0xEE:
            f.seek(SECTOR_SIZE)
            header = f.read(SECTOR_SIZE)
            if header[0:8] == b"EFI PART":
                vprint("GPT detected")
                return "GPT"

    vprint("MBR detected")
    return "MBR"


def parse_mbr(f):

    vprint("Parsing MBR partitions")

    f.seek(0)
    mbr = f.read(SECTOR_SIZE)

    partitions = []

    for i in range(4):
        entry = mbr[446 + i * 16:446 + (i + 1) * 16]

        p_type = entry[4]
        if p_type == 0x00:
            continue

        start_lba = struct.unpack("<I", entry[8:12])[0]
        size_sectors = struct.unpack("<I", entry[12:16])[0]

        type_hex = f"{p_type:02x}"
        type_name = PARTITION_TYPES.get(type_hex.lower(), "Unknown")

        vprint(f"MBR partition found: type={type_hex} start={start_lba} sectors={size_sectors}")

        partitions.append({
            "number": len(partitions) + 1,
            "type_hex": type_hex,
            "type_name": type_name,
            "start_lba": start_lba,
            "size_sectors": size_sectors
        })

    return partitions


def print_mbr_info(f, partitions, offsets):

    for p in partitions:
        start_byte = p["start_lba"] * SECTOR_SIZE
        size_bytes = p["size_sectors"] * SECTOR_SIZE
        print(f"({p['type_hex']}), {p['type_name']}, {start_byte}, {size_bytes}")

    for i, p in enumerate(partitions):
        if i >= len(offsets):
            break

        offset = offsets[i]
        boot_offset = p["start_lba"] * SECTOR_SIZE

        f.seek(boot_offset)
        boot_sector = f.read(SECTOR_SIZE)

        data = boot_sector[offset:offset + 16]

        if len(data) < 16:
            data = data + b"\x00" * (16 - len(data))

        print(f"Partition number: {i+1}")
        print(f"16 bytes of boot record from offset {offset}: {bytes_to_hex(data)}")
        print(f"ASCII:                                    {format_ascii(data)}")


def parse_gpt(f):

    vprint("Parsing GPT partitions")

    f.seek(SECTOR_SIZE)
    header = f.read(SECTOR_SIZE)

    if header[0:8] != b"EFI PART":
        return []

    entry_lba = struct.unpack("<Q", header[72:80])[0]
    num_entries = struct.unpack("<I", header[80:84])[0]
    entry_size = struct.unpack("<I", header[84:88])[0]

    partitions = []

    f.seek(entry_lba * SECTOR_SIZE)

    for i in range(num_entries):

        entry = f.read(entry_size)

        part_type_guid = entry[0:16]
        if part_type_guid == b"\x00" * 16:
            continue

        first_lba = struct.unpack("<Q", entry[32:40])[0]
        last_lba = struct.unpack("<Q", entry[40:48])[0]

        name_raw = entry[56:128]

        try:
            name = name_raw.decode("utf-16le").rstrip("\x00")
        except:
            name = ""

        size_bytes = (last_lba - first_lba + 1) * SECTOR_SIZE

        vprint(f"GPT partition {len(partitions)+1}: start={first_lba} end={last_lba} name={name}")

        partitions.append({
            "number": len(partitions) + 1,
            "type_guid": guid_bytes_to_string_raw(part_type_guid),
            "first_lba": first_lba,
            "last_lba": last_lba,
            "name": name,
            "size_bytes": size_bytes
        })

    return partitions


def print_gpt_info(partitions):

    for p in partitions:
        print(f"Partition number: {p['number']}")
        print(f"Partition Type GUID : {p['type_guid']}")
        print(f"Starting LBA in hex: {hex(p['first_lba'])}")
        print(f"ending LBA in hex: {hex(p['last_lba'])}")
        print(f"starting LBA in Decimal: {p['first_lba']}")
        print(f"ending LBA in Decimal: {p['last_lba']}")
        print(f"Partition name: {p['name']}")
        print(f"Partition size in bytes: {p['size_bytes']}")
        print()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True)
    parser.add_argument("-o", nargs="*", type=int, default=[])
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main():

    args = parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    if not os.path.exists(args.f):
        print("File not found", file=sys.stderr)
        sys.exit(1)

    compute_hashes(args.f)

    with open(args.f, "rb") as f:

        scheme = detect_partition_scheme(f)

        if scheme == "MBR":
            partitions = parse_mbr(f)
            print_mbr_info(f, partitions, args.o)
        else:
            partitions = parse_gpt(f)
            print_gpt_info(partitions)


if __name__ == "__main__":
    main()
