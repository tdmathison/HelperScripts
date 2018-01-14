# Generates shellcode hex and push dword statements for a given string.
# Pads empty bytes in a 4 byte push with null-bytes if the string isn't divisible by 4.
#
# Travis Mathison
#
# Created for use in the OSCE course.
#
# Usage:
# python3 ./str2hexpush.py --string "ipconfig /all"
# python3 ./str2hexpush.py --string $'curl http://192.168.1.1\n'

# !/usr/bin/python3

import argparse
import binascii
import itertools

parser = argparse.ArgumentParser(
    description="Create shellcode from given string.",
    usage="\n  ./str2hexpush.py --string \"ipconfig /all\"\n" +
          "  ./str2hexpush.py --string $'curl http://192.168.1.1\\n'")

parser.add_argument("-s", "--string", type=str, help="String to convert.")
parser.add_argument("-p", "--pad", type=str, help="Pad value (eg. 90). Default=00")


def byte_group(n, iterable, padvalue=None):
    return itertools.zip_longest(*[iter(iterable)] * n, fillvalue=padvalue)


if __name__ == '__main__':
    args = parser.parse_args()

    if args.pad:
        args.pad = args.pad.encode()
    else:
        args.pad = b'00'

    string_hex = binascii.hexlify(args.string.encode())
    print("\"\\x" + "\\x".join(string_hex[i:i + 2].decode() for i in range(0, len(string_hex), 2)) + "\"")
    print()

    string_bytes_split = [string_hex[i:i + 2] for i in range(0, len(string_hex), 2)]

    for x in byte_group(4, string_bytes_split[::-1], args.pad):
        print("push 0x"
              + x[0].decode()
              + x[1].decode()
              + x[2].decode()
              + x[3].decode())
