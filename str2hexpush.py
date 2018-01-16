# Generates shellcode hex and push dword statements for a given string.
# Pads empty bytes in a 4 byte push with null-bytes if the string isn't divisible by 4.
#
# Travis Mathison
#
# Created for use in the OSCE course.
#
# Examples:
# python3 ./str2hexpush.py --string "ipconfig /all"
# "\x68\x2f\x61\x6c\x6c\x68\x66\x69\x67\x20\x68\x70\x63\x6f\x6e\x68\x00\x00\x00\x69"
# 
# push 0x6c6c612f
# push 0x20676966
# push 0x6e6f6370
# push 0x69000000
#
# python3 ./str2hexpush.py --string $'curl http://192.168.1.1\n'
# "\x68\x31\x2e\x31\x0a\x68\x31\x36\x38\x2e\x68\x31\x39\x32\x2e\x68\x70\x3a\x2f\x2f\x68\x20\x68\x74\x74\x68\x63\x75\x72\x6c"
# 
# push 0x0a312e31
# push 0x2e383631
# push 0x2e323931
# push 0x2f2f3a70
# push 0x74746820
# push 0x6c727563

# !/usr/bin/python3

import argparse
import binascii
import itertools

parser = argparse.ArgumentParser(
    description="Create shellcode from given string.",
    usage="\n  ./str2hexpush.py --string \"ipconfig /all\"\n" +
          "  ./str2hexpush.py --string $'curl http://192.168.1.1\\n'")

parser.add_argument("-s", "--string", type=str, help="String to convert.", required=True)
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
    string_bytes_split = [string_hex[i:i + 2] for i in range(0, len(string_hex), 2)]

    hex_rep = "\""
    asm_rep = ""

    for x in byte_group(4, string_bytes_split[::-1], args.pad):
        byte_0 = x[0].decode()
        byte_1 = x[1].decode()
        byte_2 = x[2].decode()
        byte_3 = x[3].decode()
        asm_rep += "push 0x" + byte_0 + byte_1 + byte_2 + byte_3 + "\n"
        hex_rep += "\\x68\\x{}\\x{}\\x{}\\x{}".format(byte_3, byte_2, byte_1, byte_0)
    hex_rep += "\""

    print(hex_rep)
    print(asm_rep)

