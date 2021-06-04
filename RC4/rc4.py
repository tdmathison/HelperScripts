# RC4
# https://en.wikipedia.org/wiki/RC4

# Key-scheduling algorithm (KSA)
def ksa(key):
    s = []
    for i in range(0, 256):
        s.append(i)
    j = 0
    for i in range(0, 256):
        j = (j + s[i] + ord(key[i % len(key)])) % 256
        s[i], s[j] = s[j], s[i]
    return s


# Pseudo-random generation algorithm (PRGA)
def prga(s, text):
    output = ''
    i = 0
    j = 0
    for x in range(0, len(text)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        output += chr(k ^ ord(text[x]))
    return output


if __name__ == '__main__':
    key = "test-key"
    text = "Some text to encrypt"

    ciphertext = prga(ksa(key), text)
    print('ciphertext: %s' % ciphertext)
    plaintext = prga(ksa(key), ciphertext)
    print('plaintext: %s' % plaintext)
