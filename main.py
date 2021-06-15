import requests


def decipher(iv, block):
    intermediate = []
    for pad_byte in range(1, 17):
        padding = chr(pad_byte)
        tmp = []
        if len(intermediate) > 0:
            for byte in intermediate:
                refactor = int(hex(byte), 16) ^ int(padding.encode("hex"), 16)
                refactor_s = format(refactor, 'x')
                if len(refactor_s) < 2:
                    refactor_s = '0' + refactor_s
                tmp.append(refactor_s)

        for byte in range(256):
            bf = chr(byte).encode("hex")
            payload_pad = (30 - len(tmp) * 2) * '0'
            url = server + payload_pad + bf + (''.join(tmp[::-1])) + block
            r = requests.get(url)
            if r.status_code == 401:
                result = int(bf, 16) ^ int(padding.encode("hex"), 16)
                intermediate.append(result)
                print(str(hex(result)))
                break

    cleartext = decrypt(iv, intermediate)
    print cleartext
    return cleartext


def decrypt(iv, intermediate):
    intermediate_new = intermediate[::-1]
    intermediate_s = ''.join(format(byte, '02x') for byte in intermediate_new)
    cleartext = hex(int(iv, 16) ^ int(intermediate_s, 16))
    cleartext = cleartext[:-1][2:]
    cleartext = cleartext.decode("hex")
    return cleartext


def split_to_blocks(ciphertext):
    blocks = []
    num_block = len(ciphertext) // 32
    for i in range(0, num_block):
        byte_count = i * 32
        cipher_block = ciphertext[byte_count:byte_count + 32]
        blocks.append(cipher_block)

    return blocks


if __name__ == "__main__":
    server = "http://192.168.200.247:8080/?cipher="
    ciphertext = "a2172b31213827338b46e28123ab5e14351b2c3c35a6f49530f5ad149190b715"
    blocks = split_to_blocks(ciphertext)
    cleartext_full = []
    for i in range(len(blocks) - 1, 0, -1):
        cleartext = decipher(blocks[i - 1], blocks[i])
        cleartext_full.append(cleartext)

    print ''.join(reversed(cleartext_full))



