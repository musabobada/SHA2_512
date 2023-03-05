

# ===========================================
# AES       =================================
# ===========================================
#############################################
#   HELPERS FUNCTIONS  #############
#############################################
def printArray(A):
    # function to print 2D Array
    for i in range(len(A)):
        for j in range(len(A[0])):
            print(A[i][j], end=" ")
        print()


def sBox(row, column):
    # return s-box value for two-digit hex
    sBoxArray = [
        (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
         0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76),
        (0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
         0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0),
        (0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
         0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15),
        (0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
         0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75),
        (0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
         0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84),
        (0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
         0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF),
        (0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
         0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8),
        (0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
         0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2),
        (0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
         0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73),
        (0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
         0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB),
        (0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
         0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79),
        (0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
         0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08),
        (0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
         0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A),
        (0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
         0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E),
        (0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
         0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF),
        (0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)]
    return sBoxArray[row][column]


def sBoxInverse(row, column):
    # return invers sBox value for two-digit hex
    sBoxInverse = [
        [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
            0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
        [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
            0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
        [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
        [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
            0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
        [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
            0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
        [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
            0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
        [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
            0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
        [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
            0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
        [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
            0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
        [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
            0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
        [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
            0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
        [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
            0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
        [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
            0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
        [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
        [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
            0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
    return sBoxInverse[row][column]
# STRING - MAATRIX CONVERTION


def hexStringToHexStateMatrix(hexString):
    # converts a block (16 bytes) of string into form of 4x4 matrix
    # each string character converted to ASCII value then
    # converted into form of hex value
    # ? EXAMPLE: "A" character become => "0x41"
    stateMatrix = [["0" for _ in range(4)] for _ in range(4)]
    hex = splitString(hexString, 2)
    for i in range(4):
        for j in range(4):
            stateMatrix[j][i] = hex[i*4+j].zfill(2)
    return stateMatrix


def hexStateMatrixToHexString(stateMatrixHex):
    # converts state matrix to a string
    # ? EXAMPLE: "0x41" character become => "A"
    string = ""
    for i in range(4):
        for j in range(4):
            string += stateMatrixHex[j][i]
    return string
# STRING CONVERTION


def splitInToBlocks(message):
    # split message to blocks of 16 bytes (128 bits)
    blocks = []
    for i in range(0, len(message), 16):
        blocks.append(message[i:i+16])
    if (len(blocks[-1]) <= 16):
        blocks[-1] = blocks[-1].ljust(16, "#")
    return blocks


def splitString(word, step):
    words = [word[i:i+step] for i in range(0, len(word), step)]
    return words


def hexStringtoPlainText(hexString):
    hexList = splitString(hexString, 2)
    plainText = ""
    for i in range(len(hexList)):
        plainText += chr(int(hexList[i], 16))
    return plainText


def hexStringToIntNumber(hexString):
    return int(hexString, 16)


def plainStringToHexString(string):
    hexString = ""
    for i in range(len(string)):
        hexString += hex(ord(string[i]))[2:].zfill(2)
    return hexString
# KEY


def rotWord(word):
    words = ""
    for i in range(8):
        words += word[(i+2) % 8]
    return words


def subWord(word):
    words = ""
    bytes = splitString(word, 2)
    for i in range(4):
        row = int(bytes[i][0], 16)
        column = int(bytes[i][1], 16)
        words += hex(sBox(row, column))[2:].zfill(2)
    return words


def keyExpansion(key):
    key = plainStringToHexString(key)
    keyWords = splitString(key, 8)
    rc = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
          0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]
    words = [0 for i in range(44)]
    for i in range(4):
        words[i] = keyWords[i]
    for i in range(4, 44):
        temp = words[i-1]
        if (i % 4 == 0):
            temp = hex(rc[((i//4)-1)] ^
                       int(subWord(rotWord(words[i-1])), 16))[2:].zfill(8)
        words[i] = hex(int(temp, 16) ^ int(words[i-4], 16))[2:].zfill(8)
    keys = [0 for _ in range(11)]
    for i in range(0, 44, 4):
        keys[i//4] = words[i]+words[i+1]+words[i+2]+words[i+3]
    return keys  # MATRIX


def gf8_multiplication(a, b):
    byte1 = int(a, 16)
    byte2 = int(b, 16)
    if byte1 == 3:
        return byte2 ^ ((byte2 << 1) & 255) ^ (0x1b if byte2 & 128 else 0)
    if byte1 == 2:
        return ((byte2 << 1) & 255) ^ (0x1b if byte2 & 128 else 0)
    return byte2


def shiftRows(matrix):
    # shift rows of matrix according to AES Standards
    tempMatrix = [i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            tempMatrix[i][j] = matrix[i][(j+i) % 4].zfill(2)
    return tempMatrix


def matrixSub(matrix):
    # return s-box values for state matrix
    tempMatrix = [i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            row = int(matrix[i][j][0], 16)
            column = int(matrix[i][j][1], 16)
            tempMatrix[i][j] = hex(sBox(row, column))[2:].zfill(2)
    return tempMatrix


def inverseShiftRows(matrix):
    # inverse shifted rows to get baack state matrix before shifting
    tempMatrix = [i[:] for i in matrix]
    for i in range(4):
        for j in range(4):
            tempMatrix[i][j] = matrix[i][(j-i) % 4]
    return tempMatrix


def matrixColumnMix(matrix):
    mixArray = [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
    ]
    tempMatrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                tempMatrix[j][i] ^= gf8_multiplication(
                    mixArray[j][k], matrix[k][i])
            tempMatrix[j][i] = hex(tempMatrix[j][i])[2:].zfill(2)
    return tempMatrix


def matrixInverseColumnMix(matrix):
    mixArray = [
        ["0e", "0b", "0d", "09"],
        ["09", "0e", "0b", "0d"],
        ["0d", "09", "0e", "0b"],
        ["0b", "0d", "09", "0e"]
    ]
    tempMatrix = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                tempMatrix[j][i] ^= gf8_multiplication(
                    mixArray[j][k], matrix[k][i])
            tempMatrix[j][i] = hex(tempMatrix[j][i])[2:].zfill(2)
    return tempMatrix


def matrixInverseSub(matrix):
    # return inverse s-box values for state matrix
    for i in range(4):
        for j in range(4):
            row = int(matrix[i][j][0], 16)
            column = int(matrix[i][j][1], 16)
            matrix[i][j] = hex(sBoxInverse(row, column))[2:].zfill(2)
    return matrix
#############################################
###########  MAIN AES FUNCTION  #############
#############################################


def AES_Encrypt(plainText, key):
    message = plainStringToHexString(plainText)
    keys = keyExpansion(key)
    message = hexStringToIntNumber(message)
    message = hex(message ^ int(keys[0], 16))[2:].zfill(32)
    for i in range(1, 11):
        stateMatrix = hexStringToHexStateMatrix(message)
        stateMatrix = matrixSub(stateMatrix)
        stateMatrix = shiftRows(stateMatrix)
        if (i == 10):
            message = hexStateMatrixToHexString(stateMatrix)
            message = hexStringToIntNumber(message)
            message = hex(message ^ int(keys[i], 16))[2:].zfill(32)
            continue
        stateMatrix = matrixColumnMix(stateMatrix)
        message = hexStateMatrixToHexString(stateMatrix)
        message = hexStringToIntNumber(message)
        message = hex(message ^ int(keys[i], 16))[2:].zfill(32)
    return message


def main_Enc(message, key):
    if (len(key) != 16):
        print("key lenght is not 16-Bit long")
        exit()
    messages = splitInToBlocks(message)
    cipherText = ""
    for i in messages:
        cipherText += AES_Encrypt(i, key)
    # print("\nplainText :"+message+"\nkey : " +
        #   key+"\ncipherText : " + cipherText)
    return cipherText


# =================================================================
# =================================================================
# =================================================================
# SHA 512               ===========================================
# =================================================================
# =================================================================
# =================================================================


# ########################
# SHA 512 constants
# ########################

iv = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
]

k = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
     0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
     0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
     0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
     0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
     0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
     0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
     0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
     0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
     0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
     0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
     0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
     0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
     0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
     0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
     0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
     0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
     0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
     0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
     0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
     ]

# ########################
# Auxilary functions
# ########################


def plain_to_binary(message):
    temp = ""
    for i in message:
        temp += bin(ord(i))[2:].zfill(8)
    return temp


def binary_block_to_hex_block(block):
    blocks = ""
    for i in range(0, 1024, 8):
        blocks += hex(int(block[i:i+8], 2))[2:].zfill(2)
    return blocks


def Block_to_words(block):
    block = binary_block_to_hex_block(block)
    word_length = 16
    blocks = []
    for i in range(0, len(block), word_length):
        blocks.append(block[i:i+word_length])
    return blocks


def split_to_Blocks(message):
    message = plain_to_binary(message)
    if (len(message) > pow(2, 128)):
        print("message length is more than 2 ^ 128 bit")
        return False
    blocks = []
    block_size = 1024
    length_digits = 128
    lenght_padding = bin(len(message))[2:].zfill(length_digits)
    for i in range(0, len(message), block_size):
        blocks.append(message[i:i+block_size])
    if (len(blocks[-1]) == block_size):
        blocks.append(
            "1".ljust(block_size-length_digits, "0")+lenght_padding)
    elif (len(blocks[-1])+length_digits < block_size):
        blocks[-1] = (blocks[-1]+"1").ljust(block_size -
                                            length_digits, "0")+lenght_padding
    elif (len(blocks[-1]) + length_digits >= block_size):
        blocks[-1] = (blocks[-1] + "1").ljust(block_size, "0")
        blocks.append(
            "".ljust(block_size-length_digits, "0")+lenght_padding)
    return blocks


def word_expansion(block):
    temp = Block_to_words(block)
    words = [0 for _ in range(80)]
    for i in range(16):
        words[i] = int(temp[i], 16)
    for i in range(16, 80):
        words[i] = (sigma1(words[i-2])+words[i-7] +
                    sigma0(words[i-15]) + words[i-16]) % pow(2, 64)
    return words

# ########################
# Words mixin functions
# ########################


def ROTR(a, n):
    a = bin(a)[2:].zfill(64)
    temp = ""
    for i in range(len(a)):
        temp += a[(i-n) % len(a)]
    return int(temp, 2)


def SHR(a, n):
    return a >> n


def Ch(e, f, g):
    return (e & f) ^ (~e & g)


def Maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def sum0(x):
    return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)


def sum1(x):
    return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)


def sigma0(x):
    return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7)


def sigma1(x):
    return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6)


def add(a, b):
    return (a+b) % pow(2, 64)


# ########################
# Main
# ########################


def SHA_2_512(message):
    blocks = split_to_Blocks(message)
    hi = [i for i in iv]
    for j in range(len(blocks)):
        a, b, c, d, e, f, g, h = hi
        words = word_expansion(blocks[j])
        for i in range(80):
            T1 = (h + Ch(e, f, g) + sum1(e) + words[i] + k[i]) % pow(2, 64)
            T2 = add(sum0(a), Maj(a, b, c))
            h = g
            g = f
            f = e
            e = add(d, T1)
            d = c
            c = b
            b = a
            a = add(T1, T2)
        a = add(a, hi[0])
        b = add(b, hi[1])
        c = add(c, hi[2])
        d = add(d, hi[3])
        e = add(e, hi[4])
        f = add(f, hi[5])
        g = add(g, hi[6])
        h = add(h, hi[7])
        hi = a, b, c, d, e, f, g, h
    hash = ""
    for i in range(8):
        hash += hex(hi[i])[2:].zfill(16)
    return hash


# ########################
# Input Message
# ########################
print("Enter File name with extenstion")
print("Example2 file.txt")
print("Example2 C:/sha.txt")
# input_file="testing message for hash if file input fail"
input_file = input(">> ")
with open(input_file, 'r') as file:
    file_contents = file.read()
hash = SHA_2_512(file_contents)
key = "i love python3.9"
with open("testSha.txt", 'w') as file:
    file.write(hash)
print("\nhash code saved on file testSha.txt (on the same directory with code)\n")
Encypted_hash = main_Enc(hash, key)
with open('EncryptedSha.txt', 'w') as file:
    file.write(Encypted_hash)
print("Encrypted hash code saved on file EncryptedSha.txt using AES 128 ECB mode and key '" +
      key+"' (on the same directory with code)")
print("\nDone !!!!!!!!!!!")
