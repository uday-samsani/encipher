import os
import struct
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


class Encipher:
    def __init__(self, password, seed, inFileName, outFileName=None):
        self.key = PBKDF2(password, seed, dkLen=16)
        self.inFileName = inFileName
        self.outFileName = outFileName

    def encryptFile(self, chunkSize=64*1024):
        if not self.outFileName:
            self.outFileName = self.inFileName + '.enc'

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        fileSize = os.path.getsize(self.inFileName)

        with open(self.inFileName, 'rb') as inFile:
            with open(self.outFileName, 'wb') as outFile:
                outFile.write(struct.pack('<Q', fileSize))
                outFile.write(iv)

                while True:
                    chunk = inFile.read(chunkSize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b'\0' * (16 - len(chunk) % 16)

                    outFile.write(cipher.encrypt(chunk))

    def decryptFile(self, chunkSize=24*1024):
        if not self.outFileName:
            self.outFileName = os.path.splitext(self.inFileName)[0]

        with open(self.inFileName, 'rb') as inFile:
            origSize = struct.unpack(
                '<Q', inFile.read(struct.calcsize('Q')))[0]
            iv = inFile.read(16)
            decipher = AES.new(self.key, AES.MODE_CBC, iv)

            with open(self.outFileName, 'wb') as outFile:
                while True:
                    chunk = inFile.read(chunkSize)
                    if len(chunk) == 0:
                        break
                    outFile.write(decipher.decrypt(chunk))

                outFile.truncate(origSize)


def main():
    password = sys.argv[1]
    seed = sys.argv[2]
    inFileName = sys.argv[3]
    encrypter = Encipher(password, seed, inFileName)
    if os.path.splitext(inFileName)[1] != '.enc':
        encrypter.encryptFile()
    else:
        encrypter.decryptFile()


if __name__ == "__main__":
    main()
