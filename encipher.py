import os
import struct
import sys
import zlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


class Encipher:
    def __init__(self, password, seed):
        self.key = PBKDF2(password, seed, dkLen=16)

    def encryptFile(self, inFileName, outFileName=None, chunkSize=64*1024):
        if not outFileName:
            outFileName = inFileName + '.enc'

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        fileSize = os.path.getsize(inFileName)

        with open(inFileName, 'rb') as inFile:
            with open(outFileName, 'wb') as outFile:
                outFile.write(struct.pack('<Q', fileSize))
                outFile.write(iv)
                while True:
                    chunk = inFile.read(chunkSize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b'\0' * (16 - len(chunk) % 16)

                    outFile.write(cipher.encrypt(chunk))

    def decryptFile(self, inFileName, outFileName=None, chunkSize=24*1024):
        if not outFileName:
            outFileName = os.path.splitext(inFileName)[0]

        with open(inFileName, 'rb') as inFile:
            origSize = struct.unpack(
                '<Q', inFile.read(struct.calcsize('Q')))[0]
            iv = inFile.read(16)
            decipher = AES.new(self.key, AES.MODE_CBC, iv)

            with open(outFileName, 'wb') as outFile:
                while True:
                    chunk = inFile.read(chunkSize)
                    if len(chunk) == 0:
                        break
                    outFile.write(decipher.decrypt(chunk))

                outFile.truncate(origSize)

    def encryptDir(self, inDirName, outDirName=None):
        dirList = os.listdir(inDirName)
        for fileName in dirList:
            if os.path.isfile(inDirName + fileName):
                self.encryptFile(inDirName + fileName)
            elif os.path.isdir(inDirName + fileName):
                self.encryptDir(inDirName + fileName)

    def decryptDir(self, inDirName, outDirName=None):
        dirList = os.listdir(inDirName)
        for fileName in dirList:
            if os.path.isfile(inDirName + fileName):
                self.decryptFile(inDirName + fileName)
            elif os.path.isdir(inDirName + fileName):
                self.decryptDir(inDirName + fileName)


class Compresser:
    def compressFile(self, inFileName, outFileName=None):
        with open(inFileName, 'rb') as inFile:
            with open(inFileName, 'wb') as outFile:
                plainData = inFile.read()
                compData = zlib.compress(plainData, 6)
                outFile.write(compData)

    def decompressFile(self, inFileName, outFileName=None):
        with open(inFileName, 'rb') as inFile:
            with open(inFileName, 'wb') as outFile:
                compData = inFile.read()
                print(compData)
                plainData = zlib.decompress(
                    compData, wbits=zlib.MAX_WBITS, bufsize=zlib.DEF_BUF_SIZE)
                outFile.write(plainData)


def main1():
    inFileName = sys.argv[1]
    a = Compresser()
    a.decompressFile(inFileName)


def main():
    password = sys.argv[1]
    seed = sys.argv[2]
    inName = sys.argv[3]
    encrypter = Encipher(password, seed)
    if os.path.isfile(inName):
        if os.path.splitext(inName)[1] != '.enc':
            encrypter.encryptFile(inName)
        else:
            encrypter.decryptFile(inName)
    elif os.path.isdir(inName):
        encrypter.encryptDir(inName)


if __name__ == "__main__":
    main1()
