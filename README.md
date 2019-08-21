# Shellcode-Encrypter-Decrypter
A Shellcode Encrypter &amp; Decrypter, Using XOR Cipher to enc and dec shellcode.

## Installation

```
git clone https://github.com/blacknbunny/Shellcode-Encrypter-Decrypter.git && cd Shellcode-Encrypter-Decrypter/

python encdecshellcode.py --help
```

## Usage Example

```
Encryption:

    python encdecshellcode.py --shellcode \x41\x41\x42\x42 --key SECRETKEY --option encrypt

Decryption:

    python encdecshellcode.py --shellcode \x41\x41\x42\x42 --key SECRETKEY --option decrypt
    
```

## Finding Shellcode For Any Architecture

http://shell-storm.org/shellcode/

## Help
```
usage: enc.py [-h]  [-s SHELLCODE]  [-k KEY]  [-o OPTION]

Encrypting & Decrypting Shellcode

optional arguments:
       -h,  --help			show this help message and exit
        -s  SHELLCODE,	--shelcode SHELCODE
				Shellcode To Encrypt & Decrypt
        -k  KEY,  --key KEY		Key Of The Shellcode To Encrypt & Decrypt
        -o  OPTION,   --option  OPTION
				Argument For Encrypting & Decrypting Shellcode
```
