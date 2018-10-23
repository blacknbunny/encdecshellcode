import argparse
from sys import argv, stdout, exit

parser = argparse.ArgumentParser(description="Encrypting & Decrypting Shellcode")
parser.add_argument('-s', '--shellcode', help='Shellcode To Encrypt & Decrypt')
parser.add_argument('-k', '--key', help='Key Of The Shellcode To Encrypt & Decrpyt', default='key')
parser.add_argument('-o', '--option', help='Argument For Encrypting or Decrypting The Shellcode')

args = parser.parse_args()

def EncryptShellcode(shellcode, key):
    
    shellcode_encrypted_hex = []
    shellcode_decrypted_hex = []
    shellcode_replaced_hex = ''


    count = 0
    for d in range(0, len(shellcode) / 4):
        count += 4
        shellcode_decrypted_hex.append(shellcode[count-4:count].replace(r'\x', ''))
    
    for x in range(0, len(shellcode_decrypted_hex)):
        for d in range(0, len(key)):
            shellcode_encrypted_hex.append(hex(ord(shellcode_decrypted_hex[x].decode('hex')) ^ ord(key[d])))
    
    for y in range(0, len(shellcode_encrypted_hex)):
        shellcode_replaced_hex += shellcode_encrypted_hex[y].replace('0x', r'\x')
    
    return shellcode_replaced_hex

def DecryptShellcode(shellcode, key):
    shellcode_decrypted = []
    shellcode_xor_headers = []

    shellcode_replaced_hex = ''
    string = ''
    
    for x in shellcode:
        string += shellcode.replace(r'\x', '')
        break

    count = 0
    for y in string:
        shellcode_xor_headers.append(string[count:count+2])
        count += 6

    while '' in shellcode_xor_headers:
        shellcode_xor_headers.remove('')


    for z in range(len(shellcode_xor_headers)):
        shellcode_decrypted.append(hex(ord(shellcode_xor_headers[z].decode('hex')) ^ ord(key[0])))

    for h in range(0, len(shellcode_decrypted)):
        shellcode_replaced_hex += shellcode_decrypted[h].replace('0x', r'\x')

    print( "Real Shellcode = " + shellcode_replaced_hex)
    
    return EncryptShellcode(shellcode, key)
def PrintHelp():
    parser.print_help()
    exit(1)

def main():
    try:
        shellcode = args.shellcode
        key = args.key
        if args.option == "encrypt":
            print( "Encrypted Shellcode = " + EncryptShellcode(shellcode, key) )
        elif args.option == "decrypt":
            print( "\nDecrypted Shellcode = " + DecryptShellcode(shellcode, key) )
        else:
            PrintHelp()
    except Exception as e:
        #PrintHelp()
        print(e)

if __name__ == '__main__':
    exit(main())
