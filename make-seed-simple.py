#!/usr/bin/python3

from mnemonic import Mnemonic
from os.path import exists
from os import urandom
from hashlib import sha256
from Crypto.Util.strxor import strxor

def get_random_bytes(howmany):
    if exists("/dev/random"):
        with open("/dev/random", 'rb') as f:
            return f.read(howmany)
    else:
        print ("/dev/random not found, using os.urandom instead.")
        return urandom(howmany)
    
user_entropy = input("Type some random data (from dice rolls, decks of cards, etc): ").encode('utf-8')

myrandom = strxor(get_random_bytes(32), sha256(user_entropy+urandom(1024)).digest())

print ("\n BIP39 mnemonic, to be used as salt for the \"doubleslow-base.py\": \n\n")

words = Mnemonic('english').to_mnemonic(myrandom)
test = Mnemonic('english').to_entropy(words)

# Hmmm, It works without this line:
#test = bytes(test)

if test == myrandom:
    print(words)
else:
    print("Oops. Fatal error.")
    quit();

print ("\n\n* * * Warning: The output is not deterministic!")
print (    "               With the same user input you will get different output.")
print (    "               The script is mixing the user entropy with computer-generated entropy.")

