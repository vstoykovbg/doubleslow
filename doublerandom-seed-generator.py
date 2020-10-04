#!/usr/bin/python3

from mnemonic import Mnemonic
from os.path import exists
from os import urandom
from hashlib import sha256
import subprocess
from os import devnull
DEVNULL = open(devnull, 'wb')
from Crypto.Util.strxor import strxor

def get_random_bytes(howmany):
    if exists("/dev/random"):
        with open("/dev/random", 'rb') as f:
            return f.read(howmany)
    else:
        print ("/dev/random not found, using os.urandom instead.")
        return urandom(howmany)

def get_random_sound():
    return subprocess.Popen(["arecord", "-f", "cd", "-t", "raw", "-d", "5"], 
                                  stdout=subprocess.PIPE,stderr=DEVNULL).communicate()[0]

def haveged_1024_bytes():
    return subprocess.Popen(["haveged", "-n", "1024", "-f", "-"], 
                                  stdout=subprocess.PIPE,stderr=DEVNULL).communicate()[0]
def print_tolerant():
    print("However, this script is fault tolerant, so we continue.")

size = 32 # bytes = 256 bits = 24 words

haveged = b''

try:
    haveged = haveged_1024_bytes()
except Exception as detail:
    print("  Trying to get data from haveged failed.", detail)
    print_tolerant()
else:
    if len(haveged) == 1024:
        print("We got 1024 bytes from haveged successfully.")
    else:
        print("We got from haveged something unexpected.")
        print_tolerant()

user_entropy  = input("Type some random data (from dice rolls, decks of cards, etc): ").encode('utf-8')

user_entropy += input("Please boost the microphone input volume to the max and press Enter.").encode('utf-8')

myrandom = strxor(get_random_bytes(size), sha256(user_entropy+urandom(1024)+haveged).digest())

randomsound = b''

for counter in range(10):
    print ("Reading data from sound input... Iteration: ", counter)
    print ("\033[A\033[A") # up up (and go to new line) = up

    try:
        randomsound = get_random_sound()
    except Exception as detail:
        print("  Trying to get data from arecord failed.", detail)
        print_tolerant()
        break
    else:
        if len(randomsound) < 100000:
            print("\n\nWe got from arecrod something unexpected.")
            print_tolerant()
            print("")

    myrandom = sha256(randomsound+myrandom).digest()
    myrandom = strxor(myrandom, urandom(size))



print ("\n\n BIP39 mnemonic: \n\n")

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

