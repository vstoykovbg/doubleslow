#!/usr/bin/python3

from pynput import mouse
import time
from os.path import exists
from hashlib import sha512
from os import urandom
import binascii
from Crypto.Util.strxor import strxor
import threading

def get_random_bytes(howmany):
    if exists("/dev/random"):
        with open("/dev/random", 'rb') as f:
            return f.read(howmany)
    else:
        print ("/dev/random not found, using os.urandom instead.")
        return urandom(howmany)

mutex = threading.Lock()

# Improving efficiency of concatenation by using bytearray instead of bytestring
# https://www.guyrutenberg.com/2020/04/04/fast-bytes-concatenation-in-python/
global_buffer = bytearray()
global_hash = get_random_bytes(32)
global_counter = 0


def get_time():
    if "time_ns" in dir(time):
        timenow = time.time_ns()
    else:
        timenow = time.time()
    return timenow

def on_move(x, y):
    global global_buffer
    global global_counter
    global global_hash
    my_time = get_time()
    this_data_chunk  = bytes ( str(my_time).encode('utf-8') )
    this_data_chunk += bytes ( b' ' + str(x).encode('utf-8') )
    this_data_chunk += bytes ( b' ' + str(y).encode('utf-8') )
    if global_counter > 10:
        end_msg = " Enough move, press enter to stop"
    else:
        end_msg = ""
    with mutex:
        print(global_counter, this_data_chunk, end_msg, "  ")
        print ("\033[A\033[A") # up up (and go to new line) = up
        global_buffer += this_data_chunk
        buffer_len=len(global_buffer)
        if buffer_len > 1024 * 15:
            global_hash = sha512(global_buffer + global_hash).digest()
            global_buffer = bytearray()
            global_buffer += global_hash
            assert isinstance(global_buffer, bytearray)
            global_counter += 1


listener = mouse.Listener(on_move=on_move)
listener.start()

print("Please move the mouse over areas of the screen where this script can \"see\"")
print("the movements. You can confirm that the script sees the mouse movements")
print("by observing the change in the digits below.")
print("On systems using Xwayland the mouse movements are visible only over")
print("some areas.")

read = input("Press enter when you want to stop collecting randomnes from the mice.\n")
listener.stop()

read = read.encode()

global_hash = sha512(bytes(global_buffer + global_hash + get_random_bytes(256) + read)).digest()
global_hash = strxor( global_hash, get_random_bytes(64) )

try:
    from mnemonic import Mnemonic
    from hashlib import sha256

    myrandom = strxor(get_random_bytes(32), sha256(bytes(global_buffer + global_hash + urandom(1024))).digest())

    print ("\n\n BIP39 mnemonic: \n\n")

    words = Mnemonic('english').to_mnemonic(myrandom)
    test = Mnemonic('english').to_entropy(words)

    # Hmmm, It works without this line:
    #test = bytes(test)

    if test == myrandom:
        print(words, "\n")
    else:
        print("Oops. Fatal error.")
        quit();

except Exception as detail:
    print("  Error. Can't create mnemonic. ", detail)

    print ("Here are some random base64 data instead.")

    print ("\nRandom base64 encoded data:\n")
    print (binascii.b2a_base64(global_hash).decode("utf-8"))



