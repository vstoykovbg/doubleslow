#!/usr/bin/python3

import time
from os.path import exists
from hashlib import sha512
from os import urandom
import binascii
from Crypto.Util.strxor import strxor
import threading
import subprocess
from os import devnull
DEVNULL = open(devnull, 'wb')

mutex = threading.Lock()

global_ask_for_volume = True

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
    with mutex:
        print(global_counter, this_data_chunk, "  ")
        print ("\033[A\033[A") # up up (and go to new line) = up
        global_buffer += this_data_chunk
        buffer_len=len(global_buffer)
        if buffer_len > 1024 * 15:
            global_hash = sha512(global_buffer + global_hash).digest()
            global_buffer = bytearray()
            global_buffer += global_hash
            assert isinstance(global_buffer, bytearray)
            global_counter += 1

def print_tolerant_error(msg, detail):
    print("\n\n" + msg, detail)
    print("However, this script is fault tolerant, so we continue.\n")

def get_hash_with_mouse():

    from pynput import mouse

    counter_max = 10

    global global_hash
    global global_buffer
    global global_counter

    # Improving efficiency of concatenation by using bytearray instead of bytestring
    # https://www.guyrutenberg.com/2020/04/04/fast-bytes-concatenation-in-python/
    global_buffer = bytearray()

    global_hash = get_random_bytes(32)
    hash_sound = get_random_bytes(32)
    global_buffer += get_random_bytes(32)
    global_counter = 0
    haveged_chunk = b''

    assert isinstance(global_buffer, bytearray)

    test_hash = global_hash

    listener = mouse.Listener(on_move=on_move)
    listener.start()

    print("Please boost the microphone input volume and connect a microphone")
    print("or other noise source. The script will \"listen\" to the noise")
    print("while you move the mouse.\n")

    print("Please move the mouse over areas of the screen where this script can \"see\"")
    print("the movements. You can confirm that the script sees the mouse movements")
    print("by observing the change in the digits below.")
    print("On systems using Xwayland the mouse movements are visible only over")
    print("some areas.")

    try:

        while True:
            random_sound_chunk = get_random_sound()

            if len(random_sound_chunk) < 100000:
                with mutex:
                    print_tolerant_error("⚠ We got from arecord something unexpected.", "")

            hash_sound = sha512(hash_sound + random_sound_chunk).digest()

            if global_counter > counter_max:
                break

    except Exception as detail:
        with mutex:
            print_tolerant_error("⚠ Trying to get data from arecord failed.", detail)

    try:
        haveged_chunk = haveged_1024_bytes()
    except Exception as detail:
        with mutex:
            print_tolerant_error("⚠ Trying to get data from haveged failed.", detail)


    # in case get_random_sound() fails
    while True:
        if global_counter > counter_max:
            break
        time.sleep(1)
    

    listener.stop()
    time.sleep(0.1)

    print("Randomness collection from the mice is complete.")

    assert global_hash != test_hash

    user_entropy  = input("Please type some random data (from dice rolls, decks of cards, etc): ").encode('utf-8')

    global_hash = sha512(bytes(global_buffer + global_hash + get_random_bytes(256) + haveged_chunk + hash_sound + user_entropy)).digest()

    return strxor( global_hash, get_random_bytes(64) )

def randomness_from_dev_input_mice():
    print ("\nPlease move the mouse.")
    local_buffer = bytearray()

    with open( "/dev/input/mice", "rb" ) as file:
        outer_range = 64
        for counter in range(1, outer_range +1):
            for counter2 in range(128):
                buf = file.read(3);
                my_time = get_time()
                local_buffer += str(my_time).encode('utf-8') + buf
            print (my_time, counter, "from", outer_range, "        ")
            print ("\033[A\033[A") # up up (and go to new line) = up

    return sha512(bytes(local_buffer)).digest()


def get_hash_with_mouse_alternative():

    hash_sound = get_random_bytes(32)
    haveged_chunk = b''
    user_entropy = b''
    global global_ask_for_volume

    try:

        if global_ask_for_volume:
            print("Please boost the microphone input volume and connect a microphone")
            print("or other noise source.")
            user_entropy = input("Press Enter to continue.").encode('utf-8')
            print ("\033[A\033[A") # up up (and go to new line) = up
            global_ask_for_volume = False

        for counter in range(10):
            print ("Reading data from sound input... Iteration: ", counter)
            print ("\033[A\033[A") # up up (and go to new line) = up

            random_sound_chunk = get_random_sound()

            if len(random_sound_chunk) < 100000:
                print_tolerant_error("⚠ We got from arecord something unexpected.", "")

            hash_sound = sha512(hash_sound + random_sound_chunk).digest()

    except Exception as detail:
        print_tolerant_error("⚠ Trying to get data from arecord failed.", detail)

    try:
        haveged_chunk = haveged_1024_bytes()
    except Exception as detail:
        print_tolerant_error("⚠ Trying to get data from haveged failed.", detail)

    mice_hash = b''

    try:
        mice_hash = randomness_from_dev_input_mice()
    except Exception as detail:
        print_tolerant_error("⚠ Trying to get data from /dev/input/mice failed.", detail)

    user_entropy += input("Please type some random data (from dice rolls, decks of cards, etc): ").encode('utf-8')

    hash_64_bytes = sha512(get_random_bytes(256) + mice_hash + haveged_chunk + hash_sound + user_entropy).digest()

    return strxor( hash_64_bytes, get_random_bytes(64) )


def get_hash_with_haveged_and_arecord():

    hash_sound = get_random_bytes(32)
    haveged_chunk = b''
    user_entropy = b''
    global global_ask_for_volume

    try:

        if global_ask_for_volume:
            print("Please boost the microphone input volume and connect a microphone")
            print("or other noise source.")
            user_entropy = input("Press Enter to continue.").encode('utf-8')
            print ("\033[A\033[A") # up up (and go to new line) = up
            global_ask_for_volume = False

        for counter in range(10):
            print ("Reading data from sound input... Iteration: ", counter)
            print ("\033[A\033[A") # up up (and go to new line) = up

            random_sound_chunk = get_random_sound()

            if len(random_sound_chunk) < 100000:
                print_tolerant_error("⚠ We got from arecord something unexpected.", "")

            hash_sound = sha512(hash_sound + random_sound_chunk).digest()

    except Exception as detail:
        print_tolerant_error("⚠ Trying to get data from arecord failed.", detail)

    try:
        haveged_chunk = haveged_1024_bytes()
    except Exception as detail:
        print_tolerant_error("⚠ Trying to get data from haveged failed.", detail)

    user_entropy += input("Please type some random data (from dice rolls, decks of cards, etc): ").encode('utf-8')

    hash_64_bytes = sha512(get_random_bytes(256) + haveged_chunk + hash_sound + user_entropy).digest()

    return strxor( hash_64_bytes, get_random_bytes(64) )


def get_hash(use_mouse=True):

    this_hash = b''

    if use_mouse:
        try:
            this_hash = get_hash_with_mouse()
        except Exception as detail:
            print_tolerant_error("⚠ Trying to use get_hash_with_mouse() failed.", detail)

        if this_hash == b'':
            this_hash = get_hash_with_mouse_alternative()
    else:
        this_hash = get_hash_with_haveged_and_arecord()

    assert len(this_hash) == 64

    return this_hash


def main():

    this_hash = get_hash()

    try:
        from mnemonic import Mnemonic
        from hashlib import sha256

        myrandom = strxor(get_random_bytes(32), sha256(bytes(this_hash + urandom(1024))).digest())

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
        print_tolerant_error("⚠ Error. Can't create mnemonic. ", detail)

        print ("Here are some random base64 data instead.")

        print ("\nRandom base64 encoded data:\n")
        print (binascii.b2a_base64(this_hash).decode("utf-8"))


if __name__ == "__main__":
    main()


