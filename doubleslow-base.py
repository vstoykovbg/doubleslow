#!/usr/bin/python3

from Cryptodome.Util.RFC1751 import english_to_key
from Cryptodome.Util.RFC1751 import key_to_english

from hashlib import sha256
from hashlib import blake2b

import sys

from doubleslow_module import SlowKDF
from doubleslow_module import make_digest_for_export_160_bits
from doubleslow_module import get_memory
from doubleslow_module import get_big_enough_chunk_of_salt
from doubleslow_module import get_passphrase
from doubleslow_module import print_the_secrets
from doubleslow_module import print_security_warning


if len(sys.argv) > 2:
    print("Too many arguments.")
    quit()
elif len(sys.argv) == 2:
    if sys.argv[1] == "one":
        print("The external key stretching will NOT be performed.")
        external_key_stretching = "no"
    else:
        print("Invalid argument.")
        quit()
elif len(sys.argv) == 1:
   print("The external key stretching will be performed. If you don't want this stop the script and run it with argument \"one\" or enter 0 when asked for number of iterations on the second stage.")
   external_key_stretching = "yes"


print_security_warning()

mysalt = get_big_enough_chunk_of_salt()

def get_iterations_for_stage_1():
    while True:
        try:
            iterations = int(input("Number of iterations: "))
        except ValueError as detail:
            print("  Wrong input.", detail)
            continue
        if iterations < 1:
            print("The number of iterations should be at least 1.")
        else:
            return iterations

def get_iterations_for_stage_2():
    while True:
        try:
            iterations = int(input("Number of iterations on the second stage (external key stretching): "))
        except ValueError as detail:
            print("  Wrong input.", detail)
            continue
        if iterations > 65535:
            print ("Invalid number, it should be no more than 65535 (because we use two bytes to encode it)")
        elif iterations < 1:
            return 0
        else:
            return iterations
    

iterations_stage_1 = get_iterations_for_stage_1()

if external_key_stretching == "yes":
    iterations_stage_2 = get_iterations_for_stage_2()
    if iterations_stage_2 == 0:
        print("The external key stretching was disabled, the key will be stretched only on this computer.")
        external_key_stretching = "no"

mymemory_stage_1 = get_memory(32 , 16 * 1024, "Please enter the memory (for the first stage) in MiB (must be power of two): ")
mymemory_stage_1 = mymemory_stage_1 * 1024 # KiB

if external_key_stretching == "yes":
    mymemory_stage_2 = get_memory(32 , 16 * 1024, "Please enter the memory (for the second stage) in MiB (must be power of two): ")

mypassphrase_bytestring = get_passphrase()

digest_512_bits = SlowKDF(mypassphrase_bytestring, mysalt, mymemory_stage_1, iterations_stage_1)


if external_key_stretching == "yes":

    # up to 65535 - every number is encoded in two bytes
    second_stage_bytes = mymemory_stage_2.to_bytes(2, 'big') + iterations_stage_2.to_bytes(2, 'big')

    data_for_export_192_bits = second_stage_bytes + make_digest_for_export_160_bits(digest_512_bits)

    print ("\n\nRFC1751 words:\n\n", key_to_english(data_for_export_192_bits))

    print ("\n\nHash for detecting errors:\t", key_to_english(blake2b(data_for_export_192_bits,digest_size=8).digest()))

    print ("\nPlease run the doubleslow-external.py script on the powerful computer and enter the above RFC1751 words there. Then, write below the output from the doubleslow-external.py script. \n\n")

    while True:
        try:
            words = input("RFC1751 words: ")
            digest_external = english_to_key(words)
        except ValueError as detail:
            print("Error: ", detail,"\n")
            print("Please write the correct word sequence.\n")
            continue

        if data_for_export_192_bits == digest_external:
            print("You should not enter the above words here.")
            print("You should enter the above words where the doubleslow-external.py script is asking for them.")
            print("You should enter the output from the doubleslow-external.py script below.\n")
            continue

        the_length_of_the_digest=len(digest_external)
        if the_length_of_the_digest != 32:
           print("We expected 32 bytes, got", the_length_of_the_digest, "instead. Please write the correct word sequence.\n")
           continue

        print ("\nThe word sequence looks valid. The hash is:\n\n", key_to_english(blake2b(digest_external,digest_size=8).digest()))

        answer=input("\n\nPlease verify that the hash is correct and type \"yes\" to continue: ").lower()

        if answer == "yes":
            break
        elif answer == "quit":
            quit()
        else:
            continue
else:
    digest_external=b''

digest_from_additional_hashing = SlowKDF(mypassphrase_bytestring+digest_512_bits+digest_external, mysalt, mymemory_stage_1, 1)

digest256_final = sha256(digest_from_additional_hashing+mypassphrase_bytestring+digest_512_bits+digest_external+mysalt).digest()


print_the_secrets(digest256_final)


