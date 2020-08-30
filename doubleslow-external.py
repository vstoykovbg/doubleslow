#!/usr/bin/python3

from Cryptodome.Util.RFC1751 import english_to_key
from Cryptodome.Util.RFC1751 import key_to_english

from hashlib import sha512
from hashlib import sha256
from hashlib import blake2b

import argon2
import scrypt
import binascii

from datetime import timedelta
from time import time


def TimeToString(elapsed):
    return str(timedelta(seconds=elapsed))


def SlowKDF_stage_2(myinput, mymemory, iterations):
    beginning = time()
    # In principle, no salt is needed here, it's used in the first stage and not exported for security reasons.
    # However, without salt the Argon2 key derivation function will return error ARGON2_SALT_TOO_SHORT
    mysaltsubstitute = sha512(input_digest).digest()
    print ("\nComputing Argon2i...")
    digest=argon2.argon2_hash(password=input_digest, salt=mysaltsubstitute, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_i)
    shahehehe=sha512(input_digest+digest).digest()
    print ("Computing Argon2d...")
    digest=argon2.argon2_hash(password=digest+shahehehe, salt=mysaltsubstitute, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_d)
    start = time()
    for counter in range(iterations):
        print ("Iteration %s from %s..." % (counter+1, iterations) )
        shahehehe=sha512(input_digest+digest).digest()
        print ("    Computing Scrypt...")
        digest=scrypt.hash(digest+shahehehe, mysaltsubstitute, N = mymemory, r = 8, p = 1, buflen = 128)
        shahehehe=sha512(input_digest+digest).digest()
        print ("    Computing Argon2d...")
        digest=argon2.argon2_hash(password=digest+shahehehe, salt=mysaltsubstitute, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_d)
        current = time()
        diff=current - start
        estimated_total = (diff / (counter + 1) ) * iterations 
        print ("    Elapsed time:", TimeToString(current - beginning))
        if counter+1 < iterations:
            print ("    Estimated remaining time:", TimeToString(estimated_total - diff) )
    return sha256(input_digest+digest).digest()


security_warning = "\n\n !!! Security warning: since the keys are displayed they might be compromised, because in some consoles the history is being recorded on the hard drive. Also, there might be a camera or device receiving the radiation emitted from the monitor. It's recommended to use this script only on air-gapped computers without a hard drive (the OS is run from optical discs). You may also consider modifying the script not to show the keys on the screen.\n"

security_warning = security_warning + "\n\n !!! DANGER of catastrophic data loss! One bit flip (due to cosmic rays for example) can make the result of the hash functions completely different. Run the scripts several times to confirm that they produce the same output given the same input. Read how these scripts work and why the risk of bit flip is high (hint: RAM usage).\n"

print (security_warning)

while True:
    try:
        words = input("RFC1751 words: ")
        input_data_192_bits = english_to_key(words)
    except ValueError as detail:
        print(detail)
        continue

    the_length_of_the_input = len(input_data_192_bits)
    if the_length_of_the_input != 24:
        print("We expected 24 bytes, got", the_length_of_the_input, "instead. Can't continue.")
        quit()

    print ("\nThe word sequence looks valid. The hash is:\n\n", key_to_english(blake2b(input_data_192_bits,digest_size=8).digest()))

    answer=input("\n\nPlease verify that the hash is correct and type \"yes\" to continue: ").lower()

    if answer == "yes":
        break
    elif answer == "quit":
        quit()
    else:
        continue

mymemory_stage_2 = int.from_bytes(input_data_192_bits[0:2], 'big')
iterations_stage_2 = int.from_bytes(input_data_192_bits[2:4], 'big')
input_digest = input_data_192_bits[4:]

print("\nThe settings encoded in the RFC1751 words are:")
print("Iterations: ", iterations_stage_2)
print("Memory usage: ", mymemory_stage_2, "MiB")
print("Please consider the memory usage. The computer should have enough free RAM.\n")

while True:
    answer=input("Please type \"yes\" if you want to continue. ").lower()

    if answer == "yes":
        break
    elif answer == "quit":
        quit()
    else:
        print("Invalid response.")
        continue

mymemory_stage_2 = mymemory_stage_2 * 1024 #  MiB * 1024

digest_for_export_256_bits = SlowKDF_stage_2(input_digest, mymemory_stage_2, iterations_stage_2)

print ("\n\nRFC1751 words:\n\n", key_to_english(digest_for_export_256_bits))

print ("\n\nHash for detecting errors:\t", key_to_english(blake2b(digest_for_export_256_bits,digest_size=8).digest()))

print (security_warning)
