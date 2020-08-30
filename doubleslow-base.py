#!/usr/bin/python3

from Cryptodome.Util.RFC1751 import english_to_key
from Cryptodome.Util.RFC1751 import key_to_english

from hashlib import sha512
from hashlib import sha256
from hashlib import blake2b

import argon2
import scrypt
import binascii

import getpass
import sys
from unicodedata import normalize

import mnemonic
import bitcoin
from base58 import b58decode_check

from datetime import timedelta
from time import time


def TimeToString(elapsed):
    return str(timedelta(seconds=elapsed))


# https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def SlowKDF_stage_1(myinput, mysalt, mymemory, iterations):
    beginning = time()
    print ("Computing Argon2i...")
    digest=argon2.argon2_hash(password=myinput, salt=mysalt, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_i)
    shahehehe=sha512(myinput+mysalt+digest).digest()
    print ("Computing Argon2d...")
    digest=argon2.argon2_hash(password=digest+shahehehe, salt=mysalt, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_d)
    start = time()
    for counter in range(iterations):
        print ("Iteration %s from %s..." % (counter+1, iterations) )
        shahehehe=sha512(myinput+mysalt+digest).digest()
        print ("    Computing Scrypt...")
        digest=scrypt.hash(digest+shahehehe, mysalt, N = mymemory, r = 8, p = 1, buflen = 128)
        shahehehe=sha512(myinput+mysalt+digest).digest()
        print ("    Computing Argon2d...")
        digest=argon2.argon2_hash(password=digest+shahehehe, salt=mysalt, t=1, m=mymemory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_d)
        current = time()
        diff=current - start
        estimated_total = (diff / (counter + 1) ) * iterations 
        print ("    Elapsed time:", TimeToString(current - beginning))
        if counter+1 < iterations:
            print ("    Estimated remaining time:", TimeToString(estimated_total - diff) )
    return sha512(myinput+mysalt+digest).digest()


def make_digest_for_export_160_bits(input_512_bits):
    # Getting only the first 160 bits (20 bytes) to impede bruteforcing.
    # And also to make the result round 192 bits (24 bytes), because we add additional 4 bytes (settings).
    # It needs to be round because of RFC1751 (the length of the bytestring must be a multiple of 8 bytes).

    # This may cause collisions when brute-forcing with a dictionary (but only if the password is strong).
    # Collisions will frustrate the attacker (need to check many false positives).
    first_128_bits = input_512_bits[0:16]
    first_128_bits_hashed = sha256(first_128_bits).digest()

    # Getting only the first 160 bits (20 bytes)
    #   At first I thought to make it 96 bits (128-32) - this way the output will fit in 128 bits.
    #   But just in case made it over 128 bits.
    return first_128_bits_hashed[0:20]


# https://stackoverflow.com/questions/57025836/how-to-check-if-a-given-number-is-a-power-of-two-in-python
def is_power_of_two(n):
    return (n & (n - 1) == 0) and n != 0


# getting the memory in MiB
def get_memory(min_memory, max_memory, text):
    while True:
        multiplier = 1
        my_input = input(text)
        my_input = my_input.replace(" ","")
        my_input = my_input.upper()
        my_input = my_input.replace("MEGABYTES","")
        my_input = my_input.replace("MEGA BYTES","")
        my_input = my_input.replace("MIB","")
        my_input = my_input.replace("MB","")
        my_input = my_input.replace("M","")

        if "GIB" in my_input or "GB" in my_input or "G" in my_input:
            multiplier = 1024

        my_input = my_input.replace("GIGABYTES","")
        my_input = my_input.replace("GIGA BYTES","")
        my_input = my_input.replace("GIB","")
        my_input = my_input.replace("GB","")
        my_input = my_input.replace("G","")

        try:
            int_memory = int(my_input)
        except ValueError as detail:
            print("  Wrong input.", detail)
            continue

        int_memory = int_memory * multiplier

        if int_memory <= min_memory:
            print("Too little memory [",int_memory, "MiB ], it should be at least ", min_memory, "MiB")
            continue
        elif int_memory > max_memory:
            print("Too much memory [",int_memory, "MiB ], it should be no more than", max_memory, "MiB")
            continue

        if not is_power_of_two(int_memory):
            print ("The number", int_memory, "is not power of two.")
            continue

        answer = input("Please type \"yes\" to confirm that the memory should be " + str(int_memory) + " MiB: ").lower()

        if answer == "yes":
            return int_memory
        elif answer == "quit":
            quit()
        else:
            continue


def read_salt():
    mysalt_input = input("Please enter the salt in your desired format: ")

    try:
        print("Trying to interpret it like integer...")
        mysalt = int_to_bytes(int(mysalt_input))
    except ValueError as detail:
        print("  It does not look like an integer.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like BIP39 mnemonic...")
        mysalt = mnemonic.Mnemonic('english').to_entropy(mysalt_input)
        mysalt = bytes(mysalt)
    except Exception as detail:
        print("  It does not look like a BIP39 mnemonic.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like RFC1751 mnemonic...")
        mysalt = english_to_key(mysalt_input)
    except ValueError as detail:
        print("  It does not look like a RFC1751 mnemonic.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like Base58 with a checksum...")
        mysalt = b58decode_check(mysalt_input)
    except ValueError as detail:
        print("  It does not look like a Base58 with a checksum.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like hexidecimal...")
        mysalt = binascii.a2b_hex(mysalt_input)
    except ValueError as detail:
        print("  It does not look like a hexadecimal.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like Base64 string...")
        mysalt = binascii.a2b_base64(mysalt_input)
    except ValueError as detail:
        print("  It does not look like a Base64 string.", detail)
    else:
        looks_like = binascii.b2a_base64(mysalt, newline=False).decode("utf-8")
        if mysalt_input == looks_like:
            print("  Success!")
            return mysalt
        else:
            print("  It looks like Base64 string, but not exatly.")
            print("  Looks like: [", looks_like, "]")

    print("Normalizing the input string with NFKC...")
    mysalt = normalize('NFKC', mysalt_input)
    return mysalt.encode()


def get_big_enough_chunk_of_salt():
    while True:
        mysalt = read_salt()

        mysalt_len = len(mysalt)
        print ("\nThe size of the salt is", mysalt_len, "bytes.")
        print ("The salt in hex format: ", binascii.b2a_hex(mysalt).decode("utf-8"))
        print ("The salt:", mysalt)
        print ("The hash of the salt is:", key_to_english(blake2b(mysalt,digest_size=8).digest()), "\n")

        if mysalt_len < 10:
            print ("The salt is too small. It should be at least 10 bytes.")
        else:
            break
    return mysalt


def get_passphrase():
    while True:
        mypassphrase = getpass.getpass("Passphrase: ")

        if mypassphrase != getpass.getpass("Repeat passphrase: "):
            print ("ERROR: Passphrases do not match.")
            continue
        elif mypassphrase != getpass.getpass("Repeat passphrase (again): "):
            print ("ERROR: Passphrases do not match.")
            continue
        else:
            break

    print("Normalizing the passphrass with NFKC...")
    mypassphrase_normalized = normalize('NFKC', mypassphrase)

    if mypassphrase_normalized == mypassphrase:
        print("The normalization did not made any changes.")
    else:
        print("The normalization made changes.")

    return mypassphrase_normalized.encode()


# Copied from https://github.com/warner/python-ecdsa/blob/master/src/ecdsa/util.py
def string_to_number(string):
    return int(binascii.hexlify(string), 16)


def print_the_secrets(my_256_bit_secret):
    print ("\n\n========== The same 256 bit digest in different formats: ==========")

    # we need it also for bitcoin.encode_privkey()
    my_256_bit_secret_HEX = binascii.b2a_hex(my_256_bit_secret).decode("utf-8")

    print ("\n\nThe 256 bit digest in hex format:", my_256_bit_secret_HEX)

    print ("\nThe 256 bit digest in base64 format:", binascii.b2a_base64(my_256_bit_secret).decode("utf-8"))

    print ("\nThe 256 bit digest in BIP39 mnemonic format:\n\n", mnemonic.Mnemonic('english').to_mnemonic(my_256_bit_secret))

    print ("\n\nThe 256 bit digest in RFC1751 mnemonic format:\n\n", key_to_english(my_256_bit_secret))

    CURVE_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    my_256_bit_secret_decimal = string_to_number(my_256_bit_secret)

    print ("\n\nThe 256 bit digest in decimal format:\n\n", my_256_bit_secret_decimal)

    print ("\n\n* * * WARNING! This is the same 256 bit digest in different formats! * * *\n\n")

    if my_256_bit_secret_decimal < ( CURVE_ORDER - 1000000000 ):
        if my_256_bit_secret_decimal > 1000000000:
            print ("Looks ok for a SECP256k1 private key.")
        else:
            print ("Looks too small for a private key.")
    else:
        print ("Looks too big for a SECP256k1 private key.")

    my_256_bit_secret_WIF = bitcoin.encode_privkey(my_256_bit_secret_HEX,"wif_compressed")

    print ("\n\nThe 256 bit digest in compressed WIF format:\n\n", my_256_bit_secret_WIF)

    print ("\nThe address derived from the above WIF key:",bitcoin.privkey_to_address(my_256_bit_secret_WIF))



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

security_warning = "\n\n !!! Security warning: since the keys are displayed they might be compromised, because in some consoles the history is being recorded on the hard drive. Also, there might be a camera or device receiving the radiation emitted from the monitor. It's recommended to use this script only on air-gapped computers without a hard drive (OS is run from optical discs). You may also consider modifying the script not to show the keys on the screen.\n"

security_warning = security_warning + "\n\n !!! DANGER of catastrophic data loss! One bit flip (due to cosmic rays for example) can make the result of the hash functions completely different. Run the scripts several times to confirm that they produce the same output given the same input. Read how these scripts work and why the risk of bit flip is high (hint: RAM usage).\n"

print (security_warning)

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

digest_512_bits = SlowKDF_stage_1(mypassphrase_bytestring, mysalt, mymemory_stage_1, iterations_stage_1)


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

digest_from_additional_hashing = SlowKDF_stage_1(mypassphrase_bytestring+digest_512_bits+digest_external, mysalt, mymemory_stage_1, 1)

digest256_final = sha256(digest_from_additional_hashing+mypassphrase_bytestring+digest_512_bits+digest_external+mysalt).digest()


print_the_secrets(digest256_final)


