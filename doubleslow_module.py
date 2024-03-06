#!/usr/bin/python3

from Crypto.Util.RFC1751 import english_to_key
from Crypto.Util.RFC1751 import key_to_english

from hashlib import sha512
from hashlib import sha256
from hashlib import blake2b
from hashlib import sha3_512

import argon2
import scrypt
import binascii

import getpass
from unicodedata import normalize

import mnemonic
import bitcoin
from base58 import b58decode_check

from datetime import timedelta
from time import time

from Crypto.Util.strxor import strxor

def print_security_warning():
    security_warning = "\n\n !!! Security warning: since the keys are displayed they might be compromised, because in some consoles the history is being recorded on the hard drive. Also, there might be a camera or device receiving the radiation emitted from the monitor. It's recommended to use this script only on air-gapped computers without a hard drive (the OS is run from optical discs). You may also consider modifying the script not to show the keys on the screen.\n"
    security_warning = security_warning + "\n\n !!! DANGER of catastrophic data loss! One bit flip (due to cosmic rays for example) can make the result of the hash functions completely different. Run the scripts several times to confirm that they produce the same output given the same input. Read how these scripts work and why the risk of bit flip is high (hint: RAM usage).\n"
    print(security_warning)

def SlowKDF(input_passphrase, input_salt, memory, iterations):
    beginning = time()
    xor_digest=sha512(input_passphrase+input_salt).digest()
    xor_digest+=sha512(xor_digest+input_salt+input_passphrase).digest()
    digest=sha512(input_salt+input_passphrase+xor_digest).digest()
    digest=sha3_512(digest).digest()
    start = time()
    for counter in range(iterations):
        print ("Iteration %s from %s..." % (counter+1, iterations) )
        shahehehe=sha512(xor_digest+input_passphrase+input_salt+digest).digest()
        # The passphrase (shahehehe) size of scrypt should be equal to the block size of the SHA-256 (64 bytes)
        # to avoid the initial hashing with SHA-256 if the password is longer or shorter (HMAC-SHA256).
        # Block size should not be confused with the digest size (for SHA-256 the block size is 64 bytes, the digest size is 32 bytes).
        print ("    Computing Scrypt...")
        digest=scrypt.hash(shahehehe, input_salt, N = memory, r = 8, p = 1, buflen = 128)
        xor_digest=strxor(xor_digest, digest)
        shahehehe=sha512(xor_digest+input_passphrase+input_salt+digest).digest()
        kek=sha3_512(shahehehe).digest()
        print ("    Computing Argon2d...")
        digest=argon2.argon2_hash(password=digest+shahehehe+xor_digest+kek, salt=input_salt, t=1, m=memory, p=1, buflen=128, argon_type=argon2.Argon2Type.Argon2_d)
        xor_digest=strxor(xor_digest, digest)
        current = time()
        diff=current - start
        estimated_total = (diff / (counter + 1) ) * iterations 
        print ("    Elapsed time:", TimeToString(current - beginning))
        if counter+1 < iterations:
            print ("    Estimated remaining time:", TimeToString(estimated_total - diff) )
    kek=sha3_512(xor_digest+input_passphrase+input_salt+digest).digest()
    shahehehe=sha512(kek+digest+input_passphrase+input_salt+xor_digest).digest()
    kek2=sha3_512(kek+shahehehe+digest+input_passphrase+input_salt+xor_digest).digest()
    shahehehe=sha512(kek2+kek+shahehehe).digest()
    current = time()
    print ("    Elapsed time:", TimeToString(current - beginning))
    return shahehehe


def SlowKDF_stage_2(myinput, mymemory, iterations):
    # In principle, no salt is needed here, it's used in the first stage and not exported for security reasons.
    # However, without salt the Argon2 key derivation function will return error ARGON2_SALT_TOO_SHORT
    mysaltsubstitute = sha512(myinput).digest()
    digest=SlowKDF(myinput, mysaltsubstitute, mymemory, iterations)
    return sha256(digest+myinput).digest()


def TimeToString(elapsed):
    return str(timedelta(seconds=elapsed))


# https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def make_digest_for_export_160_bits(input_512_bits):
    # Getting only the first 160 bits (20 bytes) to impede bruteforcing.
    # And also to make the result round 192 bits (24 bytes), because we add additional 4 bytes (settings).
    # It needs to be round because of RFC1751 (the length of the bytestring must be a multiple of 8 bytes).

    # This may cause collisions when brute-forcing with a dictionary.
    # (If we lower the number of bits we get, for 128 bits it's not very likely.)
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

        if my_input == "":
            my_input = "2048" # Default 2GiB
        else:
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

        if int_memory < min_memory:
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

    mysalt_input_all_spaces_removed="".join(mysalt_input.split())

    try:
        print("Trying to interpret it like integer...")
        salt_int = int(mysalt_input_all_spaces_removed)
        mysalt = int_to_bytes(salt_int)
    except ValueError as detail:
        print("  It does not look like an integer.", detail)
    else:
        print("  Success!")
        print("  The number was:", salt_int)
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
        print("Trying to interpret it like BIP39 mnemonic not formatted correctly...")
        # strip() fixes UX issue: do not recognize BIP39 mnemonic if whitespace is present at the beginning
        mysalt_input_corrected = " ".join(mysalt_input.lower().split())
        mysalt = mnemonic.Mnemonic('english').to_entropy(mysalt_input_corrected)
        mysalt = bytes(mysalt)
    except Exception as detail:
        print("  It does not look like a BIP39 mnemonic.", detail)
    else:
        print("  Success!")
        print("  The BIP39 mnemonic was:", mysalt_input_corrected)
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
        mysalt = b58decode_check(mysalt_input_all_spaces_removed)
    except ValueError as detail:
        print("  It does not look like a Base58 with a checksum.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like hexidecimal...")
        mysalt = binascii.a2b_hex(mysalt_input_all_spaces_removed)
    except ValueError as detail:
        print("  It does not look like a hexadecimal.", detail)
    else:
        print("  Success!")
        return mysalt

    try:
        print("Trying to interpret it like Base64 string...")
        mysalt = binascii.a2b_base64(mysalt_input_all_spaces_removed)
    except ValueError as detail:
        print("  It does not look like a Base64 string.", detail)
    else:
        looks_like = binascii.b2a_base64(mysalt, newline=False).decode("utf-8")
        if mysalt_input_all_spaces_removed == looks_like:
            print("  Success!")
            return mysalt
        else:
            print("  It looks like a Base64 string, but not exactly.")
            print("  Looks like: [", looks_like, "]")

    print("Normalizing the input string with NFKC...")
    mysalt = normalize('NFKC', mysalt_input)

    if mysalt == mysalt_input:
        print("The salt has not been changed by the NFKC normalization.")
    else:
        print("The salt has been changed by the NFKC normalization.")

    if mysalt != mysalt.strip():
        print ("* * * Warning! Your salt contains leading or trailing whitespace.")

    if mysalt.count('  ') >= 1:
        print ("* * * Warning! Your salt contains consecutive whitespaces.")

    if mysalt.count('\t') >= 1:
        print ("* * * Warning! Your salt contains one or more tabs.")

    return mysalt.encode()


def get_big_enough_chunk_of_salt():
    while True:
        mysalt = read_salt()

        mysalt_len = len(mysalt)
        print ("\nThe size of the salt is", mysalt_len, "bytes.")
        print ("The salt in hex format: ", binascii.b2a_hex(mysalt).decode("utf-8"))
        print ("The salt:", mysalt)
        print ("The hash of the salt is:", key_to_english(blake2b(mysalt,digest_size=8).digest()), "\n")

        if mysalt_len < 16:
            print ("The salt is too small. It should be at least 16 bytes.")
        else:
            break
    return mysalt


def get_passphrase_inner():
    while True:
        mypassphrase = getpass.getpass("Passphrase: ")

        if mypassphrase == "":
            print ("You wrote an empty string as a passphrase!")

        repeat_passphrase = getpass.getpass("Repeat passphrase: ")

        if repeat_passphrase == "":
            if mypassphrase == "":
                print ("You confirmed an empty string as a passphrase!")
            else:
                print ("OK, you don't want to repeat the passphrase. It's at your own risk.")
                print ("Please at least check your passphrase mnemonic checksum!")
            return mypassphrase.encode()

        if mypassphrase != repeat_passphrase:
            print ("ERROR: Passphrases do not match.")
            continue

        repeat_passphrase = getpass.getpass("Repeat passphrase (again): ")

        if repeat_passphrase == "":
            print ("OK, you don't want to repeat the passphrase again. It's at your own risk.")
            break

        if mypassphrase != repeat_passphrase:
            print ("ERROR: Passphrases do not match.")
            continue
        else:
            break

    print("Normalizing the passphrass with NFKC...")
    mypassphrase_normalized = normalize('NFKC', mypassphrase)

    if mypassphrase_normalized == mypassphrase:
        print("The passphrase has not been changed by the NFKC normalization.")
    else:
        print("The passphrase has been changed by the NFKC normalization.")

    if mypassphrase_normalized != mypassphrase_normalized.strip():
        print ("* * * Warning! Your passphrase contains leading or trailing whitespace.")

    if mypassphrase_normalized.count('  ') >= 1:
        print ("* * * Warning! Your passphrase contains consecutive whitespaces.")

    if mypassphrase_normalized.count('\t') >= 1:
        print ("* * * Warning! Your passphrase contains one or more tabs.")

    return mypassphrase_normalized.encode()

def yes_or_no():

    while True:
        answer = input("Your answer (yes/no):")

        if answer == "yes":
            return answer
        if answer == "no":
            return answer
        else:
            continue

def yes_or_short_or_no():

    while True:
        answer = input("Your answer (yes/short/no): ")

        if answer == "yes":
            return answer
        if answer == "no":
            return answer
        if answer == "short":
            return answer
        else:
            continue

def get_passphrase():

    while True:
        my_encoded_and_normalized_passphrase = get_passphrase_inner()

        if my_encoded_and_normalized_passphrase == b'':
            return b''

        print ("Do you want to see the hash of your passphrase now?")
        print ("(Security risk: the hash can help attackers bruteforce your passphrase.)")
        print ("Answer \"short\" if you want to see only two words of the hash.")

        answer = yes_or_short_or_no()

        if answer == "yes":
            print ("The hash of your passphrase is:", key_to_english(blake2b(my_encoded_and_normalized_passphrase,digest_size=8).digest()), "\n")
        elif answer == "short":
            splitted_hash = key_to_english(blake2b(my_encoded_and_normalized_passphrase,digest_size=8).digest()).split()
            print ("The hash of your passphrase is: (only first two words)", splitted_hash[0], splitted_hash[1], "\n")
           
        print ("Do you want to continue with this passphrase?")

        answer = yes_or_no()

        if answer == "yes":
            return my_encoded_and_normalized_passphrase
        else:
            continue


# Copied from https://github.com/warner/python-ecdsa/blob/master/src/ecdsa/util.py
def string_to_number(string):
    return int(binascii.hexlify(string), 16)


def print_128_bit_secret(label,my_128_bit_secret):

    my_128_bit_secret_HEX = binascii.b2a_hex(my_128_bit_secret).decode("utf-8")

    print ("\n\nThe", label, "128-bit digest in hex format:", my_128_bit_secret_HEX)

    print ("\nThe", label, "128-bit digest in base64 format:", binascii.b2a_base64(my_128_bit_secret).decode("utf-8"))

    print ("\nThe", label, "128-bit digest in BIP39 mnemonic format:\n\n", mnemonic.Mnemonic('english').to_mnemonic(my_128_bit_secret))

    print ("\n\nThe", label, "128-bit digest in RFC1751 mnemonic format:\n\n", key_to_english(my_128_bit_secret))

    my_128_bit_secret_decimal = string_to_number(my_128_bit_secret)

    print ("\n\nThe", label, "128-bit digest in decimal format:\n\n", my_128_bit_secret_decimal)

    if my_128_bit_secret_decimal < 1000000000:
        print ("Warning! The key is too small! Do not use, small entropy!.")


def print_the_secrets(my_256_bit_secret):

    print ("\n\n========== 128-bit digests (12 BIP39 words): ==========")

    print ("\n\nThe two 128-bit digests are created by cutting the 256-bit digest.")

    print_128_bit_secret("FIRST",my_256_bit_secret[0:16])
    print_128_bit_secret("SECOND",my_256_bit_secret[16:32])

    print ("\n\nFor better security use only the 256-bit digest (24 BIP39 words).")
    print ("Don't forget that the two 128-bit digests were created by cutting the 256-bit digest in half.")

    print ("\n\n========== The same 256-bit digest in different formats: ==========")

    # we need it also for bitcoin.encode_privkey()
    my_256_bit_secret_HEX = binascii.b2a_hex(my_256_bit_secret).decode("utf-8")

    print ("\n\nThe 256-bit digest in hex format:", my_256_bit_secret_HEX)

    print ("\nThe 256-bit digest in base64 format:", binascii.b2a_base64(my_256_bit_secret).decode("utf-8"))

    print ("\nThe 256-bit digest in BIP39 mnemonic format:\n\n", mnemonic.Mnemonic('english').to_mnemonic(my_256_bit_secret))

    print ("\n\nThe 256-bit digest in RFC1751 mnemonic format:\n\n", key_to_english(my_256_bit_secret))

    CURVE_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337

    my_256_bit_secret_decimal = string_to_number(my_256_bit_secret)

    print ("\n\nThe 256-bit digest in decimal format:\n\n", my_256_bit_secret_decimal)

    if my_256_bit_secret_decimal < ( CURVE_ORDER - 1000000000 ):
        if my_256_bit_secret_decimal > 1000000000:
            print ("Looks ok for a SECP256k1 private key.")
        else:
            print ("Looks too small for a private key.")
    else:
        print ("Looks too big for a SECP256k1 private key.")

    my_256_bit_secret_WIF = bitcoin.encode_privkey(my_256_bit_secret_HEX,"wif_compressed")

    print ("\n\nThe 256-bit digest in compressed WIF format:\n\n", my_256_bit_secret_WIF)

    print ("\nThe address derived from the above WIF key:",bitcoin.privkey_to_address(my_256_bit_secret_WIF))

