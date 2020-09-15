#!/usr/bin/python3

from Cryptodome.Util.RFC1751 import english_to_key
from Cryptodome.Util.RFC1751 import key_to_english

from hashlib import blake2b

from doubleslow_module import SlowKDF_stage_2
from doubleslow_module import print_security_warning

print_security_warning()

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

print_security_warning()
