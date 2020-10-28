#!/usr/bin/python3

import sys
from randomness_mixer import get_random_bytes
from randomness_mixer import get_hash

global_accumulator = list()
global_use_mouse = True

def use_mouse(b):
    assert type(b) == bool
    global global_use_mouse
    global_use_mouse = b
    

def refill_global_accumulator():
    global global_accumulator
    global global_use_mouse

    print("Refilling the random numbers accumulator - refill_global_accumulator() called.")

    this_hash = b''

    #this_hash = get_hash()
    #from hashlib import sha512
    #this_hash = sha512(get_random_bytes(256)).digest()

    this_hash = get_hash(use_mouse=global_use_mouse)


    assert this_hash != b''
    assert isinstance(global_accumulator, list)

    global_accumulator += list(this_hash)

    assert isinstance(global_accumulator, list)
    

def get_random_bytes_from_global_accumulator(howmany):
    assert isinstance(howmany, int)
    assert howmany > 0

    global global_accumulator

    while len(global_accumulator) < howmany:
        refill_global_accumulator()

    result = bytearray()

    for c in range(howmany):
        result += bytes(global_accumulator.pop(0).to_bytes(1, 'big'))

    assert len(result) == howmany
        
    return result
    

def how_many_bytes_are_needed(n):
    if n < 0:
        raise ValueError("The number should not be negative.")
    i = 0
    while(n > 0):
        n = n >> 8;
        i += 1;
    return i


def get_integer_from_accumulator(size):
    assert size > 0
    assert isinstance(size, int)
    return int.from_bytes(get_random_bytes_from_global_accumulator(size), 'big')


# get random integer from [0, exclusive_upper_bound)
def random_below(exclusive_upper_bound):

    if not (isinstance(exclusive_upper_bound, int) and (exclusive_upper_bound > 0)):
        raise ValueError("Upper bound must be positive integer.")

    if (exclusive_upper_bound == 1):
        return 0

    inclusive_upper_bound = exclusive_upper_bound - 1

    # Intentionally adding one more byte to reduce the cycles
    how_many_bytes = 1 + how_many_bytes_are_needed(inclusive_upper_bound)

    source_exclusive_upper_bound = 256 ** how_many_bytes
    source_inclusive_upper_bound = source_exclusive_upper_bound - 1

    assert source_exclusive_upper_bound >= exclusive_upper_bound

    # floor division is used
    buckets = source_inclusive_upper_bound // exclusive_upper_bound

    assert isinstance(buckets, int)
    assert buckets > 0

    while (True):
        r = get_integer_from_accumulator(how_many_bytes) // buckets
        if r < ( exclusive_upper_bound):
            return r


def main():
    global global_use_mouse

    if len(sys.argv) > 2:
        print("Too many arguments.")
        quit()
    elif len(sys.argv) == 2:
        if (sys.argv[1] == "nomouse") or (sys.argv[1] == "nomice"):
            print("The mouse will not be used as randomness source.")
            use_mouse(False)
        else:
            print("Invalid argument.")
            quit()

    while True:
        try:
            exclusive_range = int(input("Exclusive range: "))
        except ValueError as detail:
            print("  Wrong input.", detail)
            continue

        if exclusive_range < 1:
            print ("Invalid number, it should be positive.")
        elif exclusive_range < 2:
            print ("It does not make senese to ask for a random number between 0 and 0.")
        else:
            break

    while True:
        try:
            how_many = int(input("How many random numbers you need: "))
        except ValueError as detail:
            print("  Wrong input.", detail)
            continue

        if how_many < 1:
            print ("It does not make senese to ask for a less than 1 random number.")
        else:
            break


    list_of_random_numbers = list()

    for c in range(how_many):
        list_of_random_numbers.append(random_below(exclusive_range))

    print (how_many, "random numbers between 0 and", exclusive_range - 1, ":")
    print (list_of_random_numbers)

if __name__ == "__main__":
    main()


