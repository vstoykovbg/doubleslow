#!/usr/bin/python3

import random
import sys


from randomness_choice import random_below
from randomness_choice import use_mouse

filename_list = [
    "wordlist.txt",
    "/usr/share/keepassxc/wordlists/eff_large.wordlist",
    "/usr/share/dict/american-english",
    "/usr/share/dict/british-english",
    "/usr/share/dict/cracklib-small",
]

filename = ""

if len(sys.argv) > 2:
    print("Too many arguments.")
    quit()
elif len(sys.argv) == 2:
    filename = sys.argv[1]

if filename == "":
    from os.path import exists
    for filename_i in filename_list:
        if exists(filename_i):
            filename = filename_i
            break

if filename == "":
    print("Dictionary file not found.")
    quit()


print("Using dictionary:", filename)

with open(filename) as f:
    mywordlist = [line.rstrip() for line in f]

random_words = list()

exclusive_range = len(mywordlist)

print("The list of words contains", exclusive_range, "elements.")

if exclusive_range < 2048:
    print("Too small list of words.")
    quit()

while True:
    try:
        how_many = int(input("How many random words you need: "))
    except ValueError as detail:
        print("  Wrong input.", detail)
        continue

    if how_many < 1:
        print ("It does not make senese to ask for a less than 1 random word.")
    else:
        break


while True:
    print("Do you want to use the mouse as a randomness source?")
    print ("Enter \"0\" (zero) or \"no\" to not ask for a mouse movements.")
    mouse_reply = input("Or just press \"enter\" to continue: ")

    if (mouse_reply == "0") or (mouse_reply == "no"):
        print ("The mouse will not be used as a randomness source.")
        use_mouse(False)
        break
    elif (mouse_reply == "yes") or (mouse_reply == "yes") or (mouse_reply == ""):
        print ("The mouse will be used as a randomness source.")
        use_mouse(True)
        break
    else:
        print ("Invalid response.")


for counter in range(how_many):
    random_number = random_below(exclusive_range)
    random_word = mywordlist[random_number]
    random_words.append(random_word)

print ("\n\n  ", how_many, "random words from a list of", exclusive_range, "words:\n")

c = 0
for word in random_words:
    c += 1
    print('{:10d}'.format(c), word)

print ("")


