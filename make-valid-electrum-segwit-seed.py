#!/usr/bin/python3

import hmac
import hashlib
import unicodedata
import string
import os
import sys

# Subroutines are copy-pasted from the Electrum source code
#
# Copyleft (C) 2021 Valentin Stoykov
#
# Copyright of the original subroutines:
#
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F, 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c):
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed: str) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed

def bh2u(x: bytes) -> str:
    """
    str with hex representation of a bytes-like object

    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    """
    return x.hex()

def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()

# mostly copy-paste from is_new_seed()
def is_electrum_segwit_seed(x: str) -> bool:
    x = normalize_text(x)
    s = bh2u(hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512))
    return s.startswith('100')

# mostly copy-paste from from_file()
def load_words():
    with open(os.path.join(sys.path[0], "electrum_words.txt"), 'r', encoding='utf-8') as f:
        s = f.read().strip()
    s = unicodedata.normalize('NFKD', s)
    lines = s.split('\n')
    words = []
    for line in lines:
        line = line.split('#')[0]
        line = line.strip(' \r')
        assert ' ' not in line
        if line:
            words.append(line)
    return words

# The end of the mostly copied code

def read_the_seed():

    seed_input_original = input("Please enter the seed to be amended: ")

    print("Normalizing the input string with NFKD...")
    seed_input = unicodedata.normalize('NFKD', seed_input_original)

    if seed_input == seed_input:
        print("The seed has not been changed by the NFKD normalization.")
    else:
        print("The seed has been changed by the NFKD normalization.")

    if seed_input == unicodedata.normalize('NFKC', seed_input_original):
        print("The NFKC version is the same as NFKD.")
    else:
        print("* * * Warning! The NFKC version is DIFFERENT than the NFKD version.")

    if seed_input != seed_input.strip():
        print ("* * * Warning! Your seed contains leading or trailing whitespace.")

    if seed_input.count('  ') >= 1:
        print ("* * * Warning! Your seed contains consecutive whitespaces.")

    if seed_input.count('\t') >= 1:
        print ("* * * Warning! Your seed contains one or more tabs.")

    if len(seed_input) < 70:
        print ("* * * Warning! Your seed looks too short! * * *")

    return seed_input

# used in search_valid_electrum_seed()
# but it's global, because of the recursion 
my_wordlist = load_words()

def search_valid_electrum_seed(input_seed):
    for my_word in my_wordlist:
        this = input_seed + " " + my_word 
        if is_electrum_segwit_seed(this):
            return(this)

    for my_word1 in my_wordlist:
        for my_word2 in my_wordlist:
            this = input_seed + " " + my_word1 + " " + my_word2
            if is_electrum_segwit_seed(this):
                return(this)

    return("We did not found a valid Electrum segwit seed! This was very unlikely event. Hm...")


def main():

    initial_seed = read_the_seed()

    print("Computing...\n")
    found = search_valid_electrum_seed(initial_seed)
    print (found, "\n")

    if len(found) < 80:
        print ( "* * * Warning! Your seed looks too short! * * *\n"*3)


if __name__ == "__main__":
    main()

