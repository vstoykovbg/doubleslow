# Doubleslow Keystretcher
## Key stretching on an air-gapped computer with additional "external key stretching" on another computer

The key stretching with the "seed extension" (also known as "extension word" and "passphrase") in the [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) is very weak (PBKDF2 using 2048 iterations of HMAC-SHA512), this is why I wrote these scripts.

These scripts utilize mnemonic code (RFC1751, BIP39) and checksums to prevent i/o human errors. 

The key stretching in `Doubleslow` scripts is done with a modern CPU and memory intensive key derivation functions (Argon2, Scrypt).

Doubleslow is included in the [Cryptopup live distro](https://github.com/vstoykovbg/cryptopup).

For ideas how to use Doubleslow securely: [How Jason Bourne Stores His Bitcoin in 2021](https://github.com/vstoykovbg/jb)

The user enters the settings interactively in the first script (`doubleslow-base.py`), the settings for the next stage are encoded inside a mnemonic code (protected with checksums).

The double-stage process is used to ensure that in case the second computer is compromised the key will be protected against dictionary brute-force attacks by the key stretching done on the first (air-gapped) computer. It's not practical to use as an air-gapped computer too powerful computer, because most of the time the air-gapped computer will be doing nothing (assuming it will be never connected to the Internet or other computers). For example, you can use your old Raspberry Pi or your old desktop computer (with stripped out unnecessary parts) for the first stage (`doubleslow-base.py`).

Optionally, the second stage key stretching can be disabled by entering 0 as number of iterations on the second stage or with a command line parameter "one".

Some enthusiasts can even implement additional ("stage zero") key stretching (with some low-RAM intensive key stretching functions, on very old computers or microcontrollers). It's more difficult to hide malware inside ancient computers or simple microcontrollers.

Don't forget to make your own backup of the scripts before using them. And write down which versions of the scripts were used along with your salt and settings (number of iterations, RAM usage). Future versions may not be compatible! I made some UX improvements and changed how the salt is interpreted (in some cases whitespaces are ignored and the salt is interpreted differently - not as a UTF-8 string).

The salt used by the `doubleslow-base.py` can be in different formats:

* RFC1751 mnemonic
* BIP39 mnemonic
* Decimal (big decimal integer)
* Base58 with a checksum
* Hexadecimal
* Base64
* Unicode string (normalized with NFKC by the script)

This might be confusing: the seed generated by the `make-seed-simple.py` is called "salt" in the context of `doubleslow-base.py`.

I moved the more sophisticated scripts for generating seeds and lists of random words from dictionaries to another repository: [Doublerandom](https://github.com/vstoykovbg/doublerandom) (they use randomness from the sound input, from the `haveged`, from the mouse movements).

Since it is possible to use any Unicode string as a salt it is possible to achieve some obscurity and plausible deniability (i.e. "this is just my shopping list", "this is just my postmodern poem"). If you want to achieve even more obscurity you can run the script several times (by using the first output as input for the next iteration) with different passphrases. Also, you can make some changes to the script and remember them (what could go wrong?).

The password is normalized with NFKC.

:warning: Security warning: since the keys are displayed they might be compromised, because in some consoles the history is being recorded on the hard drive. Also, there might be a camera or device receiving the radiation emitted from the monitor. It's recommended to use this script only on air-gapped computers without a hard drive (the OS is run from optical discs). You may also consider modifying the script not to show the keys on the screen.

:warning: DANGER of catastrophic data loss! One bit flip (due to cosmic rays for example) can make the result of the hash functions completely different. Run the scripts several times to confirm that they produce the same output given the same input. Read how these scripts work and why the risk of bit flip is high (hint: RAM usage).</p>

In reality you never know if you have a malware stealing your secrets installed inside your CPU (on the OS running inside your CPU, not accessible to the main OS), hard drive's firmware, optical drive's firmware, UEFI/BIOS, etc. (they all have access to the RAM!).

By using an air-gapped computer, you make sure that the hypothetical malware does not have a chance to transmit the stolen secrets through the Internet.

The script is more a proof of concept, but maybe you can use it in production if you take some precautions:

- Use an air-gapped computer to run the `doubleslow-base.py` script.
- Never attach the air-gapped computer to the Internet after you use it for key stretching.
- Make sure nobody watches your monitor (visually or through the electromagnetic radiation emitted by the monitor).
- Remove the hard drive of the air-gapped computer before using it for key stretching for the first time.
- Remove other unnecessary components of the air-gapped computer before using it for key stretching for the first time: video controllers (use the integrated one in the motherboard), network adapters, disk controllers, etc.
- Never connect the air-gapped computer to other devices you may want to use with other computers in the future. All devices once connected to the air-gapped computer should be considered infected with malware and containing all your secrets.
- Run the OS from a read only optical disk and make sure that there is no way for a hypothetical malware to write to the optical disk (i.e. use read-only optical drive, do not insert the optical disk into other computer after it's being used). Are you sure that the optical drive is read only? What is under that sticker... 
- Make sure to not insert the optical disk on other computer (just in case there is a malware writing secrets on the optical disk - this theoretically can be done in a way not visible by any standard OS, outside of the filesystem).
- Do not use USB devices on the air-gapped computer. Because you may forget and insert the same device to another computer.
- Do not use even USB keyboard or USB mouse. You may forget and attach the keyboard/mouse to an online computer and... it's gone.
- Read how malware can transmit information from air-gapped computers and take necessary precautions (i.e. flashing status LEDs of the hard drive, emitting sound or ultrasound, modulating the USB signals to make a transmitter).
- Do not use machine readable mediums (USB flash drives, optical disks) to copy data from/to the air-gapped computer.
- Once an optical disk is used to boot your air-gapped computer, don't insert the same optical disk into other computer's optical drive (you don't know for sure that there is no malware in your air-gapped computer, writing your secrets on the optical disk somewhat outside of the standard file system).
- For moving cryptographic signatures and public keys script like [RFC1751-encoding-decoding](https://github.com/vstoykovbg/RFC1751-encoding-decoding) can be used.
- Using QR codes (instead of the above mentioned method) can be dangerous because the hypothetical malware can display secrets on the monitor in a way humans can't see the transmission (by some fast and subtle amplitude modulation of the pixel's colour and brightness).

Ideally, the output from the script should be imported to your program directly, without copy/pasting visible text from the console (without showing the secrets on the screen). For example, the script can be modified to create Electrum wallet file (and this way not displaying secrets on the monitor).

## Example

For this input:

<blockquote>
BIP39 salt:
  
```together device asthma air nasty around notable invite team during health judge enemy clay possible across another pilot able file amazing edge forest virus``` 

Number of iterations: `4`

Number of iterations on the second stage (external key stretching): `5`

Memory (for the first stage): `64 MiB`

Memory (for the second stage): `1 GiB`

Password: `correct horse battery staple`
</blockquote>

You should get this output with version `v0.0.1`:

<blockquote>BIP39 output:
  
 ```dose engage you plate shift advice feel fish bamboo icon mammal fashion school almost inmate village trap error defy gold ball manual guilt icon```</blockquote>

With version `v0.0.2` the output is:

<blockquote>BIP39 output:
  
 ```prepare embrace goat floor lounge eight evil churn entire vintage logic state obey refuse embark saddle potato clap release rapid tackle aunt kit cable```</blockquote>

## Creating a valid Electrum segwit seed

You can make a valid Electrum segwit seed with the script `make-valid-electrum-segwit-seed.py`. The input string can contain arbitrary words. Also, you can change the dictionary `electrum_words.txt` and the checksum will still work (it's not dependent on a dictionary like the BIP39 wordlist).

Example:

```
$ ./make-valid-electrum-segwit-seed.py 
Please enter the seed to be amended: prepare embrace goat floor lounge eight evil churn entire vintage logic state
Normalizing the input string with NFKD...
The seed has not been changed by the NFKD normalization.
The NFKC version is the same as NFKD.
Computing...

prepare embrace goat floor lounge eight evil churn entire vintage logic state abandon skull 

```

Another example with arbitrary words (not from the BIP39 standard):

```
$ ./make-valid-electrum-segwit-seed.py 
Please enter the seed to be amended: стринг на кирилица юыэ тест Ὕπνος Ἡμέρα Γαῖα Ἔρως hehehe 🐈 hmmm it works even with a cat
Normalizing the input string with NFKD...
The seed has not been changed by the NFKD normalization.
* * * Warning! The NFKC version is DIFFERENT than the NFKD version.
Computing...

стринг на кирилица юыэ тест Ὕπνος Ἡμέρα Γαῖα Ἔρως hehehe 🐈 hmmm it works even with a cat candy 

```

It works perfectly even with a cat in the seed.

![Cat in the segwit seed](https://i.imgur.com/BoSEgxO.png)

![Electrum works even with a cat in the seed](https://i.imgur.com/3tGwnsQ.png)


## Dependencies

You may need to install these Python 3 modules (if they are not already installed):

```
$ pip3 install -r requirements.txt
```

## Bug: `AttributeError: module 'bitcoin' has no attribute 'encode_privkey'`

I got this error message:

```
Traceback (most recent call last):
  File "./doubleslow-base.py", line 136, in <module>
    print_the_secrets(digest256_final)
  File "/home/valentin/python/doubleslow/doubleslow_module.py", line 301, in print_the_secrets
    my_256_bit_secret_WIF = bitcoin.encode_privkey(my_256_bit_secret_HEX,"wif_compressed")
AttributeError: module 'bitcoin' has no attribute 'encode_privkey'
valentin@computer:~/python/doubleslow$ 
```

The solution was to install the module `bitcoin` again:

```
$ pip3 install --user bitcoin
Collecting bitcoin
Installing collected packages: bitcoin
Successfully installed bitcoin-1.1.42
```

I don't know why this worked.

[Topic about this on StackExchange](https://bitcoin.stackexchange.com/questions/106312/python-code-import-error-cannot-import-name-privtopub-from-bitcoin) - I was not the first to encounter this bug.

For ideas how to use Doubleslow securely: [How Jason Bourne Stores His Bitcoin in 2021](https://github.com/vstoykovbg/jb)

## Video demonstration

[![Video demo](http://img.youtube.com/vi/O-MAZZgX868/0.jpg)](http://www.youtube.com/watch?v=O-MAZZgX868)

## Backup

- BitTorrent: magnet:?xt=urn:btih:c244989104b60e10a7cfa04d01a377e9a9cf4317&dn=doubleslow-backup
- IPFS: Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F
- IPFS gateways: [local](http://localhost:8080/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F), [1](https://gateway.pinata.cloud/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F), [2](https://ninetailed.ninja/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F), [3](https://cloudflare-ipfs.com/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F), [4](https://ipfs.io/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F), [5](https://dweb.link/ipfs/Qmcs9gTBQGCbuao9FuqN3seEEPvpw6vQM9GGmjMPbBiG2F)
- [doubleslow.wordpress.com](https://doubleslow.wordpress.com/)
- [Google Drive](https://drive.google.com/drive/folders/1WM31SRsOq7tjjcOzl_I7n3244BXT-Co5?usp=sharing)

## Discussion

* [Discuission on /r/crypto](https://old.reddit.com/r/crypto/comments/ijln29/i_made_a_key_stretching_script_what_could_go/)

