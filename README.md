# Doubleslow Keystretcher
## Key stretching on air-gapped computer with additional "external key stretching" on another computer

The script utilizes mnemonic code (RFC1751, BIP39) and checksums to prevent i/o human errors. 

It is based on modern CPU and memory intensive key derivation functions (Argon2, Scrypt).

The user enters the settings interactively in the first script (`doubleslow-base.py`), the settings for the next stage are encoded inside a mnemonic code (protected with checksums).

The double-stage process is used to ensure that in case the second computer is compromised the key will be protected against dictionary brute-force attacks by the key stretching done on the first (air-gapped) computer. It's not practical to use as an air-gapped computer too powerful computer, because most of the time the air-gapped computer will be doing nothing (assuming it will be never connected to the Internet or other computers). For example, you can use your old Raspberry Pi or your old desktop computer (with stripped out unnecessary parts) for the first stage (`doubleslow-base.py`).

Some enthusiasts can even implement additional ("stage zero") key stretching (with some low-RAM intensive key stretching functions, on very old computers or microcontrollers). It's more difficult to hide malware inside ancient computers or simple microcontrollers.

Don't forget to make a backup of the script, along with your salt and settings (number of iterations, RAM usage). Future versions may not be compatible!

The salt used by the `doubleslow-base.py` can be in different formats:

* RFC1751 mnemonic
* BIP39 mnemonic
* Decimal (big decimal integer)
* Base58 with a checksum
* Hexadecimal
* Base64
* Unicode string (normalized with NFKC by the script)

This might be confusing: the seed generated by the `make-seed.py` is called "salt" in the context of `doubleslow-base.py`.

Since it is possible to use any Unicode string as a salt it is possible to achieve some obscurity and plausible deniability (i.e. "this is just my shopping list", "this is just my postmodern poem"). If you want to achieve even more obscurity you can run the script several times (by using the first output as input for the next iteration) with different passphrases. Also, you can make some changes to the script and remember them (what could go wrong?).

The password is normalized with NFKC by the script.

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

## Randomness from the mouse

The script `mouse-seed-generator.py` uses the mouse movements as a source of randomnes to produce a BIP39 mnemonic. It needs [X](https://en.wikipedia.org/wiki/X_Window_System) to be running.

## Randomness from the sound input

The script `doublerandom-seed-generator.py` creates a BIP39 mnemonic by collecting randomness from the sound input and the `haveged`. Make sure you have `arecord` and `haveged` installed on your system. The script also uses random data entered by the user via the keyboard.

There is usually noise at the microphone input even if there is no microphone attached. In this case you need to increase the microphone input's volume to the max. Don't forget to check if the microphone input is muted (it must not be muted).

Of course, it works better with a microphone or a [noise generator](https://www.google.com/search?q=simple+noise+generator+circuit) attached to the microphone input.

You need to boost the volume if the signal from the microphone is weak. You can check the signal level with apps like `pavucontrol` and `audacity`.

You can use these commands to boost the microphone input's volume:

```
$ amixer sset 'Mic Boost' 100%
$ amixer sset 'Mic' 100%
```

## Randomness mixer: randomness from the sound input and the mouse

The script `randomness_mixer.py` creates a BIP39 mnemonic by collecting randomness from the mouse, the sound input and the `haveged`. Make sure you have `arecord` and `haveged` installed on your system. The script also uses random data entered by the user via the keyboard.

In case the script is started without [X](https://en.wikipedia.org/wiki/X_Window_System) (in the virtual terminal) it will read the mouse movements directly from the `/dev/input/mice`. However, it needs to be started as *root* to do this (only the *root* have permission to access `/dev/input/mice`).

The program `arecord` will not work in virtual terminal if the script is started as *root* and the [X](https://en.wikipedia.org/wiki/X_Window_System) is running. But this problem can be avoided simply by running the script in the graphical environment (terminal emulator like `xterm`, `gnome-terminal`) or shutting down the [X](https://en.wikipedia.org/wiki/X_Window_System).

## Random choice

The script `randomness_choice.py` creates random numbers in a range. It uses randomness from the sound input (`arecord`), `haveged`, random data entered by the user via the keyboard, and from the mouse movements. If called with `nomouse` parameter it does not use the mouse as a randomness source.

## Dependencies

You may need to install these Python 3 modules (if they are not already installed):

```
$ pip3 install -r requirements.txt
```

To install `arecord` and `haveged`:

```
$ sudo apt-get install alsa-utils haveged
```


## Video demonstration

[![Video demo](http://img.youtube.com/vi/O-MAZZgX868/0.jpg)](http://www.youtube.com/watch?v=O-MAZZgX868)

## Discussion

* [Discuission on /r/crypto](https://old.reddit.com/r/crypto/comments/ijln29/i_made_a_key_stretching_script_what_could_go/)

