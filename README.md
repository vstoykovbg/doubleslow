# Doubleslow Keystretcher
## Key stretching on air-gapped computer with additional "external key stretching" on another computer

The script utilizes mnemonic code (RFC1751) and checksums to prevent i/o human errors. The user is entering the settings on the first script (`doubleslow-base.py`), the settings for the next stage are encoded inside the mnemonic code (protected with checksums).

The double-stage process is used to ensure that in case the second computer is compromised the key will be protected against dictionary brute-force attacks by the key stretching done on the first (air-gapped) computer. It's not practical to use as an air-gapped computer too powerful computer, because most of the time the air-gapped computer will do nothing. For example, you can use your old Raspberry Pi or your old desktop computer (with stripped out unnecessary parts) for the first stage of key stretching.

Some enthusiasts can even implement additional ("zero") stage key of stretching (with some low-RAM intensive key stretching functions, on very old computers or microcontrollers). It's very difficult to hide malware inside ancient computers or simple microcontrollers.

For the "zero" stage a simple (or "scientific") calculator can be used (you need to remember or write down the algorithm).

Don't forget to make a backup of the script, along with your salt and settings (number of iterations, RAM usage). Future versions may not be compatible!

The salt used by the `doubleslow-base.py` can be in different formats:

* RFC1751 mnemonic
* BIP39 mnemonic
* Decimal (big decimal integer)
* Base58 with a checksum
* Hexadecimal
* Base64
* Unicode string (normalized with NFKC by the script)

This might be confusing: the seed generated by the make-seed.py is called "salt" in the context of `doubleslow-base.py`.

Since it is possible to use any Unicode string as a salt it is possible to achieve some obscurity and plausible deniability (i.e. "this is just my shopping list", "this is just my postmodern poem"). If you want to achieve even more obscurity you can run the script several times (by using the first output as input for the next iteration) with different passphrases. Also, you can make some changes to the script and remember them (what could go wrong?).

The password is normalized with NFKC by the script.

```html
<div style="border: 1px black dotted; padding: 10px; background-color: #ffffcc">
<p>:warning: Security warning: since the keys are displayed they might be compromised, because in some consoles the history is being recorded on the hard drive. Also, there might be a camera or device receiving the radiation emitted from the monitor. It's recommended to use this script only on air-gapped computers without a hard drive (OS is run from optical discs). You may also consider modifying the script not to show the keys on the screen.</p>
</div>

<div style="border: 1px black dotted; padding: 10px; background-color: #ffffcc">
<p>:warning: DANGER of catastrophic data loss! One bit flip (due to cosmic rays for example) can make the result of the hash functions completely different. Run the scripts several times to confirm that they produce the same output given the same input. Read how these scripts work and why the risk of bit flip is high (hint: RAM usage).</p>
</div>
```

In reality you never know if you have a malware stealing your secrets installed inside your CPU (on the OS running inside your CPU, not accessible to the main OS), hard drive's firmware, optical drive's firmware, UEFI/BIOS, etc. (they all have access to the RAM!).

By using air-gapped computer you make sure that the hypothetical malware does not have a chance to transmit the stolen secrets through the Internet.

The script is more a proof of concept, but maybe you can use it in production if you take some precautions:

- Make sure nobody watches your monitor (visually or through the electromagnetic ratiation emitted by the monitor).
- Use an air-gapped computer to run the `doubleslow-base.py` script.
- Remove the hard drive of the air-gapped computer and never connect it to other devices.
- Run the OS from a read only optical disk and make sure that there is no way for a hypothetical malware to write to the optical disk.
- Make sure to not insert the optical disk on other computer (just in case there is a malware writing secrets on your air-gapped computer).
- Do not use USB devices on the air-gapped computer. Because you may forget and insert the same device to another computer.
- Do not use even USB keyboard or USB mouse. You may forget and attach the keyboard/mouse to an online computer and... it's gone.
- Read how malware can transmit information from air-gapped computers and take necessary precautions (i.e. flashing status LEDs of the hard drive, emitting sound or ultrasound, modulating the USB signals to make a transmitter).

Ideally, the output from the script should be imported to your program directly, without copy/pasting visible text from the console (without showing the secrets on the screen).
