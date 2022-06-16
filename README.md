# TDU Mod Tools

A collection of Python tools for the PS2/PSP versions of Test Drive Unlimited.

## MHPF Tool
An unpacker/repacker for the Melbourne House Pack File (`.PCK`) format. Inspired by the groundwork laid out in [mhpf-tools](https://github.com/christorrella/mhpf-tools).

### Usage
* `mhpf.py unpack PCK [-o/--output OUTPUT_DIR]` \
  Unpacks a specified `.PCK` file to the directory specified by `-o/--output`.
* `mhpf.py pack DIR [-o/--output OUTPUT_DIR] [-hp/--hash-prime PRIME] [-be/--big-endian]` \
  Repacks a specified directory into a `.PCK` file specified by `-o/--output`, or into `[DIR_NAME].PCK` otherwise.
  * `-hp/--hash-prime [PRIME]` - specify a custom prime number for the internal string hash (default 31). You shouldn't need this.
  * `-be/--big-endian` - build a big endian archive instead of a default little endian. No games are known to use BE archives,
    but TDU checks (and rejects) those, so they technically exist.
* `mhpf.py scan PCK [-l/--list]` \
  Lists the attributes of a specified MHPF file.
  * `-l/--list` - also list the archive contents on top of listing attributes.

### To-do
* Strict mode for an unpacker, validating all header fields, even those unused by the game.
* An option to generate an XML schema when unpacking files, for use with the packer to retain an original file order.

## Credits
* [Christopher Torrella](https://github.com/christorrella) - original mhpf-tools and MHPF research
* [Nenkai](https://github.com/Nenkai) - MHPF research
