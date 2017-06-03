
dwarfexport
===========

`dwarfexport` is an IDA Pro plugin that allows the user to export `dwarf` debug
information. This can then be imported in to gdb and other tools, allowing
you to debug using info you have recovered in IDA even when you cannot connect
the IDA debugger.

Usage
-----

Pre-compiled copies of `dwarfexport` are available in the `bin` folder of this
project. Just add these files to your IDA `plugins` folder (plx and plx64 for linux,
plw and p64 for windows) and you will have a new option
"Edit->Plugins->Export Dwarf Debug Info". Click this and select a folder for the
output.

The plugin will generate two files in the output directory. One will be a `.c` file
with the decompiled functions from the Hexrays decompiler. The other is a `.dbg`
file that contains the debug information. *Note that because the plugin performs
decompilation on every function in the binary, it can take a while to run.*

Move these to the device you want to debug on and load gdb (e.x, `gdb a.out`).
You will have full debug information, like normal gdb with source (shown below
using TUI mode):

![debugging in gdb](/resources/screenshot.png)

*Note: You may need to run `list` to get the source file loaded.*

Building On Linux
-----------------

`dwarfexport` depends on the IDA SDK as well as a `libdwarf`. Once you have these
available (a statically compiled copy of `libdwarf` is provided), you can set the
environment variables IDASDK\_PATH and IDA\_PATH to the SDK path and your IDA
folder location respectively. Then build the plugin using `make`.

Building On Windows
-------------------

No instructions are currently provided. I'm using a series of hacks that I will
clean up and document at some point.

License
-------

`dwarfexport` is licensed under the terms of the LGPLv2.1. See the LICENSE file for
details.
