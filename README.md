
dwarfexport
===========

`dwarfexport` is an IDA Pro plugin that allows the user to export `dwarf` debug
information. This can then be imported in to gdb and other tools, allowing
you to debug using info you have recovered in IDA even when you cannot connect
the IDA debugger.

Usage
-----

`dwarfexport` is distributed as a `plx` and `plx64` file. Just add these files to
your IDA `plugins` folder and you will have a new option 
"Edit->Plugins->Export Dwarf Debug Info". Click this and select a folder for the
output.

The plugin will generate two files in the output directory. One will be a `.c` file
with the decompiled functions from the Hexrays decompiler. The other is a `.elf`
file that contains the debug information.

Move these to the device you want to debug on and load gdb (e.x, `gdb a.out`),
then from gdb, run:

    (gdb) symbol-file a.out.elf


Building
--------

`dwarfexport` depends on the IDA SDK as well as a `libdwarf`. Once you have these
available (a statically compiled copy of `libdwarf` is provided), you can set the
environment variables IDASDK\_PATH and IDA\_PATH to the SDK path and your IDA
folder location respectively. Then build the plugin using `make`.

License
-------

`dwarfexport` is licensed under the terms of the LGPLv3. See the LICENSE file for
details.
