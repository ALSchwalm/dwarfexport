
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

Options
-------

The following options are available from the plugin GUI

`Use Decompiler`: On architectures where the decompiler is available, opt out of
using it.

`Attach Debug Info`: When checked, a `.dbg` file is created with the debug information.
However, this will only work if the target is an ELF file. When the target is not an ELF
file, uncheck this option to create a group of binary files (one for reach ELF section that
would have been created).

Building On Linux
-----------------

`dwarfexport` depends on the IDA SDK as well as a `libdwarf`. Once you have these
available (a statically compiled copy of `libdwarf` is provided), you can set the
environment variables IDASDK\_PATH and IDA\_PATH to the SDK path and your IDA
folder location respectively. Then build the plugin using `make`.

Building On Windows
-------------------

Windows build can be performed using MSVC Compiler (cl.exe) and NMAKE
(nmake.exe). First, download and extract [libdwarf](
https://sourceforge.net/p/libdwarf/code/ci/master/tree/) source code into
`deps/libdwarf` and [libelf](
https://fossies.org/linux/misc/old/libelf-0.8.13.tar.gz/) source code into
`deps/libelf-0.8.13`. The commands below assume WSL/MinGW/Cygwin, but you can
use any other method that you prefer.

```
$ git clone git://git.code.sf.net/p/libdwarf/code deps/libdwarf
$ (cd deps/libdwarf && git checkout 988618dc8be8)
$ curl https://fossies.org/linux/misc/old/libelf-0.8.13.tar.gz | tar -C deps -xz
```

Then, NMAKE can be invoked through x86 or x64 Native Tools Command Prompt for
VS (depending on whether you need 32-bit or 64-bit plugin) as follows:

```
dwarfexport> nmake /f Makefile.MSVC IDA_PATH="C:\Program Files\IDA 7.2" IDASDK_PATH="C:\Program Files\IDA 7.2\sdk"
```

32-bit version will be placed into `bin\dwarfexport.dll`, 64-bit version will
be placed into `bin\dwarfexport64.dll`.


Building on macOS
-----------------

To build dwarfexport on macOS, you must build and install 32-bit versions of
libelf and libdwarf.

```
# Download, build, and install libelf (it's a libdwarf prereq)
$ mkdir -p thirdparty
$ pushd thirdparty
$ wget http://www.mr511.de/software/libelf-0.8.13.tar.gz
$ tar zxf libelf-0.8.13.tar.gz
$ pushd libelf-0.8.13
$ CFLAGS=-m32 CXXFLAGS=-m32 ./configure
$ make && make install
$ popd

# Clone, build, and install libdwarf
$ git clone git@github.com:tomhughes/libdwarf.git
$ pushd libdwarf/
$ CFLAGS=-m32 CXXFLAGS=-m32 ./configure
$ make && make install
$ popd
$ popd

# Build dwarfexport for macos
$ IDA_PATH="/Applications/IDA\ Pro\ 6.95/idaq.app/Contents/MacOS/" IDASDK_PATH="<PATH TO IDASDK>" make -f Makefile.osx
```

Adding Support for Other Architectures
--------------------------------------

There are three functions that need to be modified to add support for a new
architectures. They are all located in `platform.cpp`:

`translate_register_num`: Translates from IDA register numbers to DWARF numbers.
The IDA register numbering can be found by running `idaapi.ph_get_regnames()`.
The index of a register in the returned list is its 'IDA register number'. A variety
of resources exist to find the DWARF mapping for a given architecture. For example,
[wine](https://source.winehq.org/source/dlls/dbghelp/cpu_x86_64.c) has the numbers
for some architectures (see `x86_64_map_dwarf_register`).

`disassembler_lvar_reg_and_offset`: This function should set the `reg` and `offset`
parameters to a dwarf register and the offset from that register that should be
used to read from a stack variable 'member'. So `reg` will typically be a register
containing a pointer to the top or bottom of the stack (so `DW_OP_breg5` is register 5
which is EBP on x86), and the offset will then be the offset from the bottom or top
of the stack.

`decompiler_lvar_reg_and_offset`: On architectures supporting the decompiler, this
function should be modified to perform the same work as the above function, but with
a `lvar_t` from the Hexrays decompiler. Note that it may be acceptable to reuse the
disassembler logic.

License
-------

`dwarfexport` is licensed under the terms of the LGPLv2.1. See the LICENSE file for
details.
