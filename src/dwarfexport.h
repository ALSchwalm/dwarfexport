#ifndef DWARFEXPORT_HPP
#define DWARFEXPORT_HPP

#include <dwarf.h>
#include <hexrays.hpp>
#include <libdwarf/libdwarf.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string.h>
#include <vector>

[[noreturn]] inline void dwarfexport_error_impl(const std::string &s) {
  throw std::runtime_error(s);
}

template <typename Arg, typename... Args>
inline void dwarfexport_error_impl(const std::string &s, Arg arg,
                                   Args... args) {
  std::ostringstream os;
  os << arg;
  dwarfexport_error_impl(s + os.str(), args...);
}

#define dwarfexport_error(...)                                                 \
  dwarfexport_error_impl(__FILE__, ":", __LINE__, " ", __VA_ARGS__)

enum class Mode { BIT32, BIT64 };

/*
  The following classes are used (heavily) modified from 'dwarfgen',
  the original copyright notice below:

  Copyright (C) 2010-2016 David Anderson.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the example nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY David Anderson ''AS IS'' AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL David Anderson BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

class strtabdata {
public:
  strtabdata() : data_(new char[1000]), datalen_(1000), nexttouse_(0) {
    data_[0] = 0;
    nexttouse_ = 1;
  };

  ~strtabdata() { delete[] data_; };

  void loadExistingTable(char *data, int length) {
    auto new_data = new char[length * 2];
    memcpy(new_data, data, length);

    delete[] data_;
    data_ = new_data;
    datalen_ = length * 2;
    nexttouse_ = length;
  }

  unsigned addString(const std::string &newstr) {
    // The 1 is for the terminating null byte.
    unsigned nsz = newstr.size() + 1;
    unsigned needed = nexttouse_ + nsz;
    if (needed >= datalen_) {
      unsigned baseincr = nsz;
      unsigned altincr = datalen_ * 2;
      if (altincr > baseincr) {
        baseincr = altincr;
      }
      unsigned newsize = datalen_ + baseincr;
      char *newdata = new char[newsize];
      memcpy(newdata, data_, nexttouse_);
      delete[] data_;
      data_ = newdata;
      datalen_ = newsize;
    }

    memcpy(data_ + nexttouse_, newstr.c_str(), nsz);
    unsigned newstrindex = nexttouse_;
    nexttouse_ += nsz;
    return newstrindex;
  };
  void *exposedata() { return (void *)data_; };
  unsigned exposelen() const { return nexttouse_; };

private:
  char *data_;

  // datalen_ is the size in bytes pointed to by data_ .
  unsigned datalen_;

  // nexttouse_ is the index of the next (unused) byte in
  // data_ , so it is also the amount of space in data_ that
  // is in use.
  unsigned nexttouse_;
};

//  It's very easy to confuse the symbol number in an elf file
//  with a symbol number in dwarfgen.
//  So this class hold an elf symbol number number
//  and gives those a recognizable type.
class ElfSymIndex {
public:
  ElfSymIndex() : elfsym_(0){};
  ElfSymIndex(unsigned v) : elfsym_(v){};
  unsigned getSymIndex() const { return elfsym_; }
  void setSymIndex(unsigned v) { elfsym_ = v; }

private:
  unsigned elfsym_;
};

class ElfSymbol {
public:
  ElfSymbol(Dwarf_Unsigned val, const std::string &name, unsigned int size,
            strtabdata &stab)
      : symbolValue_(val), name_(name), size_(size) {
    nameIndex_ = stab.addString(name);
  };
  Dwarf_Unsigned getSymbolValue() const { return symbolValue_; }
  unsigned int getNameIndex() const { return nameIndex_; }
  unsigned int getSize() const { return size_; }

private:
  Dwarf_Unsigned symbolValue_;
  std::string name_;
  // The offset in the string table.
  unsigned nameIndex_;
  unsigned size_;
};

class ElfSymbols {
public:
  ElfSymbols() {
    // The initial symbol is 'no symbol'.
    std::string emptyname("");
    syms.push_back(ElfSymbol(0, emptyname, 0, symstrtab));
  }
  ElfSymIndex addSymbol(Dwarf_Unsigned val, const std::string &name,
                        unsigned int size) {
    syms.push_back(ElfSymbol(val, name, size, symstrtab));
    ElfSymIndex indx(syms.size() - 1);
    return indx;
  };
  ElfSymbol &getSymbol(ElfSymIndex symi) {
    size_t i = symi.getSymIndex();
    return syms[i];
  }

  strtabdata symstrtab;
  std::vector<ElfSymbol> syms;
};

struct DwarfGenInfo {
  Elf *elf = nullptr;
  Mode mode = (sizeof(ea_t) == 4) ? (Mode::BIT32) : (Mode::BIT64);
  strtabdata secstrtab;
  ElfSymbols symbols;
  Dwarf_P_Debug dbg;
};

struct Options {
  char filepath[QMAXPATH];
  char filename[QMAXPATH];
  std::string dwarf_source_path = ".";
  unsigned short use_decompiler = false;
  bool attach_debug_info = true;

  std::string c_filename() const { return filename + std::string(".c"); }
  std::string dbg_filename() const { return filename + std::string(".dbg"); }
};

std::shared_ptr<DwarfGenInfo> generate_dwarf_object();
void write_dwarf_file(std::shared_ptr<DwarfGenInfo> info,
                      const Options &options);
int translate_register_num(int ida_reg_num);

#endif
