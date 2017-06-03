#ifndef DWARFEXPORT_HPP
#define DWARFEXPORT_HPP

#include <dwarf.h>
#include <hexrays.hpp>
#include <libdwarf/libdwarf.h>
#include <memory>
#include <sstream>
#include <stdexcept>

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

struct DwarfGenInfo {
  Elf *elf = nullptr;
  Mode mode = (sizeof(ea_t) == 4) ? (Mode::BIT32) : (Mode::BIT64);
  Dwarf_P_Debug dbg;
  Dwarf_Error err = 0;
};

struct Options {
  char filepath[QMAXPATH];
  char filename[QMAXPATH];
  std::string dwarf_source_path;
  unsigned short export_options;

  bool use_decompiler() const { return export_options & 0x0001; }
  bool attach_debug_info() const { return export_options & 0x0002; }

  std::string c_filename() const { return filename + std::string(".c"); }
  std::string dbg_filename() const { return filename + std::string(".dbg"); }

  Options(std::string _source_path, bool _use_decompiler,
          bool _attach_debug_info)
      : dwarf_source_path{_source_path}, export_options{
                                             _use_decompiler |
                                             (_attach_debug_info << 1)} {}
};

std::shared_ptr<DwarfGenInfo> generate_dwarf_object(const Options &options);
void write_dwarf_file(std::shared_ptr<DwarfGenInfo> info,
                      const Options &options);
int translate_register_num(int ida_reg_num);

#ifdef __NT__
#define PATH_SEP '\\'
#else
#define PATH_SEP '/'
#endif

/*
  The following strtabdata class is used (heavily) modified from 'dwarfgen',
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

#endif
