#ifndef DWARFEXPORT_HPP
#define DWARFEXPORT_HPP

#include <dwarf.h>
#include <hexrays.hpp>
#include <libdwarf/libdwarf.h>
#include <memory>
#include <stdexcept>
#include <string.h> // For memset etc
#include <vector>

[[noreturn]] inline void dwarfexport_error(const std::string &s) {
  throw std::runtime_error(s);
}

template <typename... Args>
inline void dwarfexport_error(const std::string &s, const std::string &arg,
                              Args... args) {
  dwarfexport_error(s + arg, args...);
}

enum class Mode { BIT32, BIT64 };

// from strtabdata.h
// Creates a string table in a way consistent with
// elf string tables. The zero index is a null byte always.
class strtabdata {
public:
  strtabdata() : data_(new char[1000]), datalen_(1000), nexttouse_(0) {
    data_[0] = 0;
    nexttouse_ = 1;
  };
  ~strtabdata() { delete[] data_; };
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

std::shared_ptr<DwarfGenInfo> generate_dwarf_object();
void write_dwarf_file(std::shared_ptr<DwarfGenInfo> info,
                      const std::string &filename);
int translate_register_num(int ida_reg_num);

#endif
