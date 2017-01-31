#ifndef DWARFEXPORT_HPP
#define DWARFEXPORT_HPP

#include <stdexcept>
#include <dwarf.h>
#include <libdwarf/libdwarf.h>
#include <memory>
#include <string.h> // For memset etc

[[noreturn]] inline void dwarfexport_error(const std::string& s) {
  throw std::runtime_error(s);
}

template<typename... Args>
inline void dwarfexport_error(const std::string& s,
                              const std::string& arg,
                              Args... args) {
  dwarfexport_error(s+arg, args...);
}

enum class Mode {
  BIT32,
  BIT64
};

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


struct DwarfGenInfo {
  Elf *elf = 0;
  strtabdata secstrtab;
  Dwarf_P_Debug dbg;
};

std::shared_ptr<DwarfGenInfo> generate_dwarf_object(Mode m);
void write_dwarf_file(Mode m, std::shared_ptr<DwarfGenInfo> info,
                      const std::string &filename);

#endif
