#ifndef DWARFEXPORT_HPP
#define DWARFEXPORT_HPP

#include <stdexcept>
#include <dwarf.h>
#include <libdwarf/libdwarf.h>

[[noreturn]] inline void dwarfexport_error(const std::string& s) {
  throw std::runtime_error(s);
}

template<typename... Args>
inline void dwarfexport_error(const std::string& s,
                              const std::string& arg,
                              Args... args) {
  dwarfexport_error(s+arg, args...);
}

Dwarf_P_Debug generate_dwarf_object();
void write_dwarf_file(Dwarf_P_Debug dbg, const std::string& filename);

#endif
