/*
  This file is used (heavily) modified from the dwarfgen utility. See
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

/* Windows specific header files */
#ifdef HAVE_STDAFX_H
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */

#include "gelf.h"
#include <fcntl.h> //open
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <stdlib.h> // for exit
#include <string.h> // For memset etc
#include <string>
#include <sys/stat.h> //open
#include <unistd.h>
#include <vector>

#include "dwarfexport.h"

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

static void write_object_file(Dwarf_P_Debug dbg, const std::string& filename);
static void write_generated_dbg(Dwarf_P_Debug dbg, Elf *elf);

/*  Use a generic call to open the file, due to issues with Windows */
int open_a_file(const char *name);
int create_a_file(const char *name);
void close_a_file(int f);

static Elf *elf = 0;
static Elf32_Ehdr *ehp = 0;
static strtabdata secstrtab;

//  It's very easy to confuse the section number in an elf file
//  with an array index in dwarfgen.
//  So this class hold an elf section number
//  and gives those a recognizable type.
class ElfSectIndex {
public:
  ElfSectIndex() : elfsect_(0){};
  ~ElfSectIndex(){};
  ElfSectIndex(unsigned v) : elfsect_(v){};
  unsigned getSectIndex() const { return elfsect_; }
  void setSectIndex(unsigned v) { elfsect_ = v; }

private:
  unsigned elfsect_;
};

//  It's very easy to confuse the symbol number in an elf file
//  with a symbol number in dwarfgen.
//  So this class hold an elf symbol number number
//  and gives those a recognizable type.
class ElfSymIndex {
public:
  ElfSymIndex() : elfsym_(0){};
  ~ElfSymIndex(){};
  ElfSymIndex(unsigned v) : elfsym_(v){};
  unsigned getSymIndex() const { return elfsym_; }
  void setSymIndex(unsigned v) { elfsym_ = v; }

private:
  unsigned elfsym_;
};

/*  See the Elf ABI for further definitions of these fields. */
class SectionFromDwarf {
public:
  std::string name_;
  Dwarf_Unsigned section_name_itself_;
  ElfSymIndex section_name_symidx_;
  int size_;
  Dwarf_Unsigned type_;
  Dwarf_Unsigned flags_;

  /*  type: SHT_REL, RELA: Section header index of the section
      relocation applies to.
      SHT_SYMTAB: Section header index of the associated string table. */
  Dwarf_Unsigned link_;

  /*  type: SHT_REL, RELA: Section header index of the section
      relocation applies to.
      SHT_SYMTAB: One greater than index of the last local symbol.. */
  Dwarf_Unsigned info_;

private:
  ElfSectIndex elf_sect_index_;
  Dwarf_Unsigned lengthWrittenToElf_;

public:
  Dwarf_Unsigned getNextOffset() { return lengthWrittenToElf_; }
  void setNextOffset(Dwarf_Unsigned v) { lengthWrittenToElf_ = v; }

  unsigned getSectionNameSymidx() {
    return section_name_symidx_.getSymIndex();
  };
  SectionFromDwarf()
      : section_name_itself_(0), section_name_symidx_(0), size_(0), type_(0),
        flags_(0), link_(0), info_(0), elf_sect_index_(0),
        lengthWrittenToElf_(0){};
  ~SectionFromDwarf(){};
  void setSectIndex(ElfSectIndex v) { elf_sect_index_ = v; }
  ElfSectIndex getSectIndex() const { return elf_sect_index_; }
  SectionFromDwarf(const std::string &name, int size, Dwarf_Unsigned type,
                   Dwarf_Unsigned flags, Dwarf_Unsigned link,
                   Dwarf_Unsigned info)
      : name_(name), size_(size), type_(type), flags_(flags), link_(link),
        info_(info), elf_sect_index_(0), lengthWrittenToElf_(0) {
    // Now create section name string section.
    section_name_itself_ = secstrtab.addString(name.c_str());
  };
};

std::vector<SectionFromDwarf> dwsectab;

static ElfSectIndex create_dw_elf(SectionFromDwarf &ds);

static SectionFromDwarf &FindMySection(const ElfSectIndex &elf_section_index) {
  for (unsigned i = 0; i < dwsectab.size(); ++i) {
    if (elf_section_index.getSectIndex() !=
        dwsectab[i].getSectIndex().getSectIndex()) {
      continue;
    }
    return dwsectab[i];
  }

  dwarfexport_error("dwarfgen: Unable to find my dw sec data for elf section");
}

static unsigned createnamestr(unsigned strtabstroff) {
  Elf_Scn *strscn = elf_newscn(elf);
  if (!strscn) {
    dwarfexport_error("dwarfgen: Unable to elf_newscn()");
  }
  Elf_Data *shstr = elf_newdata(strscn);
  if (!shstr) {
    dwarfexport_error("dwarfgen: Unable to elf_newdata()");
  }

  shstr->d_buf = secstrtab.exposedata();
  shstr->d_type = ELF_T_BYTE;
  shstr->d_size = secstrtab.exposelen();
  shstr->d_off = 0;
  shstr->d_align = 1;
  shstr->d_version = EV_CURRENT;

  Elf32_Shdr *strshdr = elf32_getshdr(strscn);
  if (!strshdr) {
    dwarfexport_error("dwarfgen: Unable to elf_getshdr()");
  }
  strshdr->sh_name = strtabstroff;
  strshdr->sh_type = SHT_STRTAB;
  strshdr->sh_flags = SHF_STRINGS;
  strshdr->sh_addr = 0;
  strshdr->sh_offset = 0;
  strshdr->sh_size = 0;
  strshdr->sh_link = 0;
  strshdr->sh_info = 0;
  strshdr->sh_addralign = 1;
  strshdr->sh_entsize = 0;
  return elf_ndxscn(strscn);
}

// This functional interface is defined by libdwarf.
// Please see the comments in libdwarf2p.1.pdf
// (libdwarf2p.1.mm)  on this callback interface.
// Returns (to libdwarf) an Elf section number, so
// since 0 is always empty and dwarfgen sets 1 to be a fake
// text section on the first call this returns 2, second 3, etc.
int CallbackFunc(const char *name, int size, Dwarf_Unsigned type,
                 Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
                 Dwarf_Unsigned *sect_name_symbol_index, void *,
                 int *) {
  SectionFromDwarf ds(name, size, type, flags, link, info);

  // It is up to you to provide (to libdwarf,
  // to generate relocation records)
  // a symbol index for the section.
  // In Elf, each section gets an elf symbol table entry.
  // So that relocations have an address to refer to.
  // You will create the Elf symbol table, so you have to tell
  // libdwarf the index to put into relocation records for the
  // section newly defined here.
  *sect_name_symbol_index = ds.getSectionNameSymidx();
  ElfSectIndex createdsec = create_dw_elf(ds);

  // Do all the data creation before pushing
  // (copying) ds onto dwsectab!
  dwsectab.push_back(ds);
  // The number returned is elf section, not dwsectab[] index
  return createdsec.getSectIndex();
}

// Here we create a new Elf section
// This never happens for relocations in dwarfgen,
// only a few sections are created by dwarfgen.
static ElfSectIndex create_dw_elf(SectionFromDwarf &ds) {
  Elf_Scn *scn = elf_newscn(elf);
  if (!scn) {
    dwarfexport_error("dwarfgen: Unable to elf_newscn() on ", ds.name_);
  }
  Elf32_Shdr *shdr = elf32_getshdr(scn);
  if (!shdr) {
    dwarfexport_error("dwarfgen: Unable to elf_getshdr() on ", ds.name_);
  }
  shdr->sh_name = ds.section_name_itself_;
  shdr->sh_type = ds.type_;
  shdr->sh_flags = ds.flags_;
  shdr->sh_addr = 0;
  shdr->sh_offset = 0;
  shdr->sh_size = ds.size_;
  shdr->sh_link = ds.link_;
  shdr->sh_info = ds.info_;
  shdr->sh_addralign = 1;
  shdr->sh_entsize = 0;
  ElfSectIndex si(elf_ndxscn(scn));

  ds.setSectIndex(si);
  return si;
}


Dwarf_P_Debug generate_dwarf_object() {
  // Example will return error value thru 'err' pointer
  // and return DW_DLV_BADADDR if there is an error.
  int ptrsizeflagbit = DW_DLC_POINTER32;
  int offsetsizeflagbit = DW_DLC_OFFSET32;
  const char *isa_name = "x86";
  const char *dwarf_version = "V2";
  int endian = DW_DLC_TARGET_LITTLEENDIAN;
  Dwarf_Ptr errarg = 0;
  Dwarf_Error err = 0;
  void *user_data = 0;
  Dwarf_P_Debug dbg = 0;
  // We use DW_DLC_SYMBOLIC_RELOCATIONS so we can
  // read the relocations and do our own relocating.
  // See calls of dwarf_get_relocation_info().
  int res =
    dwarf_producer_init(DW_DLC_WRITE | ptrsizeflagbit | offsetsizeflagbit |
                        DW_DLC_SYMBOLIC_RELOCATIONS | endian,
                        CallbackFunc,
                        0, // errhand
                        errarg, user_data, isa_name, dwarf_version,
                        0, // No extra identifying strings.
                        &dbg, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarfgen: Failed init_b");
  }
  res = dwarf_pro_set_default_string_form(dbg, DW_FORM_string, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarfgen: Failed dwarf_pro_set_default_string_form");
  }

  return dbg;
}

void write_dwarf_file(Dwarf_P_Debug dbg, const std::string& filename)
{
  write_object_file(dbg, filename);
  dwarf_producer_finish(dbg, 0);
}

static void write_object_file(Dwarf_P_Debug dbg, const std::string& filename) {
  int fd = create_a_file(filename.c_str());
  if (fd < 0) {
    dwarfexport_error("dwarfgen: Unable to open ", filename, " for writing.");
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    dwarfexport_error("dwarfgen: Bad elf_version");
  }

  Elf_Cmd cmd = ELF_C_WRITE;
  elf = elf_begin(fd, cmd, 0);
  if (!elf) {
    dwarfexport_error("dwarfgen: Unable to elf_begin() on ", filename);
  }
  ehp = elf32_newehdr(elf);
  if (!ehp) {
    dwarfexport_error("dwarfgen: Unable to elf_newehdr() on ", filename);
  }
  ehp->e_ident[EI_MAG0] = ELFMAG0;
  ehp->e_ident[EI_MAG1] = ELFMAG1;
  ehp->e_ident[EI_MAG2] = ELFMAG2;
  ehp->e_ident[EI_MAG3] = ELFMAG3;
  ehp->e_ident[EI_CLASS] = ELFCLASS32;
  ehp->e_ident[EI_DATA] = ELFDATA2LSB;
  ehp->e_ident[EI_VERSION] = EV_CURRENT;
  ehp->e_machine = EM_386;
  //  We do not bother to create program headers, so
  //  mark this as ET_REL.
  ehp->e_type = ET_REL;
  ehp->e_version = EV_CURRENT;

  unsigned strtabstroff = secstrtab.addString(".shstrtab");

  write_generated_dbg(dbg, elf);

  // Now create section name string section.
  unsigned shstrindex = createnamestr(strtabstroff);
  ehp->e_shstrndx = shstrindex;

  off_t ures = elf_update(elf, cmd);
  if (ures == (off_t)(-1LL)) {
    int eer = elf_errno();
    dwarfexport_error("dwarfgen: Unable to elf_update() on ", filename, "  ", elf_errmsg(eer));
  }

  elf_end(elf);
  close_a_file(fd);
}

static void InsertDataIntoElf(Dwarf_Signed d, Dwarf_P_Debug dbg, Elf *elf) {
  Dwarf_Signed elf_section_index = 0;
  Dwarf_Unsigned length = 0;
  Dwarf_Ptr bytes =
      dwarf_get_section_bytes(dbg, d, &elf_section_index, &length, 0);

  Elf_Scn *scn = elf_getscn(elf, elf_section_index);
  if (!scn) {
    dwarfexport_error("dwarfgen: Unable to elf_getscn on disk transform");
  }

  ElfSectIndex si(elf_section_index);
  SectionFromDwarf &sfd = FindMySection(si);

  Elf_Data *ed = elf_newdata(scn);
  if (!ed) {
    dwarfexport_error("dwarfgen: elf_newdata died");
  }
  ed->d_buf = bytes;
  ed->d_type = ELF_T_BYTE;
  ed->d_size = length;
  ed->d_off = sfd.getNextOffset();
  sfd.setNextOffset(ed->d_off + length);
  ed->d_align = 1;
  ed->d_version = EV_CURRENT;
}

static void write_generated_dbg(Dwarf_P_Debug dbg, Elf *elf) {
  Dwarf_Signed sectioncount = dwarf_transform_to_disk_form(dbg, 0);

  Dwarf_Signed d = 0;
  for (d = 0; d < sectioncount; ++d) {
    InsertDataIntoElf(d, dbg, elf);
  }
}

int open_a_file(const char *name) {
  /* Set to a file number that cannot be legal. */
  int f = -1;

#if defined(__CYGWIN__) || defined(_WIN32)
  /*  It is not possible to share file handles
      between applications or DLLs. Each application has its own
      file-handle table. For two applications to use the same file
      using a DLL, they must both open the file individually.
      Let the 'libelf' dll to open and close the file.  */

  /* For WIN32 open the file as binary */
  f = elf_open(name, O_RDONLY | O_BINARY);
#else
  f = open(name, O_RDONLY);
#endif
  return f;
}

int create_a_file(const char *name) {
  /* Set to a file number that cannot be legal. */
  int f = -1;

#if defined(__CYGWIN__) || defined(_WIN32)
  /*  It is not possible to share file handles
      between applications or DLLs. Each application has its own
      file-handle table. For two applications to use the same file
      using a DLL, they must both open the file individually.
      Let the 'libelf' dll to open and close the file.  */

  /* For WIN32 create the file as binary */
  f = elf_open(name, O_WRONLY | O_CREAT | O_BINARY);
#else
  int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  f = open(name, O_WRONLY | O_CREAT | O_TRUNC, mode);
#endif
  return f;
}

void close_a_file(int f) { close(f); }
