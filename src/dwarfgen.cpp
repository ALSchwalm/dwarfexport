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
#include <string>
#include <sys/stat.h> //open
#include <unistd.h>
#include <vector>

#include "dwarfexport.h"

static void write_object_file(Mode m, std::shared_ptr<DwarfGenInfo> info,
                              const std::string &filename);

static void write_generated_dbg(Dwarf_P_Debug dbg, Elf *elf);

int create_a_file(const char *name);
void close_a_file(int f);

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
  strtabdata &secstrtab_;

public:
  Dwarf_Unsigned getNextOffset() { return lengthWrittenToElf_; }
  void setNextOffset(Dwarf_Unsigned v) { lengthWrittenToElf_ = v; }

  unsigned getSectionNameSymidx() {
    return section_name_symidx_.getSymIndex();
  };

  void setSectIndex(ElfSectIndex v) { elf_sect_index_ = v; }
  ElfSectIndex getSectIndex() const { return elf_sect_index_; }
  SectionFromDwarf(const std::string &name, int size, Dwarf_Unsigned type,
                   Dwarf_Unsigned flags, Dwarf_Unsigned link,
                   Dwarf_Unsigned info, strtabdata &secstrtab)
      : name_(name), size_(size), type_(type), flags_(flags), link_(link),
        info_(info), elf_sect_index_(0), lengthWrittenToElf_(0),
        secstrtab_(secstrtab) {
    // Now create section name string section.
    section_name_itself_ = secstrtab_.addString(name.c_str());
  };
};

std::vector<SectionFromDwarf> dwsectab;

static ElfSectIndex create_dw_elf(Elf *elf, SectionFromDwarf &ds);

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

static unsigned createnamestr(Elf *elf, strtabdata &secstrtab,
                              unsigned strtabstroff) {
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

  GElf_Shdr strshdr;
  if (!gelf_getshdr(strscn, &strshdr)) {
    dwarfexport_error("dwarfgen: Unable to elf_getshdr()");
  }
  strshdr.sh_name = strtabstroff;
  strshdr.sh_type = SHT_STRTAB;
  strshdr.sh_flags = SHF_STRINGS;
  strshdr.sh_addr = 0;
  strshdr.sh_offset = 0;
  strshdr.sh_size = 0;
  strshdr.sh_link = 0;
  strshdr.sh_info = 0;
  strshdr.sh_addralign = 1;
  strshdr.sh_entsize = 0;

  if (!gelf_update_shdr(strscn, &strshdr)) {
    dwarfexport_error("dwarfgen: Unable to gelf_update_shdr()");
  }

  return elf_ndxscn(strscn);
}

int CallbackFunc(const char *name, int size, Dwarf_Unsigned type,
                 Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
                 Dwarf_Unsigned *sect_name_symbol_index, void *userdata,
                 int *) {
  DwarfGenInfo &geninfo = *(DwarfGenInfo *)userdata;
  SectionFromDwarf ds(name, size, type, flags, link, info, geninfo.secstrtab);

  *sect_name_symbol_index = ds.getSectionNameSymidx();
  ElfSectIndex createdsec = create_dw_elf(geninfo.elf, ds);

  // Do all the data creation before pushing
  // (copying) ds onto dwsectab!
  dwsectab.push_back(ds);
  // The number returned is elf section, not dwsectab[] index
  return createdsec.getSectIndex();
}

// Here we create a new Elf section
// This never happens for relocations in dwarfgen,
// only a few sections are created by dwarfgen.
static ElfSectIndex create_dw_elf(Elf *elf, SectionFromDwarf &ds) {
  Elf_Scn *scn = elf_newscn(elf);
  if (!scn) {
    dwarfexport_error("dwarfgen: Unable to elf_newscn() on ", ds.name_);
  }

  GElf_Shdr shdr;

  if (!gelf_getshdr(scn, &shdr)) {
    dwarfexport_error("dwarfgen: Unable to elf_getshdr() on ", ds.name_);
  }
  shdr.sh_name = ds.section_name_itself_;
  shdr.sh_type = ds.type_;
  shdr.sh_flags = ds.flags_;
  shdr.sh_addr = 0;
  shdr.sh_offset = 0;
  shdr.sh_size = ds.size_;
  shdr.sh_link = ds.link_;
  shdr.sh_info = ds.info_;
  shdr.sh_addralign = 1;
  shdr.sh_entsize = 0;

  if (!gelf_update_shdr(scn, &shdr)) {
    dwarfexport_error("dwarfgen: Unable to gelf_update_shdr() on ", ds.name_);
  }

  ElfSectIndex si(elf_ndxscn(scn));

  ds.setSectIndex(si);
  return si;
}

std::shared_ptr<DwarfGenInfo> generate_dwarf_object(Mode m) {
  auto info = std::make_shared<DwarfGenInfo>();

  int ptrsizeflagbit = DW_DLC_POINTER32;
  int offsetsizeflagbit = DW_DLC_OFFSET32;
  if (m == Mode::BIT64) {
    ptrsizeflagbit = DW_DLC_POINTER64;
  }

  const char *isa_name = (m == Mode::BIT32) ? "x86" : "x86_64";
  const char *dwarf_version = "V2";

  //TODO: support other endians
  int endian = DW_DLC_TARGET_LITTLEENDIAN;
  Dwarf_Ptr errarg = 0;
  Dwarf_Error err = 0;

  int res =
    dwarf_producer_init(DW_DLC_WRITE | ptrsizeflagbit | offsetsizeflagbit |
                              DW_DLC_SYMBOLIC_RELOCATIONS | endian,
                          CallbackFunc,
                          0,
                          errarg, (void *)info.get(), isa_name, dwarf_version,
                          0,
                          &info->dbg, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarfgen: Failed init_b");
  }
  res = dwarf_pro_set_default_string_form(info->dbg, DW_FORM_string, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarfgen: Failed dwarf_pro_set_default_string_form");
  }

  return info;
}

void write_dwarf_file(Mode m, std::shared_ptr<DwarfGenInfo> info,
                      const std::string &filename) {
  write_object_file(m, info, filename);
  dwarf_producer_finish(info->dbg, 0);
}

static void write_object_file(Mode m, std::shared_ptr<DwarfGenInfo> info,
                              const std::string &filename) {
  GElf_Ehdr eh;

  int fd = create_a_file(filename.c_str());
  if (fd < 0) {
    dwarfexport_error("dwarfgen: Unable to open ", filename, " for writing.");
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    dwarfexport_error("dwarfgen: Bad elf_version");
  }

  Elf_Cmd cmd = ELF_C_WRITE;
  info->elf = elf_begin(fd, cmd, 0);
  if (!info->elf) {
    dwarfexport_error("dwarfgen: Unable to elf_begin() on ", filename);
  }

  int elfclass = (m == Mode::BIT32) ? ELFCLASS32 : ELFCLASS64;

  gelf_newehdr(info->elf, elfclass);

  if (!gelf_getehdr(info->elf, &eh)) {
    dwarfexport_error("dwarfgen: Unable to gelf_newehdr() on ", filename);
  }

  eh.e_ident[EI_MAG0] = ELFMAG0;
  eh.e_ident[EI_MAG1] = ELFMAG1;
  eh.e_ident[EI_MAG2] = ELFMAG2;
  eh.e_ident[EI_MAG3] = ELFMAG3;
  eh.e_ident[EI_CLASS] = elfclass;
  eh.e_ident[EI_DATA] = ELFDATA2LSB;
  eh.e_ident[EI_VERSION] = EV_CURRENT;

  //TODO: support other arches
  // This has to be right for gdb. Otherwise, it truncates the
  // addresses computed from dwarf info.
  eh.e_machine = (m == Mode::BIT32) ? EM_386 : EM_X86_64;

  //  We do not bother to create program headers, so
  //  mark this as ET_REL.
  eh.e_type = ET_REL;
  eh.e_version = EV_CURRENT;

  unsigned strtabstroff = info->secstrtab.addString(".shstrtab");

  write_generated_dbg(info->dbg, info->elf);

  // Now create section name string section.
  unsigned shstrindex = createnamestr(info->elf, info->secstrtab, strtabstroff);
  eh.e_shstrndx = shstrindex;

  if (!gelf_update_ehdr(info->elf, &eh)) {
    dwarfexport_error("dwarfgen: gelf_update_ehdr error");
  }

  off_t ures = elf_update(info->elf, cmd);
  if (ures == (off_t)(-1LL)) {
    int eer = elf_errno();
    dwarfexport_error("dwarfgen: Unable to elf_update() on ", filename, "  ",
                      elf_errmsg(eer));
  }

  elf_end(info->elf);
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

#ifndef __NT__
#define O_BINARY 0
#endif
int create_a_file(const char *name) {
  int mode = S_IRUSR | S_IWUSR;
  return open(name, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, mode);
}

void close_a_file(int f) { close(f); }
