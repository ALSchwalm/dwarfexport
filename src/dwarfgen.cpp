/* Windows specific header files */
#ifdef HAVE_STDAFX_H
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */

#ifndef __NT__
#define O_BINARY 0
#endif

#include <gelf.h>
#include <string>

#include "dwarfexport.h"

static int add_section_header_string(Elf *elf, const char *name) {
  // The stored data has to live until the file is written, so just
  // store it statically
  static strtabdata strtab;

  std::size_t sh_index;
  if (elf_getshstrndx(elf, &sh_index) == -1) {
    dwarfexport_error("elf_getshstrndx() failed: ", elf_errmsg(-1));
  }

  auto strscn = elf_getscn(elf, sh_index);
  if (strscn == NULL) {
    dwarfexport_error("elf_getscn() failed: ", elf_errmsg(-1));
  }

  GElf_Shdr shdr;
  if (gelf_getshdr(strscn, &shdr) == NULL) {
    dwarfexport_error("gelf_getshdr() failed: ", elf_errmsg(-1));
  }

  Elf_Data *data;
  if ((data = elf_getdata(strscn, NULL)) == NULL) {
    dwarfexport_error("elf_getdata() failed: ", elf_errmsg(-1));
  }

  strtab.loadExistingTable((char *)data->d_buf, data->d_size);
  auto ret = strtab.addString(name);

  data->d_buf = strtab.exposedata();
  data->d_size = strtab.exposelen();
  shdr.sh_size = data->d_size;

  if (!gelf_update_shdr(strscn, &shdr)) {
    dwarfexport_error("Unable to gelf_update_shdr()", elf_errmsg(-1));
  }

  return ret;
}

static int attached_info_callback(const char *name, int size,
                                  Dwarf_Unsigned type, Dwarf_Unsigned flags,
                                  Dwarf_Unsigned link, Dwarf_Unsigned info,
                                  Dwarf_Unsigned *sect_name_symbol_index,
                                  void *userdata, int *) {
  DwarfGenInfo &geninfo = *(DwarfGenInfo *)userdata;
  auto elf = geninfo.elf;

  if (strncmp(name, ".rel", 4) == 0) {
    return 0;
  }

  Elf_Scn *scn = elf_newscn(elf);
  if (!scn) {
    dwarfexport_error("Unable to elf_newscn(): ", elf_errmsg(-1));
  }

  GElf_Shdr shdr;
  if (!gelf_getshdr(scn, &shdr)) {
    dwarfexport_error("Unable to elf_getshdr(): ", elf_errmsg(-1));
  }

  shdr.sh_type = type;
  shdr.sh_flags = flags;
  shdr.sh_addr = 0;
  shdr.sh_link = link;
  shdr.sh_info = info;
  shdr.sh_addralign = 1;
  shdr.sh_name = add_section_header_string(elf, name);

  // We set these correctly later
  shdr.sh_size = 0;
  shdr.sh_offset = 0;
  shdr.sh_entsize = 0;

  if (!gelf_update_shdr(scn, &shdr)) {
    dwarfexport_error("Unable to gelf_update_shdr()", elf_errmsg(-1));
  }

  return elf_ndxscn(scn);
}

static std::vector<std::string> detached_sections;
static int detached_info_callback(const char *name, int size,
                                  Dwarf_Unsigned type, Dwarf_Unsigned flags,
                                  Dwarf_Unsigned link, Dwarf_Unsigned info,
                                  Dwarf_Unsigned *sect_name_symbol_index,
                                  void *userdata, int *) {
  detached_sections.push_back(name);
  return detached_sections.size() - 1;
}

std::shared_ptr<DwarfGenInfo> generate_dwarf_object(const Options &options) {
  auto info = std::make_shared<DwarfGenInfo>();
  auto err = info->err;

  int ptrsizeflagbit = DW_DLC_POINTER32;
  int offsetsizeflagbit = DW_DLC_OFFSET32;
  if (info->mode == Mode::BIT64) {
    ptrsizeflagbit = DW_DLC_POINTER64;
  }

  // We don't use the dwarf relocations, so it probably doesn't matter what
  // we put here
  const char *isa_name = (info->mode == Mode::BIT32) ? "x86" : "x86_64";

  const char *dwarf_version = "V2";
  int endian = (inf.is_be()) ? DW_DLC_TARGET_BIGENDIAN : DW_DLC_TARGET_LITTLEENDIAN;
  Dwarf_Ptr errarg = 0;

  decltype(&attached_info_callback) callback;
  if (options.attach_debug_info()) {
    callback = &attached_info_callback;
  } else {
    callback = &detached_info_callback;
  }
  int res = dwarf_producer_init(DW_DLC_WRITE | DW_DLC_SYMBOLIC_RELOCATIONS |
                                    ptrsizeflagbit | offsetsizeflagbit | endian,
                                callback, 0, errarg, (void *)info.get(),
                                isa_name, dwarf_version, 0, &info->dbg, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarf_producer_init failed: ", dwarf_errmsg(err));
  }
  res = dwarf_pro_set_default_string_form(info->dbg, DW_FORM_string, &err);
  if (res != DW_DLV_OK) {
    dwarfexport_error("dwarf_pro_set_default_string_form failed: ",
                      dwarf_errmsg(err));
  }

  return info;
}

static Elf_Scn *get_last_section(Elf *elf) {
  std::size_t count, max_offset = 0, max_size = 0;
  GElf_Shdr shdr;
  Elf_Scn *last_scn;

  if (elf_getshdrnum(elf, &count) == -1) {
    dwarfexport_error("elf_getshdrnum() failed: ", elf_errmsg(-1));
  }
  for (std::size_t i = 0; i < count; ++i) {
    Elf_Scn *scn = elf_getscn(elf, i);
    if (!gelf_getshdr(scn, &shdr)) {
      dwarfexport_error("elf_getshdr() failed: ", elf_errmsg(-1));
    }
    if (shdr.sh_type == SHT_NOBITS) {
      continue;
    }
    if (shdr.sh_offset > max_offset ||
        (shdr.sh_offset == max_offset && shdr.sh_size > max_size)) {
      last_scn = scn;
      max_offset = shdr.sh_offset;
      max_size = shdr.sh_size;
    }
  }
  return last_scn;
}

static off_t get_current_data_offset(Elf_Scn *scn) {
  Elf_Data *data = NULL;
  off_t offset = 0;
  while ((data = elf_getdata(scn, data)) != NULL) {
    if (data->d_off >= offset) {
      offset = data->d_off + data->d_size;
    }

    // This shouldn't be necessary, but libelf complains the
    // version is unknown otherwise.
    data->d_version = EV_CURRENT;
  }
  return offset;
}

static void add_data_to_section_end(Elf *elf, Elf_Scn *scn, void *bytes,
                                    std::size_t length, Elf_Type type) {

  auto data_offset = get_current_data_offset(scn);
  Elf_Data *ed = elf_newdata(scn);
  if (!ed) {
    dwarfexport_error("elf_newdata() failed: ", elf_errmsg(-1));
  }
  ed->d_buf = bytes;
  ed->d_type = type;
  ed->d_size = length;
  ed->d_align = 1;
  ed->d_version = EV_CURRENT;
  ed->d_off = data_offset;

  // Update the section size and offset
  Elf_Scn *last_scn = get_last_section(elf);
  GElf_Shdr shdr, last_shdr;
  if (!gelf_getshdr(scn, &shdr) || !gelf_getshdr(last_scn, &last_shdr)) {
    dwarfexport_error("elf_getshdr() failed: ", elf_errmsg(-1));
  }

  if (!shdr.sh_offset) {
    shdr.sh_offset = last_shdr.sh_offset + last_shdr.sh_size;
  }
  shdr.sh_size += length;
  if (!gelf_update_shdr(scn, &shdr)) {
    dwarfexport_error("gelf_update_shdr() failed: ", elf_errmsg(-1));
  }
}

static void add_debug_section_data(std::shared_ptr<DwarfGenInfo> info) {
  auto dbg = info->dbg;
  auto elf = info->elf;
  auto err = info->err;

  // Invokes the callback to create the needed sections
  Dwarf_Signed sectioncount = dwarf_transform_to_disk_form(dbg, &err);
  if (sectioncount == DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_transform_to_disk_form() failed: ",
                      dwarf_errmsg(err));
  }

  for (Dwarf_Signed d = 0; d < sectioncount; ++d) {
    Dwarf_Signed elf_section_index = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Ptr bytes =
        dwarf_get_section_bytes(dbg, d, &elf_section_index, &length, &err);

    if (bytes == NULL) {
      dwarfexport_error("dwarf_get_section_bytes() failed: ",
                        dwarf_errmsg(err));
    }

    Elf_Scn *scn = elf_getscn(elf, elf_section_index);
    if (scn == NULL) {
      dwarfexport_error("Unable to elf_getscn on disk transform: ",
                        elf_errmsg(-1));
    }

    add_data_to_section_end(elf, scn, bytes, length, ELF_T_BYTE);
  }
}

static void log_elf(Elf *elf) {
  GElf_Ehdr ehdr;
  int scn_index;
  Elf_Scn *scn;
  GElf_Shdr shdr;

  if (gelf_getehdr(elf, &ehdr) != &ehdr)
    dwarfexport_error("gelf_getehdr() failed: ", elf_errmsg(-1));

  for (scn_index = 1; scn_index < ehdr.e_shnum; scn_index++) {
    if ((scn = elf_getscn(elf, scn_index)) == NULL)
      dwarfexport_error("getshdr() failed: ", elf_errmsg(-1));
    if (gelf_getshdr(scn, &shdr) != &shdr)
      dwarfexport_error("getshdr() failed: ", elf_errmsg(-1));
    dwarfexport_log("Section #", scn_index,
                    ": sh_name=", shdr.sh_name,
                    ", sh_type=", shdr.sh_type,
                    ", sh_flags=", shdr.sh_flags,
                    ", sh_addr=", shdr.sh_addr,
                    ", sh_offset=", shdr.sh_offset,
                    ", sh_size=", shdr.sh_size,
                    ", sh_link=", shdr.sh_link,
                    ", sh_info=", shdr.sh_info,
                    ", sh_addralign=", shdr.sh_addralign,
                    ", sh_entsize=", shdr.sh_entsize);
  }
}

static void generate_copy_with_dbg_info(std::shared_ptr<DwarfGenInfo> info,
                                        const std::string &src,
                                        const std::string &dst) {
  int fd_in = -1, fd_out = -1;
  Elf *elf_in = 0, *elf_out = 0;

  Elf_Scn *scn_in, *scn_out;
  GElf_Ehdr ehdr_in, ehdr_out;

  int scn_index = 0;

  if (elf_version(EV_CURRENT) == EV_NONE)
    dwarfexport_error("ELF library initialization failed: ", elf_errmsg(-1));

  if ((fd_in = open(src.c_str(), O_RDONLY | O_BINARY, 0)) < 0)
    dwarfexport_error("open failed: ", src);

  if ((elf_in = elf_begin(fd_in, ELF_C_READ, NULL)) == NULL)
    dwarfexport_error("elf_begin() (read) failed: ", elf_errmsg(-1));

  if (gelf_getehdr(elf_in, &ehdr_in) != &ehdr_in)
    dwarfexport_error("gelf_getehdr() failed: ", elf_errmsg(-1));

  /* Checks and warns */
  if (elf_kind(elf_in) != ELF_K_ELF) {
    dwarfexport_error(src, " : ", dst, " must be an ELF file.");
  }

  /* open output elf */
  if ((fd_out = open(dst.c_str(), O_WRONLY | O_CREAT | O_BINARY, 0777)) < 0)
    dwarfexport_error("open failed: ", dst);

  if ((elf_out = elf_begin(fd_out, ELF_C_WRITE, NULL)) == NULL)
    dwarfexport_error("elf_begin() (write) failed: ", elf_errmsg(-1));

  /* create new elf header */
  if (gelf_newehdr(elf_out, ehdr_in.e_ident[EI_CLASS]) == 0)
    dwarfexport_error("gelf_newehdr() failed: ", elf_errmsg(-1));

  info->elf = elf_out;

  /* Some compilers produce binaries with non-adjacent or overlapping sections,
   * so we cannot use the automatic layout. Suppress it and use the exact
   * layout from the input. */
  if (elf_flagelf(elf_out, ELF_C_SET, ELF_F_LAYOUT | ELF_F_LAYOUT_OVERLAP) == 0)
    dwarfexport_error("elf_flagelf failed: ", elf_errmsg(-1));

  if (gelf_getehdr(elf_out, &ehdr_out) != &ehdr_out)
    dwarfexport_error("gelf_getehdr() failed: ", elf_errmsg(-1));

  ehdr_out = ehdr_in;

  if (gelf_update_ehdr(elf_out, &ehdr_out) == 0)
    dwarfexport_error("gelf_update_ehdr() failed: ", elf_errmsg(-1));

  GElf_Phdr phdr_in, phdr_out;
  int ph_ndx;

  if (ehdr_in.e_phnum && gelf_newphdr(elf_out, ehdr_in.e_phnum) == 0)
    dwarfexport_error("gelf_newphdr() failed: ", elf_errmsg(-1));

  for (ph_ndx = 0; ph_ndx < ehdr_in.e_phnum; ++ph_ndx) {
    if (gelf_getphdr(elf_in, ph_ndx, &phdr_in) != &phdr_in)
      dwarfexport_error("gelf_getphdr() failed: ", elf_errmsg(-1));

    if (gelf_getphdr(elf_out, ph_ndx, &phdr_out) != &phdr_out)
      dwarfexport_error("gelf_getphdr() failed: ", elf_errmsg(-1));

    phdr_out = phdr_in;

    if (gelf_update_phdr(elf_out, ph_ndx, &phdr_out) == 0)
      dwarfexport_error("gelf_update_phdr() failed: ", elf_errmsg(-1));
  }

  /* copy sections to new elf */
  Elf_Data *data_in, *data_out;
  GElf_Shdr shdr_in, shdr_out;
  for (scn_index = 1; scn_index < ehdr_in.e_shnum; scn_index++) {
    if ((scn_in = elf_getscn(elf_in, scn_index)) == NULL)
      dwarfexport_error("getshdr() failed: ", elf_errmsg(-1));
    if ((scn_out = elf_newscn(elf_out)) == NULL)
      dwarfexport_error("elf_newscn() failed: ", elf_errmsg(-1));

    if (gelf_getshdr(scn_in, &shdr_in) != &shdr_in)
      dwarfexport_error("getshdr() failed: ", elf_errmsg(-1));

    data_in = NULL;
    while ((data_in = elf_getdata(scn_in, data_in)) != NULL) {
      if ((data_out = elf_newdata(scn_out)) == NULL)
        dwarfexport_error("elf_newdata() failed: ", elf_errmsg(-1));

      *data_out = *data_in;
    }

    if (gelf_getshdr(scn_out, &shdr_out) != &shdr_out)
      dwarfexport_error("gelf_getshdr() failed: ", elf_errmsg(-1));

    shdr_out = shdr_in;

    if (gelf_update_shdr(scn_out, &shdr_out) == 0)
      dwarfexport_error("gelf_update_shdr() failed: ", elf_errmsg(-1));
  }

  dwarfexport_log("After copying the original sections:");
  log_elf(elf_out);

  add_debug_section_data(info);

  dwarfexport_log("After adding the debug sections:");
  log_elf(elf_out);

  // Get the current last section (to fix section header and string table loc)
  auto last_scn = get_last_section(elf_out);
  GElf_Shdr last_shdr;
  if (gelf_getshdr(last_scn, &last_shdr) != &last_shdr)
    dwarfexport_error("gelf_getshdr() failed: ", elf_errmsg(-1));

  // Fix the section header string table start location
  std::size_t shstrndx = 0;
  if (elf_getshdrstrndx(elf_out, &shstrndx) == -1)
    dwarfexport_error("elf_getshdrstrndx() failed: ", elf_errmsg(-1));

  Elf_Scn *shstr_scn = elf_getscn(elf_out, shstrndx);
  GElf_Shdr shstr_shdr;
  if (!gelf_getshdr(shstr_scn, &shstr_shdr))
    dwarfexport_error("elf_getshdr() failed: ", elf_errmsg(-1));

  shstr_shdr.sh_offset = last_shdr.sh_offset + last_shdr.sh_size;

  if (!gelf_update_shdr(shstr_scn, &shstr_shdr))
    dwarfexport_error("gelf_update_shdr() failed: ", elf_errmsg(-1));

  // Fix the section header start location
  ehdr_out.e_shoff = shstr_shdr.sh_offset + shstr_shdr.sh_size;
  if (gelf_update_ehdr(elf_out, &ehdr_out) == 0)
    dwarfexport_error("gelf_update_ehdr() failed: ", elf_errmsg(-1));

  dwarfexport_log("After fixing various offsets:");
  log_elf(elf_out);

  if (elf_update(elf_out, ELF_C_WRITE) < 0)
    dwarfexport_error("elf_update() failed: ", elf_errmsg(-1));

  elf_end(elf_out);
  close(fd_out);
  elf_end(elf_in);
  close(fd_in);
}

void generate_detached_dbg_info(std::shared_ptr<DwarfGenInfo> info,
                                const std::string &path) {
  auto dbg = info->dbg;
  auto err = info->err;

  // Invokes the callback to create the needed sections
  Dwarf_Signed sectioncount = dwarf_transform_to_disk_form(dbg, &err);
  if (sectioncount == DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_transform_to_disk_form() failed: ",
                      dwarf_errmsg(err));
  }

  int fd = 0;
  int prev_section_index = -1;

  for (Dwarf_Signed d = 0; d < sectioncount; ++d) {
    Dwarf_Signed section_index = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Ptr bytes =
        dwarf_get_section_bytes(dbg, d, &section_index, &length, &err);

    if (bytes == NULL) {
      dwarfexport_error("dwarf_get_section_bytes() failed: ",
                        dwarf_errmsg(err));
    }

    auto section_name = detached_sections.at(section_index).substr(1);
    std::string fullpath = path + PATH_SEP + section_name;

    // We're in a different section, so open a new fd
    if (prev_section_index != section_index) {
      if (fd != 0) {
        close(fd);
      }

      // strip the leading '.' on the section name
      fd = open(fullpath.c_str(), O_WRONLY | O_CREAT, 0777);

      if (fd < 0) {
        dwarfexport_error("open failed: ", path);
      }
      prev_section_index = section_index;
    }

    // TODO: this is not necessarily an error
    if (write(fd, bytes, length) != length) {
      dwarfexport_error("write() failed");
    }
  }
}

void write_dwarf_file(std::shared_ptr<DwarfGenInfo> info,
                      const Options &options) {
  if (options.attach_debug_info()) {
    generate_copy_with_dbg_info(info, options.filename, options.dbg_filename());
  } else {
    generate_detached_dbg_info(info, options.filepath);
  }
  dwarf_producer_finish(info->dbg, 0);
}
