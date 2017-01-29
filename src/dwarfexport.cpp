#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <string>

#include "dwarfexport.h"

hexdsp_t *hexdsp = NULL;

static Dwarf_P_Die add_function(Dwarf_P_Debug dbg, Dwarf_P_Die parent,
                                func_t *func, std::ofstream &file,
                                int &linecount, Dwarf_Unsigned file_index) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;
  die = dwarf_new_die(dbg, DW_TAG_subprogram, parent, nullptr, nullptr, nullptr,
                      &err);
  if (die == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, func->startEA, 0, &err);
  dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, func->endEA, 0, &err);

  auto name = get_long_name(func->startEA);
  char *c_name = &*name.begin();
  printf("Processing %s\n", c_name);

  dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, &err);
  dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, &err);

  // dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, c_name, &err);

  if (dwarf_add_AT_name(die, c_name, &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(func, &hf);

  if (cfunc == nullptr) {
    return die;
  }

  const auto &sv = cfunc->get_pseudocode();
  for (std::size_t i = 0; i < sv.size(); i++) {
    char buf[MAXSTR];
    const char *line = sv[i].line.c_str();
    tag_remove(line, buf, MAXSTR);

    auto stripped_buf = std::string(buf);
    file << stripped_buf + "\n";
    linecount += 1;

    ctree_item_t item;
    std::size_t index = stripped_buf.find_first_not_of(' ');
    if (index == std::string::npos) {
      continue;
    }

    // For each column in the line, try to find a cexpr_t that has an
    // address inside the function, then emit a dwarf source line info
    // for that.
    for (; index < stripped_buf.size(); ++index) {
      if (!cfunc->get_line_item(line, index, true, nullptr, &item, nullptr)) {
        continue;
      }

      // item.get_ea returns strange values, so use the item_t ea for exprs
      // for now
      if (item.citype != VDI_EXPR || !item.it->is_expr()) {
        continue;
      }

      ea_t addr = item.e->ea;

      // The address for this expression is outside of this function,
      // so something strange is happening. Just ignore it.
      if (addr == (ea_t)-1 || addr < func->startEA || addr > func->endEA) {
        continue;
      }

      dwarf_add_line_entry(dbg, file_index, addr, linecount, 0, true,
                           false, &err);
      break;
    }
  }

  return die;
}

void add_debug_info(Dwarf_P_Debug dbg, std::ofstream& sourcefile,
                    std::string filepath, std::string c_filename) {
  Dwarf_Error err = 0;
  Dwarf_P_Die cu;
  cu = dwarf_new_die(dbg, DW_TAG_compile_unit, nullptr, nullptr, nullptr,
                     nullptr, &err);
  if (cu == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  if (dwarf_add_AT_name(cu, &c_filename[0], &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  auto dir_index = dwarf_add_directory_decl(dbg, &filepath[0], &err);
  auto file_index =
    dwarf_add_file_decl(dbg, &c_filename[0], dir_index, 0, 0, &err);

  dwarf_add_AT_comp_dir(cu, &filepath[0], &err);

  int linecount = 0;
  segment_t *seg = get_segm_by_name(".text");

  for (func_t *f = get_func(seg->startEA); f != nullptr;
       f = get_next_func(f->startEA)) {
    if (f->startEA > seg->endEA) {
      break;
    }

    add_function(dbg, cu, f, sourcefile, linecount, file_index);

    // Add a little space between the functions
    sourcefile << "\n\n";
    linecount += 2;
  }

  if (dwarf_add_die_to_debug(dbg, cu, &err) != DW_DLV_OK) {
    dwarfexport_error("dwarf_add_die_to_debug failed: ", dwarf_errmsg(err));
  }
}

int idaapi init(void) {
  if (!init_hexrays_plugin())
    return PLUGIN_SKIP;
  return PLUGIN_OK;
}

void idaapi run(int) {
  try {
    char filepath[QMAXPATH];
    char filename[QMAXPATH];
    get_input_file_path(filepath, QMAXPATH);
    get_root_filename(filename, QMAXPATH);

    //TODO make this portable
    char* filepath_end = strrchr(filepath, '/');
    if (filepath_end != nullptr) {
      *(filepath_end+1) = '\0';
    }

    const char *dialog =
      "STARTITEM 0\n"
      "Dwarf Export\n\n"
      "Select the location to save the exported data:\n"
      "<Save:F:1:::>\n";

    if (AskUsingForm_c(dialog, filepath) == 1) {
      auto elf_filename = std::string(filename) + ".elf";
      auto c_filename = std::string(filename) + ".c";

      std::ofstream sourcefile(filepath + c_filename);

      auto dbg = generate_dwarf_object();
      add_debug_info(dbg, sourcefile, filepath, c_filename);
      write_dwarf_file(dbg, filepath + elf_filename);

    } else {
      warning("A dwarfexport error occurred");
    }
  } catch (const std::exception &e) {
    std::string msg = "A dwarfexport error occurred: " + std::string(e.what());
    warning(msg.c_str());
  } catch (...) {
    warning("A dwarfexport error occurred");
  }
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,                // plugin flags
    init,                      // initialize
    nullptr,                   // terminate. this pointer may be nullptr.
    run,                       // invoke plugin
    nullptr,                   // long comment about the plugin
    nullptr,                   // multiline help about the plugin
    "Export Dwarf Debug Info", // the preferred short name of the plugin
    nullptr                    // the preferred hotkey to run the plugin
};
