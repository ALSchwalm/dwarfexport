
#include <cstdio>
#include <cstdlib>
#include <frame.hpp>
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

using type_record_t = std::map<tinfo_t, Dwarf_P_Die>;

static Dwarf_P_Die get_or_add_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record);

static Dwarf_P_Die add_struct_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record) {
  if (!type.is_struct()) {
    dwarfexport_error("add_struct_type: type is not struct");
  }

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  // Add type name
  std::string name = type.dstr();
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  // Add type size
  auto size = type.get_size();
  if (size != BADSIZE &&
      dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) ==
          NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }

  auto member_count = type.get_udt_nmembers();
  if (member_count == -1) {
    dwarfexport_error("add_struct_type: get_udt_nmembers error");
  }

  for (int i = 0; i < member_count; ++i) {
    udt_member_t member;
    member.offset = i;
    type.find_udt_member(STRMEM_INDEX, &member);
    auto member_type = member.type;
    auto member_die =
        dwarf_new_die(dbg, DW_TAG_member, die, NULL, NULL, NULL, &err);

    // Add member type
    auto member_type_die = get_or_add_type(dbg, cu, member_type, record);
    if (dwarf_add_AT_reference(dbg, member_die, DW_AT_type, member_type_die,
                               &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }

    // Add member name
    auto member_name = member.name;
    if (dwarf_add_AT_name(member_die, &member_name[0], &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    // Add member location in struct
    Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
    if (dwarf_add_expr_gen(loc_expr, DW_OP_plus_uconst, member.offset / 8, 0,
                           &err) == DW_DLV_NOCOUNT) {
      dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
    }

    if (dwarf_add_AT_location_expr(dbg, member_die, DW_AT_data_member_location,
                                   loc_expr, &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                        dwarf_errmsg(err));
    }
  }
  return die;
}

static Dwarf_P_Die add_array_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                  const tinfo_t &type, type_record_t &record) {
  if (!type.is_array()) {
    dwarfexport_error("add_array_type: type is not array");
  }

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_array_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto element_type = type;
  element_type.remove_ptr_or_array();
  auto element_die = get_or_add_type(dbg, cu, element_type, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, element_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }

  auto elems = type.get_array_nelems();
  if (elems != -1) {
    auto subrange =
        dwarf_new_die(dbg, DW_TAG_subrange_type, die, NULL, NULL, NULL, &err);
    if (dwarf_add_AT_unsigned_const(dbg, subrange, DW_AT_upper_bound, elems,
                                    &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                        dwarf_errmsg(err));

      tinfo_t size_type;
      qstring name;

      // Try to get size_t and use it for the index type
      if (parse_decl2(idati, "size_t x;", &name, &size_type, PT_SIL)) {
        auto index_die = get_or_add_type(dbg, cu, size_type, record);
        if (dwarf_add_AT_reference(dbg, subrange, DW_AT_type, index_die,
                                   &err) == nullptr) {
          dwarfexport_error("dwarf_add_AT_reference failed: ",
                            dwarf_errmsg(err));
        }
        if (dwarf_add_AT_reference(dbg, die, DW_AT_sibling, index_die, &err) ==
            nullptr) {
          dwarfexport_error("dwarf_add_AT_reference failed: ",
                            dwarf_errmsg(err));
        }
      }
    }
  }
  return die;
}

static Dwarf_P_Die add_const_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                  const tinfo_t &type, type_record_t &record) {
  if (!type.is_const()) {
    dwarfexport_error("add_const_type: type is not const");
  }

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_const_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto without_const = type;
  without_const.clr_const();
  auto child_die = get_or_add_type(dbg, cu, without_const, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }
  return die;
}

static Dwarf_P_Die add_ptr_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                const tinfo_t &type, type_record_t &record) {
  if (!type.is_ptr()) {
    dwarfexport_error("add_ptr_type: type is not a pointer");
  }

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_pointer_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  auto without_ptr = type;
  without_ptr.remove_ptr_or_array();
  auto child_die = get_or_add_type(dbg, cu, without_ptr, record);

  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, child_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }
  if (dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, sizeof(ea_t),
                                  &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }
  return die;
}

static Dwarf_P_Die get_or_add_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record) {
  if (record.find(type) != record.end()) {
    return record[type];
  }

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  // special cases for const, ptr, array, and struct
  if (type.is_const()) {
    die = add_const_type(dbg, cu, type, record);
    return die;
  } else if (type.is_ptr()) {
    die = add_ptr_type(dbg, cu, type, record);
    return die;
  } else if (type.is_array()) {
    die = add_array_type(dbg, cu, type, record);
    return die;
  } else if (type.is_struct()) {
    die = add_struct_type(dbg, cu, type, record);
    return die;
  }

  die = dwarf_new_die(dbg, DW_TAG_base_type, cu, NULL, NULL, NULL, &err);

  if (die == NULL) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  // Add type name
  std::string name = type.dstr();
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  // Add type size
  std::size_t size = type.get_size();
  if (size != BADSIZE &&
      dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) ==
          NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }

  record[type] = die;
  return die;
}

static Dwarf_P_Die add_variable(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                Dwarf_P_Die func_die, cfuncptr_t cfunc,
                                const lvar_t &var, type_record_t &record) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_variable, func_die, NULL, NULL, NULL, &err);

  // Add var type
  if (var.typed()) {
    auto var_type = var.type();
    auto var_type_die = get_or_add_type(dbg, cu, var_type, record);

    if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }
  }

  auto name = var.name;
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  if (var.is_stk_var()) {
    // Add frame location
    // TODO: what to do for non-bp based frames and register variables
    Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
    auto func = get_func(cfunc->entry_ea);

    // FIXME: Not sure what's going on here. stkoff returns strange values
    //       but this math seems to work out.
    int base_offset;
    if (sizeof(ea_t) == 4) {
      // IDA bug? This is off by 8 on 32 bit builds
      auto correct_stack_offset = var.location.stkoff() - 8;
      base_offset = -(func->frsize - correct_stack_offset);

      // Fixup base offset for dwarf (not sure why this is 8)
      base_offset -= 8;
    } else {
      base_offset = -(func->frsize - var.location.stkoff());

      // Fixup base offset for dwarf (not sure why this is 16)
      base_offset -= 16;
    }

    if (dwarf_add_expr_gen(loc_expr, DW_OP_fbreg, base_offset, 0, &err) ==
        DW_DLV_NOCOUNT) {
      dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
    }
    if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                        dwarf_errmsg(err));
    }
  }

  return die;
}

static Dwarf_P_Die add_function(Dwarf_P_Debug dbg, Dwarf_P_Die cu, func_t *func,
                                std::ofstream &file, int &linecount,
                                Dwarf_Unsigned file_index,
                                type_record_t &record) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;
  die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, nullptr, nullptr, nullptr,
                      &err);
  if (die == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  // Add function bounds
  dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, func->startEA, 0, &err);
  dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, func->endEA, 0, &err);

  // Add location declaration
  dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, &err);
  dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, &err);

  // Add frame base
  // TODO: what to do for non-bp based frames
  Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
  if (dwarf_add_expr_gen(loc_expr, DW_OP_call_frame_cfa, 0, 0, &err) ==
      DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
  }
  if (dwarf_add_AT_location_expr(dbg, die, DW_AT_frame_base, loc_expr, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_location_expr failed: ", dwarf_errmsg(err));
  }

  // Add function name
  auto name = get_long_name(func->startEA);
  char *c_name = &*name.begin();
  printf("Processing %s\n", c_name);

  if (dwarf_add_AT_name(die, c_name, &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  auto mangled_name = get_true_name(func->startEA);
  if (dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, &mangled_name[0],
                          &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_string failed: ", dwarf_errmsg(err));
  }

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(func, &hf);

  if (cfunc == nullptr) {
    return die;
  }

  // Add ret type
  tinfo_t func_type_info;
  if (cfunc->get_func_type(&func_type_info)) {
    auto rettype = func_type_info.get_rettype();
    auto rettype_die = get_or_add_type(dbg, cu, rettype, record);

    if (dwarf_add_AT_reference(dbg, die, DW_AT_type, rettype_die, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }
  }

  auto &lvars = *cfunc->get_lvars();
  for (std::size_t i = 0; i < lvars.size(); ++i) {
    if (lvars[i].name.size()) {
      add_variable(dbg, cu, die, cfunc, lvars[i], record);
    }
  }

  // Add line info
  const auto &sv = cfunc->get_pseudocode();
  for (std::size_t i = 0; i < sv.size(); ++i) {
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

      dwarf_add_line_entry(dbg, file_index, addr, linecount, 0, true, false,
                           &err);
      break;
    }
  }

  return die;
}

void add_debug_info(Dwarf_P_Debug dbg, std::ofstream &sourcefile,
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
  type_record_t record;

  for (func_t *f = get_func(seg->startEA); f != nullptr;
       f = get_next_func(f->startEA)) {
    if (f->startEA > seg->endEA) {
      break;
    }

    add_function(dbg, cu, f, sourcefile, linecount, file_index, record);

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

#ifdef __NT__
    char *filepath_end = strrchr(filepath, '\\');
#else
    char *filepath_end = strrchr(filepath, '/');
#endif
    if (filepath_end != nullptr) {
      *(filepath_end + 1) = '\0';
    }

    const char *dialog = "STARTITEM 0\n"
                         "Dwarf Export\n\n"
                         "Select the location to save the exported data:\n"
                         "<Save:F:1:::>\n";

    if (AskUsingForm_c(dialog, filepath) == 1) {
      auto elf_filename = std::string(filename) + ".elf";
      auto c_filename = std::string(filename) + ".c";

      std::ofstream sourcefile(filepath + c_filename);

      Mode m = (sizeof(ea_t) == 4) ? (Mode::BIT32) : (Mode::BIT64);
      auto info = generate_dwarf_object(m);
      add_debug_info(info->dbg, sourcefile, filepath, c_filename);
      write_dwarf_file(m, info, filepath + elf_filename);
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
