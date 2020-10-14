
#include <cstdio>
#include <cstdlib>
#include <frame.hpp>
#include <fstream>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <string>
#include <struct.hpp>

#include "dwarfexport.h"

static bool has_decompiler = false;
std::ofstream logger;
hexdsp_t *hexdsp = NULL;

// A mapping of IDA types to dwarf types
using type_record_t = std::map<tinfo_t, Dwarf_P_Die>;

/**
 * Add a dwarf type definitions to the compilation unit 'cu' representing
 * the IDA type 'type'. This is implemented for structs, const types,
 * arrays, and pointer types using the following 'add_*_type' functions.
 *
 * @returns The dwarf DIE associated with the new type (or the existing one)
 */
static Dwarf_P_Die get_or_add_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record);

static Dwarf_P_Die add_struct_type(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                   const tinfo_t &type, type_record_t &record) {
  if (!type.is_struct()) {
    dwarfexport_error("add_struct_type: type is not struct");
  }

  dwarfexport_log("Adding structure type");

  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_structure_type, cu, NULL, NULL, NULL, &err);
  record[type] = die;

  // Add type name
  std::string name = type.dstr();
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  dwarfexport_log("  Name = ", name);

  // Add type size
  auto size = type.get_size();
  if (size != BADSIZE &&
      dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) ==
          NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }

  dwarfexport_log("  Size = ", size);

  auto member_count = type.get_udt_nmembers();
  if (member_count == -1) {
    dwarfexport_error("add_struct_type: get_udt_nmembers error");
  }

  dwarfexport_log("  Member Count = ", member_count);

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

    dwarfexport_log("  Adding Member: ", &member_name[0]);

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

  dwarfexport_log("Adding array type");

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
    elems -= 1;

    dwarfexport_log("  Number of elements = ", elems);

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

  dwarfexport_log("Adding const type");

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

  dwarfexport_log("Adding pointer type");

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

  dwarfexport_log("Adding new type");

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

  dwarfexport_log("  Name = ", name);

  // Add type size
  std::size_t size = type.get_size();
  if (size != BADSIZE &&
      dwarf_add_AT_unsigned_const(dbg, die, DW_AT_byte_size, size, &err) ==
          NULL) {
    dwarfexport_error("dwarf_add_AT_unsigned_const failed: ",
                      dwarf_errmsg(err));
  }

  dwarfexport_log("  Size = ", size);

  record[type] = die;
  return die;
}

/**
 * For a given IDA decompiler variable 'var' from a given function
 * 'cfunc', add a dwarf variable to the provided function DIE 'func_die'.
 *
 * * @returns The dwarf DIE associated with the new variable
 */
static Dwarf_P_Die add_variable(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                                Dwarf_P_Die func_die, cfuncptr_t cfunc,
                                const lvar_t &var, type_record_t &record) {
  Dwarf_P_Die die;
  Dwarf_Error err = 0;

  die = dwarf_new_die(dbg, DW_TAG_variable, func_die, NULL, NULL, NULL, &err);

  // Add var type. We could check for 'typed' here, but this is sometimes
  // returns strange values (bug?), and I think lvars in the decompiled view
  // must be types, so skip the check.
  auto var_type = var.type();
  auto var_type_die = get_or_add_type(dbg, cu, var_type, record);
  if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
      nullptr) {
    dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
  }

  auto name = var.name;
  if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  dwarfexport_log("Adding local variable: ", &name[0]);

  if (var.is_stk_var()) {
    auto loc_expr = decompiler_stack_lvar_location(dbg, cfunc, var);
    if (loc_expr) {
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    }
  } else if (!var.is_arg_var() && var.location.is_reg1()) {
    // Try to get the DWARF register number from the IDA register number.
    // For whatever reason, the mapping is different for registers when
    // passing arguments, so we don't do those.
    auto reg_num = translate_register_num(var.location.reg1());

    if (reg_num != -1) {
      dwarfexport_log("Translated IDA register #", var.location.reg1(), " to #",
                      reg_num);

      Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
      if (dwarf_add_expr_gen(loc_expr, DW_OP_regx, reg_num, 0, &err) ==
          DW_DLV_NOCOUNT) {
        dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
      }
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    } else {
      dwarfexport_log("Unable to translate register #", reg_num);
    }
  }

  return die;
}

/**
 * Adds a DWARF variable to the provided function 'func_die' for each
 * variable in the IDA disassembly view.
 */
static void add_disassembler_func_info(std::shared_ptr<DwarfGenInfo> info,
                                       Dwarf_P_Die func_die, Dwarf_P_Die cu,
                                       func_t *func, type_record_t &record) {
  auto dbg = info->dbg;
  Dwarf_Error err = 0;

  auto frame = get_frame(func);
  if (frame == nullptr) {
    return;
  }

  for (std::size_t i = 0; i < frame->memqty; ++i) {
    auto name = get_member_name2(frame->members[i].id);

    // Ignore these special 'variables'
    if (name == " s" || name == " r") {
      continue;
    }

    dwarfexport_log("Adding local variable: ", &name[0]);

    Dwarf_P_Die die;
    die = dwarf_new_die(dbg, DW_TAG_variable, func_die, NULL, NULL, NULL, &err);

    if (dwarf_add_AT_name(die, &name[0], &err) == NULL) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    auto loc_expr =
        disassembler_stack_lvar_location(dbg, func, &frame->members[i]);

    if (loc_expr == nullptr) {
      continue;
    }

    auto member_struct = get_sptr(&frame->members[i]);
    if (member_struct) {
      tinfo_t type;
      if (guess_tinfo2(member_struct->id, &type) == GUESS_FUNC_OK) {
        auto var_type_die = get_or_add_type(dbg, cu, type, record);
        if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
            nullptr) {
          dwarfexport_error("dwarf_add_AT_reference failed: ",
                            dwarf_errmsg(err));
        }
      }
    }

    if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                        dwarf_errmsg(err));
    }
  }
}

/**
 * Adds a DWARF variable to the provided function 'func_die' for each
 * variable in the IDA decompiler view.
 *
 * @param info A handle returned by a previous call to 'generate_dwarf_object'
 * @param cu   The dwarf compilation unit containing the function
 * @param func_die The dwarf function to add variables and line info for
 * @param func The IDA function handle for this function
 * @param file An output file stream used for storing the decompiled source
 * @param linecount The current number of lines in 'file'
 * @param file_index The dwarf file index associated with 'cu'
 * @param symbol_index The symbol index associated with the function (unused)
 * @param record The type record to update when adding variable types
 */
static void add_decompiler_func_info(std::shared_ptr<DwarfGenInfo> info,
                                     Dwarf_P_Die cu, Dwarf_P_Die func_die,
                                     func_t *func, std::ostream &file,
                                     int &linecount, Dwarf_Unsigned file_index,
                                     Dwarf_Unsigned symbol_index,
                                     type_record_t &record) {
  auto dbg = info->dbg;
  auto err = info->err;

  hexrays_failure_t hf;
  cfuncptr_t cfunc = decompile(func, &hf);

  if (cfunc == nullptr) {
    dwarfexport_log("Failed to decompile function at ", func->startEA);
    return;
  }

  // Add lvars (from decompiler)
  auto &lvars = *cfunc->get_lvars();
  for (std::size_t i = 0; i < lvars.size(); ++i) {
    if (lvars[i].name.size()) {
      add_variable(dbg, cu, func_die, cfunc, lvars[i], record);
    }
  }

  // Add line info
  const auto &sv = cfunc->get_pseudocode();
  const auto &bounds = cfunc->get_boundaries();
  const auto &eamap = cfunc->get_eamap();
  ea_t previous_line_addr = 0;
  for (std::size_t i = 0; i < sv.size(); ++i, ++linecount) {
    char buf[MAXSTR];
    const char *line = sv[i].line.c_str();
    tag_remove(line, buf, MAXSTR);

    auto stripped_buf = std::string(buf);
    file << stripped_buf + "\n";

    dwarfexport_log("Processing line: ", stripped_buf);

    ctree_item_t item;
    std::size_t index = stripped_buf.find_first_not_of(' ');
    if (index == std::string::npos) {
      continue;
    }

    // For each column in the line, try to find a cexpr_t that has an
    // address inside the function, then emit a dwarf source line info
    // for that.
    ea_t lowest_line_addr = 0, highest_line_addr = 0;
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

      // Get the bounds of the expression. This fixes issues where the arguments
      // to a multi-line function call were not correctly handled.
      ea_t expr_lowest_addr = addr, expr_highest_addr = addr;
      if (eamap.count(addr)) {
        const auto &expr_areaset = bounds.at(eamap.at(addr).at(0));

        // TODO: the area set may not be sorted this way
        expr_lowest_addr = expr_areaset.getarea(0).startEA;
        expr_highest_addr = expr_areaset.lastarea().endEA - 1;
      }

      // In some situations, there are multiple lines that have the same
      // 'lowest' point. To avoid mapping multiple lines to the same address, we
      // try to ensure that the address associated with a given line is the
      // lowest one that is still higher than the highest address of the
      // previous line.
      if (!lowest_line_addr || expr_lowest_addr < lowest_line_addr) {
        if (!previous_line_addr || expr_lowest_addr > previous_line_addr) {
          lowest_line_addr = expr_lowest_addr;
        }
      }
      if (!highest_line_addr || expr_highest_addr > highest_line_addr) {
        highest_line_addr = expr_highest_addr;
      }
    }

    if (!lowest_line_addr && highest_line_addr &&
        highest_line_addr > previous_line_addr) {
      lowest_line_addr = previous_line_addr + 1;
    }
    if (lowest_line_addr) {
      dwarfexport_log("Mapping line #", linecount, " to address ",
                      lowest_line_addr);
      dwarf_lne_set_address(dbg, lowest_line_addr, 0, &err);
      dwarf_add_line_entry(dbg, file_index, lowest_line_addr, linecount, index,
                           true, false, &err);
      previous_line_addr = highest_line_addr;
    }
  }

  // Add a little space between the functions
  file << "\n\n";
  linecount += 2;
}

static Dwarf_P_Die add_function(std::shared_ptr<DwarfGenInfo> info,
                                Options &options, Dwarf_P_Die cu, func_t *func,
                                std::ostream &file, int &linecount,
                                Dwarf_Unsigned file_index,
                                type_record_t &record) {
  auto dbg = info->dbg;
  auto err = info->err;
  Dwarf_P_Die die;
  die = dwarf_new_die(dbg, DW_TAG_subprogram, cu, nullptr, nullptr, nullptr,
                      &err);
  if (die == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

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

  if (dwarf_add_AT_name(die, c_name, &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
  }

  auto mangled_name = get_true_name(func->startEA);
  if (dwarf_add_AT_string(dbg, die, DW_AT_linkage_name, &mangled_name[0],
                          &err) == nullptr) {
    dwarfexport_error("dwarf_add_AT_string failed: ", dwarf_errmsg(err));
  }

  dwarfexport_log("Adding function ", &name[0], " (", &mangled_name[0], ")");

  // Add ret type
  tinfo_t func_type_info;
  if (get_tinfo2(func->startEA, &func_type_info)) {
    auto rettype = func_type_info.get_rettype();
    auto rettype_die = get_or_add_type(dbg, cu, rettype, record);
    if (dwarf_add_AT_reference(dbg, die, DW_AT_type, rettype_die, &err) ==
        nullptr) {
      dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
    }
  }

  // Add function bounds
  dwarf_add_AT_targ_address(dbg, die, DW_AT_low_pc, func->startEA, 0, &err);
  dwarf_add_AT_targ_address(dbg, die, DW_AT_high_pc, func->endEA - 1, 0, &err);

  auto is_named = has_name(getFlags(func->startEA));
  if (has_decompiler && options.use_decompiler() &&
      (!options.only_decompile_named_funcs() ||
       (options.only_decompile_named_funcs() && is_named))) {

    // Add location declaration
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_file, file_index, &err);
    dwarf_add_AT_unsigned_const(dbg, die, DW_AT_decl_line, linecount, &err);

    // The start of every function should have a line entry
    dwarf_add_line_entry(dbg, file_index, func->startEA, linecount, 0, true,
                         false, &err);

    add_decompiler_func_info(info, cu, die, func, file, linecount, file_index,
                             0, record);
  } else {
    add_disassembler_func_info(info, cu, die, func, record);
  }

  return die;
}

/**
 * Add all structures to the debug output. This is useful for allowing casts
 * to types in the debugger that may not have actually been used at the time
 * the debug info was being exported.
 */
void add_structures(Dwarf_P_Debug dbg, Dwarf_P_Die cu, type_record_t &record) {
  dwarfexport_log("Adding unused types");
  for (auto idx = get_first_struc_idx(); idx != BADADDR;
       idx = get_next_struc_idx(idx)) {
    auto tid = get_struc_by_idx(idx);
    tinfo_t type;

    if (guess_tinfo2(tid, &type) == GUESS_FUNC_OK) {
      get_or_add_type(dbg, cu, type, record);
    }
  }
}

/**
 * Add dwarf info for the global variables in this file. These entries are
 * not given a textual representation, only a location and type.
 */
void add_global_variables(Dwarf_P_Debug dbg, Dwarf_P_Die cu,
                          type_record_t &record) {
  dwarfexport_log("Adding global variables");
  Dwarf_Error err = 0;
  auto seg_count = get_segm_qty();

  for (auto i = 0; i < seg_count; ++i) {
    auto seg = getnseg(i);
    if (seg->type != SEG_DATA && seg->type != SEG_BSS) {
      continue;
    }

    for (auto addr = seg->startEA; addr < seg->endEA; ++addr) {
      char name[MAXSTR];
      if (!get_name(BADADDR, addr, name, MAXSTR)) {
        continue;
      }

      tinfo_t type;
      if (guess_tinfo2(addr, &type) != GUESS_FUNC_OK) {
        continue;
      }

      dwarfexport_log("Adding global variable");
      dwarfexport_log("  name = ", name);
      dwarfexport_log("  location = ", addr);

      auto die =
          dwarf_new_die(dbg, DW_TAG_variable, cu, NULL, NULL, NULL, &err);
      auto var_type_die = get_or_add_type(dbg, cu, type, record);

      if (dwarf_add_AT_name(die, name, &err) == NULL) {
        dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
      }

      if (dwarf_add_AT_reference(dbg, die, DW_AT_type, var_type_die, &err) ==
          nullptr) {
        dwarfexport_error("dwarf_add_AT_reference failed: ", dwarf_errmsg(err));
      }

      // FIXME: this won't work in shared libs
      Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);
      if (dwarf_add_expr_addr_b(loc_expr, addr, 0, &err) == DW_DLV_NOCOUNT) {
        dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
      }
      if (dwarf_add_AT_location_expr(dbg, die, DW_AT_location, loc_expr,
                                     &err) == nullptr) {
        dwarfexport_error("dwarf_add_AT_location_expr failed: ",
                          dwarf_errmsg(err));
      }
    }
  }
}

void add_debug_info(std::shared_ptr<DwarfGenInfo> info,
                    std::ostream &sourcefile, Options &options) {
  auto dbg = info->dbg;
  auto err = info->err;
  Dwarf_P_Die cu;
  cu = dwarf_new_die(dbg, DW_TAG_compile_unit, nullptr, nullptr, nullptr,
                     nullptr, &err);
  if (cu == nullptr) {
    dwarfexport_error("dwarf_new_die failed: ", dwarf_errmsg(err));
  }

  Dwarf_Unsigned file_index = 0;
  if (options.use_decompiler()) {
    if (dwarf_add_AT_name(cu, &options.c_filename()[0], &err) == nullptr) {
      dwarfexport_error("dwarf_add_AT_name failed: ", dwarf_errmsg(err));
    }

    auto dir_index =
        dwarf_add_directory_decl(dbg, &options.dwarf_source_path[0], &err);
    file_index = dwarf_add_file_decl(dbg, &options.c_filename()[0], dir_index,
                                     0, 0, &err);

    dwarf_add_AT_comp_dir(cu, &options.dwarf_source_path[0], &err);
  }

  int linecount = 1;
  type_record_t record;
  auto seg_qty = get_segm_qty();
  for (std::size_t segn = 0; segn < seg_qty; ++segn) {
    auto seg = getnseg(segn);
    if (seg == nullptr) {
      dwarfexport_error("Unable to getnseg() segment number ", segn);
    }

    // Only consider EXEC segments
    // TODO: Skip plt/got?
    if (!(seg->perm & SEGPERM_EXEC) && seg->type != SEG_CODE) {
      dwarfexport_log("Segment #", segn, " is not executable. Skipping.");
      continue;
    }

    char segname[MAXSTR];
    get_true_segm_name(seg, segname, sizeof(segname));
    dwarfexport_log("Adding functions from: ", segname);

    func_t *f = get_func(seg->startEA);
    if (f == nullptr) {
      // In some cases, the start of the section may not actually be a function,
      // so get the first available function.
      f = get_next_func(seg->startEA);

      if (f == nullptr) {
        dwarfexport_log("Skipping ", lsegname, " because it has no functions");
        continue;
      }
    }

    for (; f != nullptr; f = get_next_func(f->startEA)) {
      if (f->startEA > seg->endEA) {
        break;
      }

      add_function(info, options, cu, f, sourcefile, linecount, file_index,
                   record);
    }

    if (dwarf_add_die_to_debug(dbg, cu, &err) != DW_DLV_OK) {
      dwarfexport_error("dwarf_add_die_to_debug failed: ", dwarf_errmsg(err));
    }
  }

  // Add the global variables (but don't add a file location)
  add_global_variables(dbg, cu, record);

  // Add any other structures
  add_structures(dbg, cu, record);
}

int idaapi init(void) {
  if (init_hexrays_plugin()) {
    msg("dwarfexport: Using decompiler\n");
    has_decompiler = true;
  } else {
    msg("dwarfexport: No decompiler found\n");
  }
  return PLUGIN_OK;
}

void idaapi run(int) {
  try {
    auto default_options =
        (has_decompiler) ? Options::ATTACH_DEBUG_INFO | Options::USE_DECOMPILER
                         : Options::ATTACH_DEBUG_INFO;
    Options options(".", default_options);

    get_input_file_path(options.filepath, QMAXPATH);
    get_root_filename(options.filename, QMAXPATH);

    char *filepath_end = strrchr(options.filepath, PATH_SEP);
    if (filepath_end != nullptr) {
      *(filepath_end + 1) = '\0';
    }

    const char *dialog = "STARTITEM 0\n"
                         "Dwarf Export\n\n"
                         "Select the location to save the exported data:\n"
                         "<Save:F:1:::>\n"
                         "Export Options\n <Use Decompiler:C>\n"
                         "<Only Decompile Named Functions:C>\n"
                         "<Attach Debug Info:C>\n"
                         "<Verbose:C>>\n";

    if (AskUsingForm_c(dialog, options.filepath, &options.export_options) ==
        1) {

      if (options.verbose()) {
        logger = std::ofstream("dwarfexport.log");
        msg("Verbose mode enabled. Logging to dwarfexport.log\n");
      }

      if (!options.attach_debug_info()) {
        dwarfexport_log("Generating detached debug info");
      }
      if (options.only_decompile_named_funcs()) {
        dwarfexport_log("Only decompiling named functions");
      }

      std::ofstream sourcefile;
      if (options.use_decompiler()) {
        dwarfexport_log("Using decompiler with exported source filename: ",
                        options.c_filename());
        sourcefile = std::ofstream(options.c_filename());
      }

      dwarfexport_log("Setting up DWARF object");
      auto info = generate_dwarf_object(options);

      dwarfexport_log("Adding DWARF debug information");
      add_debug_info(info, sourcefile, options);

      dwarfexport_log("Writing out DWARF file to disk");
      write_dwarf_file(info, options);
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
