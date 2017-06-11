#include <cstdio>
#include <cstdlib>
#include <frame.hpp>
#include <ida.hpp>
#include <struct.hpp>

#include "dwarfexport.h"

/**
 * IDA uses a different register numbering scheme internally, so
 * we need to convert that to the DWARF one.
 *
 * FIXME: for some reason, this doesn't work for registers when used
 *        to pass arguments.
 */

// For both amd64 and i386, IDA produces the following register list:
//
//   idaapi.ph_get_regnames() =
//   ['ax', 'cx', 'dx', 'bx', 'sp', 'bp',
//    'si', 'di', 'r8', 'r9', 'r10', 'r11',
//    'r12', 'r13', 'r14', 'r15', 'al',
//    'cl', 'dl', 'bl', 'ah', 'ch', 'dh',
//    'bh', 'spl', 'bpl', 'sil', 'dil', 'ip',
//    'es', 'cs', 'ss', 'ds', 'fs', 'gs', 'cf',
//    'zf', 'sf', 'of', 'pf', 'af', 'tf', 'if',
//    'df', 'efl', 'st0', 'st1', 'st2', 'st3',
//    'st4', 'st5', 'st6', 'st7', 'fpctrl',
//    'fpstat', 'fptags', 'mm0', 'mm1', 'mm2',
//    'mm3', 'mm4', 'mm5', 'mm6', 'mm7', 'xmm0',
//    'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5',
//    'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10',
//    'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
//    'mxcsr', 'ymm0', 'ymm1', 'ymm2', 'ymm3',
//    'ymm4', 'ymm5', 'ymm6', 'ymm7', 'ymm8',
//    'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13',
//    'ymm14', 'ymm15', 'bnd0', 'bnd1', 'bnd2',
//    'bnd3', 'xmm16', 'xmm17', 'xmm18', 'xmm19',
//    'xmm20', 'xmm21', 'xmm22', 'xmm23', 'xmm24',
//    'xmm25', 'xmm26', 'xmm27', 'xmm28', 'xmm29',
//    'xmm30', 'xmm31', 'ymm16', 'ymm17', 'ymm18',
//    'ymm19', 'ymm20', 'ymm21', 'ymm22', 'ymm23',
//    'ymm24', 'ymm25', 'ymm26', 'ymm27', 'ymm28',
//    'ymm29', 'ymm30', 'ymm31', 'zmm0', 'zmm1',
//    'zmm2', 'zmm3', 'zmm4', 'zmm5', 'zmm6', 'zmm7',
//    'zmm8', 'zmm9', 'zmm10', 'zmm11', 'zmm12',
//    'zmm13', 'zmm14', 'zmm15', 'zmm16', 'zmm17',
//    'zmm18', 'zmm19', 'zmm20', 'zmm21', 'zmm22',
//    'zmm23', 'zmm24', 'zmm25', 'zmm26', 'zmm27',
//    'zmm28', 'zmm29', 'zmm30', 'zmm31', 'k0', 'k1',
//    'k2', 'k3', 'k4', 'k5', 'k6', 'k7']

static int translate_amd64(int ida_reg_num) {

  // Numbers from http://source.winehq.org/source/dlls/dbghelp/cpu_x86_64.c#L739
  enum AMD64 {
    RAX = 0,
    RDX = 1,
    RCX = 2,
    RBX = 3,
    RSI = 4,
    RDI = 5,
    RBP = 6,
    RSP = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    RIP = 16,

    XMM0 = 17,

    ST0 = 33,
    ST1 = 34,
    ST2 = 35,
    ST3 = 36,
    ST4 = 37,
    ST5 = 38,
    ST6 = 39,
    ST7 = 40,

    EFLAGS = 49,
    ES = 50,
    CS = 51,
    SS = 52,
    DS = 53,
    FS = 54,
    GS = 55,

    TR = 62,
    LDTR = 63,
    MXCSR = 64,
    CTRL = 65,
    STAT = 66
  };

  int low_number_mapping[] = {
      RAX,    RCX,    RDX,    RBX,    RSP,    RBP,    RSI,    RDI,
      R8,     R9,     R10,    R11,    R12,    R13,    R14,    R15,
      RAX,    RCX,    RDX,    RBX,    RAX,    RCX,    RDX,    RBX,
      RSP,    RBP,    RSI,    RDI,

      -1, // ip?

      ES,     CS,     SS,     DS,     FS,     GS,     EFLAGS, EFLAGS,
      EFLAGS, EFLAGS, EFLAGS, EFLAGS, EFLAGS, EFLAGS, EFLAGS, EFLAGS,

      ST0,    ST1,    ST2,    ST3,    ST4,    ST5,    ST6,    ST7,

      CTRL,   STAT,

      -1 // fptags?
  };

  if (ida_reg_num < 56) {
    return low_number_mapping[ida_reg_num];
  } else if (ida_reg_num >= 56 && ida_reg_num < 64) {
    return XMM0 + (ida_reg_num - 56);
  } else if (ida_reg_num >= 64 && ida_reg_num < 80) {
    return XMM0 + (ida_reg_num - 64);
  } else {
    return -1;
  }
}

static int translate_i386(int ida_reg_num) {
  // Numbers from http://source.winehq.org/source/dlls/dbghelp/cpu_i386.c#L517
  enum I386 {
    EAX = 0,
    ECX = 1,
    EDX = 2,
    EBX = 3,
    ESP = 4,
    EBP = 5,
    ESI = 6,
    EDI = 7,
    EIP = 8,
    EFLAGS = 9,

    CS = 10,
    SS = 11,
    DS = 12,
    ES = 13,
    FS = 14,
    GS = 15,

    ST0 = 16,
    ST1 = 17,
    ST2 = 18,
    ST3 = 19,
    ST4 = 20,
    ST5 = 21,
    ST6 = 22,
    ST7 = 23,

    CTRL = 24,
    STAT = 25,
    TAG = 25,

    FPCS = 26,
    FPIP = 27,
    FPDS = 29,
    FPDO = 30,

    XMM0 = 32,

    MXCSR = 40
  };

  int low_number_mapping[] = {
      EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
  };

  if (ida_reg_num <
      sizeof(low_number_mapping) / sizeof(low_number_mapping[0])) {
    return low_number_mapping[ida_reg_num];
  } else {
    return -1;
  }
}

// http://infocenter.arm.com/help/topic/com.arm.doc.ihi0040b/IHI0040B_aadwarf.pdf
//
// idaapi.ph_get_regnames() =
//   ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11',
//    'R12', 'SP', 'LR', 'PC', 'CPSR', 'CPSR_flg', 'SPSR', 'SPSR_flg', 'T',
//    'CS', 'DS', 'acc0', 'FPSID', 'FPSCR', 'FPEXC', 'FPINST', 'FPINST2',
//    'MVFR0', 'MVFR1', 'APSR', 'IAPSR', 'EAPSR', 'XPSR', 'IPSR', 'EPSR',
//    'IEPSR', 'MSP', 'PSP', 'PRIMASK', 'BASEPRI', 'BASEPRI_MAX', 'FAULTMASK',
//    'CONTROL', 'Q0', 'Q1', 'Q2', 'Q3', 'Q4', 'Q5', 'Q6', 'Q7', 'Q8', 'Q9',
//    'Q10', 'Q11', 'Q12','Q13', 'Q14', 'Q15', 'D0', 'D1', 'D2', 'D3', 'D4',
//    'D5', 'D6', 'D7', 'D8', 'D9', 'D10', 'D11', 'D12', 'D13', 'D14', 'D15',
//    'D16', 'D17', 'D18', 'D19', 'D20', 'D21', 'D22', 'D23', 'D24', 'D25',
//    'D26', 'D27', 'D28', 'D29', 'D30', 'D31', 'S0', 'S1', 'S2', 'S3', 'S4',
//    'S5', 'S6', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12', 'S13', 'S14', 'S15',
//    'S16', 'S17', 'S18', 'S19', 'S20', 'S21', 'S22', 'S23', 'S24', 'S25',
//    'S26', 'S27', 'S28', 'S29', 'S30', 'S31', 'CF', 'ZF', 'NF', 'VF', 'X0',
//    'X1', 'X2', 'X3', 'X4', 'X5', 'X6', 'X7', 'X8', 'X9', 'X10', 'X11', 'X12',
//    'X13', 'X14', 'X15', 'X16', 'X17', 'X18', 'X19', 'X20', 'X21', 'X22',
//    'X23', 'X24', 'X25', 'X26', 'X27', 'X28', 'X29', 'X30', 'XZR', 'SP', 'PC',
//    'V0', 'V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7', 'V8', 'V9', 'V10', 'V11',
//    'V12', 'V13', 'V14', 'V15', 'V16', 'V17', 'V18', 'V19', 'V20', 'V21',
//    'V22', 'V23', 'V24', 'V25', 'V26', 'V27', 'V28', 'V29', 'V30', 'V31']
static int translate_arm(int ida_reg_num) {
  enum ARM {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    SP = 13,
    LR = 14,
    PC = 15,
    CPSR = 16,
  };

  int low_number_mapping[] = {R0, R1,  R2,  R3,  R4, R5, R6, R7,  R8,
                              R9, R10, R11, R12, SP, LR, PC, CPSR};
  if (ida_reg_num <
      sizeof(low_number_mapping) / sizeof(low_number_mapping[0])) {
    return low_number_mapping[ida_reg_num];
  } else {
    return -1;
  }
}

int translate_register_num(int ida_reg_num) {
  auto reg_num = (ida_reg_num / 8) - 1;
  if (reg_num == -1) {
    return -1;
  }

  switch (ph.id) {
  case PLFM_386:
    return (inf.is_64bit()) ? translate_amd64(reg_num)
                            : translate_i386(reg_num);
  case PLFM_ARM:
    return (inf.is_64bit()) ? -1 : translate_arm(reg_num);
  default:
    return -1;
  }
}

static bool decompiler_lvar_reg_and_offset(cfuncptr_t cfunc, const lvar_t &var,
                                           int *reg, int *offset) {
  // FIXME: Due to current IDA limitations, stkoff may not always return a
  //        useful value: https://forum.hex-rays.com/viewtopic.php?f=4&t=4154
  switch (ph.id) {
  case PLFM_386:
    if (inf.is_64bit()) {
      *reg = DW_OP_breg7; // rsp
      *offset = var.location.stkoff();
    } else {
      *reg = DW_OP_breg5; // ebp
      auto func = get_func(cfunc->entry_ea);
      auto correct_stack_offset = var.location.stkoff() - 8;
      *offset = -(func->frsize - correct_stack_offset);
    }
    return true;
  case PLFM_ARM:
    if (inf.is_64bit()) {
      return false;
    } else {
      *reg = DW_OP_breg13; // SP
      *offset = var.location.stkoff();
    }
  default:
    return false;
  }
}

Dwarf_P_Expr decompiler_stack_lvar_location(Dwarf_P_Debug dbg, cfuncptr_t cfunc,
                                            const lvar_t &var) {
  Dwarf_Error err = 0;
  Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);

  int stack_reg, stack_offset;
  if (!decompiler_lvar_reg_and_offset(cfunc, var, &stack_reg, &stack_offset)) {
    dwarfexport_error("decompiler_lvar_reg_and_offset failed");
  }

  if (dwarf_add_expr_gen(loc_expr, stack_reg, stack_offset, 0, &err) ==
      DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
  }
  return loc_expr;
}

static bool disassembler_lvar_reg_and_offset(func_t *func, member_t *member,
                                             int *reg, int *offset) {
  switch (ph.id) {
  case PLFM_386:
    if (inf.is_64bit()) {
      *reg = DW_OP_breg7; // rsp
      *offset = member->soff;
    } else {
      *reg = DW_OP_breg5; // ebp

      auto frame = get_frame(func);
      auto size = get_struc_size(frame->id);
      auto saved_regs = get_member_by_name(frame, " s");
      if (saved_regs == nullptr) {
        return false;
      }
      auto saved_regs_off = saved_regs->soff;
      auto s_offset = size - (size - saved_regs_off);
      int offset_from_base = member->soff - s_offset;

      if (offset_from_base > 0) {
        offset_from_base += 16;
      }
      *offset = offset_from_base;
    }
    return true;
  case PLFM_ARM:
    if (inf.is_64bit()) {
      return false;
    } else {
      *reg = DW_OP_breg11; // r11

      auto frame = get_frame(func);
      auto size = get_struc_size(frame->id);

      // NOTE: This assumes arm saved-registers is always 4 on 32 bit platforms.
      //       Needed because there is no magic ' s' member for arm.
      auto saved_regs_off = size - 4;
      auto s_offset = size - (size - saved_regs_off);
      int offset_from_base = member->soff - s_offset;
      *offset = offset_from_base;
    }
    return true;
  default:
    return false;
  }
}

Dwarf_P_Expr disassembler_stack_lvar_location(Dwarf_P_Debug dbg, func_t *func,
                                              member_t *member) {
  Dwarf_Error err = 0;
  Dwarf_P_Expr loc_expr = dwarf_new_expr(dbg, &err);

  int stack_reg, stack_offset;
  if (!disassembler_lvar_reg_and_offset(func, member, &stack_reg,
                                        &stack_offset)) {
    return nullptr;
  }

  if (dwarf_add_expr_gen(loc_expr, stack_reg, stack_offset, 0, &err) ==
      DW_DLV_NOCOUNT) {
    dwarfexport_error("dwarf_add_expr_gen failed: ", dwarf_errmsg(err));
  }

  return loc_expr;
}
