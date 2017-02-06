#include <iostream>
#include <idp.hpp>


#include "dwarfexport.h"

/**
 * IDA uses a different register numbering scheme internally, so
 * we need to convert that to the DWARF one.
 *
 * FIXME: for some reason, this doesn't work for registers when used
 *        to pass arguments.
 */

// For both amd64 and i386, IDA produces the following register list:
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

int translate_register_num(int ida_reg_num) {
  auto reg_num = (ida_reg_num / 8) - 1;
  if (reg_num == -1) {
    return -1;
  }

  switch (ph.id) {
  case PLFM_386:
    return (inf.is_64bit()) ? translate_amd64(reg_num)
                            : translate_i386(reg_num);
  default:
    return -1;
  }
}
