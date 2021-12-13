/*
$info$
tags: frontend|x86-tables
$end_info$
*/

#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Debug/X86Tables.h>
#include <FEXCore/Core/Context.h>

#include <iterator>
#include <stdint.h>

namespace FEXCore::X86Tables {
using namespace InstFlags;

#define OPD(REX, prefix, opcode) ((REX << 9) | (prefix << 8) | opcode)
  constexpr uint16_t PF_3A_NONE = 0;
  constexpr uint16_t PF_3A_66   = 1;

  constexpr U16U8InfoStructTable H0F3ATable = {{
    {OPD(0, PF_3A_NONE, 0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_INST, GenFlagsSameSize(SIZE_64BIT)  | FLAGS_MODRM | FLAGS_XMM_FLAGS | FLAGS_SF_MMX, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x08), 1, X86InstInfo{"ROUNDPS",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x09), 1, X86InstInfo{"ROUNDPD",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x0A), 1, X86InstInfo{"ROUNDSS",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x0B), 1, X86InstInfo{"ROUNDSD",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x0C), 1, X86InstInfo{"BLENDPS",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x0D), 1, X86InstInfo{"BLENDPD",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x0E), 1, X86InstInfo{"PBLENDW",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},

    {OPD(0, PF_3A_66,   0x14), 1, X86InstInfo{"PEXTRB",          TYPE_INST, GenFlagsSizes(SIZE_8BIT, SIZE_128BIT) | FLAGS_MODRM | FLAGS_SF_MOD_DST | FLAGS_SF_DST_GPR | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x15), 1, X86InstInfo{"PEXTRW",          TYPE_INST, GenFlagsSizes(SIZE_16BIT, SIZE_128BIT) | FLAGS_MODRM | FLAGS_SF_MOD_DST | FLAGS_SF_DST_GPR | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x16), 1, X86InstInfo{"PEXTRD",          TYPE_INST, GenFlagsSizes(SIZE_32BIT, SIZE_128BIT) | FLAGS_MODRM | FLAGS_SF_MOD_DST | FLAGS_SF_DST_GPR | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x17), 1, X86InstInfo{"EXTRACTPS",       TYPE_INST, GenFlagsSizes(SIZE_32BIT, SIZE_128BIT) | FLAGS_MODRM | FLAGS_SF_MOD_DST | FLAGS_SF_DST_GPR | FLAGS_XMM_FLAGS, 1, nullptr}},

    {OPD(0, PF_3A_66,   0x20), 1, X86InstInfo{"PINSRB",          TYPE_INST, GenFlagsDstSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS | FLAGS_SF_SRC_GPR,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x21), 1, X86InstInfo{"INSERTPS",        TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x22), 1, X86InstInfo{"PINSRD",          TYPE_INST, GenFlagsSizes(SIZE_128BIT, SIZE_32BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS | FLAGS_SF_SRC_GPR,           1, nullptr}},
    {OPD(0, PF_3A_66,   0x40), 1, X86InstInfo{"DPPS",            TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x41), 1, X86InstInfo{"DPPD",            TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x42), 1, X86InstInfo{"MPSADBW",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(0, PF_3A_66,   0x44), 1, X86InstInfo{"PCLMULQDQ",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},

    {OPD(0, PF_3A_66,   0x60), 1, X86InstInfo{"PCMPESTRM",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x61), 1, X86InstInfo{"PCMPESTRI",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x62), 1, X86InstInfo{"PCMPISTRM",       TYPE_UNDEC, FLAGS_NONE, 0, nullptr}},
    {OPD(0, PF_3A_66,   0x63), 1, X86InstInfo{"PCMPISTRI",       TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},

    {OPD(0, PF_3A_66,   0xDF), 1, X86InstInfo{"AESKEYGENASSIST", TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
  }};

  constexpr U16U8InfoStructTable H0F3ATable_64 = {{
    {OPD(1, PF_3A_66,   0x0F), 1, X86InstInfo{"PALIGNR",         TYPE_INST, GenFlagsSameSize(SIZE_128BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(1, PF_3A_66,   0x16), 1, X86InstInfo{"PEXTRQ",          TYPE_INST, GenFlagsSizes(SIZE_64BIT, SIZE_128BIT) | FLAGS_MODRM | FLAGS_SF_MOD_DST | FLAGS_SF_DST_GPR | FLAGS_XMM_FLAGS, 1, nullptr}},
    {OPD(1, PF_3A_66,   0x22), 1, X86InstInfo{"PINSRQ",          TYPE_INST, GenFlagsSizes(SIZE_128BIT, SIZE_64BIT) | FLAGS_MODRM | FLAGS_XMM_FLAGS | FLAGS_SF_SRC_GPR,           1, nullptr}},
  }};

#undef OPD

constinit auto H0F3ATableOps = X86TableBuilder::GenerateInitTable<MAX_0F_3A_TABLE_SIZE>(H0F3ATable);

UPDATE_STATIC_DEBUG_STATS(H0F3ATable.count);

void InitializeH0F3ATables(Context::OperatingMode Mode) {
  if (Mode == Context::MODE_64BIT) {
    DebugStats += H0F3ATable_64.count;
    X86TableBuilder::PatchTable(H0F3ATableOps, H0F3ATable_64);
  }
}
}
