/*
$info$
meta: frontend|x86-tables ~ Metadata that drives the frontend x86/64 decoding
tags: frontend|x86-tables
$end_info$
*/

#include <FEXCore/Core/Context.h>
#include <FEXCore/Debug/X86Tables.h>

namespace FEXCore::X86Tables {

std::array<X86InstInfo, MAX_REP_MOD_TABLE_SIZE> RepModOps{};
std::array<X86InstInfo, MAX_REPNE_MOD_TABLE_SIZE> RepNEModOps{};
std::array<X86InstInfo, MAX_OPSIZE_MOD_TABLE_SIZE> OpSizeModOps{};

void InitializeBaseTables(Context::OperatingMode Mode);
void InitializeSecondaryTables(Context::OperatingMode Mode);
void InitializePrimaryGroupTables(Context::OperatingMode Mode);
void InitializeH0F3ATables(Context::OperatingMode Mode);

StaticEntryCount DebugStats;

void InitializeInfoTables(Context::OperatingMode Mode) {
// TODO: Bake non-Mode dependent tables upfront (compile-time) and patch in the mode-dependent ones here

  InitializeBaseTables(Mode);
  InitializeSecondaryTables(Mode);
  InitializePrimaryGroupTables(Mode);

  InitializeH0F3ATables(Mode);

#ifndef NDEBUG
  X86InstDebugInfo::InstallDebugInfo();
#endif
}

}
