// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/IR/IR.h>

#include <cstddef>
#include <cstdint>
#include <span>

namespace FEX::HLE {
class SyscallMmapInterface;
}

namespace FEX::VDSO {
struct VDSOMapping {
  void* VDSOBase {};
  size_t VDSOSize {};
  void* OptionalSigReturnMapping {};
  size_t OptionalMappingSize {};

  explicit operator bool() const {
    return VDSOBase != nullptr;
  }
};

struct VDSOSigReturn {
  void* VDSO_kernel_sigreturn;
  void* VDSO_kernel_rt_sigreturn;
};
int OpenVDSOGuestLibraryFD(bool Is64Bit);
VDSOMapping PrepareVDSO(bool Is64Bit, FEX::HLE::SyscallMmapInterface* const);
void FinalizeVDSO(VDSOMapping& Mapping, bool Is64Bit, FEX::HLE::SyscallMmapInterface* const);
void UnloadVDSOMapping(const VDSOMapping& Mapping);

uint64_t GetVSyscallEntry(const void* VDSOBase);

const std::span<FEXCore::IR::ThunkDefinition> GetVDSOThunkDefinitions(bool Is64Bit);
const VDSOSigReturn& GetVDSOSymbols();
} // namespace FEX::VDSO
