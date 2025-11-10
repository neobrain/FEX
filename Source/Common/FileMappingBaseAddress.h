// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <span>

#include <elf.h>

namespace FEXCore {

/**
 * Infers the base virtual address from a file mapping (as described by parameters to a single
 * call to mmap()).
 *
 * The file offset of any given mapping need not match its virtual address offset from the base
 * mapping (file offset = 0). Instead, this function searches the corresponding ELF program headers
 * for an entry that generated the given file mapping.
 */
// TODO: Add unit test for Firefox's glxtest
inline fextl::vector<uint64_t>
InferMappingBaseAddress(std::span<const Elf64_Phdr> ProgramHeaders, uint64_t Addr, uint64_t Size,
                                                       uint64_t FileOffset, int AccessFlags, bool IsWine = false) {
  fextl::vector<uint64_t> Ret;
  for (auto& phdr : ProgramHeaders) {
    if (phdr.p_type != PT_LOAD) {
      // Skip headers that don't trigger memory mappings
      continue;
    }

    if ((phdr.p_flags & (PF_X | PF_W | PF_R)) != (AccessFlags & (PF_X | PF_W | PF_R))) {
      if (!IsWine) {
        continue;
      } else {
        // Wine maps PE sections as RW, so we can't use flags to distinguish mmap calls.
        // Luckily the mapping is direct in that case anyway, so the result will be reliable
        // even without the extra information.
      }
    }

    // The mapped file offset must be included at the start of the section header
    auto SegmentStartOffset = phdr.p_offset - (phdr.p_vaddr & 0xfff);
    if (FileOffset >= SegmentStartOffset && FileOffset < SegmentStartOffset + phdr.p_filesz &&
        (FileOffset & Utils::FEX_PAGE_MASK) == (phdr.p_offset & Utils::FEX_PAGE_MASK)) {
      // Compute VA offset relative to the base mapping
      Ret.push_back(Addr - (phdr.p_vaddr - (phdr.p_offset & 0xfff)) + (ProgramHeaders[0].p_vaddr - (ProgramHeaders[0].p_offset & 0xfff)) -
                    (FileOffset - SegmentStartOffset));
    }
  }

  return Ret;
}
} // namespace FEXCore
