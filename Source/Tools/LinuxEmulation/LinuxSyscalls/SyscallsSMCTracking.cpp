// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: SMC/MMan Tracking
$end_info$
*/

#include <Common/Config.h>
#include "Common/FDUtils.h"
#include "Common/FEXServerClient.h"
#include "Common/FileMappingBaseAddress.h"

#include <filesystem>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/shm.h>

#include "FEXCore/Utils/DebuggerPresence.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <Linux/Utils/ELFParser.h>
#include <PEParser.h>

namespace FEX::HLE {
// SMC interactions
bool SyscallHandler::HandleSegfault(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  const auto FaultAddress = (uintptr_t)((siginfo_t*)info)->si_addr;

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  auto CallRetStackInfo = ThreadObject->GetCallRetStackInfo();
  if (FaultAddress >= CallRetStackInfo.AllocationBase && FaultAddress < CallRetStackInfo.AllocationEnd) {
    // Reset REG_CALLRET_SP to the default location to allow for underflows/overflows
    ArchHelpers::Context::SetArmReg(ucontext, 25, CallRetStackInfo.DefaultLocation);
    return true;
  }

  {
    // Can't use the deferred signal lock in the SIGSEGV handler.
    auto lk = FEXCore::MaskSignalsAndLockMutex<std::shared_lock>(_SyscallHandler->VMATracking.Mutex);

    auto VMATracking = &_SyscallHandler->VMATracking;

    // If the write spans two pages, they will be flushed one at a time (generating two faults)
    auto Entry = VMATracking->FindVMAEntry(FaultAddress);

    // If an untracked address, or the mapping wasn't writable, it can't be handled here
    if (Entry == VMATracking->VMAs.end() || !Entry->second.Prot.Writable) {
      return false;
    }

    auto FaultBase = FEXCore::AlignDown(FaultAddress, FEXCore::Utils::FEX_PAGE_SIZE);

    auto UnprotectRegionCallback = [](uintptr_t Start, uintptr_t Length) {
      auto rv = mprotect((void*)Start, Length, PROT_READ | PROT_WRITE);
      LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", Start, Length);
    };

    if (Entry->second.Flags.Shared) {
      LOGMAN_THROW_A_FMT(Entry->second.Resource, "VMA tracking error");

      auto Offset = FaultBase - Entry->first + Entry->second.Offset;

      auto VMA = Entry->second.Resource->FirstVMA;
      LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

      // Flush all mirrors, remap the page writable as needed
      do {
        if (VMA->Offset <= Offset && (VMA->Offset + VMA->Length) > Offset) {
          auto FaultBaseMirrored = Offset - VMA->Offset + VMA->Base;

          if (VMA->Prot.Writable) {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
          } else {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }
      } while ((VMA = VMA->ResourceNextVMA));
    } else {
      _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);

    auto CTX = Thread->CTX;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !CTX->IsCurrentBlockSingleInst(Thread) &&
        CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
      // If we are not in a single-instruction block, and the SMC write address could intersect with the current block,
      // reconstruct the context and repeat the faulting instruction as a single-instruction block so any SMC it performs
      // is immediately picked up.
      ThreadObject->SignalInfo.Delegator->SpillSRA(Thread, ucontext, Thread->CurrentFrame->InSyscallInfo & 0xFFFF);

      // Adjust context to return to the dispatcher, reloading SRA from thread state
      const auto& Config = ThreadObject->SignalInfo.Delegator->GetConfig();
      ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
      ArchHelpers::Context::SetArmReg(ucontext, 1, 1); // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
    }

    return true;
  }
}

void SyscallHandler::MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  const auto Base = Start & FEXCore::Utils::FEX_PAGE_MASK;
  const auto Top = FEXCore::AlignUp(Start + Length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_MTRACK) {
      return;
    }

    auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

    // Find the first mapping at or after the range ends, or ::end().
    // Top points to the address after the end of the range
    auto Mapping = VMATracking.VMAs.lower_bound(Top);

    while (Mapping != VMATracking.VMAs.begin()) {
      Mapping--;

      const auto MapBase = Mapping->first;
      const auto MapTop = MapBase + Mapping->second.Length;

      if (MapTop <= Base) {
        // Mapping ends before the Range start, exit
        break;
      } else {
        const auto ProtectBase = std::max(MapBase, Base);
        const auto ProtectSize = std::min(MapTop, Top) - ProtectBase;

        if (Mapping->second.Flags.Shared) {
          LOGMAN_THROW_A_FMT(Mapping->second.Resource, "VMA tracking error");

          const auto OffsetBase = ProtectBase - Mapping->first + Mapping->second.Offset;
          const auto OffsetTop = OffsetBase + ProtectSize;

          auto VMA = Mapping->second.Resource->FirstVMA;
          LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

          do {
            auto VMAOffsetBase = VMA->Offset;
            auto VMAOffsetTop = VMA->Offset + VMA->Length;
            auto VMABase = VMA->Base;

            if (VMA->Prot.Writable && VMAOffsetBase < OffsetTop && VMAOffsetTop > OffsetBase) {

              const auto MirroredBase = std::max(VMAOffsetBase, OffsetBase);
              const auto MirroredSize = std::min(OffsetTop, VMAOffsetTop) - MirroredBase;

              auto rv = mprotect((void*)(MirroredBase - VMAOffsetBase + VMABase), MirroredSize, PROT_READ);
              LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", MirroredBase, MirroredSize);
            }
          } while ((VMA = VMA->ResourceNextVMA));

        } else if (Mapping->second.Prot.Writable) {
          int rv = mprotect((void*)ProtectBase, ProtectSize, PROT_READ);

          LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", ProtectBase, ProtectSize);
        }
      }
    }
  }
}

void SyscallHandler::InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  InvalidateCodeRangeIfNecessary(Thread, Start, Length);
}

void SyscallHandler::MarkGuestCodeRoot(FEXCore::Core::InternalThreadState& Thread, uint64_t Address) {
  if (!CodeMapWriter) {
    return;
  }

  auto Region = LookupExecutableFileSection(Thread, Address);
  if (Region && CodeMapWriter->IsWriteEnabled(*Region)) {
    CodeMapWriter->AppendBlock(*Region, Address);
  }
}

std::optional<FEXCore::ExecutableFileSectionInfo>
SyscallHandler::LookupExecutableFileSection(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestAddr) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, &Thread);

  auto EntryIt = VMATracking.FindVMAEntry(GuestAddr);
  if (EntryIt == VMATracking.VMAs.end() || !EntryIt->second.Resource || !EntryIt->second.Resource->MappedFile) {
    return std::nullopt;
  }
  auto& [MappingBaseAddr, Entry] = *EntryIt;
  return FEXCore::ExecutableFileSectionInfo {*Entry.Resource->MappedFile, Entry.Resource->FirstVMA->Base, (uintptr_t)MappingBaseAddr,
                                             (uintptr_t)MappingBaseAddr + (uintptr_t)Entry.Length};
}

void SyscallHandler::TriggerPostStartupCodeCacheLoad(FEXCore::Core::InternalThreadState& Thread) {
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
  for (auto& [BaseAddr, FileInfo, BinaryFD] : StartupBinaryLoads) {
    // TODO: Minimize number of calls to RequestCodeCache?
    const auto CacheFD = FEXServerClient::RequestCodeCache(FEXServerClient::GetServerFD(), BinaryFD, Multiblock());
    struct stat buf;
    if (CacheFD == -1 || (fstat(CacheFD, &buf) != 0)) {
      continue;
    }
    const auto CacheFileSize = buf.st_size;
    const auto MappedCache = (std::byte*)FEXCore::Allocator::mmap(nullptr, CacheFileSize, PROT_READ, MAP_PRIVATE, CacheFD, 0);

    auto Entry = LookupExecutableFileSection(Thread, BaseAddr);
    CTX->GetCodeCache().LoadData(Thread, MappedCache, *Entry);

    FEXCore::Allocator::munmap(MappedCache, CacheFileSize);
  }
  StartupBinaryLoads.clear();
}

FEXCore::HLE::ExecutableRangeInfo SyscallHandler::QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);

  auto Entry = VMATracking.FindVMAEntry(Address);
  if (Entry == VMATracking.VMAs.end() ||
      (!Entry->second.Prot.Executable && (!(ThreadObject->persona & READ_IMPLIES_EXEC) || !Entry->second.Prot.Readable))) {
    return {0, 0, false};
  }
  return {Entry->first, Entry->second.Length, Entry->second.Prot.Writable};
}

// TODO: Rename to something like ReadBinaryHeaders
static std::pair<bool, fextl::vector<Elf64_Phdr>> ReadELFHeaders(int FD, std::span<std::byte> HeaderData = {}) {
#if 0 // TODO: Also check PE magic, then re-enable this code
  std::string_view ELFMagic = ELFMAG;
  if (HeaderData.data()) {
    if (HeaderData.size_bytes() < ELFMagic.size() || std::memcmp(ELFMagic.data(), HeaderData.data(), ELFMagic.size()) != 0) {
      // Not an ELF file
      return {};
    }
  } else {
    // Read from FD in case the caller didn't have a mapped header available
  }
#endif

  // TODO: Is it safe to modify the FD's read cursor here?
  // TODO: Actually, the file is already mapped into memory, so we don't need to use the fd!
  auto dupfd = dup(FD);
  auto pos = lseek(dupfd, 0, SEEK_CUR);
  {
    // Check if this is a PE binary first
    PEParser Parser(dupfd);
    if (Parser) {
      fextl::vector<Elf64_Phdr> ElfSections;
      ElfSections.push_back({.p_offset = 0, .p_vaddr = Parser.ImageBase, .p_filesz = 0x1000 /* TODO: use size of headers? */});
      for (auto& Section : Parser.Sections) {
        // Convert to elf header
        Elf64_Phdr ElfSection {};
        ElfSection.p_offset = Section.PointerToRawData;
        ElfSection.p_vaddr = Parser.ImageBase + Section.VirtualAddress;
        ElfSection.p_filesz = Section.SizeOfRawData;
        ElfSections.push_back(ElfSection);
      }
      return std::pair {Parser.Is64Bit, std::move(ElfSections)};
    }
  };

  ELFParser Parser;
  Parser.ReadElf(dupfd);
  lseek(dupfd, pos, SEEK_SET); // TODO: Is this needed? Actually, dupfd is most likely an invalid FD at this point!!!!
  return std::pair {Parser.ehdr.e_machine != EM_386, std::move(Parser.phdrs)};
}

void* SyscallHandler::GuestMmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags,
                                int fd, off_t offset) {
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  FEXCore::ExecutableFileInfo* Entry;
  // ELFParser Elf;

  {
    // NOTE: Frontend calls this with a nullptr Thread during initialization, but
    //       providing this code with a valid Thread object earlier would allow
    //       us to be more optimal by using GuardSignalDeferringSection instead
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    bool Map32Bit = !Is64Bit || (flags & FEX::HLE::X86_64_MAP_32BIT);
    if (Map32Bit) {
      Result = (uint64_t)Get32BitAllocator()->Mmap((void*)addr, length, prot, flags, fd, offset);
      if (FEX::HLE::HasSyscallError(Result)) {
        return reinterpret_cast<void*>(Result);
      }
      LOGMAN_THROW_A_FMT(Is64Bit || (Result >> 32) == 0 || (Result >> 32) == 0xFFFFFFFF, "values must fit to 32 bits");
    } else {
      Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, prot, flags, fd, offset));
      if (Result == ~0ULL) {
        return reinterpret_cast<void*>(-errno);
      }
    }

    Entry = TrackMmap(Thread, Result, length, prot, flags, fd, offset);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Size);

  if (Entry) {
    auto CacheFilename = fextl::fmt::format("{}cache/{}-{:016x}", FEX::Config::GetCacheDirectory(),
                                            FEXCore::CodeMap::GetBaseFilename(*Entry, false), CodeCacheConfigId);
    int FD = open(CacheFilename.c_str(), O_RDONLY);
    struct stat buf;
    if (FD != -1 && (fstat(FD, &buf) == 0)) {
      auto CacheFileSize = buf.st_size;
      auto MappedCache = (std::byte*)FEXCore::Allocator::mmap(nullptr, CacheFileSize, PROT_READ, MAP_PRIVATE, FD, 0);
      close(FD);

      // TODO: Make TrackMmap return this instead
      auto SectionInfo = LookupExecutableFileSection(*Thread, Result);
      CTX->GetCodeCache().LoadData(*Thread, MappedCache, *SectionInfo);

      FEXCore::Allocator::munmap(MappedCache, CacheFileSize);
    }
  }

  return reinterpret_cast<void*>(Result);
}

uint64_t SyscallHandler::GuestMunmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length) {
  LOGMAN_THROW_A_FMT(Is64Bit || (reinterpret_cast<uintptr_t>(addr) >> 32) == 0, "values must fit to 32 bits: {}", fmt::ptr(addr));
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    // Frontend calls this with nullptr Thread during initialization.
    // This is why `GuardSignalDeferringSectionWithFallback` is used here.
    // To be more optimal the frontend should provide this code with a valid Thread object earlier.
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    if (reinterpret_cast<uintptr_t>(addr) < 0x1'0000'0000ULL) {
      Result = Get32BitAllocator()->Munmap(addr, length);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    } else {
      Result = ::munmap(addr, length);
      if (Result == -1) {
        return -errno;
      }
    }
    TrackMunmap(Thread, addr, length);
  }
  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), Size);

  return Result;
}

uint64_t SyscallHandler::GuestMremap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* old_address, size_t old_size,
                                     size_t new_size, int flags, void* new_address) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::mremap(old_address, old_size, new_size, flags, new_address));
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = reinterpret_cast<uint64_t>(Get32BitAllocator()->Mremap(old_address, old_size, new_size, flags, new_address));
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }
    TrackMremap(Thread, reinterpret_cast<uint64_t>(old_address), old_size, new_size, flags, Result);
  }

  InvalidateCodeRangeIfNecessaryOnRemap(Thread, reinterpret_cast<uint64_t>(old_address), Result, old_size, new_size);
  return Result;
}

uint64_t SyscallHandler::GuestMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    Result = ::mprotect(addr, len, prot);
    if (Result == -1) {
      return -errno;
    }

    TrackMprotect(Thread, addr, len, prot);
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), len);

  // Handle Wine case
  if (prot & PROT_EXEC) {
    // TODO: Iterate until len
    auto VMAEntry = VMATracking.FindVMAEntry(reinterpret_cast<uint64_t>(addr));
    if (VMAEntry != VMATracking.VMAs.end() && VMAEntry->second.Resource && VMAEntry->second.DelayedCacheLoad) {
      for (auto* VMA = VMAEntry->second.Resource->FirstVMA; VMA; VMA = VMA->ResourceNextVMA) {
        if (VMA->Prot.Executable && VMA->DelayedCacheLoad) {
          LogMan::Msg::IFmt("TRIGGERING DELAYED CACHE LOAD FOR WINE ON VMA ENTRY {:#x}-{:#x}", VMA->Base, VMA->Base + VMA->Length);
          // CTX->FetchAOTIRCacheEntry(Thread, reinterpret_cast<uint64_t>(VMA->Base));

          // TODO: Actually, use main info and use VMA bounds...
          auto SectionInfo = LookupExecutableFileSection(*Thread, VMA->Base);
          if (SectionInfo) {
            auto CacheFilename = fextl::fmt::format("{}cache/{}-{:016x}", FEX::Config::GetCacheDirectory(),
                                                    FEXCore::CodeMap::GetBaseFilename(SectionInfo->FileInfo, false), CodeCacheConfigId);
            int FD = open(CacheFilename.c_str(), O_RDONLY);
            struct stat buf;
            if (FD != -1 && (fstat(FD, &buf) == 0)) {
              auto CacheFileSize = buf.st_size;
              auto MappedCache = (std::byte*)FEXCore::Allocator::mmap(nullptr, CacheFileSize, PROT_READ, MAP_PRIVATE, FD, 0);
              close(FD);

              CTX->GetCodeCache().LoadData(*Thread, MappedCache, *SectionInfo);

              FEXCore::Allocator::munmap(MappedCache, CacheFileSize);
            }
          }

          // VMA->DelayedCacheLoad = false;
        }
      }
    }
  }

  return Result;
}

uint64_t SyscallHandler::GuestShmat(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, int shmid, const void* shmaddr, int shmflg) {
  uint64_t Result {};
  uint64_t Length {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::shmat(shmid, shmaddr, shmflg));
      if (Result == -1) {
        return -errno;
      }
    } else {
      uint32_t Addr;
      Result = Get32BitAllocator()->Shmat(shmid, shmaddr, shmflg, &Addr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
      Result = Addr;
    }

    shmid_ds stat;

    auto res = shmctl(shmid, IPC_STAT, &stat);
    LOGMAN_THROW_A_FMT(res != -1, "shmctl IPC_STAT failed");

    Length = stat.shm_segsz;
    TrackShmat(Thread, shmid, Result, shmflg, Length);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Length);
  return Result;
}

uint64_t SyscallHandler::GuestShmdt(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, const void* shmaddr) {
  uint64_t Result {};
  uint64_t Length {};
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = ::shmdt(shmaddr);
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = Get32BitAllocator()->Shmdt(shmaddr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }

    Length = TrackShmdt(Thread, reinterpret_cast<uintptr_t>(shmaddr));
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uintptr_t>(shmaddr), Length);
  return Result;
}

// MMan Tracking
FEXCore::ExecutableFileInfo* SyscallHandler::TrackMmap(FEXCore::Core::InternalThreadState* Thread, uint64_t addr, size_t length, int prot,
                                                       int flags, int fd, off_t offset) {
  const auto UnalignedSize = length;

  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  const auto ProtMapping = VMATracking::VMAProt::fromProt(prot);

  // Wine maps executables differently from normal Linux applications (see map_image_into_view in Wine's virtual.c):
  // * Anonymous memory is mmap'ed for the entire application
  // * The PE header is mmap'ed onto this range with PROT_EXEC
  // * The remaining PE sections are each mapped onto this range, however mmap will fail for unaligned PE sections
  //   * As a fallback, Wine will copy the file contents manually on the anonymous range
  // TODO: Actually, regular Linux applications also allocate anonymous memory for the entire application... so our VMATracking "WineCase" actually hits those as well.
  bool WineCase = false;

  VMATracking::MappedResource* Resource = nullptr;

  if ((flags & (MAP_ANONYMOUS | MAP_FIXED)) == MAP_FIXED && (prot & PROT_EXEC) && UnalignedSize <= 4096) {
    // Detect mmap of PE_HEADER
    auto VMAEntry = VMATracking.FindVMAEntry(addr);
    if (VMAEntry != VMATracking.VMAs.end() &&
        VMAEntry->first == addr /* TODO: Technically the range could have been merged with another one... */ && !VMAEntry->second.Resource) {
      // fmt::print(stderr, "Detected PE header mmap at address {:#x}\n", addr);
      // WineCase = true;
    }
  }

  if (!(flags & MAP_ANONYMOUS)) {
    struct stat64 buf;
    fstat64(fd, &buf);

    const VMATracking::MRID mrid {buf.st_dev, buf.st_ino};

    char Tmp[PATH_MAX];
    auto PathLength = FEX::get_fdpath(fd, Tmp);

    auto [ResourceIt, ResourceEnd] = VMATracking.FindResources(mrid);
    bool Inserted = false;
    const bool MappedELFHeaderAgain = ResourceIt != ResourceEnd && offset == 0 && !ResourceIt->second.ProgramHeaders.empty();
    if (ResourceIt == ResourceEnd || MappedELFHeaderAgain) {
      // Create a new MappedResource for previously unseen file and for re-mappings of an ELF header
      ResourceIt = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
      ResourceIt->second.Iterator = ResourceIt;
      Inserted = true;
    }
    Resource = &ResourceIt->second;

    // Only handle FDs that are backed by regular files that are executable
    if (PathLength != -1 && S_ISREG(buf.st_mode) && (buf.st_mode & S_IXUSR)) {
      // ELF files that are mapped multiple times get a separate MappedResource for each base virtual address
      if (Inserted) {
        Resource->MappedFile = fextl::make_unique<FEXCore::ExecutableFileInfo>();
        Resource->MappedFile->Filename = fextl::string(Tmp, PathLength);
        Resource->MappedFile->FileId = CTX->GetCodeCache().ComputeCodeMapId(fd);

        // Read ELF headers if applicable.
        // For performance, skip ELF checks if we're not mapping the file header
        bool CheckForElfFile = (offset == 0);
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
        CheckForElfFile = true;
#endif
        if (CheckForElfFile) {
          std::tie(Resource->Is64Bit, Resource->ProgramHeaders) = ReadELFHeaders(fd, std::span {reinterpret_cast<std::byte*>(addr), length});
          LOGMAN_THROW_A_FMT(Resource->ProgramHeaders.empty() || offset == 0, "Expected file offset 0 for the first mapping of an ELF "
                                                                              "file");
        }
      } else if (ResourceIt->second.ProgramHeaders.empty()) {
        // Not an ELF file, so we don't need to distinguish between different base addresses
      } else {
        // Mapped a non-header section of an ELF file.
        // Look up the corresponding MappedResource using the expected base address.

        ResourceIt = std::find_if(ResourceIt, ResourceEnd, [&](const VMATracking::MappedResource::ContainerType::value_type& ResourcePair) {
          auto& Resource = ResourcePair.second;
          auto ExpectedBase = FEXCore::InferMappingBaseAddress(
            Resource.ProgramHeaders, addr, Size, offset,
            (ProtMapping.Executable ? PF_X : 0) | (ProtMapping.Writable ? PF_W : 0) | (ProtMapping.Readable ? PF_R : 0));
          return ExpectedBase == Resource.FirstVMA->Base;
        });
        LOGMAN_THROW_A_FMT(ResourceIt != ResourceEnd, "ERROR: Could not find base for file mapping at {:#x} (offset {:#x})", addr, offset);
        Resource = &ResourceIt->second;
      }
    }
  } else if (flags & MAP_SHARED) {
    VMATracking::MRID mrid {VMATracking::SpecialDev::Anon, AnonSharedId++};

    auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
    LOGMAN_THROW_A_FMT(Iter == IterEnd, "VMA tracking error");

    Iter = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
    Resource = &Iter->second;
    Resource->Iterator = Iter;
  }

  // if (Resource && Resource->ProgramHeaders.empty() && VMATracking::VMAProt::fromProt(prot).Executable) {
  //   std::tie(Resource->Is64Bit, Resource->ProgramHeaders) = ReadELFHeaders(fd);
  // }

  VMATracking.TrackVMARange(CTX, Resource, addr, offset, Size, VMATracking::VMAFlags::fromFlags(flags),
                            VMATracking::VMAProt::fromProt(prot), VMATracking::VMAProt::fromProt(prot).Executable && WineCase);

  // Load cache when the first executable mapping is loaded.
  // Some important use cases to consider:
  // - Mapping a non-executable file won't trigger search for code cache files
  // - Celeste loads gameoverlayrenderer.so as read-only at first and then as executable at a different base location
  // - Libraries may be mapped as read-only before being mprotect'ed as executable
  // - During God of War launch, steam.exe's steam.exe.so will unmap one page from its `.init` section
  // - A plugin-like library may be reloaded to a different base address throughout program execution
  // TODO: Reload the cache if the same library is reloaded to a different address!
  // TODO: Ensure mprotect is properly handled as well
  // TODO: Move parts of this back inside the lock!
  // TODO: .Executable heuristic doesn't work well with Windows executables, for which even the header is mapped like this (adding an extra "WineHeuristic", but that's not ideal!)
  if (Resource && VMATracking::VMAProt::fromProt(prot).Executable) {
    // LogMan::Msg::IFmt("LOADING AOT CACHE ENTRY: {}", Resource->MappedFile->Filename);

    if (Thread) {
      // TODO: Move this to first compile?
      if (!WineCase) {
        return Resource->MappedFile.get();
      } else {
        // Delayed until mprotect
        LogMan::Msg::IFmt("Delaying code cache load for {} until mprotect {:#x}-{:#x}", Resource->MappedFile->Filename, addr, addr + Size);
      }
    } else {
      // Delay loading this entry until FEX is fully initialized
      StartupBinaryLoads.push_back({addr, Resource->MappedFile.get(), dup(fd)});
      LogMan::Msg::IFmt("Queuing post-startup code cache load for {}", Resource->MappedFile->Filename);
    }
  }

  return nullptr;
}

void SyscallHandler::TrackMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length) {
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  VMATracking.DeleteVMARange(CTX, reinterpret_cast<uintptr_t>(addr), Size);
}

void SyscallHandler::TrackMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Size = FEXCore::AlignUp(len, FEXCore::Utils::FEX_PAGE_SIZE);

  VMATracking.ChangeProtectionFlags(reinterpret_cast<uintptr_t>(addr), Size, VMATracking::VMAProt::fromProt(prot));
}

void SyscallHandler::TrackMremap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, size_t OldSize, size_t NewSize, int flags,
                                 uint64_t NewAddress) {
  OldSize = FEXCore::AlignUp(OldSize, FEXCore::Utils::FEX_PAGE_SIZE);
  NewSize = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE);

  const auto OldVMA = VMATracking.FindVMAEntry(OldAddress);

  const auto OldResource = OldVMA->second.Resource;
  const auto OldOffset = OldVMA->second.Offset + OldAddress - OldVMA->first;
  const auto OldFlags = OldVMA->second.Flags;
  const auto OldProt = OldVMA->second.Prot;

  LOGMAN_THROW_A_FMT(OldVMA != VMATracking.VMAs.end(), "VMA Tracking corruption");

  if (OldSize == 0) {
    // Mirror existing mapping
    // must be a shared mapping
    LOGMAN_THROW_A_FMT(OldResource != nullptr, "VMA Tracking error");
    LOGMAN_THROW_A_FMT(OldFlags.Shared, "VMA Tracking error");
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt, false);
  } else {

#ifndef MREMAP_DONTUNMAP
// MREMAP_DONTUNMAP is kernel 5.7+ and might not exist
#define MREMAP_DONTUNMAP 4
#endif
    if (!(flags & MREMAP_DONTUNMAP)) {
      VMATracking.DeleteVMARange(CTX, OldAddress, OldSize, OldResource);
    }

    // Make anonymous mapping
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt, false);
  }
}

void SyscallHandler::TrackShmat(FEXCore::Core::InternalThreadState* Thread, int shmid, uint64_t shmaddr, int shmflg, uint64_t Length) {
  VMATracking::MRID mrid {VMATracking::SpecialDev::SHM, static_cast<uint64_t>(shmid)};

  auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
  if (Iter == IterEnd) {
    Iter = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, Length, {}, {}});
    Iter->second.Iterator = Iter;
  }
  auto Resource = &Iter->second;
  VMATracking.TrackVMARange(CTX, Resource, shmaddr, 0, Length, VMATracking::VMAFlags::fromFlags(MAP_SHARED),
                            VMATracking::VMAProt::fromSHM(shmflg), false);
}

uint64_t SyscallHandler::TrackShmdt(FEXCore::Core::InternalThreadState* Thread, uint64_t shmaddr) {
  return VMATracking.DeleteSHMRegion(CTX, reinterpret_cast<uintptr_t>(shmaddr));
}

void SyscallHandler::TrackMadvise(FEXCore::Core::InternalThreadState* Thread, uintptr_t Base, uintptr_t Size, int advice) {
  Size = FEXCore::AlignUp(Size, FEXCore::Utils::FEX_PAGE_SIZE);
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    // TODO
  }
}

} // namespace FEX::HLE
