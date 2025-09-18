// SPDX-License-Identifier: MIT
/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ Emulation mainloop related glue logic
tags: glue|driver
desc: Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint
$end_info$
*/
#include "FEXCore/Utils/DebuggerPresence.h"

#include <cstdint>
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/CPUID.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include <Interface/GDBJIT/GDBJIT.h>
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/Allocator.h"
#include "Utils/Allocator/HostAllocator.h"
#include "Utils/SpinWaitLock.h"
#include "Utils/variable_length_integer.h"
#include "git_version.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include "FEXCore/Utils/SignalScopeGuards.h"
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/unordered_set.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <xxhash.h>

namespace FEXCore::Context {
CodeCache::CodeCache(ContextImpl& CTX_)
  : CTX(CTX_) {}
CodeCache::~CodeCache() = default;

ContextImpl::ContextImpl(const FEXCore::HostFeatures& Features)
  : HostFeatures {Features}
  , CPUID {this}
  , CodeCache {*this} {
  if (!Config.Is64BitMode()) {
    // When operating in 32-bit mode, the virtual memory we care about is only the lower 32-bits.
    Config.VirtualMemSize = 1ULL << 32;
  }

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Only initialize symbols file if enabled. Ensures we don't pollute /tmp with empty files.
    Symbols.InitFile();
  }

  uint64_t FrequencyCounter = FEXCore::GetCycleCounterFrequency();
  if (FrequencyCounter && FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM && Config.SmallTSCScale()) {
    // Scale TSC until it is at the minimum required.
    while (FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM) {
      FrequencyCounter <<= 1;
      ++Config.TSCScale;
    }
  }

  // Track atomic TSO emulation configuration.
  UpdateAtomicTSOEmulationConfig();
}

struct GetFrameBlockInfoResult {
  const CPU::CPUBackend::JITCodeHeader* InlineHeader;
  const CPU::CPUBackend::JITCodeTail* InlineTail;
};
static GetFrameBlockInfoResult GetFrameBlockInfo(FEXCore::Core::CpuStateFrame* Frame) {
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto InlineHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(BlockBegin);

  if (InlineHeader) {
    auto InlineTail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail);
    return {InlineHeader, InlineTail};
  }

  return {InlineHeader, nullptr};
}

bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && (Address + Size > InlineTail->RIP && Address < InlineTail->RIP + InlineTail->GuestSize);
}

bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && InlineTail->SingleInst;
}

uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail ? InlineTail->RIP : 0;
}

uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  const auto Frame = Thread->CurrentFrame;
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto [InlineHeader, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);

  if (InlineHeader) {
    // Check if the host PC is currently within a code block.
    // If it is then RIP can be reconstructed from the beginning of the code block.
    // This is currently as close as FEX can get RIP reconstructions.
    if (HostPC >= reinterpret_cast<uint64_t>(BlockBegin) && HostPC < reinterpret_cast<uint64_t>(BlockBegin + InlineTail->Size)) {

      auto RIPEntry =
        reinterpret_cast<const uint8_t*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail + InlineTail->OffsetToRIPEntries);

      // Reconstruct RIP from JIT entries for this block.
      uint64_t StartingHostPC = BlockBegin;
      uint64_t StartingGuestRIP = InlineTail->RIP;

      for (uint32_t i = 0; i < InlineTail->NumberOfRIPEntries; ++i) {
        auto Offset = FEXCore::Utils::vl64pair::Decode(RIPEntry);
        RIPEntry += Offset.Size;
        if (HostPC >= (StartingHostPC + Offset.IntegerARMPC)) {
          // We are beyond this entry, keep going forward.
          StartingHostPC += Offset.IntegerARMPC;
          StartingGuestRIP += Offset.IntegerX86RIP;
        } else {
          // Passed where the Host PC is at. Break now.
          break;
        }
      }
      return StartingGuestRIP;
    }
  }

  // Fallback to what is stored in the RIP currently.
  return Frame->State.rip;
}

uint32_t ContextImpl::ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs,
                                                 uint64_t PSTATE) {
  const auto Frame = Thread->CurrentFrame;
  uint32_t EFLAGS {};

  // Currently these flags just map 1:1 inside of the resulting value.
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_PF_RAW_LOC:
    case X86State::RFLAG_AF_RAW_LOC:
    case X86State::RFLAG_TF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_DF_RAW_LOC:
      // Intentionally do nothing.
      // These contain multiple bits which can corrupt other members when compacted.
      break;
    default: EFLAGS |= uint32_t {Frame->State.flags[i]} << i; break;
    }
  }

  uint32_t Packed_NZCV {};
  if (WasInJIT) {
    // If we were in the JIT then NZCV is in the CPU's PSTATE object.
    // Packed in to the same bit locations as RFLAG_NZCV_LOC.
    Packed_NZCV = PSTATE;

    // If we were in the JIT then PF and AF are in registers.
    // Move them to the CPUState frame now.
    Frame->State.pf_raw = HostGPRs[CPU::REG_PF.Idx()];
    Frame->State.af_raw = HostGPRs[CPU::REG_AF.Idx()];
  } else {
    // If we were not in the JIT then the NZCV state is stored in the CPUState RFLAG_NZCV_LOC.
    // SF/ZF/CF/OF are packed in a 32-bit value in RFLAG_NZCV_LOC.
    memcpy(&Packed_NZCV, &Frame->State.flags[X86State::RFLAG_NZCV_LOC], sizeof(Packed_NZCV));
  }

  uint32_t OF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC)) & 1;
  uint32_t CF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) & 1;
  uint32_t ZF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) & 1;
  uint32_t SF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) & 1;

  // CF is inverted in our representation, undo the invert here.
  CF ^= 1;

  // Pack in to EFLAGS
  EFLAGS |= OF << X86State::RFLAG_OF_RAW_LOC;
  EFLAGS |= CF << X86State::RFLAG_CF_RAW_LOC;
  EFLAGS |= ZF << X86State::RFLAG_ZF_RAW_LOC;
  EFLAGS |= SF << X86State::RFLAG_SF_RAW_LOC;

  // PF calculation is deferred, calculate it now.
  // Popcount the 8-bit flag and then extract the lower bit.
  uint32_t PFByte = Frame->State.pf_raw & 0xff;
  uint32_t PF = std::popcount(PFByte ^ 1) & 1;
  EFLAGS |= PF << X86State::RFLAG_PF_RAW_LOC;

  // AF calculation is deferred, calculate it now.
  // XOR with PF byte and extract bit 4.
  uint32_t AF = ((Frame->State.af_raw ^ PFByte) & (1 << 4)) ? 1 : 0;
  EFLAGS |= AF << X86State::RFLAG_AF_RAW_LOC;

  uint8_t TFByte = Frame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  EFLAGS |= (TFByte & 1) << X86State::RFLAG_TF_RAW_LOC;

  // DF is pretransformed, undo the transform from 1/-1 back to 0/1
  uint8_t DFByte = Frame->State.flags[X86State::RFLAG_DF_RAW_LOC];
  if (DFByte & 0x80) {
    EFLAGS |= 1 << X86State::RFLAG_DF_RAW_LOC;
  }

  return EFLAGS;
}

void ContextImpl::ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;

  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.avx.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.xmm.avx.data[i][2], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.sse.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.avx_high[i][0], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(XMM_Low, Thread->CurrentFrame->State.xmm.sse.data, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;
  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][2], &YMM_High[i], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.avx_high[i][0], &YMM_High[i], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(Thread->CurrentFrame->State.xmm.sse.data, XMM_Low, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) {
  const auto Frame = Thread->CurrentFrame;
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
      // Intentionally do nothing.
      break;
    case X86State::RFLAG_AF_RAW_LOC:
      // AF stored in bit 4 in our internal representation. It is also
      // XORed with byte 4 of the PF byte, but we write that as zero here so
      // we don't need any special handling for that.
      Frame->State.af_raw = (EFLAGS & (1U << i)) ? (1 << 4) : 0;
      break;
    case X86State::RFLAG_PF_RAW_LOC:
      // PF is inverted in our internal representation.
      Frame->State.pf_raw = (EFLAGS & (1U << i)) ? 0 : 1;
      break;
    case X86State::RFLAG_DF_RAW_LOC:
      // DF is encoded as 1/-1
      Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 0xff : 1;
      break;
    default: Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 1 : 0; break;
    }
  }

  // Calculate packed NZCV. Note CF is inverted.
  uint32_t Packed_NZCV {};
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_OF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_CF_RAW_LOC)) ? 0 : 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC);
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_ZF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_SF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC) : 0;
  memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &Packed_NZCV, sizeof(Packed_NZCV));

  // Reserved, Read-As-1, Write-as-1
  Frame->State.flags[X86State::RFLAG_RESERVED_LOC] = 1;
  // Interrupt Flag. Can't be written by CPL-3 userland.
  Frame->State.flags[X86State::RFLAG_IF_LOC] = 1;
}

bool ContextImpl::InitCore() {
  // Initialize the CPU core signal handlers & DispatcherConfig
  Dispatcher = FEXCore::CPU::Dispatcher::Create(this);

  // Set up the SignalDelegator config since core is initialized.
  // TODO: Drop AOT hack
  if (SignalDelegation) {
    SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());
  }

#if defined(_WIN32) && !defined(_M_ARM_64EC)
  // WOW64 always needs the interrupt fault check to be enabled.
  Config.NeedsPendingInterruptFaultCheck = true;
#endif

  if (Config.GdbServer) {
    // If gdbserver is enabled then this needs to be enabled.
    Config.NeedsPendingInterruptFaultCheck = true;
  }

  return true;
}

void ContextImpl::HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) {
  static_cast<ContextImpl*>(Thread->CTX)->Dispatcher->ExecuteJITCallback(Thread->CurrentFrame, RIP);
}

void ContextImpl::ExecuteThread(FEXCore::Core::InternalThreadState* Thread) {
  Dispatcher->ExecuteDispatch(Thread->CurrentFrame);

  // If it is the parent thread that died then just leave
  // TODO: This doesn't make sense when the parent thread doesn't outlive its children
}

void ContextImpl::InitializeCompiler(FEXCore::Core::InternalThreadState* Thread) {
  Thread->OpDispatcher = fextl::make_unique<FEXCore::IR::OpDispatchBuilder>(this);
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Thread->LookupCache = fextl::make_unique<FEXCore::LookupCache>(this);
  Thread->FrontendDecoder = fextl::make_unique<FEXCore::Frontend::Decoder>(Thread);
  Thread->PassManager = fextl::make_unique<FEXCore::IR::PassManager>();

  Thread->CurrentFrame->State.L1Pointer = Thread->LookupCache->GetL1Pointer();
  Thread->CurrentFrame->State.L1Mask = Thread->LookupCache->GetScaledL1PointerMask();

  Thread->CurrentFrame->Pointers.Common.L2Pointer = Thread->LookupCache->GetPagePointer();

  Dispatcher->InitThreadPointers(Thread);

  Thread->PassManager->AddDefaultPasses(this);
  Thread->PassManager->AddDefaultValidationPasses();

  Thread->PassManager->RegisterSyscallHandler(SyscallHandler);

  // Create CPU backend
  Thread->PassManager->InsertRegisterAllocationPass(this);
  Thread->CPUBackend = FEXCore::CPU::CreateArm64JITCore(this, Thread);

  Thread->PassManager->Finalize();
}

FEXCore::Core::InternalThreadState*
ContextImpl::CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState) {
  FEXCore::Core::InternalThreadState* Thread = new FEXCore::Core::InternalThreadState {
    .CTX = this,
  };
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));

  Thread->CurrentFrame->State.gregs[X86State::REG_RSP] = StackPointer;
  Thread->CurrentFrame->State.rip = InitialRIP;

  // Copy over the new thread state to the new object
  if (NewThreadState) {
    memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  }

  // Set up the thread manager state
  Thread->CurrentFrame->Thread = Thread;

  InitializeCompiler(Thread);

  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Allocate a JIT symbol buffer only if enabled.
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  }

  return Thread;
}

void ContextImpl::DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  FEXCore::Allocator::VirtualProtect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage),
                                     Allocator::ProtectOptions::Read | Allocator::ProtectOptions::Write);
  delete Thread;
}

#ifndef _WIN32
void ContextImpl::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Allocator::UnlockAfterFork(LiveThread, Child);

  Profiler::PostForkAction(Child);
  if (Child) {
    CodeInvalidationMutex.StealAndDropActiveLocks();
    if (Config.StrictInProcessSplitLocks) {
      StrictSplitLockMutex = 0;
    }
  } else {
    CodeInvalidationMutex.unlock();
    if (Config.StrictInProcessSplitLocks) {
      FEXCore::Utils::SpinWaitLock::unlock(&StrictSplitLockMutex);
    }
    return;
  }
}

void ContextImpl::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  CodeInvalidationMutex.lock();
  Allocator::LockBeforeFork(Thread);
  if (Config.StrictInProcessSplitLocks) {
    FEXCore::Utils::SpinWaitLock::lock(&StrictSplitLockMutex);
  }
}
#endif

void ContextImpl::OnCodeBufferAllocated(CPU::CodeBuffer& Buffer) {
  if (Config.GlobalJITNaming()) {
    Symbols.RegisterJITSpace(Buffer.Ptr, Buffer.Size);
  }
}

void ContextImpl::ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer) {
  FEXCORE_PROFILE_INSTANT("ClearCodeCache");

  // It *is* cleared now during cache generation of multiple libraries... because of this use case, we must clear Relocations here now.
  // This is done in CPUBackend though.
  // ERROR_AND_DIE_FMT("TODO: Code cache is not expected to be cleared while testing disk code caching");

  if (NewCodeBuffer) {
    // Allocate new CodeBuffer + L3 LookupCache and clear L1+L2 caches
    Thread->CPUBackend->ClearCache();
  } else {
    // Clear L1+L2 cache of this thread, and clear L3 cache across any threads using it
    auto lk = Thread->LookupCache->AcquireWriteLock();
    Thread->LookupCache->ClearCache(lk);
  }
  Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
}

static void IRDumper(FEXCore::Core::InternalThreadState* Thread, IR::IREmitter* IREmitter, uint64_t GuestRIP) {
  FEXCore::File::File FD = FEXCore::File::File::GetStdERR();
  fextl::stringstream out;
  auto NewIR = IREmitter->ViewIR();
  FEXCore::IR::Dump(&out, &NewIR);
  fextl::fmt::print(FD, "IR-ShouldDump-{} 0x{:x}:\n{}\n@@@@@\n", NewIR.PostRA() ? "post" : "pre", GuestRIP, out.str());
};

ContextImpl::GenerateIRResult
ContextImpl::GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst) {
  FEXCORE_PROFILE_SCOPED("GenerateIR");

  Thread->OpDispatcher->ReownOrClaimBuffer();
  Thread->OpDispatcher->ResetWorkingList();

  uint64_t TotalInstructions {0};
  uint64_t TotalInstructionsLength {0};

  bool HasCustomIR {};

  if (HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock lk(CustomIRMutex);
    auto Handler = CustomIRHandlers.find(GuestRIP);
    if (Handler != CustomIRHandlers.end()) {
      TotalInstructions = 1;
      TotalInstructionsLength = 1;
      Handler->second.Handler(GuestRIP, Thread->OpDispatcher.get());
      HasCustomIR = true;
    }
  }

  if (!HasCustomIR) {
    const uint8_t* GuestCode {};
    GuestCode = reinterpret_cast<const uint8_t*>(GuestRIP);

    bool HadDispatchError {false};
    bool HadInvalidInst {false};

    Thread->FrontendDecoder->DecodeInstructionsAtEntry(Thread, GuestCode, GuestRIP, MaxInst);

    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    auto CodeBlocks = &BlockInfo->Blocks;

    Thread->OpDispatcher->BeginFunction(GuestRIP, CodeBlocks, BlockInfo->TotalInstructionCount, BlockInfo->Is64BitMode,
                                        AreMonoHacksActive() && MonoBackpatcherBlock.load(std::memory_order_relaxed) == GuestRIP);

    const auto GPRSize = Thread->OpDispatcher->GetGPROpSize();

    for (size_t j = 0; j < CodeBlocks->size(); ++j) {
      const FEXCore::Frontend::Decoder::DecodedBlocks& Block = CodeBlocks->at(j);

      bool BlockInForceTSOValidRange = false;
      auto InstForceTSOIt = ForceTSOInstructions.end();
      if (ForceTSOValidRanges.Contains({Block.Entry, Block.Entry + Block.Size})) {
        if (auto It = ForceTSOInstructions.lower_bound(Block.Entry); *It < Block.Entry + Block.Size) {
          InstForceTSOIt = It;
          BlockInForceTSOValidRange = true;
        }
      }

      // Set the block entry point
      Thread->OpDispatcher->SetNewBlockIfChanged(Block.Entry);

      uint64_t BlockInstructionsLength {};

      // Reset any block-specific state
      Thread->OpDispatcher->StartNewBlock();

      uint64_t InstsInBlock = Block.NumInstructions;

      if (InstsInBlock == 0) {
        // Special case for an empty instruction block.
        Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry - GuestRIP));
      }

      for (size_t i = 0; i < InstsInBlock; ++i) {
        uint64_t InstAddress = Block.Entry + BlockInstructionsLength;
        const FEXCore::X86Tables::X86InstInfo* TableInfo {nullptr};
        const FEXCore::X86Tables::DecodedInst* DecodedInfo {nullptr};

        TableInfo = Block.DecodedInstructions[i].TableInfo;
        DecodedInfo = &Block.DecodedInstructions[i];
        bool IsLocked = DecodedInfo->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

        // Do a partial register cache flush before every instruction. This
        // prevents cross-instruction static register caching, while allowing
        // context load/stores to be optimized within a block. Theoretically,
        // this flush is not required for correctness, all mandatory flushes are
        // included in instruction-specific handlers. Instead, this is a blunt
        // heuristic to make the register cache less aggressive, as the current
        // RA generates bad code in common cases with tied registers otherwise.
        //
        // However, it makes our exception handling behaviour more predictable.
        // It is potentially correctness bearing in that sense, but that is a
        // side effect here and (if that behaviour is required) we should handle
        // that more explicitly later.
        Thread->OpDispatcher->FlushRegisterCache(true);

        if (ExtendedDebugInfo || Thread->OpDispatcher->CanHaveSideEffects(TableInfo, DecodedInfo)) {
          Thread->OpDispatcher->_GuestOpcode(InstAddress - GuestRIP);
        }

        if (Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL || Block.ForceFullSMCDetection) {
          auto ExistingCodePtr = reinterpret_cast<uint8_t*>(Block.Entry + BlockInstructionsLength);
          auto InstAddressReg = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);
          std::array<uint8_t, 0x10> CodeOriginal;
          memcpy(CodeOriginal.data(), ExistingCodePtr, DecodedInfo->InstSize);
          auto CodeChanged = Thread->OpDispatcher->_ValidateCode(CodeOriginal, InstAddressReg, DecodedInfo->InstSize);

          auto InvalidateCodeCond = Thread->OpDispatcher->CondJump(CodeChanged);

          auto CurrentBlock = Thread->OpDispatcher->GetCurrentBlock();
          auto CodeWasChangedBlock = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(InvalidateCodeCond, CodeWasChangedBlock);

          Thread->OpDispatcher->SetCurrentCodeBlock(CodeWasChangedBlock);
          Thread->OpDispatcher->_ThreadRemoveCodeEntry();
          Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, InstAddress - GuestRIP));

          auto NextOpBlock = Thread->OpDispatcher->CreateNewCodeBlockAfter(CurrentBlock);

          Thread->OpDispatcher->SetFalseJumpTarget(InvalidateCodeCond, NextOpBlock);
          Thread->OpDispatcher->SetCurrentCodeBlock(NextOpBlock);
        }

        if (TableInfo && TableInfo->OpcodeDispatcher.OpDispatch) {
          auto Fn = TableInfo->OpcodeDispatcher.OpDispatch;
          Thread->OpDispatcher->ResetHandledLock();
          Thread->OpDispatcher->ResetDecodeFailure();
          IR::ForceTSOMode ForceTSO = IR::ForceTSOMode::NoOverride;
          if (BlockInForceTSOValidRange) {
            if (InstForceTSOIt != ForceTSOInstructions.end() && *InstForceTSOIt == InstAddress) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          } else if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_FORCE_TSO) {
            ForceTSO = IR::ForceTSOMode::ForceEnabled;
          }

          Thread->OpDispatcher->SetForceTSO(ForceTSO);
          std::invoke(Fn, Thread->OpDispatcher, DecodedInfo);
          if (Thread->OpDispatcher->HadDecodeFailure()) {
            HadDispatchError = true;
          } else {
            if (Thread->OpDispatcher->HasHandledLock() != IsLocked) {
              HadDispatchError = true;
              LogMan::Msg::EFmt("Missing LOCK HANDLER at 0x{:x}{{'{}'}}", InstAddress, TableInfo->Name ?: "UND");
            }
            BlockInstructionsLength += DecodedInfo->InstSize;
            TotalInstructionsLength += DecodedInfo->InstSize;
            ++TotalInstructions;

            // Walk InstForceTSOIt forward past the handled instruction
            InstForceTSOIt =
              std::find_if(InstForceTSOIt, ForceTSOInstructions.end(), [&](auto Val) { return Val >= Block.Entry + BlockInstructionsLength; });
          }
        } else {
          // Invalid instruction
          if (!BlockInstructionsLength) {
            // SMC can modify block contents and patch invalid instructions to valid ones inline.
            // End blocks upon encountering them and only emit an invalid opcode exception if there are no prior instructions in the block (that could have modified it to be valid).

            if (TableInfo) {
              LogMan::Msg::EFmt("Invalid or Unknown instruction: {} 0x{:x}", TableInfo->Name ?: "UND", Block.Entry - GuestRIP);
            }

            if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::INVALID_INST) {
              Thread->OpDispatcher->InvalidOp(DecodedInfo);
            } else {
              Thread->OpDispatcher->NoExecOp(DecodedInfo);
            }
          }

          HadInvalidInst = true;
        }

        const bool NeedsBlockEnd = (HadDispatchError && TotalInstructions > 0) ||
                                   (Thread->OpDispatcher->NeedsBlockEnder() && i + 1 == InstsInBlock) || HadInvalidInst;

        // If we had a dispatch error then leave early
        if (HadDispatchError && TotalInstructions == 0) {
          // Couldn't handle any instruction in op dispatcher
          Thread->OpDispatcher->ResetWorkingList();
          return {{}, 0, 0, 0, 0};
        }

        if (NeedsBlockEnd) {
          // We had some instructions. Early exit
          Thread->OpDispatcher->ExitFunction(
            Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry + BlockInstructionsLength - GuestRIP));
          break;
        }


        if (Thread->OpDispatcher->FinishOp(DecodedInfo->PC + DecodedInfo->InstSize, i + 1 == InstsInBlock)) {
          break;
        }
      }
    }

    Thread->OpDispatcher->Finalize();

    Thread->FrontendDecoder->DelayedDisownBuffer();
  }

  IR::IREmitter* IREmitter = Thread->OpDispatcher.get();

  auto ShouldDump = Thread->OpDispatcher->ShouldDumpIR();
  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  // Run the passmanager over the IR from the dispatcher
  Thread->PassManager->Run(IREmitter);

  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  return {
    .IRView = IREmitter->ViewIR(),
    .TotalInstructions = TotalInstructions,
    .TotalInstructionsLength = TotalInstructionsLength,
    .StartAddr = Thread->FrontendDecoder->DecodedMinAddress,
    .Length = Thread->FrontendDecoder->DecodedMaxAddress - Thread->FrontendDecoder->DecodedMinAddress,
    .NeedsAddGuestCodeRanges = !HasCustomIR,
  };
}

ContextImpl::CompileCodeResult ContextImpl::CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  if (SourcecodeResolver && Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(*Thread, GuestRIP);
    if (MappedSection) {
      // TODO: Double-check what we should pass in here now
      MappedSection->FileInfo.SourcecodeMap =
        SourcecodeResolver->GenerateMap(MappedSection->FileInfo.Filename, CodeMap::GetBaseFilename(MappedSection->FileInfo, false));
    }
  }

  // Generate IR + Meta Info
  auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, NeedsAddGuestCodeRanges] =
    GenerateIR(Thread, GuestRIP, Config.GDBSymbols(), MaxInst);
  if (!IRView) {
    return {{}, nullptr, 0, 0, false};
  }

  // Attempt to get the CPU backend to compile this code
  // Re-check if another thread raced us in compiling this block.
  // We could lock CodeBufferWriteMutex earlier to prevent this from happening,
  // but this would increase lock contention. Redundant frontend runs aren't
  // as expensive and are easily reverted.
  if (MaxInst != 1) {
    if (auto Block = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      Thread->OpDispatcher->DelayedDisownBuffer();
      return {.CompiledCode = {.BlockBegin = reinterpret_cast<uint8_t*>(Block), .EntryPoints = {{GuestRIP, reinterpret_cast<uint8_t*>(Block)}}},
              .DebugData = nullptr,
              .StartAddr = 0,
              .Length = 0,
              .NeedsAddGuestCodeRanges = false};
    }
  }

  auto DebugData = fextl::make_unique<FEXCore::Core::DebugData>();

  // If the trap flag is set we generate single instruction blocks that each check to generate a single step exception.
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];

  auto CompiledCode = Thread->CPUBackend->CompileCode(GuestRIP, Length, TotalInstructions == 1, &*IRView, DebugData.get(), TFSet);

  // Release the IR
  Thread->OpDispatcher->DelayedDisownBuffer();

  return {
    .CompiledCode = std::move(CompiledCode),
    .DebugData = std::move(DebugData),
    .StartAddr = StartAddr,
    .Length = Length,
    .NeedsAddGuestCodeRanges = NeedsAddGuestCodeRanges,
  };
}

bool CodeCache::SaveData(Core::InternalThreadState& Thread, int fd, const ExecutableFileSectionInfo& SourceBinary, uint64_t SerializedBaseAddress) {
  auto CodeBuffer = CTX.GetLatest();
  auto& LookupCache = *Thread.LookupCache->Shared;

  auto Relocations = Thread.CPUBackend->TakeRelocations();

  // Rebase relocations to library base address
  // TODO: Do this in a dedicated "FinalizeRelocations" function
  for (auto& Relocation : Relocations) {
    switch (Relocation.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE:
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL:
      Relocation.GuestRIPMove.GuestRIP -= SourceBinary.FileStartVA;
      if (!CTX.Config.Is64BitMode()) {
        // TODO: Is masking here reasonable or should we instead *not* mask when generating the relocation in the first place?
        Relocation.GuestRIPMove.GuestRIP &= 0xffffffff;
      }
      break;
    default:;
    }
  }

  // TODO: Verify source ELF is PIE, otherwise we'll need to factor in ELF relocations

  // Write file header
  // TODO: Include information about the cached object (base VA address etc)
  //       TODO: Not clear if SMCTracking is currently aware of the main executable?
  struct Header {
    char Magic[4] = {'F', 'A', 'O', 'T'};
    uint32_t FormatVersion = 1;
    char FEXVersion[8] = {};
    uint32_t NumBlocks;
    uint32_t NumBlockLinks; // TODO: Unused
    uint32_t NumCodePages;
    uint32_t CodeBufferSize;
    uint32_t NumRelocations;
    uint64_t SerializedBaseAddress;
  } header;
  memcpy(&header.FEXVersion[0], GIT_SHORT_HASH, strlen(GIT_SHORT_HASH)); // TODO: Assert this is the correct length
  header.NumBlocks = LookupCache.BlockList.size();
  header.NumBlockLinks = LookupCache.BlockLinks->size();
  header.NumCodePages = LookupCache.CodePages.size();
  header.CodeBufferSize = CodeBuffer->UsedSize;
  header.NumRelocations = Relocations.size();
  header.SerializedBaseAddress = SerializedBaseAddress;
  ::write(fd, &header, sizeof(header));

  // Dump guest<->host block mappings
  // TODO: Strip ASLR-dependence by relocating to base ELF offset
  // TODO: Verify this all relates to the dumped ELF (and not any of its dependencies)
  // TODO: Drop blocks that don't belong to this library
  {
    fextl::vector<decltype(LookupCache.BlockList)::value_type> BlockList {LookupCache.BlockList.begin(), LookupCache.BlockList.end()};
    for (auto [Guest, Host] : LookupCache.BlockList) {
      Guest -= SourceBinary.FileStartVA;
      ::write(fd, &Guest, sizeof(Guest));
      Host -= reinterpret_cast<uintptr_t>(CodeBuffer->Ptr);
      ::write(fd, &Host, sizeof(Host));
    }
  }
  for (auto& [Record, _] : *LookupCache.BlockLinks) {
    // TODO: Consider if we need to serialize this data

    // NOTE: This is assumed to always be a direct link, since indirect ones would likely point to a (different) shared library
    // // TODO: Needs JIT interface to distinguish direct from indirect links
    // ERROR_AND_DIE_FMT("TODO: Implement BlockLinks writing");
    // auto Data = std::pair {Guest, Host};
    // ::write(fd, &Data, sizeof(Data));
  }

  std::vector<std::byte> CodeBufferData(CodeBuffer->UsedSize);
  if (!CodeBufferData.empty()) {
    memcpy(CodeBufferData.data(), CodeBuffer->Ptr, CodeBufferData.size());
  }
  // TODO: Check return value
  (void)ApplyCodeRelocations(SerializedBaseAddress, CodeBufferData, Relocations, true, SerializedBaseAddress != 0);

  // Dump relocations
  ::write(fd, Relocations.data(), Relocations.size() * sizeof(Relocations[0]));

  // Pad to next page in file so that the CodeBuffer can be mmap'ed into process on load
  char Zero[64] {};
  auto Off = lseek(fd, 0, SEEK_CUR);
  while (Off != AlignUp(Off, Utils::FEX_PAGE_SIZE)) {
    auto BytesToWrite = std::min(AlignUp(Off, Utils::FEX_PAGE_SIZE) - Off, sizeof(Zero));
    ::write(fd, Zero, BytesToWrite);
    Off += BytesToWrite;
  }

  // Dump CodeBuffer to file
  // TODO: Instead of dumping UsedSize, only dump the data belonging to the library!
  ::write(fd, CodeBufferData.data(), CodeBufferData.size());

  // TODO: Align to 64-bit?
  for (auto& [Page, Entrypoints] : LookupCache.CodePages) {
    ::write(fd, &Page, sizeof(Page));
    uint64_t NumEntrypoints = Entrypoints.size();
    ::write(fd, &NumEntrypoints, sizeof(NumEntrypoints));
    ::write(fd, Entrypoints.data(), Entrypoints.size() * sizeof(Entrypoints[0]));
  }

  // TODO:
  // Generate and dump separate "CodeMap" at runtime:
  // * Code offsets not discovered statically
  // * Code generated at runtime (if position-independent?)
  // * Referenced libraries

  return true;
}

uintptr_t ContextImpl::CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  auto Thread = Frame->Thread;
  FEXCORE_PROFILE_SCOPED("CompileBlock");
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedJITTime);

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  // Is the code in the cache?
  // The backends only check L1 and L2, not L3
  if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
    return HostCode;
  }

  // Accumulate a JIT count now, as even if another thread raced us, it should count as a compile.
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedJITCount, 1);

  auto [CompiledCode, DebugData, StartAddr, Length, NeedsAddGuestCodeRanges] = CompileCode(Thread, GuestRIP, MaxInst);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  } else if (!DebugData) {
    // DebugData wasn't populated, indicating another thread raced us for compiling this block
    return reinterpret_cast<uintptr_t>(CodePtr);
  }

  // The core managed to compile the code.
  if (Config.BlockJITNaming()) {
    auto FragmentBasePtr = CompiledCode.BlockBegin;

    if (DebugData) {
      auto GuestRIPLookup = SyscallHandler->LookupExecutableFileSection(*Thread, GuestRIP);

      if (DebugData->Subblocks.size()) {
        for (auto& Subblock : DebugData->Subblocks) {
          auto BlockBasePtr = FragmentBasePtr + Subblock.HostCodeOffset;
          if (GuestRIPLookup) {
            Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                             GuestRIP - GuestRIPLookup->FileStartVA);
          } else {
            Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, GuestRIP, Subblock.HostCodeSize);
          }
        }
      } else {
        if (GuestRIPLookup) {
          Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                           GuestRIP - GuestRIPLookup->FileStartVA);
        } else {
          Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, GuestRIP, CompiledCode.Size);
        }
      }
    }
  }

  // Clear any relocations that might have been generated
  if (!CodeCache.IsGeneratingCache) {
    Thread->CPUBackend->ClearRelocations();
  }

  if (Config.LibraryJITNaming() || Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(*Thread, GuestRIP);
    if (MappedSection) {
      if (Config.LibraryJITNaming()) {
        Symbols.RegisterNamedRegion(Thread->SymbolBuffer.get(), /*CodePtr*/ CompiledCode.BlockBegin, DebugData->HostCodeSize,
                                    MappedSection->FileInfo.Filename);
      }

      if (Config.GDBSymbols()) {
        GDBJITRegister(MappedSection->FileInfo, MappedSection->FileStartVA, GuestRIP, (uintptr_t)/*CodePtr*/ CompiledCode.BlockBegin, *DebugData);
      }
    }
  }

  if (NeedsAddGuestCodeRanges) {
    // Track in the guest to host map all entrypoints for all pages the compiled block touches, if any page didn't previously
    // contain code, inform the frontend so it can setup SMC detection.
    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    for (auto CodePage : BlockInfo->CodePages) {
      if (Thread->LookupCache->AddBlockExecutableRange(Thread, BlockInfo->EntryPoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
        SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
  }

  // Insert to lookup cache
  for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
    Thread->LookupCache->AddBlockMapping(Thread, GuestAddr, HostAddr);
  }

  SyscallHandler->MarkGuestCodeRoot(*Thread, GuestRIP);

  return (uintptr_t)CodePtr;
}

uintptr_t ContextImpl::CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  FEXCORE_PROFILE_SCOPED("CompileSingleStep");
  auto Thread = Frame->Thread;

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  auto [CompiledCode, DebugData, StartAddr, Length, _] = CompileCode(Thread, GuestRIP, 1);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  }

  // Clear any relocations that might have been generated
  Thread->CPUBackend->ClearRelocations();

  return (uintptr_t)CodePtr;
}

static void InvalidateGuestThreadCodeRange(FEXCore::Core::InternalThreadState* Thread, InvalidatedEntryAccumulator& Accumulator,
                                           uint64_t Start, uint64_t Length) {
  // Ensures now-modified mappings aren't cached as being in their previous non-executable state.
  // Accessing FrontendDecoder is safe as the thread's code invalidation mutex must be locked here.
  Thread->FrontendDecoder->ResetExecutableRangeCache();

  auto lk = Thread->LookupCache->AcquireWriteLock();
  auto& CodePages = Thread->LookupCache->Shared->CodePages;

  auto lower = CodePages.lower_bound(Start >> 12);
  auto upper = CodePages.upper_bound((Start + Length - 1) >> 12);

  for (auto it = lower; it != upper; it++) {
    Accumulator.emplace_back(std::move(it->second));
  }

  bool InvalidatedAnyEntries = false;
  for (const auto& PageEntries : Accumulator) {
    for (const auto& Entry : PageEntries) {
      if (ContextImpl::ThreadRemoveCodeEntry(Thread, Entry, lk)) {
        InvalidatedAnyEntries = true;
      }
    }
  }

  if (InvalidatedAnyEntries) {
    // This may cause access violations in the thread on Windows as zeroing is not atomic, this is handled by the frontend
    Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  }
}

void ContextImpl::InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, InvalidatedEntryAccumulator& Accumulator,
                                           uint64_t Start, uint64_t Length) {
  InvalidateGuestThreadCodeRange(Thread, Accumulator, Start, Length);
}

bool ContextImpl::ThreadRemoveCodeEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP,
                                        const FEXCore::LookupCacheWriteLockToken& lk) {
  LogMan::Throw::AFmt(static_cast<ContextImpl*>(Thread->CTX)->CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to "
                                                                                                         "be unique_locked here");

  return Thread->LookupCache->Erase(Thread->CurrentFrame, GuestRIP, lk);
}

void ContextImpl::ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  static_cast<ContextImpl*>(Frame->Thread->CTX)->SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, GuestRIP, 1);
}

std::optional<CustomIRResult>
ContextImpl::AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator, void* Data) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::unique_lock lk(CustomIRMutex);

  auto InsertedIterator = CustomIRHandlers.emplace(Entrypoint, CustomIRHandlerEntry {Handler, Creator, Data});
  HasCustomIRHandlers = true;

  if (!InsertedIterator.second) {
    const auto& [fn, Creator, Data] = InsertedIterator.first->second;
    return CustomIRResult(Creator, Data);
  }

  return std::nullopt;
}

void ContextImpl::AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) {
  LOGMAN_THROW_A_FMT(Entrypoint, "Tried to link null pointer address to guest function");
  LOGMAN_THROW_A_FMT(GuestThunkEntrypoint, "Tried to link address to null pointer guest function");
  if (!Config.Is64BitMode) {
    LOGMAN_THROW_A_FMT((Entrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
    LOGMAN_THROW_A_FMT((GuestThunkEntrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
  }

  LogMan::Msg::DFmt("Thunks: Adding guest trampoline from address {:#x} to guest function {:#x}", Entrypoint, GuestThunkEntrypoint);

  auto Result = AddCustomIREntrypoint(
    Entrypoint,
    [this, GuestThunkEntrypoint](uintptr_t Entrypoint, FEXCore::IR::IREmitter* emit) {
      auto IRHeader = emit->_IRHeader(emit->Invalid(), Entrypoint, 0, 0, 0, 0);
      auto Block = emit->CreateCodeNode(true, 0);
      IRHeader.first->Blocks = emit->WrapNode(Block);
      emit->SetCurrentCodeBlock(Block);

      const auto GPRSize = this->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;

      if (GPRSize == IR::OpSize::i64Bit) {
        IR::Ref R = emit->_StoreRegister(emit->Constant(Entrypoint), GPRSize);
        R->Reg = IR::PhysicalRegister(IR::RegClass::GPRFixed, X86State::REG_R11).Raw;
      } else {
        emit->_StoreContextFPR(GPRSize, emit->_VCastFromGPR(IR::OpSize::i64Bit, IR::OpSize::i64Bit, emit->Constant(Entrypoint)),
                               offsetof(Core::CPUState, mm[0][0]));
      }
      emit->_ExitFunction(IR::OpSize::i64Bit, emit->Constant(GuestThunkEntrypoint), IR::BranchHint::None, emit->Invalid(), emit->Invalid());
    },
    ThunkHandler, (void*)GuestThunkEntrypoint);

  if (Result.has_value()) {
    if (Result->Creator != ThunkHandler) {
      ERROR_AND_DIE_FMT("Input address for AddThunkTrampoline is already linked by another module");
    }
    if (Result->Data != (void*)GuestThunkEntrypoint) {
      // NOTE: This may happen in Vulkan thunks if the Vulkan driver resolves two different symbols
      //       to the same function (e.g. vkGetPhysicalDeviceFeatures2/vkGetPhysicalDeviceFeatures2KHR)
      LogMan::Msg::EFmt("Input address for AddThunkTrampoline is already linked elsewhere");
    }
  }
}

void ContextImpl::AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  ForceTSOValidRanges.Insert(ValidRanges);
  ForceTSOInstructions.merge(std::move(Instructions));
}

extern "C" {
extern bool g_print_ir;
}

void ContextImpl::RemoveForceTSOInformation(uint64_t Address, uint64_t Size) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  ForceTSOValidRanges.Remove({Address, Address + Size});
  ForceTSOInstructions.erase(ForceTSOInstructions.lower_bound(Address), ForceTSOInstructions.upper_bound(Address + Size));
}

void ContextImpl::MarkMonoBackpatcherBlock(uint64_t BlockEntry) {
  MonoBackpatcherBlock.store(BlockEntry, std::memory_order_relaxed);
}

void ContextImpl::RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::scoped_lock lk(CustomIRMutex);

  CustomIRHandlers.erase(Entrypoint);
  HasCustomIRHandlers = !CustomIRHandlers.empty();
  SyscallHandler->InvalidateGuestCodeRange(Thread, Entrypoint, 1);
}

void ContextImpl::MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value) {
  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);
  {
    auto lk = GuardSignalDeferringSection(CTX->CodeInvalidationMutex, Thread);

    if (Size == 8) {
      *reinterpret_cast<uint64_t*>(Address) = Value;
    } else if (Size == 4) {
      *reinterpret_cast<uint32_t*>(Address) = Value;
    } else {
      ERROR_AND_DIE_FMT("Unexpected write size for backpatcher: {}", Size);
    }
  }

  CTX->SyscallHandler->InvalidateGuestCodeRange(Thread, Address, Size);
}

void CodeCache::LoadData(Core::InternalThreadState& Thread, std::byte* MappedCacheFile, const ExecutableFileSectionInfo& GuestRIPLookup) {
  auto Lock = std::unique_lock {CTX.CodeBufferWriteMutex};

  {
    LogMan::Msg::IFmt("LoadAll of {} to VA base {:#x}: {:016x} ({:#x}-{:#x})", GuestRIPLookup.FileInfo.Filename, GuestRIPLookup.FileStartVA,
                      GuestRIPLookup.FileInfo.FileId, GuestRIPLookup.BeginVA, GuestRIPLookup.EndVA);

    {
      // TODO: Acquire write mutex?

      auto CodeBuffer = CTX.GetLatest();
      auto& LookupCache = *CodeBuffer->LookupCache;

      // TODO: Verify source ELF is PIE, otherwise we'll need to factor in ELF relocations

      // Read file header
      struct Header {
        char Magic[4] = {'F', 'A', 'O', 'T'};
        uint32_t FormatVersion = 1;
        char FEXVersion[8] = {};
        uint32_t NumBlocks;
        uint32_t NumBlockLinks;
        uint32_t NumCodePages;
        uint32_t CodeBufferSize;
        uint32_t NumRelocations;
        uint64_t SerializedBaseAddress;
      } header;
      // memcpy(&header.FEXVersion[0], GIT_SHORT_HASH, strlen(GIT_SHORT_HASH));
      ::memcpy(&header, MappedCacheFile, sizeof(header));
      MappedCacheFile += sizeof(header);

      if (header.SerializedBaseAddress && GuestRIPLookup.FileStartVA != header.SerializedBaseAddress) {
        // TODO: Implement support for translating relocations
        LogMan::Msg::EFmt("File relocated to a different base address; skipping cache");
        return;
      }

      char ExpectedVersion[8] = GIT_SHORT_HASH;
      std::fill(std::begin(ExpectedVersion) + strlen(GIT_SHORT_HASH), std::end(ExpectedVersion), 0);
      if (!std::equal(std::begin(header.FEXVersion), std::end(header.FEXVersion), std::begin(ExpectedVersion), std::end(ExpectedVersion))) {
        // fextl::fmt::print(stderr, "Version mismatch: {:02x} {:02x}\n", fmt::join(std::begin(header.FEXVersion), std::end(header.FEXVersion), ""),
        //                   fmt::join(std::begin(ExpectedVersion), std::end(ExpectedVersion), ""));
        // ERROR_AND_DIE_FMT("Version mismatch");
      }

      // Align CodeBuffer to next page
      // TODO: Use CodeBuffers.LatestOffset instead!!!
      // TODO: CheckCodeBufferUpdate and ensure enough space is still available
      if (reinterpret_cast<uintptr_t>(CodeBuffer->Ptr) % 0x1000) {
        ERROR_AND_DIE_FMT("TODO: Expected CodeBuffer to be page-aligned");
      }
      auto Delta = AlignUp(CTX.LatestOffset, 0x1000) - CTX.LatestOffset;
      CTX.LatestOffset += Delta;
      CodeBuffer->UsedSize += Delta;

      std::span<std::byte> CodeBufferRange =
        std::as_writable_bytes(std::span {CodeBuffer->Ptr, CodeBuffer->Ptr + CodeBuffer->Size}).subspan(CTX.LatestOffset, header.CodeBufferSize);

      // Read guest<->host block mappings
      // TODO: Strip ASLR-dependence by relocating to base ELF offset
      // TODO: Verify this all relates to the dumped ELF (and not any of its dependencies)
      // TODO: BlockList must use a flat std::pair!!!!
      fextl::vector<decltype(LookupCache.BlockList)::value_type> BlockList(header.NumBlocks);
      {
        ::memcpy(BlockList.data(), MappedCacheFile, sizeof(BlockList[0]) * BlockList.size());
        MappedCacheFile += sizeof(BlockList[0]) * BlockList.size();

        if (BlockList.empty()) {
          LogMan::Msg::IFmt("Code cache empty, aborting");
          return;
        }

        // Consistency check: VMA regions at the top and end should belong to the same file
        {
          auto [min_val, max_val] = std::minmax_element(BlockList.begin(), BlockList.end());
          auto MinBound = CTX.SyscallHandler->LookupExecutableFileSection(Thread, min_val->first + GuestRIPLookup.FileStartVA);
          auto MaxBound = CTX.SyscallHandler->LookupExecutableFileSection(Thread, max_val->first + GuestRIPLookup.FileStartVA);
          if (&MinBound->FileInfo != &GuestRIPLookup.FileInfo || &MaxBound->FileInfo != &GuestRIPLookup.FileInfo) {
            ERROR_AND_DIE_FMT("Cached blocks offsets {:#x}-{:#x} out of bounds for guest library {} ({:016x} @ {:#x}) while trying to load "
                              "section {:#x}-{:#x}!",
                              min_val->first, max_val->first, GuestRIPLookup.FileInfo.Filename, GuestRIPLookup.FileInfo.FileId,
                              GuestRIPLookup.FileStartVA, GuestRIPLookup.BeginVA, GuestRIPLookup.EndVA);
          }
        }

        decltype(BlockList) BlockList2;
        // TODO: Now that we constrain this to the enabled region, ensure the CodeBuffer data isn't re-loaded for each region...
        std::copy_if(BlockList.begin(), BlockList.end(), std::back_insert_iterator(BlockList2), [&](auto& Entry) {
          return (Entry.first + GuestRIPLookup.FileStartVA >= GuestRIPLookup.BeginVA &&
                  Entry.first + GuestRIPLookup.FileStartVA < GuestRIPLookup.EndVA);
        });
        // TODO: Sort when writing the cache instead!
        std::sort(BlockList2.begin(), BlockList2.end(), [](auto& a, auto& b) { return a.first < b.first; });
        BlockList = std::move(BlockList2);
        if (BlockList.empty()) {
          LogMan::Msg::IFmt("No blocks cached in this range, aborting");
          return;
        }

        for (auto& [Guest, Host] : BlockList) {
          // TODO: Can we keep this enabled when re-compiling?
          LookupCache.BlockList[Guest + GuestRIPLookup.FileStartVA] = Host + reinterpret_cast<uintptr_t>(CodeBufferRange.data());
        }
      }

      // TODO: De-serialize BlockLinks (if needed)

      // Read relocations
      fextl::vector<FEXCore::CPU::Relocation> Relocations(header.NumRelocations);
      ::memcpy(Relocations.data(), MappedCacheFile, Relocations.size() * sizeof(Relocations[0]));
      MappedCacheFile += Relocations.size() * sizeof(Relocations[0]);
      // TODO: Store relocations in JIT for later re-relocation

      // Pad to next page in file, which contains CodeBuffer data
      MappedCacheFile = reinterpret_cast<std::byte*>(AlignUp(reinterpret_cast<uintptr_t>(MappedCacheFile), Utils::FEX_PAGE_SIZE));

      // Read CodeBuffer from file
      // TODO: mmap this into memory instead
      if (header.CodeBufferSize > CodeBufferRange.size_bytes()) {
        ERROR_AND_DIE_FMT("TODO: CodeBuffer too small to load initial cache");
      }
      ::memcpy(CodeBufferRange.data(), MappedCacheFile, header.CodeBufferSize);
      MappedCacheFile += header.CodeBufferSize;
      CodeBuffer->UsedSize += header.CodeBufferSize;
      CTX.LatestOffset += header.CodeBufferSize;

      // Apply FEX relocations
      // TODO: Check return value
      (void)ApplyCodeRelocations(GuestRIPLookup.FileStartVA, CodeBufferRange, Relocations, false,
                                 GuestRIPLookup.FileStartVA == header.SerializedBaseAddress);

      // TODO: Align to 64-bit?
      fextl::vector<uint64_t> Entrypoints;
      for (uint32_t i = 0; i < header.NumCodePages; ++i) {
        uint64_t CodePage;
        memcpy(&CodePage, MappedCacheFile, sizeof(CodePage));
        MappedCacheFile += sizeof(CodePage);

        uint64_t NumEntrypoints;
        memcpy(&NumEntrypoints, MappedCacheFile, sizeof(NumEntrypoints));
        MappedCacheFile += sizeof(NumEntrypoints);

        Entrypoints.resize(NumEntrypoints);
        memcpy(Entrypoints.data(), MappedCacheFile, NumEntrypoints * sizeof(Entrypoints[0]));
        MappedCacheFile += NumEntrypoints * sizeof(Entrypoints[0]);

        // TODO: Re-use set allocations
        if (Thread.LookupCache->AddBlockExecutableRange(&Thread, fextl::set<uint64_t> {Entrypoints.begin(), Entrypoints.end()}, CodePage,
                                                        FEXCore::Utils::FEX_PAGE_SIZE)) {
          // TODO: How to do this without a thread?
          CTX.SyscallHandler->MarkGuestExecutableRange(&Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
        }
      }


      // TODO: Invalidate any pages that are affected by ELF relocations (and eventually add support for converting those relocations to FEX relocations)

      LogMan::Msg::IFmt("\tLoaded cache: {}-{} ({}/{} blocks, {} relocs)", fmt::ptr(CodeBufferRange.data()),
                        fmt::ptr(CodeBufferRange.data() + header.CodeBufferSize), BlockList.size(), header.NumBlocks, Relocations.size());

      const bool force_recompile = false;
      if (force_recompile) {
        // Validation pass:
        // * Ensures JIT configuration at cache time matches runtime
        // * Ensures relocations work properly (relocated cache code buffer should match unrelocated runtime code buffer)

        if (!ValidationCTX) {
          ValidationCTX.reset(static_cast<ContextImpl*>(FEXCore::Context::Context::CreateNewContext(CTX.HostFeatures).release()));
          ValidationCTX->SetSignalDelegator(CTX.SignalDelegation);
          ValidationCTX->SetSyscallHandler(CTX.SyscallHandler);
          ValidationCTX->SetThunkHandler(CTX.ThunkHandler);
          // ERROR_AND_DIE_FMT("TODO: Handle codemapwriter changes");
          // ValidationCTX->CodeMapWriter.reset(); // TODO: Unset CodeMapWriter and reset it at the end of this scope
          if (!ValidationCTX->InitCore()) {
            ERROR_AND_DIE_FMT("FAILED TO INIT TEMPORARY COMPILE CTX");
          }

          ValidationThread.reset(ValidationCTX->CreateThread(0, 0, nullptr));

          auto Frame = ValidationThread->CurrentFrame;
          Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &gdt[0];
          Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &gdt[0];
          Frame->State.cs_idx = 0;
          Frame->State.cs_cached = 0;

          if (ValidationCTX->Config.Is64BitMode()) {
            gdt[0].L = 1; // L = Long Mode = 64-bit
            gdt[0].D = 0; // D = Default Operand Size = Reserved
          } else {
            gdt[0].L = 0; // L = Long Mode = 32-bit
            gdt[0].D = 1; // D = Default Operand Size = 32-bit
          }
        }

        auto NewCodeBuffer = ValidationCTX->GetLatest();

        std::span<std::byte> CodeBufferRangeRef =
          std::as_writable_bytes(std::span {NewCodeBuffer->Ptr, NewCodeBuffer->Ptr + NewCodeBuffer->Size}).subspan(0, header.CodeBufferSize);

        fextl::set<uint64_t> BlockListSorted;
        for (auto& [Guest, Host] : BlockList) {
          BlockListSorted.insert(Guest);
        }
        // g_print_ir = true;
        while (!BlockListSorted.empty()) {
          auto& Guest = *BlockListSorted.begin();
          auto [CompiledBlocks, _, _2, _3, _4] =
            ValidationCTX->CompileCode(ValidationThread.get(), Guest + GuestRIPLookup.FileStartVA, 0 /* TODO: Set MaxInst? */);
          // TODO: assert CompiledBlocks.EntryPoints.contains(Guest + GuestRIPLookup.VAFileStart);
          for (auto& Entry : CompiledBlocks.EntryPoints) {
            BlockListSorted.erase(Entry.first - GuestRIPLookup.FileStartVA);
          }
        }
        g_print_ir = false;

        // Patch FEX-internal function addresses with values from the main Context to ensure the code blocks are comparable
        auto NewRelocations = ValidationThread->CPUBackend->TakeRelocations();
        NewRelocations.erase(std::remove_if(NewRelocations.begin(), NewRelocations.end(), [](const CPU::Relocation& Reloc) {
          return Reloc.Header.Type != CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL &&
                 Reloc.Header.Type != CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE;
        }));
        (void)ApplyCodeRelocations(0, CodeBufferRangeRef, NewRelocations, false, false);

        CodeBufferRangeRef = CodeBufferRangeRef.subspan(0, NewCodeBuffer->UsedSize);

        LogMan::Msg::IFmt("\tRegenerated cache");
        uint64_t drift = BlockList.front().second - sizeof(CPU::CPUBackend::JITCodeHeader);
        if (!BlockList.empty() && !std::equal(CodeBufferRange.begin() + drift, CodeBufferRange.begin() + drift + CodeBufferRangeRef.size(),
                                              CodeBufferRangeRef.begin(), CodeBufferRangeRef.end())) {
          for (size_t Idx = 0; Idx < CodeBufferRangeRef.size(); ++Idx) {
            if (CodeBufferRange[drift + Idx] != CodeBufferRangeRef[Idx]) {
              fextl::set<uint64_t> BlockHostAddrs;
              for (auto [_, HostAddr] : BlockList) {
                BlockHostAddrs.insert(HostAddr);
              }
              // TODO: Actually this is pointing to the block *after* in many (all?) cases now... hacking in an std::prev as a workaround
              auto BlockIt = /*std::prev*/ (BlockHostAddrs.lower_bound(
                drift + Idx /*+ sizeof(CPU::CPUBackend::JITCodeHeader)*/)); // If Idx points to JITCodeHeader, adding the header size will ensure the proper block is selected
              std::optional<uint64_t> GuestBlockAddr;
              std::optional<uint64_t> GuestBlockAddrRef;
              CPU::CPUBackend::JITCodeTail* tail;
              if (BlockIt != BlockHostAddrs.end()) {
                {
                  auto header =
                    reinterpret_cast<CPU::CPUBackend::JITCodeHeader*>(&CodeBufferRange[*BlockIt] - sizeof(CPU::CPUBackend::JITCodeHeader));
                  auto tail = reinterpret_cast<CPU::CPUBackend::JITCodeTail*>(reinterpret_cast<uintptr_t>(header) + header->OffsetToBlockTail);
                  GuestBlockAddr = tail->RIP - GuestRIPLookup.FileStartVA;
                  LogMan::Msg::EFmt("recorded rip 1: {:#x} - {:#x}", tail->RIP, GuestRIPLookup.FileStartVA);
                }

                auto header = reinterpret_cast<CPU::CPUBackend::JITCodeHeader*>(
                  &CodeBufferRangeRef[*BlockIt - drift] - sizeof(CPU::CPUBackend::JITCodeHeader));
                tail = reinterpret_cast<CPU::CPUBackend::JITCodeTail*>(reinterpret_cast<uintptr_t>(header) + header->OffsetToBlockTail);
                {
                  GuestBlockAddrRef = tail->RIP - GuestRIPLookup.FileStartVA;
                  LogMan::Msg::EFmt("recorded rip 2: {:#x} - {:#x}", tail->RIP, GuestRIPLookup.FileStartVA);
                }
              }
              LogMan::Msg::EFmt("Mismatch at host block {:#x}", *BlockIt);

              // TODO: When launching ManifoldGarden.exe through wine, this actually triggers this logic IN 32-BIT MODE!
              // TODO: Tunic.exe fails this because its second executable segment is mapped as non-executable first, then later remapped.
              // TODO: 32-bit libmimalloc fails at block 0x7bc9 due to patching a constant! We shouldn't fetch caches for libraries that have been modified
              //       ACTUALLY, THIS IS PROBABLY SIMPLY DUE TO PE RELOCATIONS! FEXOfflineCompiler should relocate to the PE base address instead of 0, and FEX runtime should reject caches for different addresses until relocation-translation is implemented
              LogMan::Msg::EFmt("MISMATCH AT IDX {:#x}: {:02x}{:02x}{:02x}{:02x} <-> {:02x}{:02x}{:02x}{:02x}, {} <-> {} (guest block "
                                "{:#x} / {:#x}), {} ({:016x})",
                                Idx, CodeBufferRange[Idx + drift], CodeBufferRange[Idx + drift + 1], CodeBufferRange[Idx + drift + 2],
                                CodeBufferRange[Idx + drift + 3], CodeBufferRangeRef[Idx], CodeBufferRangeRef[Idx + 1],
                                CodeBufferRangeRef[Idx + 2], CodeBufferRangeRef[Idx + 3], fmt::ptr(CodeBufferRange.data() + drift),
                                fmt::ptr(CodeBufferRangeRef.data()), GuestBlockAddr.value_or(0), GuestBlockAddrRef.value_or(0), ::getpid(),
                                GuestRIPLookup.FileInfo.FileId /* TODO: Also include cache id */);
              if (tail) {
                auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, _] =
                  ValidationCTX->GenerateIR(ValidationThread.get(), tail->RIP, false, 10000 /* TODO? */);
                fextl::stringstream ss;
                FEXCore::IR::Dump(&ss, &*IRView);
                LogMan::Msg::EFmt("IR ({}):\n{}", ValidationCTX->Config.Is64BitMode(), ss.str());
              }
              while (!FEXCore::IsDebuggerAttached()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
              }
              ERROR_AND_DIE_FMT("Bla");
            }
          }
        }

        // Reset Context state for next validation
        ValidationThread->LookupCache->ClearCache(ValidationThread->LookupCache->AcquireWriteLock());
        ValidationCTX->LatestOffset = 0;
      }
    }
  }
}

void ContextImpl::ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) {
  Thread->FrontendDecoder->SetExternalBranches(ExternalBranches);
  Thread->FrontendDecoder->SetSectionMaxAddress(SectionMaxAddress);
}
} // namespace FEXCore::Context
