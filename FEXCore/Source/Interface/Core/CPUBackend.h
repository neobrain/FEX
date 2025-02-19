// SPDX-License-Identifier: MIT
/*
$info$
category: backend ~ IR to host code generation
tags: backend|shared
$end_info$
*/

#pragma once

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/fextl/list.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <atomic>


#include <FEXCore/Utils/SignalScopeGuards.h>

// struct mymutex : private std::timed_mutex {
//   auto AcquireLock() {
//     std::unique_lock<mymutex> lock(*this, std::chrono::seconds {1});
//     if (!lock) {
//       fmt::print(stderr, "DEADLOCK\n");
//       ERROR_AND_DIE_FMT("DEADLOCK\n");
//     }
//     return lock;
//   }

//   void AssertIsLocked() {
//     if (!IsLocked) {
//       fmt::print(stderr, "NOT LOCKED\n");
//       ERROR_AND_DIE_FMT("NOT LOCKED\n");
//     }
//   }

//   std::atomic<bool> IsLocked = false;
//   void lock() {
//     std::timed_mutex::lock();
//     IsLocked = true;
//     // fmt::print(stderr, "LOCKING\n");
//   }
//   bool try_lock() {
//     bool ret = std::timed_mutex::try_lock();
//     if (ret) {
//       IsLocked = true;
//     }
//     return ret;
//     // fmt::print(stderr, "LOCKING\n");
//   }
//   template< class Rep, class Period >
//   bool try_lock_for(const std::chrono::duration<Rep, Period>& timeout_duration) {
//     bool ret = std::timed_mutex::try_lock_for(timeout_duration);
//     if (ret) {
//       IsLocked = true;
//     }
//     return ret;
//   }
//   template< class Clock, class Duration >
//   bool try_lock_until(const std::chrono::time_point<Clock, Duration>& timeout_time) {
//     bool ret = std::timed_mutex::try_lock_until(timeout_time);
//     if (ret) {
//       IsLocked = true;
//     }
//     return ret;
//   }
//   void unlock() {
//     // fmt::print(stderr, "UNLOCKING\n");
//     IsLocked = false;
//     std::timed_mutex::unlock();
//   }
// };

struct mymutex : public FEXCore::ForkableUniqueMutex {
  auto AcquireLock() {
    return std::unique_lock<FEXCore::ForkableUniqueMutex> {*this};
  }

  void AssertIsLocked() {}
};


namespace FEXCore::CPU {
union Relocation;
}

namespace FEXCore {

namespace IR {
  class IRListView;
  class RegisterAllocationData;
} // namespace IR

namespace Core {
  struct DebugData;
  struct ThreadState;
  struct CpuStateFrame;
  struct InternalThreadState;
} // namespace Core

namespace CodeSerialize {
  struct CodeObjectFileSection;
}

struct SharedLookupCache;

namespace CPU {
  struct CodeBuffer {
    uint8_t* Ptr;
    size_t Size;
    // TODO: Only for profiling
    size_t UsedSize = 0;

    std::shared_ptr<CodeBuffer> next;

    fextl::unique_ptr<SharedLookupCache> LookupCache;

    CodeBuffer(size_t Size);
    CodeBuffer(const CodeBuffer&) = delete;
    CodeBuffer& operator=(const CodeBuffer&) = delete;
    CodeBuffer(CodeBuffer&& oth);
    CodeBuffer& operator=(CodeBuffer&&) = delete;

    ~CodeBuffer();
  };

  class CodeBufferManager {
  public:
    fextl::shared_ptr<CodeBuffer> AllocateNewCodeBuffer(size_t Size);

    size_t GetCurrentCodeBufferSize() {
      return GetCurrentCodeBuffer()->Size;
    }

    // TODO: Consider making const?
    std::shared_ptr<CodeBuffer> GetCurrentCodeBuffer();

    bool IsAddressInCodeBuffer(uintptr_t Address) const;

    // TODO: Turn back into fextl::vector
    // TODO: Do we need fextl::weak_ptr?
    fextl::vector<std::weak_ptr<CodeBuffer>> CodeBuffers;
    std::shared_ptr<CodeBuffer> Latest;
    std::size_t LatestOffset;
  };

  class CPUBackend {
  public:

    /**
     * @param InitialCodeSize - Initial size for the code buffers
     * @param MaxCodeSize - Max size for the code buffers
     */
    CPUBackend(CodeBufferManager&, FEXCore::Core::InternalThreadState*, size_t InitialCodeSize, size_t MaxCodeSize);

    virtual ~CPUBackend();

    struct CompiledCode {
      // Where this code block begins.
      uint8_t* BlockBegin;
      /**
       * The function entrypoint to this codeblock.
       *
       * This may or may not equal `BlockBegin` above. Depending on the CPU backend, it may stick data
       * prior to the BlockEntry.
       *
       * Is actually a function pointer of type `void (FEXCore::Core::ThreadState *Thread)`
       */
      uint8_t* BlockEntry;
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;
    };

    // Header that can live at the start of a JIT block.
    // We want the header to be quite small, with most data living in the tail object.
    struct JITCodeHeader {
      // Offset from the start of this header to where the tail lives.
      // Only 32-bit since the tail block won't ever be more than 4GB away.
      uint32_t OffsetToBlockTail;
    };

    // Header that can live at the end of the JIT block.
    // For any state reconstruction or other data, this is where it should live.
    // Any data that is explicitly tied to the JIT code and needs to be cached with it
    // should end up in this data structure.
    struct JITCodeTail {
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;

      // RIP that the block's entry comes from.
      uint64_t RIP;

      // The length of the guest code for this block.
      size_t GuestSize;

      // Number of RIP entries for this JIT Code section.
      uint32_t NumberOfRIPEntries;

      // Offset after this block to the start of the RIP entries.
      uint32_t OffsetToRIPEntries;

      // Shared-code modification spin-loop futex.
      uint32_t SpinLockFutex;

      // If this block represents a single guest instruction.
      bool SingleInst;

      uint8_t _Pad[3];
    };

    /**
     * @brief Tells this CPUBackend to compile code for the provided IR and DebugData
     *
     * The returned pointer needs to be long lived and be executable in the host environment
     * FEXCore's frontend will store this pointer in to a cache for the current RIP when this was executed
     *
     * This is a thread specific compilation unit since there is one CPUBackend per guest thread
     *
     * @param Size - The byte size of the guest code for this block
     * @param SingleInst - If this block represents a single guest instruction
     * @param IR -  IR that maps to the IR for this RIP
     * @param DebugData - Debug data that is available for this IR indirectly
     * @param CheckTF - If EFLAGS.TF checks should be emitted at the start of the block
     *
     * @return Information about the compiled code block.
     */
    [[nodiscard]]
    virtual CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                     FEXCore::Core::DebugData* DebugData, const FEXCore::IR::RegisterAllocationData* RAData, bool CheckTF) = 0;

    /**
     * @brief Relocates a block of code from the JIT code object cache
     *
     * @param Entry - RIP of the entry
     * @param SerializationData - Serialization data referring to the object cache for `Entry`
     *
     * @return An executable function pointer relocated from the cache object
     */
    [[nodiscard]]
    virtual void* RelocateJITObjectCode(uint64_t Entry, std::span<const char> HostCode, std::span<const Relocation> Relocations) = 0;

    virtual void ClearCache() {}

    /**
     * @brief Clear any relocations after JIT compiling
     */
    virtual void ClearRelocations() {}

    // TODO: Remove. Just a wrapper around CodeBufferManager now
    bool IsAddressInCodeBuffer(uintptr_t Address) const;

    // Returns true if the CodeBuffer changed
    bool CheckCodeBufferUpdate();

  protected:
  public:
    // Max spill slot size in bytes. We need at most 32 bytes
    // to be able to handle a 256-bit vector store to a slot.
    constexpr static uint32_t MaxSpillSlotSize = 32;

    FEXCore::Core::InternalThreadState* ThreadState;

    size_t InitialCodeSize, MaxCodeSize;
    [[nodiscard]]
    CodeBuffer* GetEmptyCodeBuffer();

    // This is the current code buffer that we are tracking
    // TODO: Drop in favor of a plain uint32_t to track the current code buffer *size*
    // CodeBuffer* CurrentCodeBuffer {};
    std::shared_ptr<CodeBuffer> CurrentCodeBuffer;

    // Old CodeBuffer generations required to be valid until returning from signal handlers
    fextl::vector<std::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;

    CodeBufferManager& manager; // TODO: Rename
  };

} // namespace CPU
} // namespace FEXCore
