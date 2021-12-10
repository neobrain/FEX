/*
$info$
tags: frontend|x86-tables
$end_info$
*/

#pragma once
#include <FEXCore/Debug/X86Tables.h>
#include <FEXCore/Core/Context.h>

#include <FEXCore/Utils/LogManager.h>

namespace FEXCore::X86Tables {

template <typename OpcodeType>
struct X86TablesInfoStruct {
  OpcodeType first;
  uint8_t second;
  X86InstInfo Info;
};
using U8U8InfoStruct = X86TablesInfoStruct<uint8_t>;
using U16U8InfoStruct = X86TablesInfoStruct<uint16_t>;

template<typename OpcodeType>
[[nodiscard]] static consteval StaticEntryCount
CountEntries(X86TablesInfoStruct<OpcodeType> const * const LocalTable, size_t TableSize) {
  StaticEntryCount count;
  for (size_t j = 0; j < TableSize; ++j) {
    X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
    if (Op.Info.Type != TYPE_COPY_OTHER) {
      count.total += Op.second;
    }
    if (Op.Info.Type == TYPE_INST) {
      count.num_insts += Op.second;
    }
  }
  return count;
};

template<typename DATA, size_t N>
struct X86TablesInfoStructTable;
template<size_t N>
struct X86TablesInfoStructTable<uint8_t, N> {
  consteval X86TablesInfoStructTable(std::initializer_list<U8U8InfoStruct> data) {
    std::copy(data.begin(), data.end(), table.begin());
    count = CountEntries(table.data(), table.size());
  }

  std::array<U8U8InfoStruct, N> table;
  StaticEntryCount count;
};
template<size_t N>
struct X86TablesInfoStructTable<uint16_t, N> {
  consteval X86TablesInfoStructTable(std::initializer_list<U16U8InfoStruct> data) {
    std::copy(data.begin(), data.end(), table.begin());
    count = CountEntries(table.data(), table.size());
  }

  std::array<U16U8InfoStruct, N> table;
  StaticEntryCount count;
};

// Derive separate types for the specializations to allow matching template parameters via function overloading
template<size_t N>
struct U8U8InfoStructTable : X86TablesInfoStructTable<uint8_t, N> {};
template<size_t N>
struct U16U8InfoStructTable : X86TablesInfoStructTable<uint16_t, N> {};

// deduction guides for array size
template<size_t N>
U8U8InfoStructTable(const U8U8InfoStruct (&data)[N]) -> U8U8InfoStructTable<N>;
template<size_t N>
U16U8InfoStructTable(const U16U8InfoStruct (&data)[N]) -> U16U8InfoStructTable<N>;

#if __clang_major__ < 13
/* earlier clang versions can't initialize constinit variables from a consteval expression */
#define CONSTEVAL constexpr
#else
#define CONSTEVAL consteval
#endif

struct X86TableBuilder { /* TODO: Remove struct? */
  template<size_t N, typename OpcodeType, size_t TableSize>
  static CONSTEVAL std::array<X86InstInfo, N>
  GenerateInitTable(const X86TablesInfoStructTable<OpcodeType, TableSize>& LocalTable) {
    // TODO: Should move the check for internal conflicts to the tables themselves...
    CheckForInternalConflicts(LocalTable.table.data(), TableSize, true);

    std::array<X86InstInfo, N> ret {};
    GenerateTable(ret.data(), LocalTable.table.data(), TableSize);
    return ret;
  };

  template<size_t N, typename OpcodeType, size_t TableSize>
  static constexpr void PatchTable(std::array<X86InstInfo, N>& FinalTable, const X86TablesInfoStructTable<OpcodeType, TableSize>& LocalTable) {
//    CheckForEntryConflicts(FinalTable.data(), LocalTable, TableSize);
    GenerateTable(FinalTable.data(), LocalTable.table.data(), TableSize);
  };

  template<size_t N, typename OpcodeType, size_t TableSize>
  static constexpr void PatchTableWithCopy(std::array<X86InstInfo, N>& FinalTable, const X86TablesInfoStructTable<OpcodeType, TableSize>& LocalTable, X86InstInfo *OtherLocal) {
    return PatchTableWithCopy(FinalTable.data(), LocalTable.table.data(), TableSize, OtherLocal);
  }

  template<typename OpcodeType>
  static constexpr void PatchTableWithCopy(X86InstInfo *FinalTable, X86TablesInfoStruct<OpcodeType> const *LocalTable, size_t TableSize, X86InstInfo *OtherLocal) {
//    CheckForEntryConflicts(FinalTable, LocalTable, TableSize);
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
      auto OpNum = Op.first;
      X86InstInfo const &Info = Op.Info;
      for (uint32_t i = 0; i < Op.second; ++i) {
        if (Info.Type == TYPE_COPY_OTHER) {
          FinalTable[OpNum + i] = OtherLocal[OpNum + i];
        }
        // Assume other ops have been initialized statically already ... TODO: Should have a parameter for this instead
//        else {
//          FinalTable[OpNum + i] = Info;
//        }
      }
    }
  }

  template<size_t N, size_t TableSize>
  static CONSTEVAL std::array<X86InstInfo, N>
  GenerateX87Table(const U16U8InfoStructTable<TableSize>& LocalTable) {
    CheckForInternalConflicts(LocalTable.table.data(), TableSize, true);

    std::array<X86InstInfo, N> FinalTable{};
    for (size_t j = 0; j < TableSize; ++j) {
      U16U8InfoStruct const &Op = LocalTable.table[j];
      auto OpNum = Op.first;

      if ((OpNum & 0b11'000'000) == 0b11'000'000) {
        // If the mod field is 0b11 then it is a regular op
        std::fill_n(&FinalTable[OpNum], Op.second, Op.Info);
      } else {
        // If the mod field is !0b11 then this instruction is duplicated through the whole mod [0b00, 0b10] range
        // and the modrm.rm space because that is used part of the instruction encoding
        for (uint16_t mod = 0b00'000'000; mod < 0b11'000'000; mod += 0b01'000'000) {
          for (uint16_t rm = 0b000; rm < 0b1'000; ++rm) {
            std::fill_n(&FinalTable[OpNum | mod | rm], Op.second, Op.Info);
          }
        }
      }
    }
    return FinalTable;
  };

private:
  template<typename OpcodeType>
  static void CheckForEntryConflicts(X86InstInfo* FinalTable, X86TablesInfoStruct<OpcodeType> const * const LocalTable, size_t TableSize, bool IsX87) {
#ifndef NDEBUG
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
      auto OpNum = Op.first;
      for (uint32_t i = 0; i < Op.second; ++i) {
        // TODO: Perform this check in release mode too, at compile-time!
        LOGMAN_THROW_A_FMT(!FinalTable || FinalTable[OpNum + i].Type == TYPE_UNKNOWN, "Duplicate Entry {}->{}", FinalTable[OpNum + i].Name, Op.Info.Name);
        if (IsX87 && (OpNum & 0b11'000'000) != 0b11'000'000) {
          LOGMAN_THROW_A_FMT((OpNum & 0b11'000'000) == 0, "Only support mod field of zero in this path");
        }
      }
    }
#endif
  }

  template<typename OpcodeType>
  static
  CONSTEVAL
  void CheckForInternalConflicts(X86TablesInfoStruct<OpcodeType> const * const LocalTable, size_t TableSize, bool IsX87) {
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
//      auto OpNum = Op.first;
      for (uint32_t i = 0; i < Op.second; ++i) {
        // TODO: Implement?
      }
    }
  }

  template<typename OpcodeType>
  static constexpr void GenerateTable(X86InstInfo* FinalTable, X86TablesInfoStruct<OpcodeType> const * const LocalTable, size_t TableSize) {
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
      if (Op.Info.Type == TYPE_COPY_OTHER) {
        // Must be patched in at runtime with PatchTableWithCopy
        continue;
      }
      std::fill_n(&FinalTable[Op.first], Op.second, Op.Info);
    }
  };
};

extern StaticEntryCount DebugStats;

#ifndef NDEBUG
// Use this macro to update DebugStats with StaticEntryCounts computed from tables that are always active.
// The declared variable is never used, but its initializer will take care of updating DebugStats on program startup
#define UPDATE_STATIC_DEBUG_STATS(count) static auto run_side_effect = (DebugStats += (count));
#else
#define UPDATE_STATIC_DEBUG_STATS(count)
#endif

void InitializeInfoTables(Context::OperatingMode Mode);

}
