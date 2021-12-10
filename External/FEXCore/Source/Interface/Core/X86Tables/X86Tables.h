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

#ifndef NDEBUG
extern uint64_t Total;
extern uint64_t NumInsts;
#endif

template <typename OpcodeType>
struct X86TablesInfoStruct {
  OpcodeType first;
  uint8_t second;
  X86InstInfo Info;
};
using U8U8InfoStruct = X86TablesInfoStruct<uint8_t>;
using U16U8InfoStruct = X86TablesInfoStruct<uint16_t>;

struct X86TableBuilder {
  // TODO: Instead, use a sequence of sorted operations?

#ifndef NDEBUG
  uint64_t Total = 0;
  uint64_t NumInsts = 0;
#endif

  template<typename OpcodeType>
  constexpr void GenerateTable(X86InstInfo* FinalTable, X86TablesInfoStruct<OpcodeType> const * const LocalTable, size_t TableSize) {
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
      auto OpNum = Op.first;
      X86InstInfo const &Info = Op.Info;
      for (uint32_t i = 0; i < Op.second; ++i) {
  //      LOGMAN_THROW_A_FMT(FinalTable[OpNum + i].Type == TYPE_UNKNOWN, "Duplicate Entry {}->{}", FinalTable[OpNum + i].Name, Info.Name);
        FinalTable[OpNum + i] = Info;
  #ifndef NDEBUG
        ++Total;
        if (Info.Type == TYPE_INST)
          NumInsts++;
  #endif
      }
    }
  };

  template<size_t N, typename OpcodeType, size_t TableSize>
  static consteval std::array<X86InstInfo, N>
  GenerateInitTable(const X86TablesInfoStruct<OpcodeType> (&LocalTable)[TableSize]) {
    std::array<X86InstInfo, N> ret {};
    X86TableBuilder{}.GenerateTable(ret.data(), LocalTable, TableSize);
    return ret;
  };

  template<size_t N, typename OpcodeType, size_t TableSize>
  static consteval std::array<X86InstInfo, N> GenerateX87Table(const X86TablesInfoStruct<OpcodeType> (&LocalTable)[TableSize]) {
    std::array<X86InstInfo, N> FinalTable{};
    for (size_t j = 0; j < TableSize; ++j) {
      X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
      auto OpNum = Op.first;
      X86InstInfo const &Info = Op.Info;
      for (uint32_t i = 0; i < Op.second; ++i) {
//        LOGMAN_THROW_A_FMT(FinalTable[OpNum + i].Type == TYPE_UNKNOWN, "Duplicate Entry {}->{}", FinalTable[OpNum + i].Name, Info.Name);
        if ((OpNum & 0b11'000'000) == 0b11'000'000) {
          // If the mod field is 0b11 then it is a regular op
          FinalTable[OpNum + i] = Info;
        }
        else {
          // If the mod field is !0b11 then this instruction is duplicated through the whole mod [0b00, 0b10] range
          // and the modrm.rm space because that is used part of the instruction encoding
//          LOGMAN_THROW_A_FMT((OpNum & 0b11'000'000) == 0, "Only support mod field of zero in this path");
          for (uint16_t mod = 0b00'000'000; mod < 0b11'000'000; mod += 0b01'000'000) {
            for (uint16_t rm = 0b000; rm < 0b1'000; ++rm) {
              FinalTable[(OpNum | mod | rm) + i] = Info;
            }
          }
        }
#ifndef NDEBUG
          ++Total;
          if (Info.Type == TYPE_INST)
            NumInsts++;
#endif
      }
    }
    return FinalTable;
  };
};

// TODO: Move to X86TableBuilder?
template<typename OpcodeType>
static inline void GenerateTableWithCopy(X86InstInfo *FinalTable, X86TablesInfoStruct<OpcodeType> const *LocalTable, size_t TableSize, X86InstInfo *OtherLocal) {
  for (size_t j = 0; j < TableSize; ++j) {
    X86TablesInfoStruct<OpcodeType> const &Op = LocalTable[j];
    auto OpNum = Op.first;
    X86InstInfo const &Info = Op.Info;
    for (uint32_t i = 0; i < Op.second; ++i) {
      LOGMAN_THROW_A_FMT(FinalTable[OpNum + i].Type == TYPE_UNKNOWN, "Duplicate Entry {}->{}", FinalTable[OpNum + i].Name, Info.Name);
      if (Info.Type == TYPE_COPY_OTHER) {
        FinalTable[OpNum + i] = OtherLocal[OpNum + i];
      }
      else {
        FinalTable[OpNum + i] = Info;
#ifndef NDEBUG
        ++Total;
        if (Info.Type == TYPE_INST)
          NumInsts++;
#endif
      }
    }
  }
};

void InitializeInfoTables(Context::OperatingMode Mode);

}

