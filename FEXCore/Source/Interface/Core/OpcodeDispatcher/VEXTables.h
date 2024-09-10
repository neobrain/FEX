// SPDX-License-Identifier: MIT
#pragma once
#include "Interface/Core/OpcodeDispatcher.h"

namespace FEXCore::IR {
constexpr inline void InstallToTable(auto& FinalTable, auto& LocalTable) {
  for (auto Op : LocalTable) {
    auto OpNum = std::get<0>(Op);
    auto Dispatcher = std::get<2>(Op);
    for (uint8_t i = 0; i < std::get<1>(Op); ++i) {
      auto& TableOp = FinalTable[OpNum + i];
      if (TableOp.OpcodeDispatcher) {
        LOGMAN_MSG_A_FMT("Duplicate Entry {} 0x{:x}", TableOp.Name, OpNum + i);
      }

      TableOp.OpcodeDispatcher = Dispatcher;
    }
  }
}

consteval inline void VEXTable_Install(auto& FinalTable) {
#define OPD(map_select, pp, opcode) (((map_select - 1) << 10) | (pp << 8) | (opcode))
  constexpr std::tuple<uint16_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> Table[] = {
    {OPD(2, 0b00, 0xF2), 1, &OpDispatchBuilder::ANDNBMIOp}, {OPD(2, 0b00, 0xF5), 1, &OpDispatchBuilder::BZHI},
    {OPD(2, 0b10, 0xF5), 1, &OpDispatchBuilder::PEXT},      {OPD(2, 0b11, 0xF5), 1, &OpDispatchBuilder::PDEP},
    {OPD(2, 0b11, 0xF6), 1, &OpDispatchBuilder::MULX},      {OPD(2, 0b00, 0xF7), 1, &OpDispatchBuilder::BEXTRBMIOp},
    {OPD(2, 0b01, 0xF7), 1, &OpDispatchBuilder::BMI2Shift}, {OPD(2, 0b10, 0xF7), 1, &OpDispatchBuilder::BMI2Shift},
    {OPD(2, 0b11, 0xF7), 1, &OpDispatchBuilder::BMI2Shift},

    {OPD(3, 0b11, 0xF0), 1, &OpDispatchBuilder::RORX},
  };
#undef OPD

  InstallToTable(FinalTable, Table);
}

consteval inline void VEXGroupTable_Install(auto& FinalTable) {
#define OPD(group, pp, opcode) (((group - X86Tables::InstType::TYPE_VEX_GROUP_12) << 4) | (pp << 3) | (opcode))
  constexpr std::tuple<uint8_t, uint8_t, X86Tables::OpDispatchPtr> Table[] = {
    {OPD(X86Tables::InstType::TYPE_VEX_GROUP_17, 0, 0b001), 1, &OpDispatchBuilder::BLSRBMIOp},
    {OPD(X86Tables::InstType::TYPE_VEX_GROUP_17, 0, 0b010), 1, &OpDispatchBuilder::BLSMSKBMIOp},
    {OPD(X86Tables::InstType::TYPE_VEX_GROUP_17, 0, 0b011), 1, &OpDispatchBuilder::BLSIBMIOp},
  };
#undef OPD

  InstallToTable(FinalTable, Table);
}

} // namespace FEXCore::IR
