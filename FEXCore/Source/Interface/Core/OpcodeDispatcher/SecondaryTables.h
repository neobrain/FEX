// SPDX-License-Identifier: MIT
#pragma once
#include "Interface/Core/OpcodeDispatcher.h"

namespace FEXCore::IR {
consteval inline void SecondaryTables_Install(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> TwoByteOpTable[] = {
    // Instructions
    {0x06, 1, &OpDispatchBuilder::PermissionRestrictedOp},
    {0x07, 1, &OpDispatchBuilder::PermissionRestrictedOp},
    {0x0B, 1, &OpDispatchBuilder::INTOp},
    {0x0E, 1, &OpDispatchBuilder::X87EMMS},

    {0x19, 7, &OpDispatchBuilder::NOPOp}, // NOP with ModRM

    {0x20, 4, &OpDispatchBuilder::PermissionRestrictedOp},

    {0x30, 1, &OpDispatchBuilder::PermissionRestrictedOp},
    {0x31, 1, &OpDispatchBuilder::RDTSCOp},
    {0x32, 2, &OpDispatchBuilder::PermissionRestrictedOp},
    {0x34, 3, &OpDispatchBuilder::UnimplementedOp},

    {0x3F, 1, &OpDispatchBuilder::ThunkOp},
    {0x40, 16, &OpDispatchBuilder::CMOVOp},
    {0x6E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVBetweenGPR_FPR, OpDispatchBuilder::VectorOpType::MMX>},
    {0x6F, 1, &OpDispatchBuilder::MOVQMMXOp},
    {0x7E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVBetweenGPR_FPR, OpDispatchBuilder::VectorOpType::MMX>},
    {0x7F, 1, &OpDispatchBuilder::MOVQMMXOp},
    {0x80, 16, &OpDispatchBuilder::CondJUMPOp},
    {0x90, 16, &OpDispatchBuilder::SETccOp},
    {0xA2, 1, &OpDispatchBuilder::CPUIDOp},
    {0xA3, 1, &OpDispatchBuilder::BTOp<0, BTAction::BTNone>}, // BT
    {0xA4, 1, &OpDispatchBuilder::SHLDImmediateOp},
    {0xA5, 1, &OpDispatchBuilder::SHLDOp},
    {0xAB, 1, &OpDispatchBuilder::BTOp<0, BTAction::BTSet>}, // BTS
    {0xAC, 1, &OpDispatchBuilder::SHRDImmediateOp},
    {0xAD, 1, &OpDispatchBuilder::SHRDOp},
    {0xAF, 1, &OpDispatchBuilder::IMUL1SrcOp},
    {0xB0, 2, &OpDispatchBuilder::CMPXCHGOp},                  // CMPXCHG
    {0xB3, 1, &OpDispatchBuilder::BTOp<0, BTAction::BTClear>}, // BTR
    {0xB6, 2, &OpDispatchBuilder::MOVZXOp},
    {0xBB, 1, &OpDispatchBuilder::BTOp<0, BTAction::BTComplement>}, // BTC
    {0xBC, 1, &OpDispatchBuilder::BSFOp},                           // BSF
    {0xBD, 1, &OpDispatchBuilder::BSROp},                           // BSF
    {0xBE, 2, &OpDispatchBuilder::MOVSXOp},
    {0xC0, 2, &OpDispatchBuilder::XADDOp},
    {0xC3, 1, &OpDispatchBuilder::MOVGPRNTOp},
    {0xC4, 1, &OpDispatchBuilder::PINSROp<2>},
    {0xC5, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PExtrOp, 2>},
    {0xC8, 8, &OpDispatchBuilder::BSWAPOp},

    // SSE
    {0x10, 2, &OpDispatchBuilder::MOVVectorUnalignedOp},
    {0x12, 2, &OpDispatchBuilder::MOVLPOp},
    {0x14, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 4>},
    {0x15, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 4>},
    {0x16, 2, &OpDispatchBuilder::MOVHPDOp},
    {0x28, 2, &OpDispatchBuilder::MOVVectorAlignedOp},
    {0x2A, 1, &OpDispatchBuilder::InsertMMX_To_XMM_Vector_CVT_Int_To_Float},
    {0x2B, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0x2C, 1, &OpDispatchBuilder::XMM_To_MMX_Vector_CVT_Float_To_Int<4, false, false>},
    {0x2D, 1, &OpDispatchBuilder::XMM_To_MMX_Vector_CVT_Float_To_Int<4, false, true>},
    {0x2E, 2, &OpDispatchBuilder::UCOMISxOp<4>},
    {0x50, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVMSKOp, 4>},
    {0x51, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorUnaryOp, IR::OP_VFSQRT, 4>},
    {0x52, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorUnaryOp, IR::OP_VFRSQRT, 4>},
    {0x53, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorUnaryOp, IR::OP_VFRECP, 4>},
    {0x54, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VAND, 16>},
    {0x55, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUROp, IR::OP_VANDN, 8>},
    {0x56, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VOR, 16>},
    {0x57, 1, &OpDispatchBuilder::VectorXOROp},
    {0x58, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFADD, 4>},
    {0x59, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMUL, 4>},
    {0x5A, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::Vector_CVT_Float_To_Float, 8, 4, false>},
    {0x5B, 1, &OpDispatchBuilder::Vector_CVT_Int_To_Float<4, false>},
    {0x5C, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFSUB, 4>},
    {0x5D, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMIN, 4>},
    {0x5E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFDIV, 4>},
    {0x5F, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMAX, 4>},
    {0x60, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 1>},
    {0x61, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 2>},
    {0x62, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 4>},
    {0x63, 1, &OpDispatchBuilder::PACKSSOp<2>},
    {0x64, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 1>},
    {0x65, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 2>},
    {0x66, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 4>},
    {0x67, 1, &OpDispatchBuilder::PACKUSOp<2>},
    {0x68, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 1>},
    {0x69, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 2>},
    {0x6A, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 4>},
    {0x6B, 1, &OpDispatchBuilder::PACKSSOp<4>},
    {0x70, 1, &OpDispatchBuilder::PSHUFW8ByteOp},

    {0x74, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 1>},
    {0x75, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 2>},
    {0x76, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 4>},
    {0x77, 1, &OpDispatchBuilder::X87EMMS},

    {0xC2, 1, &OpDispatchBuilder::VFCMPOp<4>},
    {0xC6, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::SHUFOp, 4>},

    {0xD1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 2>},
    {0xD2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 4>},
    {0xD3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 8>},
    {0xD4, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 8>},
    {0xD5, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VMUL, 2>},
    {0xD7, 1, &OpDispatchBuilder::MOVMSKOpOne}, // PMOVMSKB
    {0xD8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQSUB, 1>},
    {0xD9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQSUB, 2>},
    {0xDA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUMIN, 1>},
    {0xDB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VAND, 8>},
    {0xDC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQADD, 1>},
    {0xDD, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQADD, 2>},
    {0xDE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUMAX, 1>},
    {0xDF, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUROp, IR::OP_VANDN, 8>},
    {0xE0, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VURAVG, 1>},
    {0xE1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRAOp, 2>},
    {0xE2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRAOp, 4>},
    {0xE3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VURAVG, 2>},
    {0xE4, 1, &OpDispatchBuilder::PMULHW<false>},
    {0xE5, 1, &OpDispatchBuilder::PMULHW<true>},
    {0xE7, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0xE8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQSUB, 1>},
    {0xE9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQSUB, 2>},
    {0xEA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSMIN, 2>},
    {0xEB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VOR, 8>},
    {0xEC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQADD, 1>},
    {0xED, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQADD, 2>},
    {0xEE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSMAX, 2>},
    {0xEF, 1, &OpDispatchBuilder::VectorXOROp},

    {0xF1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 2>},
    {0xF2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 4>},
    {0xF3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 8>},
    {0xF4, 1, &OpDispatchBuilder::PMULLOp<4, false>},
    {0xF5, 1, &OpDispatchBuilder::PMADDWD},
    {0xF6, 1, &OpDispatchBuilder::PSADBW},
    {0xF7, 1, &OpDispatchBuilder::MASKMOVOp},
    {0xF8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 1>},
    {0xF9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 2>},
    {0xFA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 4>},
    {0xFB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 8>},
    {0xFC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 1>},
    {0xFD, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 2>},
    {0xFE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 4>},

    // FEX reserved instructions
    {0x37, 1, &OpDispatchBuilder::CallbackReturnOp},
  };

  InstallToTable(FinalTable, TwoByteOpTable);
}

consteval inline void SecondaryRepModTables_Install(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> Table[] = {
    {0x10, 2, &OpDispatchBuilder::MOVSSOp},
    {0x12, 1, &OpDispatchBuilder::VMOVSLDUPOp},
    {0x16, 1, &OpDispatchBuilder::VMOVSHDUPOp},
    {0x2A, 1, &OpDispatchBuilder::InsertCVTGPR_To_FPR<4>},
    {0x2B, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0x2C, 1, &OpDispatchBuilder::CVTFPR_To_GPR<4, false>},
    {0x2D, 1, &OpDispatchBuilder::CVTFPR_To_GPR<4, true>},
    {0x51, 1, &OpDispatchBuilder::VectorScalarUnaryInsertALUOp<IR::OP_VFSQRTSCALARINSERT, 4>},
    {0x52, 1, &OpDispatchBuilder::VectorScalarUnaryInsertALUOp<IR::OP_VFRSQRTSCALARINSERT, 4>},
    {0x53, 1, &OpDispatchBuilder::VectorScalarUnaryInsertALUOp<IR::OP_VFRECPSCALARINSERT, 4>},
    {0x58, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFADDSCALARINSERT, 4>},
    {0x59, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMULSCALARINSERT, 4>},
    {0x5A, 1, &OpDispatchBuilder::InsertScalar_CVT_Float_To_Float<8, 4>},
    {0x5B, 1, &OpDispatchBuilder::Vector_CVT_Float_To_Int<4, false, false>},
    {0x5C, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFSUBSCALARINSERT, 4>},
    {0x5D, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMINSCALARINSERT, 4>},
    {0x5E, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFDIVSCALARINSERT, 4>},
    {0x5F, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMAXSCALARINSERT, 4>},
    {0x6F, 1, &OpDispatchBuilder::MOVVectorUnalignedOp},
    {0x70, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSHUFWOp, false>},
    {0x7E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVQOp, OpDispatchBuilder::VectorOpType::SSE>},
    {0x7F, 1, &OpDispatchBuilder::MOVVectorUnalignedOp},
    {0xB8, 1, &OpDispatchBuilder::PopcountOp},
    {0xBC, 1, &OpDispatchBuilder::TZCNT},
    {0xBD, 1, &OpDispatchBuilder::LZCNT},
    {0xC2, 1, &OpDispatchBuilder::InsertScalarFCMPOp<4>},
    {0xD6, 1, &OpDispatchBuilder::MOVQ2DQ<true>},
    {0xE6, 1, &OpDispatchBuilder::Vector_CVT_Int_To_Float<4, true>},
  };

  InstallToTable(FinalTable, Table);
}

consteval inline void SecondaryRepNEModTables_Install(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> Table[] = {
    {0x10, 2, &OpDispatchBuilder::MOVSDOp},
    {0x12, 1, &OpDispatchBuilder::MOVDDUPOp},
    {0x2A, 1, &OpDispatchBuilder::InsertCVTGPR_To_FPR<8>},
    {0x2B, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0x2C, 1, &OpDispatchBuilder::CVTFPR_To_GPR<8, false>},
    {0x2D, 1, &OpDispatchBuilder::CVTFPR_To_GPR<8, true>},
    {0x51, 1, &OpDispatchBuilder::VectorScalarUnaryInsertALUOp<IR::OP_VFSQRTSCALARINSERT, 8>},
    // x52 = Invalid
    {0x58, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFADDSCALARINSERT, 8>},
    {0x59, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMULSCALARINSERT, 8>},
    {0x5A, 1, &OpDispatchBuilder::InsertScalar_CVT_Float_To_Float<4, 8>},
    {0x5C, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFSUBSCALARINSERT, 8>},
    {0x5D, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMINSCALARINSERT, 8>},
    {0x5E, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFDIVSCALARINSERT, 8>},
    {0x5F, 1, &OpDispatchBuilder::VectorScalarInsertALUOp<IR::OP_VFMAXSCALARINSERT, 8>},
    {0x70, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSHUFWOp, true>},
    {0x7C, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFADDP, 4>},
    {0x7D, 1, &OpDispatchBuilder::HSUBP<4>},
    {0xD0, 1, &OpDispatchBuilder::ADDSUBPOp<4>},
    {0xD6, 1, &OpDispatchBuilder::MOVQ2DQ<false>},
    {0xC2, 1, &OpDispatchBuilder::InsertScalarFCMPOp<8>},
    {0xE6, 1, &OpDispatchBuilder::Vector_CVT_Float_To_Int<8, true, true>},
    {0xF0, 1, &OpDispatchBuilder::MOVVectorUnalignedOp},
  };

  InstallToTable(FinalTable, Table);
}

consteval inline void SecondaryOpSizeModTables_Install(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> Table[] = {
    {0x10, 2, &OpDispatchBuilder::MOVVectorUnalignedOp},
    {0x12, 2, &OpDispatchBuilder::MOVLPOp},
    {0x14, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 8>},
    {0x15, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 8>},
    {0x16, 2, &OpDispatchBuilder::MOVHPDOp},
    {0x28, 2, &OpDispatchBuilder::MOVVectorAlignedOp},
    {0x2A, 1, &OpDispatchBuilder::MMX_To_XMM_Vector_CVT_Int_To_Float},
    {0x2B, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0x2C, 1, &OpDispatchBuilder::XMM_To_MMX_Vector_CVT_Float_To_Int<8, true, false>},
    {0x2D, 1, &OpDispatchBuilder::XMM_To_MMX_Vector_CVT_Float_To_Int<8, true, true>},
    {0x2E, 2, &OpDispatchBuilder::UCOMISxOp<8>},

    {0x50, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVMSKOp, 8>},
    {0x51, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorUnaryOp, IR::OP_VFSQRT, 8>},
    {0x54, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VAND, 16>},
    {0x55, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUROp, IR::OP_VANDN, 8>},
    {0x56, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VOR, 16>},
    {0x57, 1, &OpDispatchBuilder::VectorXOROp},
    {0x58, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFADD, 8>},
    {0x59, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMUL, 8>},
    {0x5A, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::Vector_CVT_Float_To_Float, 4, 8, false>},
    {0x5B, 1, &OpDispatchBuilder::Vector_CVT_Float_To_Int<4, false, true>},
    {0x5C, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFSUB, 8>},
    {0x5D, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMIN, 8>},
    {0x5E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFDIV, 8>},
    {0x5F, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFMAX, 8>},
    {0x60, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 1>},
    {0x61, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 2>},
    {0x62, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 4>},
    {0x63, 1, &OpDispatchBuilder::PACKSSOp<2>},
    {0x64, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 1>},
    {0x65, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 2>},
    {0x66, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPGT, 4>},
    {0x67, 1, &OpDispatchBuilder::PACKUSOp<2>},
    {0x68, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 1>},
    {0x69, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 2>},
    {0x6A, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 4>},
    {0x6B, 1, &OpDispatchBuilder::PACKSSOp<4>},
    {0x6C, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKLOp, 8>},
    {0x6D, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PUNPCKHOp, 8>},
    {0x6E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVBetweenGPR_FPR, OpDispatchBuilder::VectorOpType::SSE>},
    {0x6F, 1, &OpDispatchBuilder::MOVVectorAlignedOp},
    {0x70, 1, &OpDispatchBuilder::PSHUFDOp},

    {0x74, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 1>},
    {0x75, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 2>},
    {0x76, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VCMPEQ, 4>},
    {0x78, 1, nullptr}, // GROUP 17
    {0x7C, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VFADDP, 8>},
    {0x7D, 1, &OpDispatchBuilder::HSUBP<8>},
    {0x7E, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVBetweenGPR_FPR, OpDispatchBuilder::VectorOpType::SSE>},
    {0x7F, 1, &OpDispatchBuilder::MOVVectorAlignedOp},
    {0xC2, 1, &OpDispatchBuilder::VFCMPOp<8>},
    {0xC4, 1, &OpDispatchBuilder::PINSROp<2>},
    {0xC5, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PExtrOp, 2>},
    {0xC6, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::SHUFOp, 8>},

    {0xD0, 1, &OpDispatchBuilder::ADDSUBPOp<8>},
    {0xD1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 2>},
    {0xD2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 4>},
    {0xD3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRLDOp, 8>},
    {0xD4, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 8>},
    {0xD5, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VMUL, 2>},
    {0xD6, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::MOVQOp, OpDispatchBuilder::VectorOpType::SSE>},
    {0xD7, 1, &OpDispatchBuilder::MOVMSKOpOne}, // PMOVMSKB
    {0xD8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQSUB, 1>},
    {0xD9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQSUB, 2>},
    {0xDA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUMIN, 1>},
    {0xDB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VAND, 16>},
    {0xDC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQADD, 1>},
    {0xDD, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUQADD, 2>},
    {0xDE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VUMAX, 1>},
    {0xDF, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUROp, IR::OP_VANDN, 8>},
    {0xE0, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VURAVG, 1>},
    {0xE1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRAOp, 2>},
    {0xE2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSRAOp, 4>},
    {0xE3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VURAVG, 2>},
    {0xE4, 1, &OpDispatchBuilder::PMULHW<false>},
    {0xE5, 1, &OpDispatchBuilder::PMULHW<true>},
    {0xE6, 1, &OpDispatchBuilder::Vector_CVT_Float_To_Int<8, true, false>},
    {0xE7, 1, &OpDispatchBuilder::MOVVectorNTOp},
    {0xE8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQSUB, 1>},
    {0xE9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQSUB, 2>},
    {0xEA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSMIN, 2>},
    {0xEB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VOR, 16>},
    {0xEC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQADD, 1>},
    {0xED, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSQADD, 2>},
    {0xEE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSMAX, 2>},
    {0xEF, 1, &OpDispatchBuilder::VectorXOROp},

    {0xF1, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 2>},
    {0xF2, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 4>},
    {0xF3, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::PSLL, 8>},
    {0xF4, 1, &OpDispatchBuilder::PMULLOp<4, false>},
    {0xF5, 1, &OpDispatchBuilder::PMADDWD},
    {0xF6, 1, &OpDispatchBuilder::PSADBW},
    {0xF7, 1, &OpDispatchBuilder::MASKMOVOp},
    {0xF8, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 1>},
    {0xF9, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 2>},
    {0xFA, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 4>},
    {0xFB, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VSUB, 8>},
    {0xFC, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 1>},
    {0xFD, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 2>},
    {0xFE, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::VectorALUOp, IR::OP_VADD, 4>},
  };

  InstallToTable(FinalTable, Table);
}

inline void SecondaryTables_Install64(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> TwoByteOpTable[] = {
    {0x05, 1, &OpDispatchBuilder::Bind<&OpDispatchBuilder::SyscallOp, true>},
    {0xA0, 1, &OpDispatchBuilder::PUSHSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX>},
    {0xA1, 1, &OpDispatchBuilder::POPSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX>},
    {0xA8, 1, &OpDispatchBuilder::PUSHSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX>},
    {0xA9, 1, &OpDispatchBuilder::POPSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX>},
  };

  InstallToTable(FinalTable, TwoByteOpTable);
}

inline void SecondaryTables_Install32(auto& FinalTable) {
  constexpr std::tuple<uint8_t, uint8_t, FEXCore::X86Tables::OpDispatchPtr> TwoByteOpTable[] = {
    {0x05, 1, &OpDispatchBuilder::NOPOp},
    {0xA0, 1, &OpDispatchBuilder::PUSHSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX>},
    {0xA1, 1, &OpDispatchBuilder::POPSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX>},
    {0xA8, 1, &OpDispatchBuilder::PUSHSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX>},
    {0xA9, 1, &OpDispatchBuilder::POPSegmentOp<FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX>},
  };

  InstallToTable(FinalTable, TwoByteOpTable);
}

} // namespace FEXCore::IR
