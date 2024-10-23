// SPDX-License-Identifier: MIT
#pragma once

#include "FEXCore/Utils/EnumUtils.h"
#include "Interface/Core/ObjectCache/Relocations.h"

#ifdef VIXL_DISASSEMBLER
#include <aarch64/disasm-aarch64.h>
#endif
#ifdef VIXL_SIMULATOR
#include <aarch64/simulator-aarch64.h>
#include <aarch64/simulator-constants-aarch64.h>
#endif

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/vector.h>
#include <CodeEmitter/Emitter.h>
#include <CodeEmitter/Registers.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <span>

namespace FEXCore::Context {
class ContextImpl;
}

namespace FEXCore::CPU {
// Contains the address to the currently available CPU state
constexpr auto STATE = ARMEmitter::XReg::x28;

#ifndef _M_ARM_64EC
// GPR temporaries. Only x3 can be used across spill boundaries
// so if these ever need to change, be very careful about that.
constexpr auto TMP1 = ARMEmitter::XReg::x0;
constexpr auto TMP2 = ARMEmitter::XReg::x1;
constexpr auto TMP3 = ARMEmitter::XReg::x2;
constexpr auto TMP4 = ARMEmitter::XReg::x3;
constexpr bool TMP_ABIARGS = true;

// We pin r26/r27 as PF/AF respectively, this is internal FEX ABI.
constexpr auto REG_PF = ARMEmitter::Reg::r26;
constexpr auto REG_AF = ARMEmitter::Reg::r27;

// Vector temporaries
constexpr auto VTMP1 = ARMEmitter::VReg::v0;
constexpr auto VTMP2 = ARMEmitter::VReg::v1;
#else
constexpr auto TMP1 = ARMEmitter::XReg::x10;
constexpr auto TMP2 = ARMEmitter::XReg::x11;
constexpr auto TMP3 = ARMEmitter::XReg::x12;
constexpr auto TMP4 = ARMEmitter::XReg::x13;
constexpr bool TMP_ABIARGS = false;

// We pin r11/r12 as PF/AF respectively for arm64ec, as r26/r27 are used for SRA.
constexpr auto REG_PF = ARMEmitter::Reg::r9;
constexpr auto REG_AF = ARMEmitter::Reg::r24;

// Vector temporaries
constexpr auto VTMP1 = ARMEmitter::VReg::v16;
constexpr auto VTMP2 = ARMEmitter::VReg::v17;

// Entry/Exit ABI
constexpr auto EC_CALL_CHECKER_PC_REG = ARMEmitter::XReg::x9;
constexpr auto EC_ENTRY_CPUAREA_REG = ARMEmitter::XReg::x17;

// These structures are not included in the standard Windows headers, define the offsets of members we care about for EC here.
constexpr size_t TEB_CPU_AREA_OFFSET = 0x1788;
constexpr size_t TEB_PEB_OFFSET = 0x60;
constexpr size_t PEB_EC_CODE_BITMAP_OFFSET = 0x368;
constexpr size_t CPU_AREA_IN_SYSCALL_CALLBACK_OFFSET = 0x1;
constexpr size_t CPU_AREA_EMULATOR_STACK_BASE_OFFSET = 0x8;
constexpr size_t CPU_AREA_EMULATOR_DATA_OFFSET = 0x30;
#endif

// Predicate register temporaries (used when AVX support is enabled)
// PRED_TMP_16B indicates a predicate register that indicates the first 16 bytes set to 1.
// PRED_TMP_32B indicates a predicate register that indicates the first 32 bytes set to 1.
constexpr ARMEmitter::PRegister PRED_TMP_16B = ARMEmitter::PReg::p6;
constexpr ARMEmitter::PRegister PRED_TMP_32B = ARMEmitter::PReg::p7;


// This class contains common emitter utility functions that can
// be used by both Arm64 JIT and ARM64 Dispatcher
class Arm64Emitter : public ARMEmitter::Emitter {
protected:
  Arm64Emitter(FEXCore::Context::ContextImpl* ctx, void* EmissionPtr = nullptr, size_t size = 0);

  FEXCore::Context::ContextImpl* EmitterCTX;

  std::span<const ARMEmitter::Register> ConfiguredDynamicRegisterBase {};
  std::span<const ARMEmitter::Register> StaticRegisters {};
  std::span<const ARMEmitter::Register> GeneralRegisters {};
  std::span<const ARMEmitter::VRegister> StaticFPRegisters {};
  std::span<const ARMEmitter::VRegister> GeneralFPRegisters {};
  uint32_t PairRegisters = 0;

  void LoadConstant(ARMEmitter::Size s, ARMEmitter::Register Reg, uint64_t Constant, bool NOPPad = true);

  void FillSpecialRegs(ARMEmitter::Register TmpReg, ARMEmitter::Register TmpReg2, bool SetFIZ, bool SetPredRegs);

  // Correlate an ARM register back to an x86 register index.
  // Returning REG_INVALID if there was no mapping.
  FEXCore::X86State::X86Reg GetX86RegRelationToARMReg(ARMEmitter::Register Reg);

  // NOTE: These functions WILL clobber the register TMP4 if AVX support is enabled
  //       and FPRs are being spilled or filled. If only GPRs are spilled/filled, then
  //       TMP4 is left alone.
  void SpillStaticRegs(ARMEmitter::Register TmpReg, bool FPRs = true, uint32_t GPRSpillMask = ~0U, uint32_t FPRSpillMask = ~0U);
  void FillStaticRegs(bool FPRs = true, uint32_t GPRFillMask = ~0U, uint32_t FPRFillMask = ~0U,
                      std::optional<ARMEmitter::Register> OptionalReg = std::nullopt,
                      std::optional<ARMEmitter::Register> OptionalReg2 = std::nullopt);

  // Register 0-18 + 29 + 30 are caller saved
  static constexpr uint32_t CALLER_GPR_MASK = 0b0110'0000'0000'0111'1111'1111'1111'1111U;

  // This isn't technically true because the lower 64-bits of v8..v15 are callee saved
  // We can't guarantee only the lower 64bits are used so flush everything
  static constexpr uint32_t CALLER_FPR_MASK = ~0U;

  // Generic push and pop vector registers.
  void PushVectorRegisters(ARMEmitter::Register TmpReg, bool SVERegs, std::span<const ARMEmitter::VRegister> VRegs);
  void PushGeneralRegisters(ARMEmitter::Register TmpReg, std::span<const ARMEmitter::Register> Regs);

  void PopVectorRegisters(bool SVERegs, std::span<const ARMEmitter::VRegister> VRegs);
  void PopGeneralRegisters(std::span<const ARMEmitter::Register> Regs);

  void PushDynamicRegsAndLR(ARMEmitter::Register TmpReg);
  void PopDynamicRegsAndLR();

  void PushCalleeSavedRegisters();
  void PopCalleeSavedRegisters();

  // Spills and fills SRA/Dynamic registers that are required for Arm64 `preserve_all` ABI.
  // This ABI changes most registers to be callee saved.
  // Caller Saved:
  // - X0-X8, X16-X18.
  // - v0-v7
  // - For 256-bit SVE hosts: top 128-bits of v8-v31
  //
  // Callee Saved:
  // - X9-X15, X19-X31
  // - Low 128-bits of v8-v31
  void SpillForPreserveAllABICall(ARMEmitter::Register TmpReg, bool FPRs = true);
  void FillForPreserveAllABICall(bool FPRs = true);

  void SpillForABICall(bool SupportsPreserveAllABI, ARMEmitter::Register TmpReg, bool FPRs = true) {
    if (SupportsPreserveAllABI) {
      SpillForPreserveAllABICall(TmpReg, FPRs);
    } else {
      SpillStaticRegs(TmpReg, FPRs);
      PushDynamicRegsAndLR(TmpReg);
    }
  }

  void FillForABICall(bool SupportsPreserveAllABI, bool FPRs = true) {
    if (SupportsPreserveAllABI) {
      FillForPreserveAllABICall(FPRs);
    } else {
      PopDynamicRegsAndLR();
      FillStaticRegs(FPRs);
    }
  }

  void Align16B();

#ifdef VIXL_SIMULATOR
  // Generates a vixl simulator runtime call.
  //
  // This matches behaviour of vixl's macro assembler, but we need to reimplement it since we aren't using the macro assembler.
  // This isn't too complex with how vixl emits this.
  //
  // Emit:
  // 1) hlt(kRuntimeCallOpcode)
  // 2) Simulator wrapper handler
  // 3) Function to call
  // 4) Style of the function call (Call versus tail-call)

  template<typename R, typename... P>
  void GenerateRuntimeCall(R (*Function)(P...)) {
    uintptr_t SimulatorWrapperAddress = reinterpret_cast<uintptr_t>(&(vixl::aarch64::Simulator::RuntimeCallStructHelper<R, P...>::Wrapper));

    uintptr_t FunctionAddress = reinterpret_cast<uintptr_t>(Function);

    hlt(vixl::aarch64::kRuntimeCallOpcode);

    // Simulator wrapper address pointer.
    dc64(SimulatorWrapperAddress);

    // Runtime function address to call
    dc64(FunctionAddress);

    // Call type
    dc32(vixl::aarch64::kCallRuntime);
  }

  template<typename R, typename... P>
  void GenerateIndirectRuntimeCall(ARMEmitter::Register Reg) {
    uintptr_t SimulatorWrapperAddress = reinterpret_cast<uintptr_t>(&(vixl::aarch64::Simulator::RuntimeCallStructHelper<R, P...>::Wrapper));

    hlt(vixl::aarch64::kIndirectRuntimeCallOpcode);

    // Simulator wrapper address pointer.
    dc64(SimulatorWrapperAddress);

    // Register that contains the function to call
    dc32(Reg.Idx());

    // Call type
    dc32(vixl::aarch64::kCallRuntime);
  }

  template<>
  void GenerateIndirectRuntimeCall<float, __uint128_t>(ARMEmitter::Register Reg) {
    uintptr_t SimulatorWrapperAddress =
      reinterpret_cast<uintptr_t>(&(vixl::aarch64::Simulator::RuntimeCallStructHelper<float, __uint128_t>::Wrapper));

    hlt(vixl::aarch64::kIndirectRuntimeCallOpcode);

    // Simulator wrapper address pointer.
    dc64(SimulatorWrapperAddress);

    // Register that contains the function to call
    dc32(Reg.Idx());

    // Call type
    dc32(vixl::aarch64::kCallRuntime);
  }
#else
  template<typename R, typename... P>
  void GenerateRuntimeCall(R (*Function)(P...)) {
    // Explicitly doing nothing.
  }
  template<typename R, typename... P>
  void GenerateIndirectRuntimeCall(ARMEmitter::Register Reg) {
    // Explicitly doing nothing.
  }
#endif

#ifdef VIXL_SIMULATOR
  vixl::aarch64::Decoder SimDecoder;
  vixl::aarch64::Simulator Simulator;
  constexpr static size_t SimulatorStackSize = 8 * 1024 * 1024;
#endif

#ifdef VIXL_DISASSEMBLER
  fextl::vector<char> DisasmBuffer;
  constexpr static int DISASM_BUFFER_SIZE {256};
  fextl::unique_ptr<vixl::aarch64::Disassembler> Disasm;
  fextl::unique_ptr<vixl::aarch64::Decoder> DisasmDecoder;

  FEX_CONFIG_OPT(Disassemble, DISASSEMBLE);
#endif
};

} // namespace FEXCore::CPU
