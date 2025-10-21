// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
desc: relocation logic of the arm64 splatter backend
$end_info$
*/
#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/JITClass.h"

#include <FEXCore/Core/Thunks.h>

namespace FEXCore::Context {
static uint64_t GetNamedSymbolLiteral(ContextImpl& CTX, FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) {
  switch (Op) {
  case FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER:
    return CTX.Dispatcher->ExitFunctionLinkerAddress;

  default: ERROR_AND_DIE_FMT("Unknown named symbol literal: {}", static_cast<uint32_t>(Op));
  }
}
} // namespace FEXCore::Context

namespace FEXCore::CPU {
void Arm64JITCore::InsertNamedThunkRelocation(ARMEmitter::Register Reg, const IR::SHA256Sum& Sum) {
  Relocation MoveABI {};
  MoveABI.NamedThunkMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE;
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = GetCursorAddress<uint8_t*>();
  // TODO: Switch back to BlockBegin
  MoveABI.NamedThunkMove.Offset = GetCursorOffset();
  MoveABI.NamedThunkMove.Symbol = Sum;
  MoveABI.NamedThunkMove.RegisterIndex = Reg.Idx();

  uint64_t Pointer = reinterpret_cast<uint64_t>(EmitterCTX->ThunkHandler->LookupThunk(Sum));

  LoadConstant(ARMEmitter::Size::i64Bit, Reg, Pointer, true);
  Relocations.emplace_back(MoveABI);
}

auto Arm64JITCore::InsertNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) -> NamedSymbolLiteralPair {
  uint64_t Pointer = GetNamedSymbolLiteral(*CTX, Op);

  NamedSymbolLiteralPair Lit {
    .Lit = Pointer,
    .MoveABI =
      {
        .NamedSymbolLiteral =
          {
            .Header =
              {
                .Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL,
              },
            .Symbol = Op,
            .Offset = 0,
          },
      },
  };
  return Lit;
}

auto Arm64JITCore::InsertGuestRIPLiteral(uint64_t GuestRIP) -> NamedSymbolLiteralPair {
  NamedSymbolLiteralPair Lit {
    .Lit = GuestRIP,
    .MoveABI =
      {
        .GuestRIPMove = {.Header =
                           {
                             .Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL,
                           },
                         .Offset = 0,
                         // TODO: Initialize properly, just setting value for debug now.
                         // .GuestEntryOffset = GuestRIP - Entry,
                         // .GuestEntryOffset = GuestRIP - Entry,
                         .GuestRIP = GuestRIP /*- Entry*/},
      },
  };
  return Lit;
}

void Arm64JITCore::PlaceNamedSymbolLiteral(NamedSymbolLiteralPair& Lit) {
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = GetCursorAddress<uint8_t*>();
  switch (Lit.MoveABI.Header.Type) {
  case RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
    // TODO: Switch back to BlockBegin
    Lit.MoveABI.NamedSymbolLiteral.Offset = GetCursorOffset();
    break;
  }

  case RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
    // TODO: Switch back to BlockBegin
    Lit.MoveABI.GuestRIPMove.Offset = GetCursorOffset();
    // fextl::fmt::print(stderr, "  EMITTING RELOCATION AT OFFSET {:#x} for guest rip {:#x} with literal {:#x}\n",
    //                   CurrentCursor - CodeData.BlockEntry, Lit.MoveABI.GuestRIPMove.GuestRIP + Entry, Lit.Lit);
    break;
  }

  default: ERROR_AND_DIE_FMT("UNKNOWN RELOCATION TYPE FOR PLACENAMEDSYMBOLLITERAL\n");
  }

  BindOrRestart(&Lit.Loc);
  dc64(Lit.Lit);
  Relocations.emplace_back(Lit.MoveABI);
}

void Arm64JITCore::InsertGuestRIPMove(ARMEmitter::Register Reg, uint64_t Constant) {
  Relocation MoveABI {};
  MoveABI.GuestRIPMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE;
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = GetCursorAddress<uint8_t*>();
  // TODO: BlockBegin?
  MoveABI.GuestRIPMove.Offset = GetCursorOffset();
  MoveABI.GuestRIPMove.GuestRIP = Constant;
  MoveABI.GuestRIPMove.RegisterIndex = Reg.Idx();

  // fextl::fmt::print("  GENERATING GUEST_RIP_MOVE RELOC FROM {:#x}-{:#x} at OFFSET {:#x}\n", Constant, Entry, MoveABI.GuestRIPMove.Offset);

  // fextl::fmt::print("  Before load constant: {}\n", fmt::ptr(GetCursorAddress<uint8_t*>()));
  LoadConstant(ARMEmitter::Size::i64Bit, Reg, Constant, true);
  // fextl::fmt::print("  After load constant: {}\n", fmt::ptr(GetCursorAddress<uint8_t*>()));
  Relocations.emplace_back(MoveABI);
}
} // namespace FEXCore::CPU

namespace FEXCore::Context {
bool CodeCache::ApplyCodeRelocations(uint64_t GuestEntry, std::span<std::byte> Code,
                                     std::span<const FEXCore::CPU::Relocation> EntryRelocations, bool ForStorage, bool ExpectNopRelocation) {
  using namespace FEXCore::CPU; // TODO

  CPU::Arm64Emitter Emitter(&CTX, Code.data(), Code.size_bytes());
  for (size_t j = 0; j < EntryRelocations.size(); ++j) {
    const FEXCore::CPU::Relocation& Reloc = EntryRelocations[j];
    // fextl::fmt::print(stderr, "RELOCATION {}: {}\n", j, ToUnderlying(Reloc.Header.Type));
    switch (Reloc.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
      uint64_t Pointer = ForStorage ? 0 : GetNamedSymbolLiteral(CTX, Reloc.NamedSymbolLiteral.Symbol);
      Emitter.SetCursorOffset(Reloc.NamedSymbolLiteral.Offset);

      // Generate a literal so we can place it
      Emitter.dc64(Pointer);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: {
      uint64_t Pointer = ForStorage ? 0 : reinterpret_cast<uint64_t>(CTX.ThunkHandler->LookupThunk(Reloc.NamedThunkMove.Symbol));
      if (Pointer == ~0ULL) {
        return false;
      }

      Emitter.SetCursorOffset(Reloc.NamedThunkMove.Offset);
      Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.NamedThunkMove.RegisterIndex), Pointer, true);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
      // TODO: In particular, should assert the RIP is still in the same library!
      // TODO: This often comes up for GOT/PLT tables... is the offset always fixed?
      uint64_t Pointer = Reloc.GuestRIPMove.GuestRIP + GuestEntry;

      // Re-emit constant in case it requires more/fewer instructions at the new location
      // TODO: Can this overflow for 32-bit?
      Emitter.SetCursorOffset(Reloc.GuestRIPMove.Offset);
      auto Cursor = Emitter.GetCursorAddress<uint64_t*>();
      std::array<uint64_t, 2> Old = {
        Cursor[0],
        Cursor[1],
      };
      Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.GuestRIPMove.RegisterIndex), Pointer, true);
      std::array<uint64_t, 2> New = {
        Cursor[0],
        Cursor[1],
      };
      if (ExpectNopRelocation && (Old[0] != New[0] || Old[1] != New[1])) {
        ERROR_AND_DIE_FMT("Expected non-modifying relocation!");
      }
      break;
    }

    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
      // TODO: For this to function, I think the page alignment of arm code within the original host page and the new host page must be the same?

      // fextl::fmt::print(stderr, "  GUEST_RIP_LITERAL patching host addr {:#x} / {:#x}: RIP delta {:#x} -> {:#x}\n", Reloc.GuestRIPMove.Offset,
      //                   CodeEntry + Reloc.GuestRIPMove.Offset, Reloc.GuestRIPMove.GuestRIP, GuestEntry + Reloc.GuestRIPMove.GuestRIP);
      Emitter.SetCursorOffset(Reloc.GuestRIPMove.Offset);
      auto Cursor = Emitter.GetCursorAddress<uint64_t*>();
      uint64_t Old = Cursor[0];
      Emitter.dc64((GuestEntry + Reloc.GuestRIPMove.GuestRIP) & (CTX.Config.Is64BitMode() ? 0xffff'ffff'ffff'ffff : 0xffff'ffff));
      uint64_t New = Cursor[0];
      if (ExpectNopRelocation && Old != New) {
        ERROR_AND_DIE_FMT("Expected non-modifying literal relocation! (expected {:#x}, got {:#x})", New, Old);
      }
      break;
    }
    default: ERROR_AND_DIE_FMT("Unknown relocation type {}", ToUnderlying(Reloc.Header.Type));
    }
  }

  return true;
}
} // namespace FEXCore::Context

namespace FEXCore::CPU {

fextl::vector<FEXCore::CPU::Relocation> Arm64JITCore::TakeRelocations() {
  return std::move(Relocations);
}

} // namespace FEXCore::CPU
