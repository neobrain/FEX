// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
desc: relocation logic of the arm64 splatter backend
$end_info$
*/
#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/Arm64/JITClass.h"

#include <FEXCore/Core/Thunks.h>

namespace FEXCore::CPU {

uint64_t Arm64JITCore::GetNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) {
  switch (Op) {
  case FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER:
    return ThreadState->CurrentFrame->Pointers.Common.ExitFunctionLinker;
    break;
  default: ERROR_AND_DIE_FMT("Unknown named symbol literal: {}", static_cast<uint32_t>(Op)); break;
  }
  return ~0ULL;
}

void Arm64JITCore::InsertNamedThunkRelocation(ARMEmitter::Register Reg, const IR::SHA256Sum& Sum) {
  Relocation MoveABI {};
  MoveABI.NamedThunkMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE;
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = GetCursorAddress<uint8_t*>();
  // TODO: Switch back to BlockBegin
  MoveABI.NamedThunkMove.Offset = CurrentCursor - CodeData.BlockEntry;
  MoveABI.NamedThunkMove.Symbol = Sum;
  MoveABI.NamedThunkMove.RegisterIndex = Reg.Idx();

  uint64_t Pointer = reinterpret_cast<uint64_t>(EmitterCTX->ThunkHandler->LookupThunk(Sum));

  LoadConstant(ARMEmitter::Size::i64Bit, Reg, Pointer, /*EmitterCTX->Config.CacheObjectCodeCompilation()*/ true);
  Relocations.emplace_back(MoveABI);
}

auto Arm64JITCore::InsertNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) -> NamedSymbolLiteralPair {
  uint64_t Pointer = GetNamedSymbolLiteral(Op);

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
                         .GuestRIP = GuestRIP - Entry},
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
    Lit.MoveABI.NamedSymbolLiteral.Offset = CurrentCursor - CodeData.BlockEntry;
    break;
  }

  case RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
    // TODO: Switch back to BlockBegin
    Lit.MoveABI.GuestRIPMove.Offset = CurrentCursor - CodeData.BlockEntry;
    fmt::print(stderr, "  EMITTING RELOCATION AT OFFSET {:#x} for guest rip {:#x} with literal {:#x}\n",
               CurrentCursor - CodeData.BlockEntry, Lit.MoveABI.GuestRIPMove.GuestRIP + Entry, Lit.Lit);
    break;
  }

  default: ERROR_AND_DIE_FMT("UNKNOWN RELOCATION TYPE FOR PLACENAMEDSYMBOLLITERAL\n");
  }

  Bind(&Lit.Loc);
  dc64(Lit.Lit);
  Relocations.emplace_back(Lit.MoveABI);
}

void Arm64JITCore::InsertGuestRIPMove(ARMEmitter::Register Reg, uint64_t Constant) {
  Relocation MoveABI {};
  MoveABI.GuestRIPMove.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE;
  // Offset is the offset from the entrypoint of the block
  auto CurrentCursor = GetCursorAddress<uint8_t*>();
  // TODO: BlockBegin?
  MoveABI.GuestRIPMove.Offset = CurrentCursor - CodeData.BlockEntry;
  MoveABI.GuestRIPMove.GuestRIP = Constant;
  MoveABI.GuestRIPMove.RegisterIndex = Reg.Idx();

  LoadConstant(ARMEmitter::Size::i64Bit, Reg, Constant, /*EmitterCTX->Config.CacheObjectCodeCompilation()*/ true);
  Relocations.emplace_back(MoveABI);
}

bool Arm64JITCore::ApplyRelocations(uint64_t GuestEntry, uint64_t CodeEntry, uint64_t CursorEntry, std::span<const Relocation> EntryRelocations) {
  for (size_t j = 0; j < EntryRelocations.size(); ++j) {
    const FEXCore::CPU::Relocation& Reloc = EntryRelocations[j];
    fmt::print(stderr, "RELOCATION {}: {}\n", j, ToUnderlying(Reloc.Header.Type));
    switch (Reloc.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
      uint64_t Pointer = GetNamedSymbolLiteral(Reloc.NamedSymbolLiteral.Symbol);
      // Relocation occurs at the cursorEntry + offset relative to that cursor
      SetCursorOffset(CursorEntry + Reloc.NamedSymbolLiteral.Offset);

      // Generate a literal so we can place it
      dc64(Pointer);

      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: {
      uint64_t Pointer = reinterpret_cast<uint64_t>(EmitterCTX->ThunkHandler->LookupThunk(Reloc.NamedThunkMove.Symbol));
      if (Pointer == ~0ULL) {
        return false;
      }

      // Relocation occurs at the cursorEntry + offset relative to that cursor.
      SetCursorOffset(CursorEntry + Reloc.NamedThunkMove.Offset);
      LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.NamedThunkMove.RegisterIndex), Pointer, true);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
      // XXX: Reenable once the JIT Object Cache is upstream
      // XXX: Should spin the relocation list, create a list of guest RIP moves, and ask for them all once, reduces lock contention.
      fextl::fmt::print(stderr, "  at {:#x}: move RIP {:#x} (at host {:#x})\n", Reloc.GuestRIPMove.Offset, Reloc.GuestRIPMove.GuestRIP,
                        CursorEntry + Reloc.GuestRIPMove.Offset);

      // ERROR_AND_DIE_FMT("Did we implement this?");
      // TODO: err... recompute the RIP properly!
      uint64_t Pointer = /*EmitterCTX->JITObjectCache->FindRelocatedRIP*/ (Reloc.GuestRIPMove.GuestRIP);
      // if (Pointer == ~0ULL) {
      //   if (j < 1 || GuestEntry == 0x7ffffffe280e) {
      //     continue;
      //   } else {
      //     // return false;
      //   }
      // }

      // Re-emit constant in case it requires more/fewer instructions at the new location
      SetCursorOffset(CursorEntry + Reloc.GuestRIPMove.Offset);
      LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.GuestRIPMove.RegisterIndex), Pointer, true);
      break;
    }

    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
      // TODO: For this to function, I think the page alignment of arm code within the original host page and the new host page must be the same?

      fextl::fmt::print(stderr, "  GUEST_RIP_LITERAL patching host addr {:#x} / {:#x}: RIP {:#x}\n", Reloc.GuestRIPMove.Offset,
                        CodeEntry + Reloc.GuestRIPMove.Offset, Reloc.GuestRIPMove.GuestRIP);
      SetCursorOffset(CursorEntry + Reloc.GuestRIPMove.Offset);
      dc64(GuestEntry + Reloc.GuestRIPMove.GuestRIP);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unknown relocation type {}", ToUnderlying(Reloc.Header.Type));
    }
  }

  return true;
}
} // namespace FEXCore::CPU
