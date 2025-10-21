// SPDX-License-Identifier: MIT
#pragma once

#include "ELFCodeLoader.h"

namespace FEX::AOT {
void AOTGenSection(FEXCore::Core::InternalThreadState&, FEXCore::Context::Context* CTX, ELFCodeLoader::LoadedSection& Section,
                   fextl::set<uintptr_t> InitialBranchTargets);
}
