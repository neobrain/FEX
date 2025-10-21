// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/CodeCache.h>

#include <fstream>

namespace FEX {

class CodeMapWriterSingleThreaded : public FEXCore::CodeMapWriter {
public:
  CodeMapWriterSingleThreaded(std::string Filename)
    : Output(std::move(Filename), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc) {}
  ~CodeMapWriterSingleThreaded() {
    Flush(GetBufferOffset());
  }

  explicit operator bool() const {
    return !!Output;
  }

private:
  bool IsWriteEnabled(const FEXCore::ExecutableFileSectionInfo&) override {
    return true;
  }

  void CommitData(std::span<const std::byte> Data) override {
    Output.write(reinterpret_cast<const char*>(Data.data()), Data.size_bytes());
  }

  std::ofstream Output;
};

} // namespace FEX
