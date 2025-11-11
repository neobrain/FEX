// SPDX-License-Identifier: MIT
#include "FEXHeaderUtils/Filesystem.h"
#include "Interface/Context/Context.h"

#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/fextl/fmt.h>

#include <Interface/GDBJIT/GDBJIT.h>

#include <Common/FDUtils.h>

#include <fstream>
#include <thread>

#include <xxhash.h>

namespace FEXCore {
// TODO: Define elsewhere?
ExecutableFileInfo::~ExecutableFileInfo() = default;

// TODO: Move to common code...
uint64_t AbstractCodeCache::ComputeConfigId(std::span<std::byte> Data) {

  // TODO: Also encode HostFeatures

  // TODO: Hash only used data instead of all 4096 bytes

  return XXH3_64bits(Data.data(), Data.size_bytes());
}

fextl::string CodeMap::GetBaseFilename(const ExecutableFileInfo& MainExecutable, bool AddNombSuffix) {
  auto FileId = MainExecutable.FileId;

  std::string_view base_filename = FHU::Filesystem::GetFilename(std::string_view {MainExecutable.Filename});
  if (FileId != 0xffff'ffff'ffff'ffff) {
    return fextl::fmt::format("{}-{:016x}{}", base_filename, MainExecutable.FileId, AddNombSuffix ? "-nomb" : "");
  }

  return "";
}

fextl::map<CodeMapFileId, CodeMap::ParsedContents> CodeMap::ParseCodeMap(std::ifstream& File) {
  fextl::map<CodeMapFileId, CodeMap::ParsedContents> Ret;
  while (true) {
    Entry Entry;
    File.read(reinterpret_cast<char*>(&Entry), sizeof(Entry));
    if (!File) {
      break;
    }

    if (Entry.FileId == LoadExternalLibrary.FileId && Entry.BlockOffset == LoadExternalLibrary.BlockOffset) {
      ExternalLibraryInfo Info;
      File.read(reinterpret_cast<char*>(&Info), sizeof(Info));

      fextl::string Filename;
      std::getline(File, Filename, '\0');

      // Align to 4-byte boundary
      char Null[4];
      File.read(Null, AlignUp(Filename.size() + 1, 4) - Filename.size() - 1);
      if (!File) {
        break;
      }
      Ret[Info.ExternalFileId].Filename = std::move(Filename);
      // TODO: Check for conflict if a previous entry already existed?
    } else if (Entry.FileId == SetExecutableFileId {}.Marker.FileId && Entry.BlockOffset == SetExecutableFileId {}.Marker.BlockOffset) {
      CodeMapFileId ExecutableFileId;
      File.read(reinterpret_cast<char*>(&ExecutableFileId), sizeof(ExecutableFileId));
      if (!File) {
        break;
      }
      Ret[ExecutableFileId].IsExecutable = true;
    } else {
      if (!Ret.contains(Entry.FileId)) {
        LogMan::Msg::EFmt("Code map referenced unknown file id {:016x}", Entry.FileId);
      } else {
        Ret[Entry.FileId].Blocks.insert(Entry.BlockOffset);
      }
    }

    if (!File) {
      break;
    }
  }
  return Ret;
}

CodeMapWriter::CodeMapWriter()
  : Buffer(4096) {}

void CodeMapWriter::Flush(size_t Offset) {
  // Acquire exclusive lock and flush circular buffer
  std::unique_lock Lock {Mutex};
  Flush(Offset, Lock);
}

void CodeMapWriter::Flush(size_t Offset, std::unique_lock<std::shared_mutex>&) {
  CommitData(std::span {Buffer}.subspan(0, Offset));
  BufferOffset = 0;
}

void CodeMapWriter::AppendBlock(const FEXCore::ExecutableFileSectionInfo& SectionInfo, uint64_t BlockEntry) {
  BlockEntry -= SectionInfo.FileStartVA;
  if (BlockEntry > std::numeric_limits<uint32_t>::max()) {
    ERROR_AND_DIE_FMT("Cannot write code map");
  }

  // Register new library if not already known
  bool NewLibraryLoad = false;
  {
    // Check prior registration with shared lock
    std::shared_lock Lock {Mutex};
    NewLibraryLoad = !KnownFileIds.contains(SectionInfo.FileInfo.FileId);
  }
  if (NewLibraryLoad) {
    // Register to map with exclusive lock
    std::unique_lock Lock {Mutex};
    NewLibraryLoad &= KnownFileIds.insert(SectionInfo.FileInfo.FileId).second;
  }
  if (NewLibraryLoad) {
    // Add entry to code map
    AppendLibraryLoad(SectionInfo.FileInfo);
  }

  // Register the actual code block
  CodeMap::Entry DataEntry {SectionInfo.FileInfo.FileId, static_cast<uint32_t>(BlockEntry)};
  AppendData(std::as_bytes(std::span {&DataEntry, 1}));
}

void CodeMapWriter::AppendLibraryLoad(const FEXCore::ExecutableFileInfo& FileInfo) {
  // See CodeMap::ExternalLibraryInfo
  auto ExternalFileId = FileInfo.FileId;
  auto TotalSize = AlignUp(sizeof(CodeMap::LoadExternalLibrary) + sizeof(ExternalFileId) + FileInfo.Filename.size() + 1, 4);
  const auto Data = reinterpret_cast<char*>(alloca(TotalSize));
  auto WritePtr = std::copy_n(reinterpret_cast<const char*>(&CodeMap::LoadExternalLibrary), sizeof(CodeMap::LoadExternalLibrary), Data);
  WritePtr = std::copy_n(reinterpret_cast<const char*>(&ExternalFileId), sizeof(ExternalFileId), WritePtr);
  WritePtr = std::copy(FileInfo.Filename.begin(), FileInfo.Filename.end(), WritePtr);
  std::fill(WritePtr, Data + TotalSize, 0);
  AppendData(std::as_bytes(std::span {Data, TotalSize}));
}

void CodeMapWriter::AppendSetMainExecutable(const FEXCore::ExecutableFileInfo& FileInfo) {
  CodeMap::SetExecutableFileId Data {.ExecutableFileId = FileInfo.FileId};
  AppendData(std::span {reinterpret_cast<const std::byte*>(&Data), sizeof(Data)});
}

void CodeMapWriter::AppendData(std::span<const std::byte> Data) {
  std::shared_lock Lock {Mutex};
  auto Offset = BufferOffset.fetch_add(Data.size_bytes());
  if (Offset + Data.size_bytes() > Buffer.size()) {
    // Acquire exclusive lock and flush the buffer.
    // Under heavy pressure, multiple threads may observe an exhausted buffer simultaneously.
    // The thread with the last in-bounds Offset is responsible for flushing the buffer.
    Lock.unlock();
    bool IsResponsibleForFlush = false;
    {
      std::unique_lock ExclusiveLock {Mutex};
      IsResponsibleForFlush = (Offset <= Buffer.size());
      if (IsResponsibleForFlush) {
        Flush(Offset, ExclusiveLock);
      }
    }
    if (!IsResponsibleForFlush) {
      // Wait for the buffer to be flushed on the responsible thread
      while (BufferOffset > Buffer.size()) {
        std::this_thread::yield();
      }
    }
    AppendData(Data);
    return;
  }

  memcpy(&Buffer.at(Offset), Data.data(), Data.size_bytes());
}

} // namespace FEXCore

namespace FEXCore::Context {

uint64_t CodeCache::ComputeCodeMapId(int FD) {
  char Tmp[PATH_MAX];
  auto PathLength = FEX::get_fdpath(FD, Tmp);
  auto Filename = std::string_view(Tmp, PathLength);

  std::string_view base_filename = FHU::Filesystem::GetFilename(Filename);
  if (!base_filename.empty()) {
    // TODO: Identify via ELF build id instead
    auto filename_hash = XXH3_64bits(Filename.data(), Filename.size());

    return filename_hash;
  }

  return 0xffff'ffff'ffff'ffff;
}

} // namespace FEXCore::Context
