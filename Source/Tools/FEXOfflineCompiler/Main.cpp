// SPDX-License-Identifier: MIT
// TODO: Things that affect code gen:
// VIXL_SIMULATOR preprocessor define
// FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS (?)

#include "../FEXInterpreter/ELFCodeLoader.h"
#include <CodeMapWriterSingleThreaded.h>
#include <PortabilityInfo.h>
#include "Thunks.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CodeCache.h>

#include <Common/ArgumentLoader.h>
#include <Common/Config.h>
#include <Common/FEXServerClient.h>
#include <Common/HostFeatures.h>

#include <FEXCore/Core/HostFeatures.h>

#include <OptionParser.h>

#include <sys/wait.h>
#include <xxhash.h>

#include <fmt/printf.h>

#include <fstream>
#include <PEParser.h>

// TODO: Change FinalizeAOTIRCache to take VAFileStart as a parameter instead...
static uintptr_t VAFileStart = 0;
static FEXCore::HLE::SyscallOSABI SyscallOSABI = {};

#include <Common/Config.h>
#include <Common/FEXServerClient.h>
#include <FEXCore/Core/CodeCache.h>

#include <optional>
#include <sys/file.h>

class AOTSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEX::HLE::SyscallMmapInterface {
public:
  AOTSyscallHandler() {
    // TODO: From command line
    OSABI = SyscallOSABI;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    // Don't do anything
    return 0;
  }

  // TODO: Fill with placeholder data?
  FEXCore::ExecutableFileInfo FileInfo;

  // These are no-ops implementations of the SyscallHandler API
  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState&, uint64_t) override {
    return FEXCore::ExecutableFileSectionInfo {FileInfo, VAFileStart};
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    // TODO: Not sure about this
    return {0, UINT64_MAX, true};
  }

  // void ForEachVMAMapping(FEXCore::Core::InternalThreadState*, std::function<void(uint64_t)>) override {}

  void* GuestMmap(FEXCore::Core::InternalThreadState*, void* addr, size_t Size, int prot, int Flags, int fd, off_t offset) override {
    auto Ret = mmap(addr, Size, prot, Flags, fd, offset);
    if (Ret != MAP_FAILED && VAFileStart == 0) {
      VAFileStart = reinterpret_cast<uintptr_t>(Ret);
      fmt::print("Mapped to {:#x}\n", VAFileStart);
    }
    return Ret;
  }

  uint64_t GuestMunmap(FEXCore::Core::InternalThreadState*, void* addr, uint64_t length) override {
    return munmap(addr, length);
  }
};

class DummySignalDelegator final : public FEXCore::SignalDelegator {};

static void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

static void AssertHandler(const char* Message) {
  fmt::print("[A] {}\n", Message);
}

using FileIdWithPath = FEXCore::ExecutableFileInfo;

namespace FEXCore {
inline bool operator<(const FileIdWithPath& a, const FileIdWithPath& b) noexcept {
  return a.FileId < b.FileId;
}
} // namespace FEXCore

extern "C" {
extern bool g_print_ir;
}

template<>
struct std::hash<FileIdWithPath> {
  std::size_t operator()(const FileIdWithPath& Val) const noexcept {
    return Val.FileId;
  }
};

// TODO: Use CodeMap::ParseCodeMap directly
std::map<FileIdWithPath, fextl::set<uintptr_t>> ParseCodeMap(std::ifstream& Codemap, FileIdWithPath* OutMainFileId) {
  auto Parsed = FEXCore::CodeMap::ParseCodeMap(Codemap);

  std::map<FileIdWithPath, fextl::set<uintptr_t>> Ret;
  if (OutMainFileId && Parsed.size() == 1) {
    OutMainFileId->FileId = Parsed.begin()->first;
    OutMainFileId->Filename = Parsed.begin()->second.Filename;
  }
  for (auto& [FileId, Contents] : Parsed) {
    if (OutMainFileId && Contents.IsExecutable) {
      OutMainFileId->FileId = FileId;
      OutMainFileId->Filename = Contents.Filename;
    }
    Ret.emplace(std::piecewise_construct, std::forward_as_tuple(nullptr, FileId, std::move(Contents.Filename)),
                std::forward_as_tuple(std::move(Contents.Blocks)));
  }

  return Ret;
}

int CombineCodeMaps(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--output").help("Filename for output code map");

  optparse::Values Options = Parser.parse_args(argc, argv);
  auto Inputs = Parser.args();
  if (Inputs.empty()) {
    Parser.print_usage();
    return EXIT_FAILURE;
  }

  if (!Options.is_set("output")) {
    fmt::print("{}: error: Output not specified (--output)", argv[0]);
    return EXIT_FAILURE;
  }

  std::map<FileIdWithPath, fextl::set<uintptr_t>> CodeMaps;

  for (auto& Input : Inputs) {
    std::ifstream Codemap(Input.c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", Input);
      return EXIT_FAILURE;
    }

    auto NewCodeMap = ParseCodeMap(Codemap, nullptr);
    for (auto& [Filename, Blocks] : NewCodeMap) {
      auto& TargetBlocks =
        CodeMaps.emplace(std::piecewise_construct, std::forward_as_tuple(nullptr, Filename.FileId, Filename.Filename), std::tuple {}).first->second;
      TargetBlocks.merge(std::move(Blocks));
    }
  }

  FEX::CodeMapWriterSingleThreaded OutputCodeMap((std::string)Options.get("output"));
  if (!OutputCodeMap) {
    fmt::print("Could not open {} for writing\n", (std::string)Options.get("output"));
    return EXIT_FAILURE;
  }
  // Pull all library loads to the front
  for (auto& [File, Blocks] : CodeMaps) {
    fmt::print("Parsed {} codemap entries for {} ({:016x})\n", Blocks.size(), File.Filename, File.FileId);
    OutputCodeMap.AppendLibraryLoad(FEXCore::ExecutableFileInfo {nullptr, File.FileId, File.Filename});
  }
  for (auto& [File, Blocks] : CodeMaps) {
    auto FileInfo = FEXCore::ExecutableFileInfo {nullptr, File.FileId, File.Filename};
    for (auto& Block : Blocks) {
      OutputCodeMap.AppendBlock(FEXCore::ExecutableFileSectionInfo {FileInfo, 0}, Block);
    }
  }

  return 0;
}

int GenerateCache(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--codemap").help("Path to code map");
  Parser.add_option("--limit").action("store_true").help("Limit processing to the given binary");
  Parser.add_option("--outdir").set_default(FEX::Config::GetCacheDirectory() + "cache").help("Output directory for generated cache files");

  optparse::Values Options = Parser.parse_args(argc, argv);
  if (Parser.args().size() != 0) {
    Parser.print_usage();
    return 1;
  }

  FileIdWithPath ProgramName;

  fextl::set<uintptr_t> InitialBranchTargets;

  if (Options.is_set("codemap")) {
    std::ifstream Codemap(((std::string)Options.get("codemap")).c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", (std::string)Options.get("codemap"));
      return 1;
    }

    fextl::set<std::string> Files;

    auto Data = ParseCodeMap(Codemap, &ProgramName);
    if (!ProgramName.FileId) {
      fmt::print("Cannot generate cache from unsanitized code map {}", (std::string)Options.get("codemap"));
      return 1;
    }

    for (auto& [File, Blocks] : Data) {
      fmt::print("Parsed {} codemap entries for {} ({:016x})\n", Blocks.size(), File.Filename, File.FileId);
    }

    for (auto& [File, Blocks] : Data) {
      if (File.FileId == ProgramName.FileId) {
        // Continue as normal
      } else if (!Options.is_set("limit")) {
        if (Blocks.empty()) {
          // Purely listed as a dependency, skip
          continue;
        }

        // Process in fork
        auto child_pid = fork();
        if (child_pid == 0) {
          ProgramName.FileId = File.FileId;
          ProgramName.Filename = File.Filename;
          break;
        } else {
          int status;
          ::wait(&status);
          if (status != 0) {
            fmt::print("CHILD PROCESS FAILED\n");
            return 1;
          }
        }
      }
    }

    if (!Data.contains(ProgramName)) {
      throw std::runtime_error(fmt::format("Input code map {} did not contain {} ({})", (std::string)Options.get("codemap"),
                                           ProgramName.Filename, ProgramName.FileId));
    }

    InitialBranchTargets.merge(Data.at(ProgramName));
  } else {
    // TODO: Turn it into the first argument instead
    fmt::println("codemap argument is mandatory now");
    return 1;
  }

  // TODO: Support compiling from an FD

  uint64_t CodeCacheConfigId = 0; // TODO: Make unique to active configuration
  const auto PortableInfo = FEX::ReadPortabilityInformation();
  char* envp[] = {nullptr};
  FEX::Config::LoadConfig("", envp, PortableInfo);
  // TODO: Also load app config

  bool Is64Bit;
  bool LoadedFromPE = false;
  std::variant<std::monostate, PEParser, ELFCodeLoader> Loader;
  {
    auto fd = open(ProgramName.Filename.c_str(), O_RDONLY);
    Loader = PEParser {fd};
    auto& Parser = std::get<PEParser>(Loader);
    if (Parser) {
      Is64Bit = Parser.Is64Bit;

      if (!Is64Bit) {
        // Block upper address space
        FEXCore::Allocator::SetupHooks();
      }

      auto SyscallHandler = std::make_unique<AOTSyscallHandler>();
      // TODO: Handle relocation in case ImageBase is already blocked?
      Parser.MapMemory(SyscallHandler.get(), fd);
      LoadedFromPE = true;
    }
    close(fd);
  }

  if (!LoadedFromPE) {
    Loader.emplace<ELFCodeLoader>(ProgramName.Filename.c_str(), -1, "", fextl::vector<fextl::string> {ProgramName.Filename.c_str()},
                                  fextl::vector<fextl::string> {}, nullptr, nullptr, true /* skip interpreter */);
    auto& ELFLoader = std::get<ELFCodeLoader>(Loader);
    if (!ELFLoader.ELFWasLoaded()) {
      fmt::print("Invalid or unsupported ELF file.\n");
      return EXIT_FAILURE;
    }
    Is64Bit = ELFLoader.Is64BitMode();
  }
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Is64Bit ? "1" : "0");

  // TODO: OS_GENERIC?
  SyscallOSABI = Is64Bit ? FEXCore::HLE::SyscallOSABI::OS_LINUX64 : FEXCore::HLE::SyscallOSABI::OS_LINUX32;

  // Load HostFeatures
  // This can be customized via Config.json
  auto HostFeatures = FEX::FetchHostFeatures();

  // TODO: Verify the file exists
  if (!std::filesystem::exists(ProgramName.Filename)) {
    fmt::print("File {} does not exist\n", ProgramName.Filename);
    // TODO: Pressure vessel hits this
    return /*EXIT_FAILURE*/ 0;
  }

  auto CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);

  auto SignalDelegation = std::make_unique<DummySignalDelegator>();

  auto SyscallHandler = std::make_unique<AOTSyscallHandler>();

  // TODO: How to handle VDSO with code caching? Does this need purpose-specific FEX relocations?

  if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
    // ELFLoader->SetVDSOBase(VDSOMapping.VDSOBase); // TODO: Check interaction with disk caching?
    ELFLoader->CalculateHWCaps(CTX.get());
  }

  CTX->SetSignalDelegator(SignalDelegation.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  auto ThunkHandler = FEX::HLE::CreateThunkHandler();
  CTX->SetThunkHandler(ThunkHandler.get());

  if (!CTX->InitCore()) {
    return 1;
  }

  if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
    if (!Is64Bit) {
      // Block upper address space
      FEXCore::Allocator::SetupHooks();
    }
    auto ElfBase = ELFLoader->LoadElfFile(ELFLoader->MainElf, nullptr, SyscallHandler.get());
    if (!ElfBase.has_value()) {
      ERROR_AND_DIE_FMT("Failed to load ELF file {} ({})", ProgramName.Filename, ProgramName.FileId);
    }
  }

  {
    decltype(InitialBranchTargets) InitialBranchTargets2;
    for (auto Offset : InitialBranchTargets) {
      InitialBranchTargets2.insert(Offset + VAFileStart);
    }
    InitialBranchTargets = std::move(InitialBranchTargets2);
  }

  const auto SMCChecks = Options.is_set("smc") ? static_cast<FEXCore::Config::ConfigSMCChecks>(static_cast<long>(Options.get("smc"))) :
                                                 FEXCore::Config::CONFIG_SMC_NONE;

  // TODO: From command line
  // TODO: Use full TSO configuration
  FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  if (TSOEnabled) {
    // TODO: Fetch from command line
    // CTX->SetHardwareTSOSupport(true);
  }

  auto Thread = CTX->CreateThread(0, 0);

  // GDT data
  FEXCore::Core::CPUState::gdt_segment gdt[32] {};

  {
    auto Frame = Thread->CurrentFrame;
    // GDT and LDT are tracked per thread.
    Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &gdt[0];
    // TODO: LDTs are currently unsupported, mirror them to GDT.
    Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &gdt[0];

    // Default code segment indexes match the numbers that the Linux kernel uses.
    Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
    auto GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(GDT, 0);
    FEXCore::Core::CPUState::SetGDTLimit(GDT, 0xF'FFFFU);
    Frame->State.cs_cached =
      FEXCore::Core::CPUState::CalculateGDTBase(*FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx));

    if (Is64Bit) {
      GDT->L = 1; // L = Long Mode = 64-bit
      GDT->D = 0; // D = Default Operand SIze = Reserved
    } else {
      GDT->L = 0; // L = Long Mode = 32-bit
      GDT->D = 1; // D = Default Operand Size = 32-bit
    }
  }

  CTX->GetCodeCache().InitiateCacheGeneration();

  // g_print_ir = true;
  {
    std::vector<std::unique_ptr<ELFCodeLoader>> LoaderMem;

    fmt::print(stderr, "Running code discovery...\n");
    for (auto Addr : InitialBranchTargets) {
      CTX->CompileRIP(Thread, Addr);
    }

    fmt::print(stderr, "Compiling code...\n");

    fextl::string OutDir(Options.get("outdir"));
    if (!OutDir.ends_with('/')) {
      OutDir.push_back('/');
    }
    std::filesystem::create_directories(OutDir);

    // TODO: Consider O_EXCL so that this fails to overwrite existing files?
    // TODO: Handle non-multiblock? Should ideally be able to use multiblock-codemaps, too
    auto Filename =
      fmt::format("{}{}-{:016x}", OutDir,
                  FEXCore::CodeMap::GetBaseFilename(FEXCore::ExecutableFileInfo {nullptr, ProgramName.FileId, ProgramName.Filename}, false),
                  CodeCacheConfigId);
    auto FilenameNew = Filename + ".new";
    int fd = open(FilenameNew.c_str(), O_CREAT | O_WRONLY, 0644);
    if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
      auto Entry = SyscallHandler->LookupExecutableFileSection(*Thread, ELFLoader->MainElfBase).value();
      CTX->GetCodeCache().SaveData(*Thread, fd, Entry, 0 /* TODO */);
    } else {
      auto Entry = SyscallHandler->LookupExecutableFileSection(*Thread, std::get<PEParser>(Loader).ImageBase).value();
      CTX->GetCodeCache().SaveData(*Thread, fd, Entry, std::get<PEParser>(Loader).ImageBase);
    }
    std::filesystem::rename(FilenameNew.c_str(), Filename.c_str());
    fmt::print("Successfully populated cache {} ({} blocks) via {}\n\n", Filename, InitialBranchTargets.size(),
               (std::string)Options.get("codemap"));
    close(fd);
  }
  return 0;
}

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  std::vector<const char*> Args {argv + 1, argv + argc};
  auto CommandName = std::string {basename(argv[0])} + " " + (argc > 1 ? argv[1] : "");
  Args[0] = CommandName.c_str();

  if (argc >= 2 && argv[1] == std::string_view {"combine"}) {
    return CombineCodeMaps(argc - 1, Args.data());
  } else if (argc >= 2 && argv[1] == std::string_view {"generate"}) {
    return GenerateCache(argc - 1, Args.data());
  } else {
    fmt::print("Usage: {} <command>\n\n", basename(argv[0]));
    fmt::print("Commands:\n");
    fmt::print("  combine\tCombine code maps and prepare them for cache generation\n");
    fmt::print("  generate\tTrigger cache generation from combined code map\n");
    return EXIT_FAILURE;
  }
}
