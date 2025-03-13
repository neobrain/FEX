// SPDX-License-Identifier: MIT
// TODO: Things that affect code gen:
// VIXL_SIMULATOR preprocessor define
// FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS (?)

#include "../FEXLoader/ELFCodeLoader.h"
#include "../FEXLoader/AOT/AOTGenerator.h"

#include <FEXCore/Core/Context.h>

#include <Common/Config.h>
#include <Common/FEXServerClient.h>
#include <Common/HostFeatures.h>

#include <FEXCore/Core/HostFeatures.h>

#include <OptionParser.h>

#include <sys/wait.h>
#include <xxhash.h>

#include <fmt/printf.h>

#include <fstream>

// TODO: Change FinalizeAOTIRCache to take VAFileStart as a parameter instead...
static uintptr_t VAFileStart = 0;
static FEXCore::HLE::SyscallOSABI SyscallOSABI = {};

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

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    // TODO: Should fill this in properly (from command line?)
    return {0, false, 0};
  }

  // These are no-ops implementations of the SyscallHandler API
  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) override {
    // ERROR_AND_DIE_FMT("MUST RETURN THE ACTUAL SEGMENT OFFSET NOW...\n");
    return {(FEXCore::IR::AOTIRCacheEntry*)1, VAFileStart};
  }

  FEXCore::IR::AOTIRCacheEntry* Entry = nullptr;

  void* GuestMmap(FEXCore::Core::InternalThreadState*, void* addr, size_t Size, int prot, int Flags, int fd, off_t offset) override {
    auto Ret = mmap(addr, Size, prot, Flags, fd, offset);
    if (Ret != MAP_FAILED && VAFileStart == 0) {
      VAFileStart = reinterpret_cast<uintptr_t>(Ret);
      fmt::print("Mapped to {:#x}\n", VAFileStart);
    }
    return Ret;
  }

  int GuestMunmap(FEXCore::Core::InternalThreadState*, void* addr, uint64_t length) override {
    return munmap(addr, length);
  }
};

class DummySignalDelegator final : public FEXCore::SignalDelegator {};

static void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

static void AssertHandler(const char* Message) {
  fmt::print("[ASSERT] {}\n", Message);
}

std::map<std::string, fextl::set<uintptr_t>> ParseCodeMap(std::ifstream& Codemap) {
  std::map<std::string, fextl::set<uintptr_t>> Ret;
  while (true) {
    std::string Filename;
    std::getline(Codemap, Filename, '\0');
    uint64_t Start, Size;
    Codemap.read(reinterpret_cast<char*>(&Start), sizeof(Start));
    Codemap.read(reinterpret_cast<char*>(&Size), sizeof(Size));
    if (!Codemap) {
      break;
    }
    Ret[Filename].insert(Start);
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

  std::map<std::string, fextl::set<uintptr_t>> CodeMaps;

  for (auto& Input : Inputs) {
    std::ifstream Codemap(Input.c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", Input);
      return EXIT_FAILURE;
    }

    auto NewCodeMap = ParseCodeMap(Codemap);
    for (auto& [Filename, Blocks] : NewCodeMap) {
      CodeMaps[Filename].merge(Blocks);
    }
  }

  std::ofstream Output(Options.get("output"), std::ios_base::binary);
  if (!Output) {
    fmt::print("Could not open {} for writing\n", (std::string)Options.get("output"));
    return EXIT_FAILURE;
  }
  for (auto& [File, Blocks] : CodeMaps) {
    fmt::print("Parsed codemap entries for {}\n", File);

    for (auto& Block : Blocks) {
      Output.write(File.c_str(), File.size() + 1);
      Output.write(reinterpret_cast<const char*>(&Block), sizeof(Block));
      uint64_t Size = 0; // TODO: Not sure if we should track really this
      Output.write(reinterpret_cast<char*>(&Size), sizeof(Size));
    }
  }

  return 0;
}

int GenerateCache(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--host-dcache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-icache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-features").type("long").help("Target HostFeatures to use when compiling code (default: detect from host)");

  Parser.add_option("--smc").type("long").help("Strategy for self-modifying-code (default: none)");

  Parser.add_option("--codemap").help("Path to code map");
  Parser.add_option("--limit").action("store_true").help("Limit processing to the given binary");

  optparse::Values Options = Parser.parse_args(argc, argv);
  if (Parser.args().size() != 1) {
    Parser.print_usage();
    return 1;
  }

  auto ProgramName = Parser.args()[0];

  fextl::set<uintptr_t> InitialBranchTargets;

  if (Options.is_set("codemap")) {
    std::ifstream Codemap(((std::string)Options.get("codemap")).c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", (std::string)Options.get("codemap"));
      return 1;
    }

    fextl::set<std::string> Files;

    auto Data = ParseCodeMap(Codemap);

    for (auto& [File, Blocks] : Data) {
      fmt::print("Parsed codemap entries for {}\n", File);
    }

    for (auto& [File, Blocks] : Data) {
      if (File == ProgramName.c_str()) {
        // Continue as normal
      } else if (!Options.is_set("limit")) {
        // Process in fork
        auto child_pid = fork();
        if (child_pid == 0) {
          ProgramName = File;
          break;
        } else {
          int status;
          ::wait(&status);
          if (status != 0) {
            fmt::print("CHILD PROCESS FOR {} FAILED\n", File);
            return 1;
          }
        }
      }
    }

    InitialBranchTargets.merge(Data.at(ProgramName.c_str()));
  }

  // TODO: Support compiling from an FD

  // TODO: Generate substitute config?
  FEX::Config::InitializeConfigs({});
  FEXCore::Config::Initialize();

  // TODO: From command line
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_MULTIBLOCK, "0");

  // TODO: Consider re-enabling it for code statistics
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_DISABLETELEMETRY, "1");

  ELFCodeLoader Loader {ProgramName, -1, "", {ProgramName}, {}, {}, nullptr, true /* skip interpreter */};
  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, Loader.Is64BitMode() ? "1" : "0");
  // TODO: OS_GENERIC?
  SyscallOSABI = Loader.Is64BitMode() ? FEXCore::HLE::SyscallOSABI::OS_LINUX64 : FEXCore::HLE::SyscallOSABI::OS_LINUX32;

  // Load HostFeatures
  // NOTE: Config must be fully initialized for detection to work
  FEXCore::HostFeatures HostFeatures {};
  // TODO: Setup   FEX_CONFIG_OPT(ForceSVEWidth, FORCESVEWIDTH);


  const auto DetectedFeatures = FEX::FetchHostFeatures();
  if (Options.is_set("host-features")) {
    uint32_t RawValue = Options.get("host-features");
    memcpy(reinterpret_cast<char*>(&HostFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           &RawValue, sizeof(RawValue));
  } else {
    memcpy(reinterpret_cast<char*>(&HostFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           reinterpret_cast<const char*>(&DetectedFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           sizeof(uint32_t));
  }
  if (Options.is_set("host-dcache-line-size")) {
    HostFeatures.DCacheLineSize = Options.get("host-dcache-line-size");
  } else {
    HostFeatures.DCacheLineSize = DetectedFeatures.DCacheLineSize;
  }
  if (Options.is_set("host-icache-line-size")) {
    HostFeatures.ICacheLineSize = Options.get("host-icache-line-size");
  } else {
    HostFeatures.ICacheLineSize = DetectedFeatures.ICacheLineSize;
  }
  HostFeatures = DetectedFeatures;

  FEX_CONFIG_OPT(MultiBlock, MULTIBLOCK);

  if (!std::filesystem::exists(ProgramName)) {
    if (ProgramName.starts_with("/run/pressure-vessel")) {
      // TODO: Find a way to support this cleanly
      fmt::print("Cannot handle libs from pressure-vessel, yet\n");
      return 0;
    } else {
      fmt::print("File {} does not exist\n", ProgramName);
      return EXIT_FAILURE;
    }
  }

  if (!Loader.ELFWasLoaded()) {
    fmt::print("Invalid or Unsupported elf file.\n");
    return EXIT_FAILURE;
  }

  FEXCore::Context::InitializeStaticTables(Loader.Is64BitMode() ? FEXCore::Context::MODE_64BIT : FEXCore::Context::MODE_32BIT);

  auto CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);

  auto SignalDelegation = std::make_unique<DummySignalDelegator>();
  // TODO: Is this needed?
  // auto ThunkHandler = FEX::HLE::CreateThunkHandler();

  auto SyscallHandler = std::make_unique<AOTSyscallHandler>();

  // TODO: How to handle VDSO with code caching? Does this need purpose-specific FEX relocations?

  {
    // Loader.SetVDSOBase(VDSOMapping.VDSOBase); // TODO: Check interaction with disk caching?
    Loader.CalculateHWCaps(CTX.get());
  }

  CTX->SetSignalDelegator(SignalDelegation.get());
  CTX->SetSyscallHandler(SyscallHandler.get());

  if (!CTX->InitCore()) {
    return 1;
  }

  auto ParentThread = new FEX::HLE::ThreadStateObject;
  {
    auto& ThreadStateObject = ParentThread;

    ThreadStateObject->ThreadInfo.parent_tid = 0;
    ThreadStateObject->ThreadInfo.PID = ::getpid();
    ThreadStateObject->ThreadInfo.TID = FHU::Syscalls::gettid();

    ThreadStateObject->Thread =
      CTX->CreateThread(Loader.DefaultRIP(), Loader.GetStackPointer(), nullptr, ThreadStateObject->ThreadInfo.parent_tid);

    // TODO: Does ThreadStateObject->persona affect codegen?
  }

  auto ElfBase = Loader.LoadElfFile(Loader.MainElf, nullptr, SyscallHandler.get());
  if (!ElfBase.has_value()) {
    ERROR_AND_DIE_FMT("Failed to load ELF file {}", ProgramName);
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
  FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  if (TSOEnabled) {
    CTX->SetHardwareTSOSupport(true);
  }

  FEX_CONFIG_OPT(ABILocalFlags, ABILOCALFLAGS);

  {
    fmt::print(stderr, "Compiling code...\n");
    for (auto GuestAddr : InitialBranchTargets) {
      CTX->CompileRIP(ParentThread->Thread, GuestAddr);
    }

    std::filesystem::create_directories("/tmp/fexcache");
    // TODO: Merge with AOTIR.cpp code
    // TODO: Capture external configuration more accurately
    auto filename_hash = XXH3_64bits(ProgramName.data(), ProgramName.size());
    auto fileid = fmt::format("{}-{}-{}{}{}", std::filesystem::path {ProgramName}.filename().string(), filename_hash,
                              (SMCChecks == FEXCore::Config::CONFIG_SMC_FULL) ? 'S' : 's', TSOEnabled ? 'T' : 't', ABILocalFlags ? 'L' : 'l');

    // TODO: Consider O_EXCL so that this fails to overwrite existing files?
    auto Filename = fmt::format("/tmp/fexcache/{}", fileid);
    auto FilenameNew = Filename + ".new";
    int fd = open(FilenameNew.c_str(), O_CREAT | O_WRONLY, 0644);
    CTX->FinalizeAOTIRCache(*ParentThread->Thread, fd, VAFileStart);
    std::filesystem::rename(FilenameNew.c_str(), Filename.c_str());
    fmt::print("Output written to {}\n", Filename);
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
