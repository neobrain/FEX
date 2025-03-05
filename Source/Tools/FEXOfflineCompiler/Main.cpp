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

#include <xxhash.h>

#include <fmt/printf.h>

// TODO: Change FinalizeAOTIRCache to take VAFileStart as a parameter instead...
static uintptr_t VAFileStart = 0;

class AOTSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEX::HLE::SyscallMmapInterface {
public:
  AOTSyscallHandler() {
    // TODO: From command line
    OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64;
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
    return {(FEXCore::IR::AOTIRCacheEntry*)1, VAFileStart};
  }

  void ForEachVMAMapping(FEXCore::Core::InternalThreadState*, std::function<void(uint64_t)>) override {}

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

int main(int argc, char** argv, char** const envp /* TODO: Drop */) {
  optparse::OptionParser Parser {};
  Parser.add_option("--host-dcache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-icache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-features").type("long").help("Target HostFeatures to use when compiling code (default: detect from host)");

  Parser.add_option("--smc").type("long").help("Strategy for self-modifying-code (default: none)");

  optparse::Values Options = Parser.parse_args(argc, argv);
  if (Parser.args().size() != 1) {
    Parser.print_usage();
    return 1;
  }

  const auto ProgramName = Parser.args()[0];

  // TODO: Support compiling from an FD

  // TODO: Generate substitute config?
  FEX::Config::InitializeConfigs({});
  FEXCore::Config::Initialize();

  // TODO: From command line
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, "0");

  // Load HostFeatures
  FEXCore::HostFeatures HostFeatures {};
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
  if (MultiBlock()) {
    ERROR_AND_DIE_FMT("SHOULD NOT HAVE MULTIBLOCK ENABLED");
  }

  // TODO: Verify the file exists
  if (!std::filesystem::exists(ProgramName)) {
    fmt::print("File {} does not exist\n", ProgramName);
    return EXIT_FAILURE;
  }

  ELFCodeLoader Loader {ProgramName, -1, "", {ProgramName}, {}, {}, nullptr};
  if (!Loader.ELFWasLoaded()) {
    fmt::print("Invalid or Unsupported elf file.\n");
    return EXIT_FAILURE;
  }

  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Loader.Is64BitMode() ? "1" : "0");

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

  const auto SMCChecks = Options.is_set("smc") ? static_cast<FEXCore::Config::ConfigSMCChecks>(static_cast<long>(Options.get("smc"))) :
                                                 FEXCore::Config::CONFIG_SMC_NONE;

  // TODO: From command line
  // TODO: Use full TSO configuration
  // FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  const bool TSOEnabled = false;
  if (TSOEnabled) {
    CTX->SetHardwareTSOSupport(true);
  }

  {
    std::vector<std::unique_ptr<ELFCodeLoader>> LoaderMem;

    fmt::print(stderr, "Running code discovery...\n");
    for (auto& Section : Loader.Sections) {
      FEX::AOT::AOTGenSection(*ParentThread->Thread, CTX.get(), Section);
    }

    fmt::print(stderr, "Compiling code...\n");
    std::filesystem::create_directories("/tmp/fexcache");
    // TODO: Merge with AOTIR.cpp code
    // TODO: Capture external configuration more accurately
    auto filename_hash = XXH3_64bits(ProgramName.data(), ProgramName.size());
    auto fileid = fmt::format("{}-{}-{}{}{}", std::filesystem::path {ProgramName}.filename().string(), filename_hash,
                              (SMCChecks == FEXCore::Config::CONFIG_SMC_FULL) ? 'S' : 's', TSOEnabled ? 'T' : 't',
                              /*CTX->Config.ABILocalFlags ? 'L' :*/ 'l');

    // TODO: Consider O_EXCL so that this fails to overwrite existing files?
    auto Filename = fmt::format("/tmp/fexcache/{}", fileid);
    auto FilenameNew = Filename + ".new";
    int fd = open(FilenameNew.c_str(), O_CREAT | O_WRONLY, 0644);
    CTX->FinalizeAOTIRCache(*ParentThread->Thread, fd, Loader.MainElfBase);
    std::filesystem::rename(FilenameNew.c_str(), Filename.c_str());
    fmt::print("Successfully populated cache {}\n", Filename);
    close(fd);
  }
}
