/*
$info$
tags: LinuxSyscalls|common
desc: Rootfs overlay logic
$end_info$
*/

#include "Tests/LinuxSyscalls/FileManagement.h"
#include "Tests/LinuxSyscalls/Syscalls.h"

#include <FEXCore/Utils/LogManager.h>
#include <cstring>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <tiny-json.h>

#include <fstream>
#include <filesystem>

namespace FEX::HLE {

static bool LoadFile(std::vector<char> &Data, const std::string &Filename) {
  std::fstream File(Filename, std::ios::in);

  if (!File.is_open()) {
    return false;
  }

  if (!File.seekg(0, std::fstream::end)) {
    LogMan::Msg::DFmt("Couldn't load configuration file: Seek end");
    return false;
  }

  auto FileSize = File.tellg();
  if (File.fail()) {
    LogMan::Msg::DFmt("Couldn't load configuration file: tellg");
    return false;
  }

  if (!File.seekg(0, std::fstream::beg)) {
    LogMan::Msg::DFmt("Couldn't load configuration file: Seek beginning");
    return false;
  }

  if (FileSize <= 0) {
    LogMan::Msg::DFmt("FileSize less than or equal to zero specified");
    return false;
  }

  Data.resize(FileSize);
  if (!File.read(Data.data(), FileSize)) {
    // Probably means permissions aren't set. Just early exit
    return false;
  }
  return true;
}

FileManager::FileManager(FEXCore::Context::Context *ctx)
  : EmuFD {ctx} {
  
  auto ThunkConfigFile = ThunkConfig();

  if (ThunkConfigFile.size()) {

    auto ThunkGuestPath = std::filesystem::path(ThunkGuestLibs());

    std::vector<char> FileData;
    if (LoadFile(FileData, ThunkConfigFile)) {
      FileData.push_back(0);

      json_t mem[128];
      json_t const* json = json_create( &FileData.at(0), mem, sizeof mem / sizeof *mem );

      json_t const* thunks = json_getProperty( json, "thunks" );
      if ( !thunks || JSON_OBJ != json_getType( thunks ) ) {
        return;
      }

      json_t const* thunk;
      for( thunk = json_getChild( thunks ); thunk != 0; thunk = json_getSibling( thunk )) {
        char const* GuestThunk = json_getName( thunk );
        jsonType_t propertyType = json_getType( thunk );

        if (propertyType == JSON_TEXT) {
          char const* RootFSLib = json_getValue( thunk );
          ThunkOverlays.emplace(RootFSLib, ThunkGuestPath / GuestThunk);
        } else if (propertyType == JSON_ARRAY) {
          json_t const* child;
          for( child = json_getChild( thunk ); child != 0; child = json_getSibling( child ) ) {
            if (json_getType( child ) == JSON_TEXT) {
              char const* RootFSLib = json_getValue( child );
              ThunkOverlays.emplace(RootFSLib, ThunkGuestPath / GuestThunk);
            }
          }
        }
      }
    }

    if (ThunkOverlays.size()) {
      LogMan::Msg::I("Thunk Overlays:");
      for (auto &Thunk: ThunkOverlays) {
        LogMan::Msg::I("\t%s -> %s", Thunk.first.c_str(), Thunk.second.c_str());
      }
    }
  }
}

FileManager::~FileManager() {
}

std::string FileManager::GetEmulatedPath(const char *pathname, bool FollowSymlink) {
  auto RootFSPath = LDPath();
  if (!pathname ||
      pathname[0] != '/' ||
      RootFSPath.empty()) {
    return {};
  }

  auto thunkOverlay = ThunkOverlays.find(pathname);
  if (thunkOverlay != ThunkOverlays.end()) {
    return thunkOverlay->second;
  }

  std::string Path = RootFSPath + pathname;
  if (FollowSymlink) {
    std::error_code ec;
    while(std::filesystem::is_symlink(Path, ec)) {
      auto SymlinkTarget = std::filesystem::read_symlink(Path);
      if (SymlinkTarget.is_absolute()) {
        Path = RootFSPath + SymlinkTarget.string();
      }
      else {
        break;
      }
    }
  }
  return Path;
}


std::optional<std::string> FileManager::GetSelf(const char *Pathname) {
  if (!Pathname) {
    return std::nullopt;
  }

  int pid = getpid();

  char PidSelfPath[50];
  snprintf(PidSelfPath, 50, "/proc/%i/exe", pid);

  if (strcmp(Pathname, "/proc/self/exe") == 0 ||
      strcmp(Pathname, "/proc/thread-self/exe") == 0 ||
      strcmp(Pathname, PidSelfPath) == 0) {
    return Filename();
  }

  return Pathname;
}

uint64_t FileManager::Open(const char *pathname, [[maybe_unused]] int flags, [[maybe_unused]] uint32_t mode) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;
  return ::open(SelfPath, flags, mode);
}

uint64_t FileManager::Close(int fd) {
  {
    std::lock_guard<std::mutex> lk(FDLock);
    FDToNameMap.erase(fd);
  }
  return ::close(fd);
}

uint64_t FileManager::CloseRange(unsigned int first, unsigned int last, unsigned int flags) {
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

  if (!(flags & CLOSE_RANGE_CLOEXEC)) {
    // If the flag was set then it doesn't actually close the FDs
    // Just sets the flag on a range
    std::lock_guard<std::mutex> lk(FDLock);
    for (unsigned int i = first; i <= last; ++i) {
      // We remove from first to last inclusive
      FDToNameMap.erase(i);
    }
  }
  return ::syscall(SYS_close_range, first, last, flags);
}

uint64_t FileManager::Stat(const char *pathname, void *buf) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::stat(Path.c_str(), reinterpret_cast<struct stat*>(buf));
    if (Result != -1)
      return Result;
  }
  return ::stat(SelfPath, reinterpret_cast<struct stat*>(buf));
}

uint64_t FileManager::Lstat(const char *pathname, void *buf) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::lstat(Path.c_str(), reinterpret_cast<struct stat*>(buf));
    if (Result != -1)
      return Result;
  }

  return ::lstat(SelfPath, reinterpret_cast<struct stat*>(buf));
}

uint64_t FileManager::Access(const char *pathname, [[maybe_unused]] int mode) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::access(Path.c_str(), mode);
    if (Result != -1)
      return Result;
  }

  return ::access(SelfPath, mode);
}

uint64_t FileManager::FAccessat(int dirfd, const char *pathname, int mode) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::syscall(SYS_faccessat, dirfd, Path.c_str(), mode);
    if (Result != -1)
      return Result;
  }

  return ::syscall(SYS_faccessat, dirfd, SelfPath, mode);
}

uint64_t FileManager::FAccessat2(int dirfd, const char *pathname, int mode, int flags) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

#ifndef SYS_faccessat2
  const uint32_t SYS_faccessat2 = 439;
#endif
  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::syscall(SYS_faccessat2, dirfd, Path.c_str(), mode, flags);
    if (Result != -1)
      return Result;
  }

  return ::syscall(SYS_faccessat2, dirfd, SelfPath, mode, flags);
}

uint64_t FileManager::Readlink(const char *pathname, char *buf, size_t bufsiz) {
  // calculate the non-self link to exe
  // Some executables do getpid, stat("/proc/$pid/exe")
  int pid = getpid();

  char PidSelfPath[50];
  snprintf(PidSelfPath, 50, "/proc/%i/exe", pid);

  if (strcmp(pathname, "/proc/self/exe") == 0 ||
      strcmp(pathname, "/proc/thread-self/exe") == 0 ||
      strcmp(pathname, PidSelfPath) == 0) {
    auto App = Filename();
    strncpy(buf, App.c_str(), bufsiz);
    return std::min(bufsiz, App.size());
  }

  auto Path = GetEmulatedPath(pathname);
  if (!Path.empty()) {
    uint64_t Result = ::readlink(Path.c_str(), buf, bufsiz);
    if (Result != -1)
      return Result;

    if (Result == -1 &&
        errno == EINVAL) {
      // This means that the file wasn't a symlink
      // This is expected behaviour
      return -errno;
    }
  }

  return ::readlink(pathname, buf, bufsiz);
}

uint64_t FileManager::Chmod(const char *pathname, mode_t mode) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::chmod(Path.c_str(), mode);
    if (Result != -1)
      return Result;
  }

  return ::chmod(SelfPath, mode);
}

uint64_t FileManager::Readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
  // calculate the non-self link to exe
  // Some executables do getpid, stat("/proc/$pid/exe")
  // Can't use `GetSelf` directly here since readlink{at,} returns EINVAL if it isn't a symlink
  // Self is always a symlink and isn't expected to fail
  int pid = getpid();

  char PidSelfPath[50];
  snprintf(PidSelfPath, 50, "/proc/%i/exe", pid);

  if (strcmp(pathname, "/proc/self/exe") == 0 ||
      strcmp(pathname, "/proc/thread-self/exe") == 0 ||
      strcmp(pathname, PidSelfPath) == 0) {
    auto App = Filename();
    strncpy(buf, App.c_str(), bufsiz);
    return std::min(bufsiz, App.size());
  }

  auto Path = GetEmulatedPath(pathname);
  if (!Path.empty()) {
    uint64_t Result = ::readlinkat(dirfd, Path.c_str(), buf, bufsiz);
    if (Result != -1)
      return Result;

    if (Result == -1 &&
        errno == EINVAL) {
      // This means that the file wasn't a symlink
      // This is expected behaviour
      return -errno;
    }
  }

  return ::readlinkat(dirfd, pathname, buf, bufsiz);
}

uint64_t FileManager::Openat([[maybe_unused]] int dirfs, const char *pathname, int flags, uint32_t mode) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  int32_t fd = -1;

  fd = EmuFD.OpenAt(dirfs, SelfPath, flags, mode);
  if (fd == -1) {
    auto Path = GetEmulatedPath(SelfPath, true);
    if (!Path.empty()) {
      fd = ::openat(dirfs, Path.c_str(), flags, mode);
    }

    if (fd == -1)
      fd = ::openat(dirfs, SelfPath, flags, mode);
  }

  if (fd != -1) {
    std::lock_guard lk(FDLock);
    FDToNameMap.insert_or_assign(fd, SelfPath);
  }

  return fd;
}

uint64_t FileManager::Openat2(int dirfs, const char *pathname, FEX::HLE::open_how *how, size_t usize) {
#ifndef SYS_openat2
#define SYS_openat2 437
#endif

  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  int32_t fd = -1;

  fd = EmuFD.OpenAt(dirfs, SelfPath, how->flags, how->mode);
  if (fd == -1) {
    auto Path = GetEmulatedPath(SelfPath, true);
    if (!Path.empty()) {
      fd = ::syscall(SYS_openat2, dirfs, Path.c_str(), how, usize);
    }

    if (fd == -1)
      fd = ::syscall(SYS_openat2, dirfs, SelfPath, how, usize);
  }

  if (fd != -1) {
    std::lock_guard lk(FDLock);
    FDToNameMap.insert_or_assign(fd, SelfPath);
  }

  return fd;

}

uint64_t FileManager::Statx(int dirfd, const char *pathname, int flags, uint32_t mask, struct statx *statxbuf) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::statx(dirfd, Path.c_str(), flags, mask, statxbuf);
    if (Result != -1)
      return Result;
  }
  return ::statx(dirfd, SelfPath, flags, mask, statxbuf);
}

uint64_t FileManager::Mknod(const char *pathname, mode_t mode, dev_t dev) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::mknod(Path.c_str(), mode, dev);
    if (Result != -1)
      return Result;
  }
  return ::mknod(SelfPath, mode, dev);
}

uint64_t FileManager::Statfs(const char *path, void *buf) {
  auto Path = GetEmulatedPath(path);
  if (!Path.empty()) {
    uint64_t Result = ::statfs(Path.c_str(), reinterpret_cast<struct statfs*>(buf));
    if (Result != -1)
      return Result;
  }
  return ::statfs(path, reinterpret_cast<struct statfs*>(buf));
}

uint64_t FileManager::NewFSStatAt(int dirfd, const char *pathname, struct stat *buf, int flag) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::fstatat(dirfd, Path.c_str(), buf, flag);
    if (Result != -1) {
      return Result;
    }
  }
  return ::fstatat(dirfd, SelfPath, buf, flag);
}

uint64_t FileManager::NewFSStatAt64(int dirfd, const char *pathname, struct stat64 *buf, int flag) {
  auto NewPath = GetSelf(pathname);
  const char *SelfPath = NewPath ? NewPath->c_str() : nullptr;

  auto Path = GetEmulatedPath(SelfPath);
  if (!Path.empty()) {
    uint64_t Result = ::fstatat64(dirfd, Path.c_str(), buf, flag);
    if (Result != -1) {
      return Result;
    }
  }
  return ::fstatat64(dirfd, SelfPath, buf, flag);
}

std::string *FileManager::FindFDName(int fd) {
  std::lock_guard<std::mutex> lk(FDLock);
  auto it = FDToNameMap.find(fd);
  if (it == FDToNameMap.end()) {
    return nullptr;
  }
  return &it->second;
}

}
