#include <dlfcn.h>

#include <cstdio>
#include <cstdlib>

#include <chrono>
#include <thread>

thread_local int value = 5;

void mycall(void *data, struct wl_registry *registry,
            uint32_t name, const char *interface, uint32_t version) {
//printf("Hello from mycall: %d\n", value);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
printf("Hello from mycall: %d\n", value++);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
fputs("OMG\n", stderr);
}

int main() {
  value = 0;

  fprintf(stderr, "from main: %d\n", value++);

std::thread thr{
[]() {
fprintf(stderr, "from thread: %d\n", value++);
}
};
thr.join();
//exit(1);

  auto lib = dlopen("libfex_thunk_test.so.0", RTLD_LAZY);
  if (!lib) {
    printf("Failed to open lib\n");
    exit(1);
  }

  auto set = (void(*)(void(*)()))dlsym(lib, "SetAsyncCallback");
  fprintf(stderr, "Got callback: %p\n", set);
  set((void(*)())mycall);
  set((void(*)())mycall);
  set((void(*)())mycall);
  set((void(*)())mycall);
  set((void(*)())mycall);
  set((void(*)())mycall);

  {
    using namespace std::chrono_literals;
//    std::this_thread::sleep_for(2000ms);
  }
}
