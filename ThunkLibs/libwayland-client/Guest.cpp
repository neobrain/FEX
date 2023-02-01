/*
$info$
tags: thunklibs|wayland-client
$end_info$
*/

// Redefine these to strip away the "const"
#define WL_OUTPUT_INTERFACE
#define WL_SURFACE_INTERFACE
#define WL_SHM_POOL_INTERFACE
#define WL_POINTER_INTERFACE
#define WL_COMPOSITOR_INTERFACE
#define WL_SHM_INTERFACE
#define WL_REGISTRY_INTERFACE
#define WL_BUFFER_INTERFACE
#define WL_SEAT_INTERFACE
//struct wl_interface;
#include <wayland-util.h>

/*extern*/ wl_interface wl_output_interface{};
/*extern*/ wl_interface wl_shm_pool_interface{};
/*extern*/ wl_interface wl_pointer_interface{};
/*extern*/ wl_interface wl_compositor_interface{};
/*extern*/ wl_interface wl_shm_interface{};
/*extern*/ wl_interface wl_registry_interface{};
/*extern*/ wl_interface wl_buffer_interface{};
/*extern*/ wl_interface wl_seat_interface{};
// /*extern*/ wl_interface wl_surface_interface{ .name = "helloooo" };

//extern const wl_interface wl_surface_interface = []() {
//  loadlib();
//  fprintf(stderr, "wl_surface_interface %p %s\n", (void*)&wl_surface_interface, wl_surface_interface.name);
//  fprintf(stderr, "MYFANCE_interface %p\n", (void*)&MYFANCY_interface);
////  memset(&wl_surface_interface, 0, sizeof(wl_surface_interface));
////wl_surface_interface.name = nullptr; // TODO: Crashes... why?
//MYFANCY_interface.name = nullptr; // TODO: Crashes... why?
//  fprintf(stderr, "XX %d\n", __LINE__);
//  auto ret = fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_surface_interface), "wl_surface");
//  fprintf(stderr, "XX %d %s\n", __LINE__, ret->name);

////  return wl_surface_interface;
//  return wl_interface {.name=ret->name};
//}();
wl_interface wl_surface_interface;

//  return wl_interface {"nammemee"};
////  return wl_surface_interface;
////  return wl_interface {.name=ret->name};
//}();


#include <wayland-client.h>

#include <stdio.h>

#include <cstring>
#include <map>
#include <string>

#include "common/Guest.h"
#include <stdarg.h>

#include <array>
#include <thread>

#include <sys/mman.h>

#include "thunkgen_guest_libwayland-client.inl"

//extern wl_interface wl_output_interface;
//extern wl_interface wl_surface_interface;
//extern wl_interface wl_shm_pool_interface;
//extern wl_interface wl_pointer_interface;
//extern wl_interface wl_compositor_interface;
//extern wl_interface wl_shm_interface;
//extern wl_interface wl_registry_interface;
//extern wl_interface wl_buffer_interface;
//extern wl_interface wl_seat_interface;

void OnThunksLoaded();

struct OnStart {
  std::thread thr;

  OnStart() : thr([]() {
    struct { unsigned id = 1; } args;
    fexthunks_fex_register_async_worker_thread(&args);
  }) {}

  ~OnStart() {
    struct { unsigned id = 1; } args;
    fexthunks_fex_unregister_async_worker_thread(&args);
    thr.join();
  }
} on_start;

static void FexWLListener(void) {

}

struct wl_proxy_private {
  wl_interface* interface;
  // Other data members omitted
};

static std::array<void (*)(), 2> thecallback;

const wl_registry_listener glob_registry_listener = {
  +[](void* ptr, wl_registry* reg, uint32_t name, const char* interface, uint32_t version) {
    fprintf(stderr, "HELLOOOO: %p, %p %x, %s, %d\n", ptr, reg, name, interface, version);
  },
  +[](void*, wl_registry*, uint32_t name) {
    puts("HELLOOOO remove\n");
  },
};

extern "C" int wl_proxy_add_listener(struct wl_proxy *proxy,
      void (**callback)(void), void *data) {
//OnThunksLoaded();
//  glob_registry_listener.global = (decltype(glob_registry_listener.global))callback[0];
//  glob_registry_listener.global_remove = (decltype(glob_registry_listener.global_remove))callback[1];
  memcpy(thecallback.data(), callback, sizeof(thecallback));

  fprintf(stderr, "WAYLAND GUEST: %s with proxy %p, using interface %p\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface);

  static int lol = 0;
  ++lol;

  std::array<void*, 20> host_callbacks;
  // The signatures of entries in the "callback" function pointer table are specific
  // to each interface:
  // TODO: Dynamically determine func pointer types
  if (proxy == (wl_proxy*)&wl_registry_interface || lol == 1) {
    wl_registry_listener listener {
      AllocateHostTrampolineForGuestFunction((decltype(listener.global))callback[0]),
      AllocateHostTrampolineForGuestFunction((decltype(listener.global_remove))callback[1]),
  //    AllocateHostTrampolineForGuestFunction(glob_registry_listener.global),
  //    AllocateHostTrampolineForGuestFunction(glob_registry_listener.global_remove),
    };
    memcpy(host_callbacks.data(), &listener, sizeof(listener));
  } else if (proxy == (wl_proxy*)&wl_seat_interface || lol == 2) {
    wl_seat_listener listener {
      AllocateHostTrampolineForGuestFunction((decltype(listener.capabilities))callback[0]),
      AllocateHostTrampolineForGuestFunction((decltype(listener.name))callback[1]),
    };
    memcpy(host_callbacks.data(), &listener, sizeof(listener));
  } else {
    fprintf(stderr, "TODO: add_listener can only be called a limited number of times\n");
    std::abort();
  }

  return fexfn_pack_wl_proxy_add_listener(proxy, (void(**)())host_callbacks.data(), data);
}

struct argument_details {
        char type;
        int nullable;
};

// TODO: Must happen on host
static const char *
get_next_argument(const char *signature, argument_details *details)
{
        details->nullable = 0;
        for(; *signature; ++signature) {
                switch(*signature) {
                case 'i':
                case 'u':
                case 'f':
                case 's':
                case 'o':
                case 'n':
                case 'a':
                case 'h':
                        details->type = *signature;
                        return signature + 1;
                case '?':
                        details->nullable = 1;
                }
        }
        details->type = '\0';
        return signature;
}

static void wl_argument_from_va_list(const char *signature, wl_argument *args,
                                     int count, va_list ap) {
  int i;
  const char *sig_iter;
  argument_details arg;

  sig_iter = signature;
  for (i = 0; i < count; i++) {
    sig_iter = get_next_argument(sig_iter, &arg);

    switch (arg.type) {
    case 'i':
      args[i].i = va_arg(ap, int32_t);
      break;
    case 'u':
      args[i].u = va_arg(ap, uint32_t);
      break;
    case 'f':
      args[i].f = va_arg(ap, wl_fixed_t);
      break;
    case 's':
      args[i].s = va_arg(ap, const char *);
      break;
    case 'o':
      args[i].o = va_arg(ap, struct wl_object *);
      break;
    case 'n':
      args[i].o = va_arg(ap, struct wl_object *);
      break;
    case 'a':
      args[i].a = va_arg(ap, struct wl_array *);
      break;
    case 'h':
      args[i].h = va_arg(ap, int32_t);
      break;
    case '\0':
      return;
    }
  }
}

#define WL_CLOSURE_MAX_ARGS 20
extern "C" wl_proxy *wl_proxy_marshal_flags(wl_proxy *proxy, uint32_t opcode,
           const wl_interface *interface,
           uint32_t version,
           uint32_t flags, ...) {

// TODO: Move this somewhere else
static bool inited = false;
if (!inited) {
  OnThunksLoaded();
  inited = true;
}

  fprintf(stderr, "WAYLAND GUEST: %s with proxy %p, using interface %s\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface->name);

  wl_argument args[WL_CLOSURE_MAX_ARGS];
  va_list ap;

  va_start(ap, flags);
  // TODO: Must extract signature from host due to different data layout on 32-bit!
  wl_argument_from_va_list(((wl_proxy_private*)proxy)->interface->methods[opcode].signature,
                           args, WL_CLOSURE_MAX_ARGS, ap);
  va_end(ap);

  return wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags, args);

}

extern "C" int wl_display_dispatch(wl_display *display) {
  fprintf(stderr, "TODO: %s\n", __FUNCTION__);
  std::abort();
}

//wl_interface* fex_wl_exchange_interface_pointer(wl_interface* interface, const char* name) {
//  auto rodata_begin = reinterpret_cast<uintptr_t>(&wl_surface_interface) & ~uintptr_t { 0xfff };

//  if (0 != mprotect((void*)rodata_begin, 0x1000, PROT_READ | PROT_WRITE)) {
//    fprintf(stderr, "ERRORXX: %s\n", strerror(errno));
//  }

//  fex_wl_exchange_interface_pointer(interface, name);

//  mprotect((void*)rodata_begin, 0x1000, PROT_READ);
//}

// TODO: Must run after LOAD_LIB *and* after setting up global variables
void OnThunksLoaded() {
  fex_wl_exchange_interface_pointer(&wl_output_interface, "wl_output");
  fex_wl_exchange_interface_pointer(&wl_shm_pool_interface, "wl_shm_pool");
  fex_wl_exchange_interface_pointer(&wl_pointer_interface, "wl_pointer");
  fex_wl_exchange_interface_pointer(&wl_compositor_interface, "wl_compositor");
  fex_wl_exchange_interface_pointer(&wl_shm_interface, "wl_shm");
  fex_wl_exchange_interface_pointer(&wl_registry_interface, "wl_registry");
  fex_wl_exchange_interface_pointer(&wl_buffer_interface, "wl_buffer");
  fex_wl_exchange_interface_pointer(&wl_seat_interface, "wl_seat");

  fprintf(stderr, "Proxy wl_output_interface: %p\n", (void*)&wl_output_interface);
  fprintf(stderr, "Proxy wl_surface_interface: %p\n", (void*)&wl_surface_interface);
  fprintf(stderr, "Proxy wl_shm_pool_interface: %p\n", (void*)&wl_shm_pool_interface);
  fprintf(stderr, "Proxy wl_pointer_interface: %p\n", (void*)&wl_pointer_interface);
  fprintf(stderr, "Proxy wl_compositor_interface: %p\n", (void*)&wl_compositor_interface);
  fprintf(stderr, "Proxy wl_shm_interface: %p\n", (void*)&wl_shm_interface);
  fprintf(stderr, "Proxy wl_registry_interface: %p\n", (void*)&wl_registry_interface);
  fprintf(stderr, "Proxy wl_buffer_interface: %p\n", (void*)&wl_buffer_interface);
  fprintf(stderr, "Proxy wl_seat_interface: %p\n", (void*)&wl_seat_interface);

}

//LOAD_LIB_INIT(libwayland-client, OnThunksLoaded)
LOAD_LIB(libwayland-client)
