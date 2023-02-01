/*
$info$
tags: thunklibs|wayland-client
$end_info$
*/

#include <wayland-client.h>

#include <stdio.h>

#include "common/Host.h"
#include <dlfcn.h>

#include <sys/mman.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <map>

#include "thunkgen_host_libwayland-client.inl"

// Maps guest interface to host_interfaces
static std::map<void*, wl_interface*> guest_to_host_interface;

struct wl_proxy_private {
  wl_interface* interface;
  // Other data members omitted
};

// Maps guest interface pointers to host pointers
wl_interface* lookup_wl_interface(const wl_interface* interface) {
  fprintf(stderr, "WAYLAND HOST: %s using interface %p\n", __FUNCTION__, interface);

  for (auto& interface_mapping : guest_to_host_interface) {
    if (interface_mapping.first == interface) {
      fprintf(stderr, "HOST Proxy %s_interface: %p (<- %p on guest)\n", interface_mapping.second->name, (void*)interface_mapping.second, interface_mapping.first);
    }
  }
  if (!guest_to_host_interface.count((void*)interface)) {
      static int lol = 0;
      lol++;
//    if (lol == 1) {
//      return reinterpret_cast<wl_interface*>(wl_registry_interface);
//    }
    fprintf(stderr, "Unknown wayland interface %p. Need to map from guest?\n", interface);
    std::abort();
  }

  return guest_to_host_interface.at((void*)interface);

//  fprintf(stderr, "Proxy wl_output_interface: %p\n", (void*)&wl_output_interface);
//  fprintf(stderr, "Proxy wl_surface_interface: %p\n", (void*)&wl_surface_interface);
//  fprintf(stderr, "Proxy wl_shm_pool_interface: %p\n", (void*)&wl_shm_pool_interface);
//  fprintf(stderr, "Proxy wl_pointer_interface: %p\n", (void*)&wl_pointer_interface);
//  fprintf(stderr, "Proxy wl_compositor_interface: %p\n", (void*)&wl_compositor_interface);
//  fprintf(stderr, "Proxy wl_shm_interface: %p\n", (void*)&wl_shm_interface);
//  fprintf(stderr, "Proxy wl_registry_interface: %p\n", (void*)&wl_registry_interface);
//  fprintf(stderr, "Proxy wl_buffer_interface: %p\n", (void*)&wl_buffer_interface);
//  fprintf(stderr, "Proxy wl_seat_interface: %p\n", (void*)&wl_seat_interface);


    // TODO: Properly look up interfaces
    return const_cast<wl_interface*>(interface);
}

// Specialization for pointers to opaque types
//template<>
//struct unpacked_arg<wl_interface*> {
//  unpacked_arg(/*const */guest_layout<wl_interface*>& data_) : data(reinterpret_cast<host_layout<wl_interface>*>(data_.get_pointer())) {
//  }

//  wl_interface* get() {
//    static_assert(sizeof(wl_interface) == sizeof(host_layout<wl_interface>));
//    static_assert(alignof(wl_interface) == alignof(host_layout<wl_interface>));
//    return reinterpret_cast<wl_interface*>(data);
//  }

//  host_layout<wl_interface>* data;
//};

extern "C" wl_proxy*
fexfn_impl_libwayland_client_wl_proxy_marshal_array_flags(
            wl_proxy *proxy, uint32_t opcode,
            const wl_interface *interface,
            uint32_t version, uint32_t flags,
            guest_layout<wl_argument> *args) {
  auto wl_registry_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_registry_interface");
  if (((wl_proxy_private*)proxy)->interface == wl_registry_interface) {
    // TODO: How to handle already existing interfaces? Should we copy the data back to guest?
    auto& host_interface = guest_to_host_interface[(void*)interface];
    if (!host_interface) {
      host_interface = new wl_interface;
      memcpy(host_interface, interface, sizeof(wl_interface));
    }
    fprintf(stderr, "HOST: wl_registry_bind for guest interface %s (%p -> %p)\n", interface->name, interface, host_interface);
  }

  interface = lookup_wl_interface(interface);
#define WL_CLOSURE_MAX_ARGS 20
  std::array<wl_argument, WL_CLOSURE_MAX_ARGS> host_args;
  for (int i = 0; i < host_args.size(); ++i) {
    std::memcpy(&host_args[i], &args[i], sizeof(args[i]));
  }

  return fexldr_ptr_libwayland_client_wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags, host_args.data());
}

extern "C" int fexfn_impl_libwayland_client_wl_proxy_add_listener(struct wl_proxy *proxy,
      void (**callback)(void), void *data) {
//  fprintf(stderr, "wayland host: add_listener\n");
  fprintf(stderr, "WAYLAND HOST: %s with proxy %p, using interface %p\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface);

  auto wl_output_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_output_interface");
  auto wl_surface_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_surface_interface");
  auto wl_shm_pool_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_shm_pool_interface");
  auto wl_pointer_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_pointer_interface");
  auto wl_compositor_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_compositor_interface");
  auto wl_shm_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_shm_interface");
  auto wl_registry_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_registry_interface");
  auto wl_buffer_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_buffer_interface");
  auto wl_seat_interface = (wl_interface*)dlsym(fexldr_ptr_libwayland_client_so, "wl_seat_interface");

  if (((wl_proxy_private*)proxy)->interface == wl_registry_interface) {
    wl_registry_listener registry_listener {
      (decltype(wl_registry_listener::global))callback[0],
      (decltype(wl_registry_listener::global_remove))callback[1],
    };
    FinalizeHostTrampolineForGuestFunction(registry_listener.global);
    MakeHostTrampolineForGuestFunctionAsyncCallable(registry_listener.global, 1);
    FinalizeHostTrampolineForGuestFunction(registry_listener.global);
    MakeHostTrampolineForGuestFunctionAsyncCallable(registry_listener.global_remove, 1);
//    wl_registry_listener registry_listener;
//    MakeHostTrampolineForGuestFunctionAt(reinterpret_cast<uintptr_t>(callback[0]), GUESTUNPACKER, &registry_listener.global),
//    MakeHostTrampolineForGuestFunctionAt(reinterpret_cast<uintptr_t>(callback[1]), GUESTUNPACKER, &registry_listener.global_remove),
//    MakeHostTrampolineForGuestFunctionAsyncCallable(registry_listener.global, 1);
//    MakeHostTrampolineForGuestFunctionAsyncCallable(registry_listener.global_remove, 1);
  } else if (((wl_proxy_private*)proxy)->interface == (wl_interface*)wl_seat_interface) {
    wl_seat_listener listener {
      (decltype(listener.capabilities))callback[0],
      (decltype(listener.name))callback[1],
    };
    FinalizeHostTrampolineForGuestFunction(listener.capabilities);
    MakeHostTrampolineForGuestFunctionAsyncCallable(listener.capabilities, 1);
    FinalizeHostTrampolineForGuestFunction(listener.name);
    MakeHostTrampolineForGuestFunctionAsyncCallable(listener.name, 1);
  } else {
    fprintf(stderr, "TODO: Unhandled interface %s for add_listener (proxy %p)\n", ((wl_proxy_private*)proxy)->interface->name, proxy);
    std::abort();
  }

  // Pass the original function pointer table to the host wayland library. This ensures the table is valid until the listener is unregistered.
  return fexldr_ptr_libwayland_client_wl_proxy_add_listener(proxy, callback, data);
}

#include <mutex>

static std::once_flag interfaces_setup;

void fexfn_impl_libwayland_client_fex_wl_exchange_interface_pointer2() {
return;
}

wl_interface* fexfn_impl_libwayland_client_fex_wl_exchange_interface_pointer(wl_interface* guest_interface, char const* name) {
  auto& host_interface = guest_to_host_interface[(void*)guest_interface];
  host_interface = reinterpret_cast<wl_interface*>(dlsym(fexldr_ptr_libwayland_client_so, (std::string { name } + "_interface").c_str()));
  if (!host_interface) {
    fprintf(stderr, "Could not find host interface corresponding to %p (%s)\n", guest_interface, name);
    std::abort();
  }

  // Wayland-client declares interface pointers as `const`, which makes LD put
  // them into the rodata section of the application itself instead of the
  // library. To copy the host information to them on startup, we must
  // temporarily disable write-protection on this data hence.
  auto page_begin = reinterpret_cast<uintptr_t>(guest_interface) & ~uintptr_t { 0xfff };
  if (0 != mprotect((void*)page_begin, 0x1000, PROT_READ | PROT_WRITE)) {
    fprintf(stderr, "ERROR: %s\n", strerror(errno));
    std::abort();
  }

#ifdef IS_32BIT_THUNK
//  #error Implement opt-in struct repacking for wl_interface
    std::abort();
#else
  memcpy(guest_interface, host_interface, sizeof(wl_interface));
#endif

  mprotect((void*)page_begin, 0x1000, PROT_READ);

  return host_interface;
}

EXPORTS(libwayland_client)
