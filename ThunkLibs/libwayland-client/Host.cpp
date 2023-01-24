/*
$info$
tags: thunklibs|wayland-client
$end_info$
*/

#include <wayland-client.h>

#include <stdio.h>

#include "common/Host.h"
#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cstring>

#include "thunkgen_host_libwayland-client.inl"

// Maps guest interface pointers to host pointers
wl_interface* lookup_wl_interface(const wl_interface* interface) {
fprintf(stderr, "TODO: map wayland interfaces\n");
  fprintf(stderr, "WAYLAND GUEST: %s using interface %p\n", __FUNCTION__, interface);
  auto wl_output_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_output_interface");
  auto wl_surface_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_surface_interface");
  auto wl_shm_pool_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_shm_pool_interface");
  auto wl_pointer_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_pointer_interface");
  auto wl_compositor_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_compositor_interface");
  auto wl_shm_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_shm_interface");
  auto wl_registry_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_registry_interface");
  auto wl_buffer_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_buffer_interface");
  auto wl_seat_interface = dlsym(fexldr_ptr_libwayland_client_so, "wl_seat_interface");
  if (interface != wl_output_interface &&
      interface != wl_surface_interface &&
      interface != wl_shm_pool_interface &&
      interface != wl_pointer_interface &&
      interface != wl_compositor_interface &&
      interface != wl_shm_interface &&
      interface != wl_registry_interface &&
      interface != wl_buffer_interface &&
      interface != wl_seat_interface) {
      static int lol = 0;
      lol++;
    if (lol == 1) {
      return reinterpret_cast<wl_interface*>(wl_registry_interface);
    }
    fprintf(stderr, "Unknown wayland interface %p. Need to map from guest?\n", interface);
    std::abort();
  }

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
  interface = lookup_wl_interface(interface);
#define WL_CLOSURE_MAX_ARGS 20
  std::array<wl_argument, WL_CLOSURE_MAX_ARGS> host_args;
  for (int i = 0; i < host_args.size(); ++i) {
    std::memcpy(&host_args[i], &args[i], sizeof(args[i]));
  }
  return fexldr_ptr_libwayland_client_wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags, host_args.data());
}

EXPORTS(libwayland_client)
