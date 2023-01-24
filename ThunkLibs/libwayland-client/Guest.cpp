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
/*extern*/ wl_interface wl_output_interface;
/*extern*/ wl_interface wl_surface_interface;
/*extern*/ wl_interface wl_shm_pool_interface;
/*extern*/ wl_interface wl_pointer_interface;
/*extern*/ wl_interface wl_compositor_interface;
/*extern*/ wl_interface wl_shm_interface;
/*extern*/ wl_interface wl_registry_interface;
/*extern*/ wl_interface wl_buffer_interface;
/*extern*/ wl_interface wl_seat_interface;

#include <wayland-client.h>

#include <stdio.h>
#include <cstring>
#include <map>
#include <string>

#include "common/Guest.h"
#include <stdarg.h>

#include <array>

#include "thunkgen_guest_libwayland-client.inl"

extern wl_interface wl_output_interface;
extern wl_interface wl_surface_interface;
extern wl_interface wl_shm_pool_interface;
extern wl_interface wl_pointer_interface;
extern wl_interface wl_compositor_interface;
extern wl_interface wl_shm_interface;
extern wl_interface wl_registry_interface;
extern wl_interface wl_buffer_interface;
extern wl_interface wl_seat_interface;

static void FexWLListener(void) {

}

struct wl_proxy_private {
  wl_interface* interface;
  // Other data members omitted
};

static std::array<void (*)(), 2> thecallback;

const wl_registry_listener glob_registry_listener = {
  +[](void*, wl_registry*, uint32_t name, const char* interface, uint32_t version) {
    puts("HELLOOOO\n");
  },
  +[](void*, wl_registry*, uint32_t name) {
    puts("HELLOOOO remove\n");
  },
};

extern "C" int wl_proxy_add_listener(struct wl_proxy *proxy,
      void (**callback)(void), void *data) {
//  glob_registry_listener.global = (decltype(glob_registry_listener.global))callback[0];
//  glob_registry_listener.global_remove = (decltype(glob_registry_listener.global_remove))callback[1];
  memcpy(thecallback.data(), callback, sizeof(thecallback));

  fprintf(stderr, "WAYLAND GUEST: %s with proxy %p, using interface %p\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface);
  fexfn_pack_wl_proxy_add_listener(proxy, (void(**)())&glob_registry_listener, data);
//  std::abort();
  return 0;
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
  fprintf(stderr, "WAYLAND GUEST: %s with proxy %p, using interface %p\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface);

  wl_argument args[WL_CLOSURE_MAX_ARGS];
  va_list ap;

  va_start(ap, flags);
  // TODO: Must extract signature from host!
  wl_argument_from_va_list(((wl_proxy_private*)proxy)->interface->methods[opcode].signature,
                           args, WL_CLOSURE_MAX_ARGS, ap);
  va_end(ap);


//  wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags);
  fprintf(stderr, "WAYLAND GUEST: %s with proxy %p, using interface %p\n", __FUNCTION__, proxy, ((wl_proxy_private*)proxy)->interface);
  fprintf(stderr, "Proxy wl_output_interface: %p\n", (void*)&wl_output_interface);
  fprintf(stderr, "Proxy wl_surface_interface: %p\n", (void*)&wl_surface_interface);
  fprintf(stderr, "Proxy wl_shm_pool_interface: %p\n", (void*)&wl_shm_pool_interface);
  fprintf(stderr, "Proxy wl_pointer_interface: %p\n", (void*)&wl_pointer_interface);
  fprintf(stderr, "Proxy wl_compositor_interface: %p\n", (void*)&wl_compositor_interface);
  fprintf(stderr, "Proxy wl_shm_interface: %p\n", (void*)&wl_shm_interface);
  fprintf(stderr, "Proxy wl_registry_interface: %p\n", (void*)&wl_registry_interface);
  fprintf(stderr, "Proxy wl_buffer_interface: %p\n", (void*)&wl_buffer_interface);
  fprintf(stderr, "Proxy wl_seat_interface: %p\n", (void*)&wl_seat_interface);
//  std::abort();

  return wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags, args);

}

extern "C" int wl_display_dispatch(wl_display *display) {
  fprintf(stderr, "TODO: %s\n", __FUNCTION__);
  std::abort();
}

//extern "C" int wl_display_roundtrip(wl_display *display) {
//  fprintf(stderr, "TODO: %s\n", __FUNCTION__);
//  std::abort();
//}

LOAD_LIB(libwayland-client)
