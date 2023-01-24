#include <common/GeneratorInterface.h>

#include <wayland-client.h>

template<auto>
struct fex_gen_config {
//    unsigned version = 2;
};

template<typename>
struct fex_gen_type {};

// Function, parameter index, parameter type [optional]
template<auto, int, typename = void>
struct fex_gen_param {};

template<> struct fex_gen_type<wl_display> : fexgen::opaque_type {};
template<> struct fex_gen_type<wl_proxy> : fexgen::opaque_type {};
template<> struct fex_gen_type<wl_interface> : fexgen::opaque_type, fexgen::customize {};
//template<> struct fex_gen_type<wl_argument> /*: fexgen::custom_repack*/ {};


template<> struct fex_gen_config<wl_display_connect> {};
template<> struct fex_gen_config<wl_display_roundtrip> {};
template<> struct fex_gen_config<wl_proxy_get_version> {};
template<> struct fex_gen_config<wl_proxy_add_listener> : fexgen::custom_guest_entrypoint {};
template<> struct fex_gen_param<wl_proxy_add_listener, 1, void(**)()> : fexgen::ptr_passthrough {};

//template<> struct fex_gen_config<wl_proxy_marshal_array_flags> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
template<> struct fex_gen_config<wl_proxy_marshal_array_flags> : fexgen::custom_host_impl {};
template<> struct fex_gen_param<wl_proxy_marshal_array_flags, 5, wl_argument*> : fexgen::ptr_passthrough {};

// Returns proxy->object.interface->methods[opcode].signature
const char* fex_wl_get_method_signature(wl_proxy *proxy, uint32_t opcode);
