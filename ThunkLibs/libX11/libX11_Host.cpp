/*
$info$
tags: thunklibs|X11
desc: Handles callbacks and varargs
$end_info$
*/

#include <stdio.h>
#include <type_traits>
#include <utility>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xresource.h>
#include "common/Host.h"
#include <dlfcn.h>

#include "callback_structs.inl"
#include "callback_typedefs.inl"

struct CALLBACK_UNPACKS {
    #include "callback_unpacks_header.inl"
} *callback_unpacks;

#include "ldr_ptrs.inl"

_XIC *fexfn_impl_libX11_XCreateIC_internal(XIM a_0, size_t count, unsigned long *list) {
    switch(count) {
        case 0: return fexldr_ptr_libX11_XCreateIC(a_0, nullptr); break;
        case 1: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], nullptr); break;
        case 2: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], nullptr); break;
        case 3: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], nullptr); break;
        case 4: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], nullptr); break;
        case 5: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
        case 6: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
        case 7: return fexldr_ptr_libX11_XCreateIC(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
        default:
        printf("XCreateIC_internal FAILURE\n");
        return nullptr;
    }
}

static char ErrorReply[] = "FEX: Unable to match arg count";

char* fexfn_impl_libX11_XGetICValues_internal(XIC a_0, size_t count, unsigned long *list) {
    switch(count) {
        case 0: return fexldr_ptr_libX11_XGetICValues(a_0, nullptr); break;
        case 1: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], nullptr); break;
        case 2: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], nullptr); break;
        case 3: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], nullptr); break;
        case 4: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], nullptr); break;
        case 5: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], nullptr); break;
        case 6: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], nullptr); break;
        case 7: return fexldr_ptr_libX11_XGetICValues(a_0, list[0], list[1], list[2], list[3], list[4], list[5], list[6], nullptr); break;
        default:
        printf("XCreateIC_internal FAILURE\n");
        return ErrorReply;
    }
}

//struct XIfEventCB_args {
//    XIfEventCBFN *fn;
//    XPointer arg;
//};

//static int XIfEventCB(Display* a0, XEvent* a1, XPointer a2) {

//    XIfEventCB_args *arg = (XIfEventCB_args*)a2;

//    XIfEventCB_Args argsrv { a0, a1, arg->arg};

//    call_guest(callback_unpacks->libX11_XIfEventCB, (void*) arg->fn, &argsrv);
    
//    return argsrv.rv;
//}

template<typename Arg, typename... GuestCB>
struct WrappedCBArgs;

template<typename T>
struct lowered { using type = T; };
template<typename Arg, typename... GuestCB>
struct lowered<WrappedCBArgs<Arg, GuestCB...>*> { using type = Arg; };

template<typename T>
constexpr T lower(const T& t) {
    static_assert(std::is_trivially_copyable_v<T>);
    return t;
}

template<typename Arg, typename... GuestCBs>
constexpr Arg lower(WrappedCBArgs<Arg, GuestCBs...>* args) {
    return args->guest_arg;
}

template<typename T, typename... Args>
constexpr T& Get(Args&... arg) {
    T* t;
    (void)((std::is_same_v<T, Args> ? (t = (T*)&arg, true) : false) || ...);
    return *t;
}

template<typename GuestCB, std::size_t Idx>
struct CBInternalArgsBaseBase {
    GuestCB guest_cb;

    // Getter with compile-time constant parameter to allow for
    // distinguishing overloaded member functions in the child class
    GuestCB get(std::integral_constant<std::size_t, Idx>) {
        return guest_cb;
    }
};

template<typename Idxs, typename... GuestCB>
struct CBInternalArgsBase;

template<std::size_t... Idxs, typename... GuestCBs>
struct CBInternalArgsBase<std::integer_sequence<std::size_t, Idxs...>, GuestCBs...>
        : CBInternalArgsBaseBase<GuestCBs, Idxs>... {
    CBInternalArgsBase(GuestCBs... cbs) : CBInternalArgsBaseBase<GuestCBs, Idxs> { cbs }... {
    }

    using CBInternalArgsBaseBase<GuestCBs, Idxs>::get...;
};

template<typename GuestArg, typename... GuestCBs>
struct WrappedCBArgs : CBInternalArgsBase<std::index_sequence_for<GuestCBs...>, GuestCBs...> {
    WrappedCBArgs(GuestArg guest_arg_, GuestCBs... cbs)
        : CBInternalArgsBase<std::index_sequence_for<GuestCBs...>, GuestCBs...>(cbs...),
          guest_arg(guest_arg_) {

    }

    template<std::size_t Idx>
    constexpr auto GetCB() {
        return this->get(std::integral_constant<std::size_t, 0>{});
    }

    GuestArg guest_arg;
};

template<std::size_t CBIdx,
         auto& UnpackerTable, auto Unpacker, typename ArgsStruct,
         typename... HostArgs, typename GuestArg, typename... GuestCBs>
constexpr auto wrap_guest_callback(WrappedCBArgs<GuestArg, GuestCBs...>& wrapped_args) {
    static_assert((std::is_same_v<HostArgs, decltype(&wrapped_args)> || ...),
                  "One of the parameters of the wrapped callback must be WrappedCBArgs to indicate where to store the wrapped arguments");

    // The signature of the wrapped callback replaces the guest-provided
    // parameter with a CBInternalArgs pointer containing the original argument
    // and callbacks. This lambda unwraps the indirection and calls the
    // guest-provided callback with the guest-provided arguments.
    return +[](decltype(lower(std::declval<HostArgs>()))... args) -> decltype(ArgsStruct::rv) {
        auto guest_cb = Get<decltype(&wrapped_args)>(*(HostArgs*)&args...)->template GetCB<CBIdx>();

        ArgsStruct argsrv { lower(args)..., {} /* return value */ };

        call_guest(UnpackerTable->*Unpacker, (void*)guest_cb, &argsrv);

        return argsrv.rv;
    };
}

int fexfn_impl_libX11_XIfEvent_internal(Display* a0, XEvent* a1, XIfEventCBFN* guest_cb, XPointer guest_arg) {
    WrappedCBArgs<XPointer, XIfEventCBFN*> internal_args = { guest_arg, guest_cb };
    auto internal_cb = wrap_guest_callback<0, callback_unpacks, &CALLBACK_UNPACKS::libX11_XIfEventCB, XIfEventCB_Args,
                                           Display*, XEvent*, decltype(&internal_args)>(internal_args);
    return fexldr_ptr_libX11_XIfEvent(a0, a1, internal_cb, (XPointer)&internal_args);
}

int test_function(Display* a0, XEvent* a1, XIfEventCBFN* guest_cb, XIfEventCBFN* guest_cb2, XPointer guest_arg) {
    WrappedCBArgs<XPointer, XIfEventCBFN*, XIfEventCBFN*> internal_args = { guest_arg, guest_cb, guest_cb2 };
    auto internal_cb = wrap_guest_callback<0, callback_unpacks, &CALLBACK_UNPACKS::libX11_XIfEventCB, XIfEventCB_Args,
                                           Display*, XEvent*, decltype(&internal_args)>(internal_args);
    auto internal_cb2 = wrap_guest_callback<1, callback_unpacks, &CALLBACK_UNPACKS::libX11_XIfEventCB, XIfEventCB_Args,
                                            Display*, XEvent*, decltype(&internal_args)>(internal_args);
//    return fexldr_ptr_libX11_XIfEvent(a0, a1, internal_cb, (XPointer)&internal_args);
    return 0;
}

XErrorHandler guest_handler;

int XSetErrorHandlerCB(Display* a_0, XErrorEvent* a_1) {
    XSetErrorHandlerCB_Args argsrv { a_0, a_1};
    
    call_guest(callback_unpacks->libX11_XSetErrorHandlerCB, (void*) guest_handler, &argsrv);
    
    return argsrv.rv;
}

XSetErrorHandlerCBFN* fexfn_impl_libX11_XSetErrorHandler_internal(XErrorHandler a_0) {
    auto old = guest_handler;
    guest_handler = a_0;

    fexldr_ptr_libX11_XSetErrorHandler(&XSetErrorHandlerCB);
    return old;
}

#include "function_unpacks.inl"

static ExportEntry exports[] = {
    #include "tab_function_unpacks.inl"
    { nullptr, nullptr }
};

#include "ldr.inl"

EXPORTS_WITH_CALLBACKS(libX11, callback_unpacks)
