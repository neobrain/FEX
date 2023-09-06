/*
$info$
tags: thunklibs|fex_thunk_test
$end_info$
*/

#include <dlfcn.h>

#include <chrono>
#include <cstring>
#include <new>
#include <thread>
#include <unordered_map>

#include "common/Host.h"

#include "api.h"

#include "thunkgen_host_libfex_thunk_test.inl"

static uint32_t fexfn_impl_libfex_thunk_test_QueryOffsetOf(guest_layout<ReorderingType*> data, int index) {
    if (index == 0) {
        return offsetof(guest_layout<ReorderingType>::type, a);
    } else {
        return offsetof(guest_layout<ReorderingType>::type, b);
    }
}

template<>
void fex_custom_repack<&CustomRepackedType::data>(host_layout<CustomRepackedType>& to, guest_layout<CustomRepackedType> const& from) {
  to.data.custom_repack_invoked = 1;
}

template<>
void fex_custom_repack_postcall<&CustomRepackedType::data>(ReorderingType* const&) {

}

#if 0
std::thread* thr;

void fexfn_impl_libfex_thunk_test_SetAsyncCallback(void(*cb)()) {
  auto host_cb = (void (*)())cb;
  FinalizeHostTrampolineForGuestFunction(host_cb);
  MakeHostTrampolineForGuestFunctionAsyncCallable(host_cb, 1);

  thr = new std::thread { [host_cb]() {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(500ms);
    host_cb();
  }};

//  host_cb();
  printf("HELLO WORLD\n");
}
#endif

using const_void_ptr = const void*;

template<StructType TypeIndex, typename Type>
static const TestBaseStruct* convert(const TestBaseStruct* source) {
    // Using malloc here since no easily available type information is available at the time of destruction
    auto child = (host_layout<Type>*)malloc(sizeof(host_layout<Type>));
    new (child) host_layout<Type> { *reinterpret_cast<guest_layout<Type>*>((void*)(source)) }; // TODO: Use proper cast?
    // TODO: Trigger *full* custom repack for children, not just the Next member
//    fex_custom_repack<&Type::Next>(child, source);
    fex_custom_repack<&Type::Next>(*child, *reinterpret_cast<guest_layout<Type>*>((void*)(source)));

    return (const TestBaseStruct*)child; // TODO: Use proper cast?
}

template<StructType TypeIndex, typename Type>
inline constexpr std::pair<StructType, const TestBaseStruct*(*)(const TestBaseStruct*)> converters =
  { TypeIndex, convert<TypeIndex, Type> };


static std::unordered_map<StructType, const TestBaseStruct*(*)(const TestBaseStruct*)> next_handlers {
    converters<StructType::Struct1, TestStruct1>,
    converters<StructType::Struct2, TestStruct2>,
};

// Normally, we would implement fex_custom_repack individually for each customized struct.
// In this case, they all need the same repacking, so we just implement it once and alias all fex_custom_repack instances
extern "C" void default_fex_custom_repack(host_layout<TestStruct1>& into, const guest_layout<TestStruct1>& from) {
    if (!from.data.Next.get_pointer()) {
        return;
    }

    auto typed_source = reinterpret_cast<const TestBaseStruct*>(from.data.Next.get_pointer());
    auto child = next_handlers.at(typed_source->Type)(typed_source);
    into.data.Next = child;
}

template<> __attribute__((alias("default_fex_custom_repack"))) void fex_custom_repack<&TestStruct1::Next>(host_layout<TestStruct1>&, const guest_layout<TestStruct1>&);
template<> __attribute__((alias("default_fex_custom_repack"))) void fex_custom_repack<&TestStruct2::Next>(host_layout<TestStruct2>&, const guest_layout<TestStruct2>&);

extern "C" void default_fex_custom_repack_postcall(const const_void_ptr& Next) {
  if (Next) {
    auto NextNext = ((TestBaseStruct*)Next)->Next;
    default_fex_custom_repack_postcall(NextNext);
    fprintf(stderr, "Destroying %p\n", Next);
    free((void*)Next);
  }
}

template<> __attribute__((alias("default_fex_custom_repack_postcall"))) void fex_custom_repack_postcall<&TestStruct1::Next>(const const_void_ptr&);
template<> __attribute__((alias("default_fex_custom_repack_postcall"))) void fex_custom_repack_postcall<&TestStruct2::Next>(const const_void_ptr&);

void fexfn_impl_libfex_thunk_test_TestFunction(TestStruct1* arg) {
  fprintf(stderr, "Hello from %s\n", __FUNCTION__);
  fprintf(stderr, "  TestStruct1: %c %d %p\n", arg->Data2, arg->Data1, arg->Next);
  if (!arg->Next || ((TestBaseStruct*)arg->Next)->Type != StructType::Struct2) {
    fprintf(stderr, "ERROR: Expected Next with StructType::Struct2, got %d\n", (arg->Next ? (int)((TestBaseStruct*)arg->Next)->Type : 0));
    std::abort();
  }
  auto Next = (TestStruct2*)arg->Next;
  fprintf(stderr, "  TestStruct2: %d %p\n", Next->Data1, Next->Next);
  auto Next2 = (TestStruct1*)Next->Next;
  fprintf(stderr, "  TestStruct3: %d %p\n", Next2->Data1, Next2->Next);
}

EXPORTS(libfex_thunk_test)
