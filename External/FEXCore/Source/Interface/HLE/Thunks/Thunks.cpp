/*
$info$
meta: glue|thunks ~ FEXCore side of thunks: Registration, Lookup
tags: glue|thunks
$end_info$
*/

#include <FEXCore/Utils/LogManager.h>
#include "Thunks.h"

#include "stdio.h"
#include <dlfcn.h>


#include <string>
#include <map>
#include <array>
#include <Interface/Context/Context.h>
#include "Interface/Core/InternalThreadState.h"
#include "FEXCore/Core/X86Enums.h"
#include <mutex>
#include <shared_mutex>

struct LoadlibArgs {
    const char *Name;
    uintptr_t CallbackThunks;
};

static thread_local FEXCore::Core::InternalThreadState *Thread;

extern uint64_t OMGTARGET;
extern uint64_t blessed_function;

namespace FEXCore {

    struct ExportEntry { uint8_t *sha256; ThunkedFunction* Fn; };

    class ThunkHandler_impl final: public ThunkHandler {
        std::shared_mutex ThunksMutex;

        std::map<IR::SHA256Sum, ThunkedFunction*> Thunks = {
            {
                // sha256(fex:loadlib)
                { 0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44, 0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x80},
                &LoadLib
            },
            {
                // TODO: Remove placeholder hash
                { 0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44, 0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x79},
                &MakeHostFunctionGuestCallable
            }
        };

        /*
            Set arg0/1 to arg regs, use CTX::HandleCallback to handle the callback
        */
        static void CallCallback(void *callback, void *arg0, void* arg1) {
            Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI] = (uintptr_t)arg0;
            Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSI] = (uintptr_t)arg1;

            Thread->CTX->HandleCallback((uintptr_t)callback);
        }

        static void MakeHostFunctionGuestCallable(void* argsv) {
            struct args_t {
                uintptr_t host_addr;
                uintptr_t guest_addr; // Function to call when branching to host_addr
            };

            auto args = reinterpret_cast<args_t*>(argsv);

            OMGTARGET = args->guest_addr;
            blessed_function = args->host_addr;
//            Thread->CTX->CompileBlockJit()
        }

        static void LoadLib(void *ArgsV) {

            auto Args = reinterpret_cast<LoadlibArgs*>(ArgsV);

            auto CTX = Thread->CTX;

            auto Name = Args->Name;
            auto CallbackThunks = Args->CallbackThunks;

            auto SOName = CTX->Config.ThunkHostLibsPath() + "/" + (const char*)Name + "-host.so";

            LogMan::Msg::D("Load lib: %s -> %s", Name, SOName.c_str());

            auto Handle = dlopen(SOName.c_str(), RTLD_LOCAL | RTLD_NOW);

            if (!Handle) {
                LogMan::Msg::E("Load lib: failed to dlopen %s: %s", SOName.c_str(), dlerror());
                return;
            }

            ExportEntry* (*InitFN)(void *, uintptr_t);

            auto InitSym = std::string("fexthunks_exports_") + (const char*)Name;

            (void*&)InitFN = dlsym(Handle, InitSym.c_str());

            if (!InitFN) {
                LogMan::Msg::E("Load lib: failed to find export %s", InitSym.c_str());
                return;
            }

            auto Exports = InitFN((void*)&CallCallback, CallbackThunks);

            auto That = reinterpret_cast<ThunkHandler_impl*>(CTX->ThunkHandler.get());

            {
                std::unique_lock lk(That->ThunksMutex);

                int i;
                for (i = 0; Exports[i].sha256; i++) {
                    That->Thunks[*reinterpret_cast<IR::SHA256Sum*>(Exports[i].sha256)] = Exports[i].Fn;
                }

                LogMan::Msg::D("Loaded %d syms", i);
            }
        }

        public:

        ThunkedFunction* LookupThunk(const IR::SHA256Sum &sha256) {

            std::shared_lock lk(ThunksMutex);

            auto it = Thunks.find(sha256);

            if (it != Thunks.end()) {
                return it->second;
            } else {
                return nullptr;
            }
        }

        void RegisterTLSState(FEXCore::Core::InternalThreadState *Thread) {
            ::Thread = Thread;
        }

        ThunkHandler_impl() {

        }
    };

    ThunkHandler* ThunkHandler::Create() {
        return new ThunkHandler_impl();
    }
}
