/*
 * RemoteCall.h
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */

#ifndef REMOTECALL_H_
#define REMOTECALL_H_

#include <sys/types.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>

#include <elf.h>

class Debugger;

namespace Remote {
#ifdef __arm__
    const std::string DLOPEN_NAME = "dlopen";
    const std::string DLSYM_NAME = "dlsym";
    const std::string DLCLOSE_NAME = "dlclose";
    const std::string DYNLINK_NAME = "libdl";

    namespace DynamicLinker {
        typedef void (*linker_function_t)();
        const unsigned int SOINFO_NAME_LEN = 128;

        struct link_map_t {
            uintptr_t l_addr;
            char* l_name;
            uintptr_t l_ld;
            link_map_t* l_next;
            link_map_t* l_prev;
        };

        struct soinfo {
            char name[SOINFO_NAME_LEN];
            const Elf32_Phdr* phdr;
            size_t phnum;
            Elf32_Addr entry;
            Elf32_Addr base;
            unsigned size;

            uint32_t unused1;

            Elf32_Dyn* dynamic;

            uint32_t unused2;
            uint32_t unused3;

            soinfo* next;
            unsigned flags;

            // We need to copy these two from the debuggee.
            const char* strtab;
            Elf32_Sym* symtab;

            size_t nbucket;
            size_t nchain;
            unsigned* bucket;
            unsigned* chain;

            unsigned* plt_got;

            Elf32_Rel* plt_rel;
            size_t plt_rel_count;

            Elf32_Rel* rel;
            size_t rel_count;

            linker_function_t* preinit_array;
            size_t preinit_array_count;

            linker_function_t* init_array;
            size_t init_array_count;
            linker_function_t* fini_array;
            size_t fini_array_count;

            linker_function_t init_func;
            linker_function_t fini_func;

            unsigned* ARM_exidx;
            size_t ARM_exidx_count;

            size_t ref_count;
            link_map_t link_map;

            bool constructors_called;

            Elf32_Addr load_bias;

            bool has_text_relocations;
            bool has_DT_SYMBOLIC;
        };
    }

#else
    const std::string DLOPEN_NAME = "__libc_dlopen_mode";
    const std::string DLSYM_NAME = "__libc_dlsym";
    const std::string DLCLOSE_NAME = "__libc_dlclose";
    const std::string DYNLINK_NAME = "libc";
#endif

    // Routines that will be called on the host.
    bool call_mmap(Debugger *debugger, void **ret, void *addr, size_t length, int prot, int flags,
            int fd, off_t offset);
    bool call_munmap(Debugger *debugger, void **ret, void *addr, size_t length);
    bool call_mprotect(Debugger *debugger, void **ret, void *addr, size_t len, int prot);
    bool call_dlopen(Debugger *debugger, void **ret, char *filename, int flag);
    bool call_dlclose(Debugger *debugger, void **ret, void *handle);
    bool call_dlsym(Debugger *debugger, void **ret, void *handle, char *symbol);
    bool call_named(Debugger *debugger, void **ret, std::string library, std::string function,
            std::vector<void *> args);
    bool call_address(Debugger *debugger, void **ret, uintptr_t function_address,
            std::vector<void *> args);

    // Generic routine to make arbitrary function calls.
    bool call(Debugger *debugger, void **ret, uintptr_t address, std::vector<void *> args);
}

#endif /* REMOTECALL_H_ */
