/*
 * RemoteCall.cpp
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */
#include "Assorted.h"
#include "Debugger.h"
#include "RemoteCall.h"
#include "Modules.h"
#include "Logging.h"
#include "MemoryRegion.h"

#include <sys/types.h>
#include <cstddef>
#include <vector>

using namespace std;

class RemoteCall {
    public:
        RemoteCall(Debugger *debugger) :
                m_debugger(debugger) {
        }

        bool call(void **fx_ret, uintptr_t address, vector<void *> args);

    private:
        bool save_context();
        bool restore_context();
        bool prepare_context(uintptr_t address, vector<void*> args);

        Debugger *m_debugger;
        Registers saved_registers;
        unsigned char saved_instructions[4];

        Registers new_registers;
        unsigned char new_instructions[4];
        size_t trampoline_size;
};

bool RemoteCall::save_context() {
    // Make a backup of the registers.
    if (!m_debugger->getRegisters(m_debugger->getLeaderProcess()->pid(), &saved_registers)) {
        LOG(ERROR) << "Could not save registers";
        return false;
    }

    // Save the overwritten instructions.
    if (!m_debugger->read_memory(REGISTERS_PC(saved_registers), saved_instructions,
            sizeof(saved_instructions))) {
        LOG(ERROR) << "Could not save instruction backup.";
        return false;
    }

    return true;
}

bool RemoteCall::restore_context() {
    // Restore the saved registers.
    if (!m_debugger->setRegisters(m_debugger->getLeaderProcess()->pid(), &saved_registers)) {
        LOG(ERROR) << "Could not restore saved registers.";
        return false;
    }

    // We need to manualy set SP due to ptrace being fucked up.
    if (!m_debugger->setSP(m_debugger->getLeaderProcess()->pid(), REGISTERS_SP(saved_registers))) {
        LOG(ERROR) << "Could not restore saved registers.";
        return false;
    }

    // Restore the overwritten instructions.
    if (!m_debugger->write_memory(REGISTERS_PC(saved_registers), saved_instructions,
            sizeof(saved_instructions))) {
        LOG(ERROR) << "Could not restore overwritten instructions.";
        return false;
    }

    return true;
}

#ifdef __arm__
bool RemoteCall::prepare_context(uintptr_t address, vector<void*> args) {
    bool ret = true;

    switch (args.size()) {
        case 1:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            break;

        case 2:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            new_registers.r1 = reinterpret_cast<uintptr_t>(args[1]);
            break;

        case 3:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            new_registers.r1 = reinterpret_cast<uintptr_t>(args[1]);
            new_registers.r2 = reinterpret_cast<uintptr_t>(args[2]);
            break;

        case 4:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            new_registers.r1 = reinterpret_cast<uintptr_t>(args[1]);
            new_registers.r2 = reinterpret_cast<uintptr_t>(args[2]);
            new_registers.r3 = reinterpret_cast<uintptr_t>(args[3]);
            break;

        case 5:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            new_registers.r1 = reinterpret_cast<uintptr_t>(args[1]);
            new_registers.r2 = reinterpret_cast<uintptr_t>(args[2]);
            new_registers.r3 = reinterpret_cast<uintptr_t>(args[3]);
            m_debugger->push_value(m_debugger->getLeaderProcess()->pid(),
                    reinterpret_cast<uintptr_t>(args[4]));
            new_registers.sp -= 4;
            break;

        case 6:
            new_registers.r0 = reinterpret_cast<uintptr_t>(args[0]);
            new_registers.r1 = reinterpret_cast<uintptr_t>(args[1]);
            new_registers.r2 = reinterpret_cast<uintptr_t>(args[2]);
            new_registers.r3 = reinterpret_cast<uintptr_t>(args[3]);
            m_debugger->push_value(m_debugger->getLeaderProcess()->pid(),
                    reinterpret_cast<uintptr_t>(args[5]));
            m_debugger->push_value(m_debugger->getLeaderProcess()->pid(),
                    reinterpret_cast<uintptr_t>(args[4]));
            new_registers.sp -= 8;
            break;

        default:
            LOG(ERROR) << "Cannot call functions with more than 6 parameters.";
            ret = false;
            break;
    }

    // We check the processor mode here because the branch must match it.
    if ((new_registers.cpsr & CPSR_MODE) == ARM_MODE) {
        // ARM
        // e1 2f ff 38  blx r8
        memcpy(new_instructions, "\x38\xff\x2f\xe1", sizeof(new_instructions));
        trampoline_size = 4;

        LOG(DEBUG) << "Using ARM Mode trampoline to " << (void *) address;
    } else {
        // THUMB
        // 47 c0        blx r8
        // bf 00        nop
        memcpy(new_instructions, "\xc0\x47\x00\xbf", sizeof(new_instructions));
        trampoline_size = 4;

        LOG(DEBUG) << "Using THUMB Mode trampoline to " << (void *) address;
    }

    // Set the address of the function we want to call.
    new_registers.r8 = address;

    return ret;
}

#elif __i386__
#elif __x86_64__
bool RemoteCall::prepare_context(uintptr_t address, vector<void*> args) {
    bool ret = true;

    switch (args.size()) {
        case 1:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        break;

        case 2:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        new_registers.rsi = reinterpret_cast<uintptr_t>(args[1]);
        break;

        case 3:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        new_registers.rsi = reinterpret_cast<uintptr_t>(args[1]);
        new_registers.rdx = reinterpret_cast<uintptr_t>(args[2]);
        break;

        case 4:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        new_registers.rsi = reinterpret_cast<uintptr_t>(args[1]);
        new_registers.rdx = reinterpret_cast<uintptr_t>(args[2]);
        new_registers.rcx = reinterpret_cast<uintptr_t>(args[3]);
        break;

        case 5:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        new_registers.rsi = reinterpret_cast<uintptr_t>(args[1]);
        new_registers.rdx = reinterpret_cast<uintptr_t>(args[2]);
        new_registers.rcx = reinterpret_cast<uintptr_t>(args[3]);
        new_registers.r8 = reinterpret_cast<uintptr_t>(args[4]);
        break;

        case 6:
        new_registers.rdi = reinterpret_cast<uintptr_t>(args[0]);
        new_registers.rsi = reinterpret_cast<uintptr_t>(args[1]);
        new_registers.rdx = reinterpret_cast<uintptr_t>(args[2]);
        new_registers.rcx = reinterpret_cast<uintptr_t>(args[3]);
        new_registers.r8 = reinterpret_cast<uintptr_t>(args[4]);
        new_registers.r9 = reinterpret_cast<uintptr_t>(args[5]);
        break;

        default:
        LOG(ERROR) << "Cannot call functions with more than 6 parameters.";
        ret = false;
        break;
    }

    // ff d0 ; call rax
    // 90    ; nop
    // 90    ; nop
    memcpy(new_instructions, "\xff\xd0\x90\x90", sizeof(new_instructions));
    trampoline_size = 2;

    // Set the address of the function we want to call.
    new_registers.rax = address;

    return ret;
}
#endif

bool RemoteCall::call(void **fx_ret, uintptr_t address, vector<void*> args) {
    // Save a copy of the context to be restored after the function call.
    if (!save_context()) {
        LOG(ERROR) << "Could not save the context.";
        return false;
    }

    // Make a copy of the saved registers so we get the previous env and modify it.
    new_registers = saved_registers;

    // Prepare the context to make the call. This is arch dependant.
    if (!prepare_context(address, args)) {
        LOG(ERROR) << "Could not set call context.";
        return false;
    }

    // Place our payload.
    if (!m_debugger->write_memory(REGISTERS_PC(saved_registers), new_instructions,
            sizeof(new_instructions))) {
        LOG(ERROR) << "Could not restore overwritten instructions.";
        return false;
    }

    // Set the new context.
    if (!m_debugger->setRegisters(m_debugger->getLeaderProcess()->pid(), &new_registers)) {
        LOG(ERROR) << "Could not set new registers.";
        return false;
    }

    // Execute the function call and wait until the function returns.
    if (!m_debugger->stepUntil(m_debugger->getLeaderProcess()->pid(),
            REGISTERS_PC(saved_registers) + trampoline_size)) {
        LOG(ERROR) << "Could not run past the injected instruction.";
        return false;
    }

    // Get the registers to get the return value.
    if (!m_debugger->getRegisters(m_debugger->getLeaderProcess()->pid(), &new_registers)) {
        LOG(ERROR) << "Could not get registers";
        return false;
    }

    // Save the function return value.
    if (fx_ret) {
        *fx_ret = reinterpret_cast<void *>(CALL_RET_VAL(new_registers));
    }

    if (!restore_context()) {
        LOG(ERROR) << "Could not restore the context.";
        return false;
    }

    return true;
}

namespace Remote {
    namespace DynamicLinker {
        static uintptr_t dlopen_addr = -1;
        static uintptr_t dlsym_addr = -1;
        static uintptr_t dlclose_addr = -1;
        static bool initialized = false;

        char* strtab = NULL;
        Elf32_Sym* symtab = NULL;
        struct soinfo *soinfo = NULL;

        static uintptr_t find_symbol(const char *symbol) {
            int i;
            for (i = 0; i < soinfo->nchain; i++) {
                Elf32_Sym* sym = &soinfo->symtab[i];
                if (!strcmp(soinfo->strtab + sym->st_name, symbol) && sym->st_value) {
                    return (uintptr_t) sym->st_value;
                }
            }

            return 0;
        }

        static bool initialize(Debugger *debugger) {
            MemoryRegion linker_data_region;
            bool found = false;
            vector<MemoryRegion> maps = MemoryMapLoader::load(debugger->getLeaderProcess());
            for (auto map = maps.begin(); map != maps.end(); ++map) {
                if (!map->isWriteable())
                    continue;

                if (map->getPath().find("linker") == string::npos)
                    continue;

                linker_data_region = *map;
                found = true;
            }

            if (!found) {
                LOG(ERROR) << "There is no data segment backing 'linker' up. Weird";
                return false;
            }

            // Allocate memory to read he whole region.
            unsigned char *buffer = reinterpret_cast<unsigned char *>(malloc(
                    linker_data_region.getSize()));
            if (!buffer) {
                LOG(ERROR) << "Could not allocate buffer";
                return false;
            }

            // Read the whole chunk.
            if (!debugger->read_memory(linker_data_region.getStartAddress(), buffer,
                    linker_data_region.getSize())) {
                LOG(ERROR) << "Could not read memory";
                free(buffer);
                return false;
            }

            // Find a reference to the soinfo structure.
            soinfo = (struct soinfo *) memmem((const void *) buffer, linker_data_region.getSize(),
                    "libdl.so", strlen("libdl.so"));

            // Do some heuristics to check we've got a valid reference.
            if (!soinfo || soinfo->flags != 1 || soinfo->nbucket != 1) {
                LOG(ERROR) << "Could not find soinfo list";
                free(buffer);
                return false;
            }

            LOG(INFO) << "Got a reference to struct soinfo *";

            // TODO: Get the string table size from somewhere.
            size_t strtab_size = 1024;
            size_t symtab_size = sizeof(Elf32_Sym) * soinfo->nchain;

            // Allocate space for our copy of the string table.
            strtab = reinterpret_cast<char *>(malloc(strtab_size));
            if (!strtab) {
                LOG(ERROR) << "Could not allocate buffer for the string table.";
                free(buffer);
                return false;
            }

            // Allocate space for our copy of the symbol table.
            symtab = reinterpret_cast<Elf32_Sym*>(malloc(symtab_size));
            if (!strtab) {
                LOG(ERROR) << "Could not allocate buffer for the string table.";
                free(buffer);
                free(strtab);
                return false;
            }

            // Read the whole symbol table.
            if (!debugger->read_memory((uintptr_t) soinfo->symtab, (unsigned char *) symtab,
                    symtab_size)) {
                LOG(ERROR) << "Could not read symbol table memory.";
                free(buffer);
                free(symtab);
                free(strtab);
                return false;
            }

            // Read the whole string table.
            if (!debugger->read_memory((uintptr_t) soinfo->strtab, (unsigned char *) strtab,
                    strtab_size)) {
                LOG(ERROR) << "Could not read string table memory.";
                free(buffer);
                free(symtab);
                free(strtab);
                return false;
            }

            // Replace the original pointers with ours.
            soinfo->strtab = strtab;
            soinfo->symtab = symtab;

            // Resolve the dynamic linker api.
            dlopen_addr = find_symbol("dlopen");
            dlsym_addr = find_symbol("dlsym");
            dlclose_addr = find_symbol("dlclose");

            if (!dlopen_addr || !dlsym_addr || !dlclose_addr) {
                LOG(ERROR) << "Failed resolving dynamic linker api functions";
                free(buffer);
                free(symtab);
                free(strtab);
                return false;
            }

            initialized = true;

            return true;
        }

        static uintptr_t dlopen_address(Debugger *debugger) {
            if (!initialized)
                initialize(debugger);

            return dlopen_addr;
        }

        static uintptr_t dlsym_address(Debugger *debugger) {
            if (!initialized)
                initialize(debugger);

            return dlsym_addr;
        }

        static uintptr_t dlclose_address(Debugger *debugger) {
            if (!initialized)
                initialize(debugger);

            return dlclose_addr;
        }
    }

    /*!
     * Call a given 'function' in a particular 'library with 'args'.
     *
     * @param debugger
     * @param ret
     * @param library
     * @param function
     * @param args
     * @return
     */
    bool call_named(Debugger *debugger, void **ret, std::string library, std::string function,
            std::vector<void *> args) {
        // Get a reference to the lead process.
        shared_ptr<Process> process = debugger->getLeaderProcess();

        // We will need the module list to resolve 'function'.
        ModuleList &module_list = process->getModuleList();

        // Obtain a reference to module.
        shared_ptr<Module> module = module_list.find(library);
        if (!module.get()) {
            LOG(ERROR) << "Could not find module " << library;
            return false;
        }

        // Resolve the address of function.
        uintptr_t function_address = module->resolve(function);
        if (function_address == INVALID_ADDRESS) {
            LOG(ERROR) << "Could not resolve '" << function << "' address.";
            return false;
        }

        LOG(INFO) << "Found function " << function << " in module " << module->path().native()
                << " @ " << (void *) function_address;

        return call_address(debugger, ret, function_address, args);
    }

    /*!
     * Call the function at address 'function_address'.
     * @param debugger
     * @param ret
     * @param function_address
     * @param args
     * @return
     */
    bool call_address(Debugger *debugger, void **ret, uintptr_t function_address,
            std::vector<void *> args) {
        // Call function with its arguments.
        RemoteCall remote(debugger);
        return remote.call(ret, function_address, args);
    }

    /*!
     * Call mmap on the debuggee.
     *
     * @param debugger
     * @param ret
     * @param addr
     * @param length
     * @param prot
     * @param flags
     * @param fd
     * @param offset
     * @return
     */
    bool call_mmap(Debugger *debugger, void **ret, void *addr, size_t length, int prot, int flags,
            int fd, off_t offset) {
        // Prepare arguments for 'mmap'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(addr));
        args.push_back(reinterpret_cast<void *>(length));
        args.push_back(reinterpret_cast<void *>(prot));
        args.push_back(reinterpret_cast<void *>(flags));
        args.push_back(reinterpret_cast<void *>(0));
        args.push_back(reinterpret_cast<void *>(0));

        // Call mmap with its arguments.
        return call_named(debugger, ret, "libc", "mmap", args);
    }

    /*!
     * Call munmap on the debuggee.
     *
     * @param debugger
     * @param ret
     * @param addr
     * @param length
     * @return
     */
    bool call_munmap(Debugger *debugger, void **ret, void *addr, size_t length) {
        // Prepare arguments for 'munmap'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(addr));
        args.push_back(reinterpret_cast<void *>(length));

        // Call munmap with its arguments.
        return call_named(debugger, ret, "libc", "munmap", args);
    }

    /*!
     * Call mprotect in the debuggee.
     *
     * @param debugger
     * @param reg
     * @param addr
     * @param len
     * @param prot
     * @return
     */
    bool call_mprotect(Debugger *debugger, void **ret, void *addr, size_t len, int prot) {
        // Prepare arguments for 'mprotect'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(addr));
        args.push_back(reinterpret_cast<void *>(len));
        args.push_back(reinterpret_cast<void *>(prot));

        // Call mprotect with its arguments.
        return call_named(debugger, ret, "libc", "mprotect", args);
    }

    bool call_dlopen(Debugger *debugger, void **ret, char *filename, int flag) {
        // Prepare arguments for 'dlopen'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(filename));
        args.push_back(reinterpret_cast<void *>(flag));

        // Call dlopen with its arguments.
#if __arm__
        return call_address(debugger, ret, DynamicLinker::dlopen_address(debugger), args);
#else
        return call_named(debugger, ret, DYNLINK_NAME, DLOPEN_NAME, args);
#endif
    }

    bool call_dlclose(Debugger *debugger, void **ret, void *handle) {
        // Prepare arguments for 'dlclose'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(handle));

        // Call __libc_dlclose with its arguments.
#if __arm__
        return call_address(debugger, ret, DynamicLinker::dlclose_address(debugger), args);
#else
        return call_named(debugger, ret, DYNLINK_NAME, DLCLOSE_NAME, args);
#endif
    }

    bool call_dlsym(Debugger *debugger, void **ret, void *handle, char *symbol) {
        // Prepare arguments for 'dlsym'
        vector<void *> args;
        args.push_back(reinterpret_cast<void *>(handle));
        args.push_back(reinterpret_cast<void *>(symbol));

        // Call dlsym with its arguments.
#if __arm__
        return call_address(debugger, ret, DynamicLinker::dlsym_address(debugger), args);
#else
        return call_named(debugger, ret, DYNLINK_NAME, DLSYM_NAME, args);
#endif
    }
}
