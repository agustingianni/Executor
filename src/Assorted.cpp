/*
 * Assorted.cpp
 *
 *  Created on: Jul 3, 2013
 *      Author: anon
 */

#include "Logging.h"
#include "Assorted.h"
#include "Debugger.h"
#include <libelf.h>
#include <gelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstddef>
#include <string>

using namespace std;

#ifdef __arm__
extern "C" {
    // Apparently libelf on Android AOSP is linked against libintl which we don't have.
    // To avoid link issues we fake the only imported function.
    char * dgettext(const char * domainname, const char * msgid) {
        return NULL;
    }
}
#endif

namespace ELF {
    /*!
     * Get the offset from the start of the elf file of a given symbol
     * on the .dynsym section.
     *
     * @param file_path
     * @param symbol
     * @return
     */
    uintptr_t GetDynamicSymbolOffset(string file_path, string symbol) {
        Elf *elf;

        LOG(DEBUG) << "Trying to resovle " << symbol << " from " << file_path;

        int fd = open(file_path.c_str(), O_RDONLY, 0);
        if (fd < 0) {
            LOG(ERROR) << "Could not open file " << file_path;
            return -1;
        }

        if (elf_version(EV_CURRENT) == EV_NONE) {
            LOG(ERROR) << "ELF library initialization failed (" << elf_errmsg(-1) << ")";
            close(fd);
            return -1;
        }

        elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            LOG(ERROR) << "Could not open ELF file " << file_path << " (" << elf_errmsg(-1)
                    << ")";
            close(fd);
            return -1;
        }

        Elf_Scn *scn = 0;
        GElf_Shdr shdr;
        GElf_Sym sym;
        GElf_Rel rel;

        while ((scn = elf_nextscn(elf, scn)) != 0) {
            gelf_getshdr(scn, &shdr);

            Elf_Data *edata = 0;

            // Get the symbol table.
            if (shdr.sh_type == SHT_DYNSYM) {
                edata = elf_getdata(scn, edata);
                size_t symbol_count = shdr.sh_size / shdr.sh_entsize;

                for (size_t i = 0; i < symbol_count; i++) {
                    gelf_getsym(edata, i, &sym);

                    // Check the name of the symbol and that it is not UND
                    if (symbol == string(elf_strptr(elf, shdr.sh_link, sym.st_name))
                            && sym.st_value) {
                        return sym.st_value;
                    }
                }
            }
        }

        elf_end(elf);
        close(fd);

        return -1;
    }
}

string StringToHex(const string &string_) {
    stringstream ss;
    for (const char &c : string_) {
        ss << hex << setfill('0') << setw(2) << (static_cast<unsigned int>(c) & 0xff) << " ";
    }

    return ss.str();
}

namespace Dump {
    void Context(Registers &regs) {
#ifdef __arm__
        printf("r0 = %.8lx r1 = %.8lx r2 = %.8lx r3 = %.8lx r4 = %.8lx r5 = %.8lx\n", regs.r0,
                regs.r1, regs.r2, regs.r3, regs.r4, regs.r5);

        printf("r6 = %.8lx r7 = %.8lx r8 = %.8lx r9  = %.8lx r10  = %.8lx r11 = %.8lx\n", regs.r6,
                regs.r7, regs.r8, regs.r9, regs.r10, regs.r11);

        printf("r12 = %.8lx sp = %.8lx lr = %.8lx pc = %.8lx cpsr = %.8lx\n", regs.r12, regs.sp,
                regs.lr, regs.pc, regs.cpsr);

#else
        printf(
                "rax = %.16llx rbx = %.16llx rcx = %.16llx rdx = %.16llx rsi = %.16llx rdi = %.16llx\n",
                regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi);

        printf(
                "rip = %.16llx rsp = %.16llx rbp = %.16llx r8  = %.16llx r9  = %.16llx r10 = %.16llx\n",
                regs.rip, regs.rsp, regs.rbp, regs.r8, regs.r9, regs.r10);

        printf(
                "r11 = %.16llx r12 = %.16llx r13 = %.16llx r14 = %.16llx r15 = %.16llx eflags = %.16llx \n",
                regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.eflags);
#endif
    }

    void Stack(Debugger &debugger, pid_t tid) {
        Registers regs;
        debugger.getRegisters(tid, &regs);

        unsigned char *stack_bytes;
        size_t stack_size = REGISTERS_SP(regs) - REGISTERS_BP(regs);

        if (stack_size > 4 * 1024) {
            cerr << "Stack size is greater than 4KB. Dumping a small chunk" << endl;
            stack_size = 0x10 * 8;
        }

        stack_bytes = static_cast<unsigned char *>(calloc(stack_size, sizeof(uint8_t)));
        if (!stack_bytes) {
            cerr << "Could not allocate memory for stack dump." << endl;
            return;
        }

        debugger.read_memory(REGISTERS_SP(regs), stack_bytes, stack_size);

        uintptr_t *casted = reinterpret_cast<uintptr_t *>(stack_bytes);

        size_t nentries = stack_size / sizeof(void *);
        printf("Stack:\n");
        for (unsigned int i = 0; i < nentries; ++i) {
            printf("  %.16llx: %lx\n", REGISTERS_SP(regs) + i * 4, casted[i]);
        }
    }

    bool AroundPC(Debugger &debugger, pid_t tid) {
        uintptr_t pc;
        unsigned char buffer[32];

        debugger.getPC(tid, &pc);
        debugger.read_memory(pc, buffer, 32);

#ifdef __arm__
#else
        StringDisassembler dis(pc, 64);
        vector<Instruction> res = dis.disassemble(buffer, 32, 1);
        for (auto ins = res.begin(); ins != res.end(); ++ins) {
            printf("%.16lx: %s\n", pc, ins->m_instruction.c_str());
        }
#endif

        return true;
    }
}

namespace System {
    long PageSize() {
        return sysconf(_SC_PAGESIZE);
    }

    uintptr_t AlignToPage(uintptr_t address) {
        return address & (~(PageSize() - 1));
    }

    void *AlignToPage(void *address) {
        return (void *) AlignToPage((uintptr_t) address);
    }

}
