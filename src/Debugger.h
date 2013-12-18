/*
 * Debugger.h
 *
 *  Created on: Jun 28, 2013
 *      Author: anon
 */

#ifndef DEBUGGER_H_
#define DEBUGGER_H_

#include "Breakpoint.h"
#include "Disassembler.h"
#include "Process.h"
#include "RemoteAllocator.h"

#include <signal.h>
#include <set>
#include <vector>
#include <string>
#include <cstddef>
#include <memory>
#include <boost/function.hpp>
#include <boost/signal.hpp>
#include <boost/unordered_map.hpp>
#include <boost/noncopyable.hpp>

#ifdef __arm__
struct user_regs_struct {
    unsigned long int r0;
    unsigned long int r1;
    unsigned long int r2;
    unsigned long int r3;
    unsigned long int r4;
    unsigned long int r5;
    unsigned long int r6;
    unsigned long int r7;
    unsigned long int r8;
    unsigned long int r9;
    unsigned long int r10;
    unsigned long int r11;
    unsigned long int r12;
    unsigned long int sp;
    unsigned long int lr;
    unsigned long int pc;
    unsigned long int cpsr;
    unsigned long int orig_r0;
};

#define ARM_MODE 0
#define THUMB_MODE 1
#define CPSR_MODE (1 << 5)

#define CALL_RET_VAL(regs) regs.r0
#define REGISTERS_PC(regs) regs.pc
#define REGISTERS_SP(regs) regs.sp
#define REGISTERS_BP(regs) regs.r11
#define REGISTERS_FLAGS(regs) regs.cpsr

// Definition of these is at: http://lxr.free-electrons.com/source/arch/arm/kernel/ptrace.c
const unsigned long BREAKPOINT_ARM = 0xe7f001f0;
const unsigned short BREAKPOINT_THUMB = 0xde01;

typedef struct user_regs_struct Registers;

#else
#include <sys/user.h>
typedef struct user_regs_struct Registers;
#define CALL_RET_VAL(regs) regs.rax
#define REGISTERS_PC(regs) regs.rip
#define REGISTERS_SP(regs) regs.rsp
#define REGISTERS_BP(regs) regs.rbp
#define REGISTERS_FLAGS(regs) regs.eflags

#endif

typedef enum Permissions {
    Writable = (1u << 0), Readable = (1u << 1), Executable = (1u << 2)
} Permissions;

class Debugger: boost::noncopyable {
    public:
        typedef boost::signal<bool(int)> signal_t;
        typedef boost::signals::connection connection_t;
        typedef boost::unordered_map<uintptr_t, Breakpoint> breakmap_t;

        // The leader process is the process that we've attached or executed.
        std::shared_ptr<Process> getLeaderProcess() {
            return m_lead_process;
        }

        // Set the leader process. There is exactly one per Debugger instance.
        void setLeaderProcess(std::shared_ptr<Process> process) {
            m_lead_process = process;
        }

        Debugger();
        bool initProcess(pid_t tid);

        std::map<std::string, void *> m_lib2handle;

        bool loadRemoteLibrary(std::string filename, void **handle = 0);
        bool unLoadRemoteLibrary(std::string filename);

        // Misc
        bool disableASLR();
        bool enableASLR();

        // These ideally should not be called. The memory cache is better.
        uintptr_t allocateMemory(size_t length, int permissions);
        void freeMemory(uintptr_t address);

        // Call this in order to work with memory inside the debuggee.
        AllocatedMemoryCache &getMemoryCache() {
            return m_memory_cache;
        }

        // Attach and detach routines.
        bool attach(std::shared_ptr<Process> process);
        bool detach();

        // Process state machine handlers.
        bool cont(pid_t tid, int signum = 0);
        bool kill(pid_t tid);
        bool loop();
        bool stop(pid_t tid);
        bool wait(int *status, pid_t *pid);

        // Process execution.
        std::shared_ptr<Process> execute(std::string filename, std::vector<std::string> args = std::vector<std::string>());

        // Tracing utilities.
        bool singleStep(pid_t tid, int *signo = 0);
        bool syscallStep(pid_t tid);
        bool stepUntil(pid_t tid, uintptr_t address);

        // Signal utilities.
        bool getSignalInformation(pid_t tid, siginfo_t *siginfo);
        bool setSignalInformation(pid_t tid, siginfo_t *siginfo);

        // Specific register utilities.
        bool setPC(pid_t tid, uintptr_t address);
        bool getPC(pid_t tid, uintptr_t *address);
        bool setSP(pid_t tid, uintptr_t address);
        bool getSP(pid_t tid, uintptr_t *address);

        // General register utilities.
        bool getRegisters(pid_t tid, Registers *regs);
        bool setRegisters(pid_t tid, const Registers *regs);

        // Breakpoint handling.
        Breakpoint addBreakpoint(uintptr_t address, Breakpoint::handler_t handler);
        bool delBreakpoint(Breakpoint &breakpoint);
        bool enableBreakpoint(Breakpoint &breakpoint);
        bool disableBreakpoint(Breakpoint &breakpoint);

        // Data handling utilities.
        uint8_t read_byte(uintptr_t address, bool *res);
        uint16_t read_word(uintptr_t address, bool *res);
        uint32_t read_dword(uintptr_t address, bool *res);
        uint64_t read_qword(uintptr_t address, bool *res);

        void write_byte(uintptr_t address, uint8_t val, bool *res);
        void write_word(uintptr_t address, uint16_t val, bool *res);
        void write_dword(uintptr_t address, uint32_t val, bool *res);
        void write_qword(uintptr_t address, uint64_t val, bool *res);

        bool read_memory(uintptr_t address, unsigned char *buffer, size_t size);
        bool read_string(uintptr_t address, unsigned char *buffer, size_t size, bool unicode);
        bool write_memory(uintptr_t address, const unsigned char *buffer, size_t size);
        bool write_string(uintptr_t address, std::string string);
        bool write_instruction(Instruction ins, uintptr_t address = 0);

        // Methods to work with the stack.
        bool push_value(pid_t tid, uintptr_t value);
        bool pop_value(pid_t tid, uintptr_t *value);

        bool fill_memory(uintptr_t address, int byte, size_t size);

        // Event handling routines.
        connection_t connectHandler(signal_t::slot_function_type subscriber);
        bool disconnectHandler(connection_t subscriber);

        bool stopAll();
        bool continueAll();

        bool enterAtomic();
        bool leaveAtomic();

    private:
        template<typename T> T peek(uintptr_t address, bool *res = 0);
        template<typename T> void poke(uintptr_t address, T value, bool *res = 0);

        // Debugger event handlers.
        bool onBreakpointEvent(pid_t tid);
        bool onThreadCreateEvent(pid_t tid);
        bool onThreadDestroyEvent(pid_t tid);

    private:
        // This will register signal handlers.
        signal_t m_handlers;
        bool m_delayed_breakpoints;
        breakmap_t m_breakpoints;

        std::shared_ptr<Process> m_lead_process;

        // Map that gives you the mmap size of a given address
        std::map<uintptr_t, size_t> m_address_to_size;

        // For allocation inside the debugee address space.
        AllocatedMemoryCache m_memory_cache;

        // Set of threads stopped by enterAtomic.
        std::set<pid_t> atomic_set;
};

#endif /* DEBUGGER_H_ */
