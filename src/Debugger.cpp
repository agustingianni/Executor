/*
 * Debugger.cpp
 *
 *  Created on: Jun 28, 2013
 *      Author: anon
 */
#include "Assorted.h"
#include "Debugger.h"
#include "EventHandler.h"
#include "Breakpoint.h"
#include "Logging.h"
#include "RemoteCall.h"
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdio.h>
#include <dlfcn.h>

#ifdef __arm__
#include <linux/user.h>
#else
#include <sys/user.h>
#include <sys/personality.h>
#endif

#include <iostream>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include <boost/signal.hpp>
#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

#pragma GCC diagnostic ignored "-Wwrite-strings"

using namespace std;

// Handler for keyboard interrups.
static bool got_sigint = false;
static void sigint_handler(int dummy) {
    got_sigint = true;
}

/*!
 * Add an EventListener to the list of event handlers.
 * @param subscriber
 * @return
 */
Debugger::connection_t Debugger::connectHandler(signal_t::slot_function_type subscriber) {
    LOG(DEBUG) << "Connected handler";
    return m_handlers.connect(subscriber);
}

/*!
 * Remove an EventListener from the list of event handlers.
 * @param subscriber
 * @return
 */
bool Debugger::disconnectHandler(connection_t subscriber) {
    LOG(DEBUG) << "Disconnected handler";
    subscriber.disconnect();
    return true;
}

/*!
 * Retrieve information about the signal that caused the stop.
 * @param siginfo
 * @return
 */
bool Debugger::getSignalInformation(pid_t tid, siginfo_t *siginfo) {
    LOG(DEBUG) << "Getting signal information.";

    long ret = ptrace(PTRACE_GETSIGINFO, tid, NULL, siginfo);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Replace the siginfo_t data on the debuggee.
 * @param tid
 * @param siginfo
 * @return
 */
bool Debugger::setSignalInformation(pid_t tid, siginfo_t *siginfo) {
    LOG(DEBUG) << "Setting signal information.";

    long ret = ptrace(PTRACE_SETSIGINFO, tid, NULL, siginfo);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Restart the stopped tracee as for PTRACE_CONT, but arrange for the tracee to be
 * stopped at the next entry to or exit from a system call.
 * @return
 */
bool Debugger::syscallStep(pid_t tid) {
    LOG(DEBUG) << "Stepping syscall";

    long ret = ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    int status;
    pid_t pid;
    if (!wait(&status, &pid)) {
        LOG(DEBUG) << "Could not wait for process";
    }

    return true;
}

/*!
 * Restart the stopped tracee as for PTRACE_CONT, but arrange for the tracee to be
 * stopped after execution of a single instruction.
 * @return
 */
bool Debugger::singleStep(pid_t tid, int *signo) {
#ifdef __arm__
    // PTRACE_SINGLESTEP does not work on ARM devices, we emulate this with a
    // breakpoint past the instruction we need to single step. This has
    // some corner cases I'm aware of such as the instruction modifying the
    // pc and skipping the breakpoint.
    // We check the processor mode here because the branch must match it.
    Registers regs;
    if (!getRegisters(tid, &regs)) {
        LOG(ERROR) << "Cannot single step.";
        return false;
    }

    size_t size = 0;
    if ((regs.cpsr & CPSR_MODE) == ARM_MODE) {
        LOG(DEBUG) << "Using ARM step until";
        size = 4;
    } else {
        LOG(DEBUG) << "Using THUMB step until";
        size = 4;
    }

    if (!stepUntil(tid, REGISTERS_PC(regs) + size)) {
        LOG(ERROR) << "Could not single step.";
        return false;
    }

#else
    long ret = ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    int status;
    pid_t pid;
    if (!wait(&status, &pid)) {
        LOG(DEBUG) << "Cannot wait for process.";
    }

    assert(WIFSTOPPED(status));
    int tmp = WSTOPSIG(status);

    if (signo) {
        *signo = tmp;
    }
#endif

    return true;
}

/*!
 * Read a single byte from the tracee memory space.
 * @param address
 * @param res
 * @return
 */
uint8_t Debugger::read_byte(uintptr_t address, bool *res = 0) {
    return peek<uint8_t>(address, res);
}

/*!
 * Read a single two byte word from the tracee memory space.
 * @param address
 * @param res
 * @return
 */
uint16_t Debugger::read_word(uintptr_t address, bool *res = 0) {
    return peek<uint16_t>(address, res);
}

/*!
 * Read a single four byte dword from the tracee memory space.
 * @param address
 * @param res
 * @return
 */
uint32_t Debugger::read_dword(uintptr_t address, bool *res = 0) {
    return peek<uint32_t>(address, res);
}

/*!
 * Read a single eight byte qword from the tracee memory space.
 * @param address
 * @param res
 * @return
 */
uint64_t Debugger::read_qword(uintptr_t address, bool *res = 0) {
    return peek<uint64_t>(address, res);
}

/*!
 * Write an arbitrary number of bytes into tracees address space.
 * @param address
 * @param buffer
 * @param size
 * @return
 */
bool Debugger::write_memory(uintptr_t address, const unsigned char *buffer, size_t size) {
    unsigned int ndwords = size / sizeof(uint32_t);
    unsigned int rem = size % sizeof(uint32_t);

    const uint32_t *src_buffer = reinterpret_cast<const uint32_t *>(buffer);
    bool res;

    // Get each dword.
    for (unsigned int i = 0; i < ndwords; ++i) {
        write_dword(address + i * 4, src_buffer[i], &res);
        if (!res) {
            return res;
        }
    }

    // Add also the remainding single bytes.
    for (unsigned int i = 0; i < rem; ++i) {
        write_byte(address + (ndwords * 4) + i, buffer[(ndwords * 4) + i], &res);
        if (!res) {
            return res;
        }
    }

    return true;
}

/*!
 * Write a string 'string_' to address 'address'.
 *
 * @param address
 * @param string_
 * @return
 */
bool Debugger::write_string(uintptr_t address, string string_) {
    return write_memory(address, reinterpret_cast<const unsigned char *>(string_.c_str()),
            string_.size() + 1);
}

/*!
 * Write the instruction 'ins' at address 'address', if address is not
 * specified, write the instruction to the current PC value.
 *
 * @param ins
 * @param address
 * @return
 */
bool Debugger::write_instruction(Instruction ins, uintptr_t address) {
    if (address == 0) {
        getPC(m_lead_process->pid(), &address);
    }

    return write_memory(address, ins.m_bytes, ins.m_size);
}

/*!
 * Push a value to the top of the stack. This modifies the SP value.
 * This assumes that the stack grows toward smaller addresses.
 * The size of the pushed value will depend on the architecture DWORD size.
 * @param value
 * @return
 */
bool Debugger::push_value(pid_t tid, uintptr_t value) {
    uintptr_t curr_sp;
    if (!getSP(tid, &curr_sp)) {
        LOG(ERROR) << "Could not get SP value";
        return false;
    }

    uintptr_t new_sp = curr_sp - sizeof(value);

    // Make room for the variable
    if (!setSP(tid, new_sp)) {
        LOG(ERROR) << "Could not set SP value";
        return false;
    }

    if (!write_memory(new_sp, reinterpret_cast<const unsigned char *>(&value), sizeof(value))) {
        LOG(ERROR) << "Could not push value to the stack";
        return false;
    }

    return true;
}

/*!
 * Pop a value from the top of the stack. This modifies the SP value.
 * This assumes that the stack grows toward smaller addresses.
 * @param value
 * @return
 */
bool Debugger::pop_value(pid_t tid, uintptr_t *value) {
    uintptr_t curr_sp;
    if (!getSP(tid, &curr_sp)) {
        LOG(ERROR) << "Could not get SP value";
        return false;
    }

    // Read the value at the top of the stack.
    if (!read_memory(curr_sp, reinterpret_cast<unsigned char *>(value), sizeof(*value))) {
        LOG(ERROR) << "Could not pop value from the stack";
        return false;
    }

    uintptr_t new_sp = curr_sp + sizeof(*value);

    // Make room for the variable
    if (!setSP(tid, new_sp)) {
        LOG(ERROR) << "Could not set SP value";
        return false;
    }

    return true;
}

/*!
 * Fill the memory range [address, address+size) with 'byte' value.
 *
 * @param address
 * @param byte
 * @param size
 * @return
 */
bool Debugger::fill_memory(uintptr_t address, int byte, size_t size) {
    unsigned char * buffer = static_cast<unsigned char *>(malloc(size));
    if (!buffer) {
        LOG(ERROR) << "Could not allocate memory.";
        return false;
    }

    memset(static_cast<void *>(buffer), byte, size);

    if (!write_memory(address, buffer, size)) {
        LOG(ERROR) << "Culd not fill memory correctly";
        free(buffer);
        return false;
    }

    free(buffer);

    return true;
}

/*!
 * Read a chunk of memory from the tracee memory space.
 * @param address
 * @param size
 * @param buffer
 * @return
 */
bool Debugger::read_memory(uintptr_t address, unsigned char *buffer, size_t size) {
    unsigned int ndwords = size / sizeof(uint32_t);
    unsigned int rem = size % sizeof(uint32_t);

    uint32_t *dst_buffer = reinterpret_cast<uint32_t *>(buffer);
    bool res;

    // Get each dword.
    for (unsigned int i = 0; i < ndwords; ++i) {
        dst_buffer[i] = read_dword(address + i * 4, &res);
        if (!res) {
            return false;
        }
    }

    // Add also the remainding single bytes.
    for (unsigned int i = 0; i < rem; ++i) {
        buffer[ndwords * 4] = read_byte(address + (ndwords * 4) + i, &res);
        if (!res) {
            return false;
        }
    }

    return true;
}

/*!
 * Read a string from the tracee address space. A string is defined as a series of bytes
 * that end up on a single null terminator. The null terminator is a single zero byte in the
 * case of non unicode strings and two consecutive zero bytes on unicode strings.
 * @param address
 * @param buffer
 * @param size
 * @param unicode
 * @return
 */
bool Debugger::read_string(uintptr_t address, unsigned char *buffer, size_t size, bool unicode =
        false) {
    uint32_t current = 0;
    unsigned int i = 0;
    bool res;

    // Read byte by byte and check
    do {
        if (unicode) {
            current = static_cast<uint32_t>(read_word(address + i * sizeof(uint16_t), &res));
            if (!res) {
                return false;
            }

            i += sizeof(uint16_t);
        } else {
            current = static_cast<uint32_t>(read_word(address + i * sizeof(uint8_t), &res));
            if (!res) {
                return false;
            }

            i += sizeof(uint8_t);
        }
    } while (current && i < size && res);

    // If the last char is not null fill return the empty string.
    if (current != 0) {
        memset(buffer, 0x00, size);
        return false;
    }

    return true;
}

/*!
 * Write a byte into tracee's address space.
 * @param address
 * @param val
 * @param res
 */
void Debugger::write_byte(uintptr_t address, uint8_t val, bool *res = 0) {
    poke<uint8_t>(address, val, res);
}

/*!
 * Write two bytes into tracee's address space.
 * @param address
 * @param val
 * @param res
 */
void Debugger::write_word(uintptr_t address, uint16_t val, bool *res = 0) {
    poke<uint16_t>(address, val, res);
}

/*!
 * Write four bytes into tracee's address space.
 * @param address
 * @param val
 * @param res
 */
void Debugger::write_dword(uintptr_t address, uint32_t val, bool *res = 0) {
    poke<uint32_t>(address, val, res);
}

/*!
 * Write eight bytes into tracee's address space.
 * @param address
 * @param val
 * @param res
 */
void Debugger::write_qword(uintptr_t address, uint64_t val, bool *res = 0) {
    poke<uint64_t>(address, val, res);
}

/*!
 * Copy the tracee's general-purpose registers into 'regs'.
 * @param regs
 * @return
 */
bool Debugger::getRegisters(pid_t tid, Registers *regs) {
    long ret = ptrace(PTRACE_GETREGS, tid, NULL, (void *) regs);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Set the tracee's general-purpose registers to 'regs'.
 * @param regs
 * @return
 */
bool Debugger::setRegisters(pid_t tid, const Registers *regs) {
    long ret = ptrace(PTRACE_SETREGS, tid, NULL, (void *) regs);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Get the instruction counter value into 'address'.
 * @param address
 * @return
 */
bool Debugger::getPC(pid_t tid, uintptr_t *address) {
    Registers regs;
    bool ret = getRegisters(tid, &regs);

#ifdef __x86_64__
    *address = regs.rip;
#elif __i386__
    *address = regs.eip;
#elif __arm__
    *address = regs.pc;
#else
#error "Architecture not supported";
#endif

    return ret;
}

/*!
 * Set the instruction pointer value to 'address'.
 * @param address
 * @return
 */
bool Debugger::setPC(pid_t tid, uintptr_t address) {
    Registers regs;
    bool ret = getRegisters(tid, &regs);
    if (!ret) {
        return false;
    }

#ifdef __x86_64__
    regs.rip = address;
#elif __i386__
    regs.eip = address;
#elif __arm__
    regs.pc = address;
#else
#error "Architecture not supported";
#endif

    ret = setRegisters(tid, &regs);

    return ret;
}

/*!
 * Set the value of the stack pointer.
 * This is the preferred method to change the stack pointer value
 * since setting multiple registers and the stack pointer was causing
 * problems on some architectures.
 *
 * @param tid
 * @param address
 * @return
 */
bool Debugger::setSP(pid_t tid, uintptr_t address) {
    Registers regs;
    bool ret = getRegisters(tid, &regs);
    if (!ret) {
        return false;
    }

#ifdef __x86_64__
    regs.rsp = address;
#elif __i386__
    regs.esp = address;
#elif __arm__
    regs.sp = address;
#else
#error "Architecture not supported";
#endif

    ret = setRegisters(tid, &regs);

    return ret;
}

/*!
 * Get the value of the stack pointer.
 * @param tid
 * @param address
 * @return
 */
bool Debugger::getSP(pid_t tid, uintptr_t *address) {
    Registers regs;
    bool ret = getRegisters(tid, &regs);

#ifdef __x86_64__
    *address = regs.rsp;
#elif __i386__
    *address = regs.esp;
#elif __arm__
    *address = regs.sp;
#else
#error "Architecture not supported";
#endif

    return ret;
}

/*!
 * Restart the stopped tracee process optionally sending the signal 'signum'
 * to the tracee process.
 * @param signum
 * @return
 */
bool Debugger::cont(pid_t tid, int signum) {
    LOG(DEBUG) << "Continuing process " << tid;

    errno = 0;
    long ret = ptrace(PTRACE_CONT, tid, NULL, (void *) signum);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Kill the tracee.
 * @return
 */
bool Debugger::kill(pid_t tid) {
    LOG(DEBUG) << "Killing process " << tid;
    long ret = ptrace(PTRACE_KILL, tid, NULL, NULL);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Stop all the threads running on the process leader.
 * @return
 */
bool Debugger::stopAll() {
    LOG(INFO) << "Stopping all threads";
    int non_stopped = 0;

    ThreadList &tl = m_lead_process->getThreadList();

    // Call stop for each thread.
    for (auto it = tl.m_threads.begin(); it != tl.m_threads.end(); ++it) {
        // Send SIGSTOP to the thread.
        if (it->first && !stop(it->first)) {
            non_stopped++;
        }
    }

    return non_stopped == 0;
}

/*!
 * Stop all the non stopped threads.
 * @return
 */
bool Debugger::enterAtomic() {
    // TODO: Implement.
    return true;
}

/*!
 * Continue the threads stopped by Debugger::enterAtomic. This
 * does _not_ continue threads that were stopped by other means.
 * @return
 */
bool Debugger::leaveAtomic() {
    // TODO: Implement.
    return true;
}


/*!
 * Continue all the debugged threads.
 *
 * @return
 */
bool Debugger::continueAll() {
    LOG(INFO) << "Continuing all threads";
    int non_continued = 0;

    ThreadList &tl = m_lead_process->getThreadList();

    // Call stop for each thread.
    for (auto it = tl.m_threads.begin(); it != tl.m_threads.end(); ++it) {
        // Send SIGCONT to the thread.
        if (!cont(it->first)) {
            non_continued++;
        }
    }

    return non_continued == 0;

}

/*!
 * Stop the thread identified by 'tid'.
 * @return
 */
bool Debugger::stop(pid_t tid) {
    LOG(DEBUG) << "Stopping process " << tid;
    int ec = ::kill(tid, SIGSTOP);
    if (ec == -1) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Wait for a process to change state.
 *
 * @param status
 * @param pid
 * @return
 */
bool Debugger::wait(int *status, pid_t *pid) {
    *pid = waitpid(-1, status, __WALL);
    if (*pid == -1) {
        LOG(DEBUG) << strerror(errno);
        return false;
    }

    return true;
}

/*!
 * Continue the process until a state change occours.
 * @return
 */
bool Debugger::loop() {
    shared_ptr<Process> process = getLeaderProcess();

    // If we had any delayed breakpoints enable them.
    if (m_delayed_breakpoints) {
        LOG(DEBUG) << "Enabling delayed breakpoints";

        BOOST_FOREACH(breakmap_t::value_type &value, m_breakpoints) {
            enableBreakpoint(value.second);
        }

        m_delayed_breakpoints = false;
    }

    LOG(INFO) << "Entered debugging loop, continuing leader process.";

    // Continue the process since either attaching or executing it will stop the process.
    if (!continueAll()) {
        LOG(ERROR) << "Failed to resume stopped process.";
        return false;
    }

    int status, signo;
    pid_t pid;

    // Loop while we have not received a sigint and we have threads.
    while (!got_sigint && getLeaderProcess()->getNumberOfThreads()) {
        // Wait for state changes on the debuggee.
        pid = waitpid(-1, &status, WNOHANG | __WALL);
        if (pid == -1) {
            if (errno == EINTR)
                continue;

            LOG(ERROR) << "Cannot wait for process events.";
            break;
        } else if (pid == 0) {
            // There was no process in a waitable state.
            continue;
        }

#ifdef __arm__
// Android does not support WIFICONTINUED, it uses WIFSTOPPED instead.
#define WIFCONTINUED(x) 0
#endif

        if (WIFSTOPPED(status)) {
            // Child process that is currently stopped.
            // LOG(INFO) << "Child stopped";

        } else if (WIFEXITED(status)) {
            // Child process that terminated normally.
            LOG(INFO) << "Child " << pid << " exited";
            continue;

        } else if (WIFSIGNALED(status)) {
            // Child process that terminated due to the receipt of a signal that was not caught
            LOG(INFO) << "Child " << pid << " signaled";
            continue;

        } else if (WIFCONTINUED(status)) {
            // Child process that has continued from a job control stop.
            LOG(INFO) << "Child " << pid << " continued";

        }

        // Get detailed information about the signal.
        siginfo_t siginfo;
        if (getSignalInformation(pid, &siginfo)) {
            signo = siginfo.si_signo;

            LOG(INFO) << "Child " << pid << " stopped by signal `" << strsignal(signo)
                    << "' handling ...";

            switch (signo) {
                case SIGTRAP:
                    switch (siginfo.si_code) {
                        case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
                            // Handle thread creation.
                            LOG(INFO) << "Thread created";
                            onThreadCreateEvent(pid);
                            signo = 0;
                            break;

                        case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
                            // Stop before return from execve(2).
                            LOG(INFO) << "Thread called execve";
                            signo = 0;
                            break;

                        case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
                            // Stop before exit
                            LOG(INFO) << "Thread called exit";
                            onThreadDestroyEvent(pid);
                            signo = 0;
                            break;

                        case TRAP_BRKPT:
                            // Process breakpoint
                            onBreakpointEvent(pid);
                            signo = 0;
                            break;

                        default:
                            assert(false && "Unexpected SIGTRAP code!");
                            break;
                    }

                    break;

                default:
                    break;
            }
        }

        // Check if we have event handlers.
        if (m_handlers.num_slots()) {
            m_handlers(signo);
        }

        // Continue the process again since we have nothing to do with this signal.
        if (!cont(pid, signo)) {
            LOG(ERROR) << "Could not continue process.";
        }
    }

    // Stop all the threads.
    stopAll();

    // Disable all breakpoints.
    BOOST_FOREACH(breakmap_t::value_type &value, m_breakpoints) {
        disableBreakpoint(value.second);
    }

    return true;
}

/*!
 * Execute a new process under the debugger and set it as the session leader.
 *
 * @param filename
 * @param args
 * @return
 */
shared_ptr<Process> Debugger::execute(string filename, vector<string> args) {
    pid_t child;
    shared_ptr<Process> ret = make_shared<Process>();

    unsigned int numArgs = args.size();

    // TODO: Use boost::scoped_ptr
    char **argv;

    if (!numArgs) {
        argv = new char*[2];

        size_t i = filename.rfind("/");
        if (i != string::npos) {
            argv[0] = strdup(string(filename, i + 1, filename.length()).c_str());
        } else {
            argv[1] = "noname";
        }

        argv[1] = NULL;

    } else {
        argv = new char*[numArgs + 1];
        for (unsigned int i = 0; i < numArgs; ++i) {
            argv[i] = strdup(args[i].c_str());
        }

        argv[numArgs] = NULL;
    }

    LOG(INFO) << "Executing " << filename;

    child = fork();

    switch (child) {
        case 0:
            LOG(INFO) << "Forked new process ...";

            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                LOG(ERROR) << "Error trying to trace child.";
                exit(-1);
            }

            setgid(getgid());

            setpgid(0, 0);

            execv(filename.c_str(), argv);

            // Should never reach this unless execv fails.
            exit(-1);
            break;

        case -1:
            LOG(ERROR) << "Could not fork: " << strerror(errno);
            break;

        default:
            LOG(INFO) << "Waiting for child " << child << " to send the attach signal.";

            int status;
            pid_t pid;
            if (!wait(&status, &pid)) {
                LOG(DEBUG) << "Cannot wait for process.";
                *ret = Process::invalid();
                break;
            }

            if (WIFEXITED (status)) {
                LOG(ERROR) << "Could not debug child";
                *ret = Process::invalid();
                break;
            }

            assert(WIFSTOPPED (status) && child == pid && "Could not sync with inferior process.");

            // Set some options for the traced child.
            if (!initProcess(child)) {
                *ret = Process::invalid();
                break;
            }

            shared_ptr<Process> process = Process::getProcessByPid(child);
            if (*process == Process::invalid()) {
                LOG(ERROR) << "Could not find our child.";
                *ret = Process::invalid();
                break;
            }

            // This process will be the session leader.
            setLeaderProcess(process);

            // Create a new thread and add it to the process thread list.
            shared_ptr<Thread> new_thread = make_shared < Thread > (process, child);
            getLeaderProcess()->getThreadList().addThread(new_thread);

            if (!process->loadModuleList()) {
                LOG(ERROR) << "Could not load module list.";
                *ret = Process::invalid();
                break;
            }

            ret = process;
            break;
    }

    return ret;
}

Debugger::Debugger() :
        m_delayed_breakpoints(false), m_lead_process(), m_memory_cache(this) {
    signal(SIGCHLD, SIG_DFL);
    signal(SIGINT, sigint_handler);
}

/*!
 * Peek a value from the tracee address space.
 * @param address
 * @param res
 * @return
 */
template<typename T> T Debugger::peek(uintptr_t address, bool *res) {
    if (res) {
        *res = false;
    }

    union u {
            long val;
            T readValue;
    } value;

    errno = 0;
    value.val = ptrace(PTRACE_PEEKDATA, m_lead_process->pid(), (void *) address, NULL);
    if (value.val == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << m_lead_process->pid() << ")";
        return 0;
    }

    if (res) {
        *res = true;
    }

    return value.readValue;
}

/*!
 * Write 'value' into address inside the tracee address space.
 * @param address
 * @param value
 * @param res
 */
template<typename T> void Debugger::poke(uintptr_t address, T value, bool *res) {
    if (res) {
        *res = false;
    }

    // Read the original value.
    errno = 0;
    long orig_val = ptrace(PTRACE_PEEKDATA, m_lead_process->pid(), (void *) address, 0);
    if (orig_val == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << m_lead_process->pid() << ")";
        return;
    }

    // Replace only the bytes we want to set, leave the others intact.
    memcpy(reinterpret_cast<void *>(&orig_val), reinterpret_cast<void *>(&value), sizeof(T));

    errno = 0;
    long ret = ptrace(PTRACE_POKEDATA, m_lead_process->pid(), (void *) address, (void *) orig_val);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << m_lead_process->pid() << ")";
        return;
    }

    if (res) {
        *res = true;
    }
}

/*!
 * Handle the destruction of an execution thread.
 *
 * @param tid
 * @return
 */
bool Debugger::onThreadDestroyEvent(pid_t tid) {
    LOG(INFO) << "Destroyed thread " << tid;

    // Remove the thread from the thread list.
    shared_ptr<Thread> thread = getLeaderProcess()->getThreadList().getThreadByID(tid);
    if (*thread == Thread::invalid()) {
        LOG(ERROR) << "Cannot destroy untracked thread " << tid;
        return false;
    }

    getLeaderProcess()->getThreadList().removeThreadByID(tid);

    return true;
}

/*!
 * Handle the creation of an execution thread.
 *
 * @param tid
 * @return
 */
bool Debugger::onThreadCreateEvent(pid_t tid) {
    // Get the pid of the new thread.
    pid_t new_pid;
    long ret = ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_pid);
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    LOG(INFO) << "Created new thread " << new_pid;

    // Create a new thread and add it to the process thread list.
    shared_ptr<Thread> new_thread = make_shared < Thread > (getLeaderProcess(), new_pid);
    getLeaderProcess()->getThreadList().addThread(new_thread);

    return true;
}

/*!
 * Dispatch SIGTRAP to its corresponding breakpoint handler.
 * @return
 */
bool Debugger::onBreakpointEvent(pid_t tid) {
    // 18:10 <@Scrippie> but if you single step that thread over a syscall that suspends it you have deadlocks
    // 18:10 <@sergio> unlol glad you bring the british humour while wtbw isnt here ;)
    // 18:10 <@Scrippie> so it's not completely fool proof
    // 18:10 <@agustin> oh right, good one
    // 18:10 <@agustin> never thought about it
    // 18:10 <@Scrippie> could happen if one of the other threads is supposed to wake it up
    // 18:10 <@Scrippie> small chance, but still
    // 18:10 <@Scrippie> also, if you wake the other threads up
    // 18:10 <@Scrippie> you need to ensure you don't miss breakpoint events
    // 18:10 <@Scrippie> what i did was actually single step /all/ threads
    // 18:11 <@Scrippie> and then if any one of those is at the address the breakpoint was at
    // 18:11 <@Scrippie> i fake a debug event
    // 18:11 <@Scrippie> that way you don't deadlock and don't miss stuff
    // 18:11 <@Scrippie> but it's a bit cumbersome to write up
    // 18:11 <@agustin> yeah but we love convoluted =D
    // 18:11 <@Scrippie> so i can understand anyone going: fuck it, single stepping the thread that hit the 0xcc works
    // 18:11 <@Scrippie> let's leave the rest sleeping
    // 18:12 <@Scrippie> \o/

    LOG(INFO) << "Dispatching breakpoints";

    uintptr_t pc;
    getPC(tid, &pc);

    // PC is already past the breakpoint, fix PC.
    pc -= 1;

    auto it = m_breakpoints.find(pc);
    if (it == m_breakpoints.end()) {
        return false;
    }

    Breakpoint breakpoint = it->second;
    breakpoint.hit();

    // Disable the breakpoint so the breakpoint handler sees memory as it should.
    disableBreakpoint(breakpoint);

    // Go back to the start of the instruction.
    setPC(tid, pc);

    // Execute the handler for this breakpoint.
    breakpoint.handle(this);

    // Execute the instruction.
    singleStep(tid);

    // Re-enable the breakpoint so it can be hit again.
    enableBreakpoint(breakpoint);

    LOG(DEBUG) << "BREAK HITS " << breakpoint.hits();
    return true;
}

/*!
 * Attach to 'pid' and wait until the process is stopped.
 * Here we will attach to a new session leader.
 * This function leaves the attached process in stopped state.
 *
 * @param pid
 * @return
 */
bool Debugger::attach(shared_ptr<Process> process) {
    // One can only attach to a leader project once.
    if (m_lead_process && *m_lead_process != Process::invalid()) {
        LOG(INFO) << "Detaching from previous attached session.";
        detach();
    }

    // Collection of threads we discover by reading /proc
    map<pid_t, bool> toAttach;

    // Find all the process threads by looking at /proc/<pid>/task. Iterate until there are no more changes.
    while (process->getThreads(toAttach)) {
        for (auto it = toAttach.begin(); it != toAttach.end(); ++it) {
            // If the thread was not already attached.
            if (it->second == false) {
                pid_t tid = it->first;
                LOG(INFO) << "Attaching to thread with pid " << tid;

                // The tracee will stop but might not do it right when this call ends.
                errno = 0;
                if (ptrace(PTRACE_ATTACH, tid, 0, 0) == -1 && errno) {
                    LOG(ERROR) << strerror(errno) << " (" << tid << ")";
                    return false;
                }

                LOG(INFO) << "Waiting for thread";

                int status = 0;
                if (waitpid(-1, &status, __WALL) == -1 || !WIFSTOPPED(status)) {
                    // No such thread. The thread may have exited.
                    if (errno == ESRCH) {
                        LOG(INFO) << "No such thread, the thread might have exited before attaching.";
                        toAttach.erase(it);
                        continue;
                    }

                    LOG(ERROR) << strerror(errno);
                    return false;
                }

                LOG(INFO) << "Attached to child " << tid;

                // Set some options for the traced child.
                if (!initProcess(tid)) {
                    return false;
                }

                // Create a new thread and add it to the process thread list.
                shared_ptr<Thread> new_thread = make_shared < Thread > (process, tid);
                process->getThreadList().addThread(new_thread);

                // Mark the thread as attached.
                it->second = true;
            }
        }
    }

    if (!process->loadModuleList()) {
        LOG(ERROR) << "Could not load module list.";
    }

    // This process will be the session leader.
    setLeaderProcess(process);

    return true;
}

/*!
 * Detach from the currently debugged process. This will end the debugging session
 * since it will detach from the session leader and all its threads.
 * @return
 */
bool Debugger::detach() {
    if (!stopAll()) {
        LOG(INFO) << "Could not stop _all_ threads to detach.";
    }

    int non_detached = 0;

    ThreadList &tl = m_lead_process->getThreadList();

    // Call PTRACE_DETACH for each thread.
    for (auto it = tl.m_threads.begin(); it != tl.m_threads.end(); ++it) {
        LOG(INFO) << "Dettaching from pid " << it->first;

        if (ptrace(PTRACE_DETACH, it->first, NULL, NULL) == -1) {
            LOG(DEBUG) << strerror(errno) << " (" << it->first << ")";
            non_detached++;
        }

        // We cannot use ptrace to continue the process anymore.
        ::kill(it->first, SIGCONT);
    }

    m_lead_process = make_shared<Process>();

    return non_detached == 0;
}

/*!
 * Add a new breakpoint and enable it.
 * @param address
 * @param handler
 * @return
 */
Breakpoint Debugger::addBreakpoint(uintptr_t address, Breakpoint::handler_t handler) {
    LOG(DEBUG) << "Added breakpoint";

    // Check if it already exists.
    auto tmp = m_breakpoints.find(address);
    if (tmp != m_breakpoints.end()) {
        return tmp->second;
    }

    Breakpoint breakpoint(address, handler);
    m_breakpoints.insert(make_pair(address, breakpoint));

    // Actually write the breakpoint in memory.
    enableBreakpoint(breakpoint);

    return breakpoint;
}

/*!
 * Delete a breakpoint.
 * @param breakpoint
 * @return
 */
bool Debugger::delBreakpoint(Breakpoint &breakpoint) {
    LOG(INFO) << "Removed breakpoint";

    // Check if it exists.
    if (m_breakpoints.find(breakpoint.address()) == m_breakpoints.end()) {
        return false;
    }

    // Restore the original instruction iif the bp was enabled.
    if (breakpoint.enabled()) {
        bool ret;
        uint32_t original = breakpoint.getReplaced();
        write_dword(breakpoint.address(), original, &ret);
        if (!ret) {
            return false;
        }

    }

    // Remove the breakpoint.
    m_breakpoints.erase(breakpoint.address());

    return true;
}

/*!
 * Enable an existing breakpoint.
 * @param breakpoint
 * @return
 */
bool Debugger::enableBreakpoint(Breakpoint &breakpoint) {
    LOG(INFO) << "Enabling breakpoint";

    if (breakpoint.enabled()) {
        return false;
    }

    bool ret;

    // Save a copy of the replaced instruction(s).
    uint32_t replaced = read_dword(breakpoint.address(), &ret);
    if (!ret) {
        return false;
    }

    breakpoint.setReplaced(replaced);

    // Write the int3 instruction.
    write_dword(breakpoint.address(), (replaced & ~0xff) | 0xcc, &ret);
    if (!ret) {
        return false;
    }

    // Enable the breakpoint.
    breakpoint.enable();

    return true;
}

/*!
 * Disable an existing breakpoint.
 * @param breakpoint
 * @return
 */
bool Debugger::disableBreakpoint(Breakpoint &breakpoint) {
    LOG(INFO) << "Disabling breakpoint";

    if (!breakpoint.enabled()) {
        return false;
    }

    bool ret;
    write_dword(breakpoint.address(), breakpoint.getReplaced(), &ret);
    if (!ret) {
        return false;
    }

    breakpoint.disable();

    return true;
}

/*!
 * Continue until reaching 'address' and then return back the control to
 * the debugger.
 *
 * @param address
 * @return
 */
bool Debugger::stepUntil(pid_t tid, uintptr_t address) {
    bool ret;
    // Backup the instruction.
    uint32_t replaced = read_dword(address, &ret);
    if (!ret) {
        LOG(ERROR) << "Could not read instruction to replace.";
        return false;
    }

    // Write the breakpoint instruction.
#ifdef __arm__
    Registers regs;
    if(!getRegisters(tid, &regs)) {
        LOG(ERROR) << "Could not read registers.";
        return false;
    }

    if ((regs.cpsr & CPSR_MODE) == ARM_MODE) {
        LOG(DEBUG) << "Using ARM Breakpoint";
        write_dword(address, BREAKPOINT_ARM, &ret);
    } else {
        LOG(DEBUG) << "Using THUMB Breakpoint";
        write_dword(address, BREAKPOINT_THUMB, &ret);
    }
#else
    write_dword(address, (replaced & ~0xff) | 0xcc, &ret);
#endif

    if (!ret) {
        LOG(ERROR) << "Could not write breakpoint.";
        return false;
    }

    // Continue executing the process.
    if (!cont(tid)) {
        LOG(ERROR) << "Could not continue.";
        return false;
    }

    // Check if the breakpoint hit.
    int status;
    while (::wait(&status) != -1) {
        assert(WIFSTOPPED(status));

        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
                LOG(INFO) << "Temporary breakpoint hit.";
                break;

            } else if (WSTOPSIG(status) == SIGSTOP) {
                LOG(INFO) << "Got SIGSTOP continuing";

                if (!cont(tid, 0)) {
                    LOG(ERROR) << "Could not proxy signal to process";
                    return false;
                }
            } else {
                LOG(INFO) << "Got signal (" << strsignal(WSTOPSIG(status))
                        << ") we cannot continue.";
                return false;
            }
        }
    }

    // Restore the instruction.
    write_dword(address, replaced, &ret);
    if (!ret) {
        LOG(ERROR) << "Could not restore instruction.";
        return false;
    }

    return true;
}

/*!
 * Disable address space randomization.
 * @return
 */
bool Debugger::disableASLR() {
#ifndef __arm__
    errno = 0;

    int orig = personality(0xffffffff);
    if (errno == 0 && !(orig & ADDR_NO_RANDOMIZE)) {
        personality(orig | ADDR_NO_RANDOMIZE);
    }

    if (errno != 0 || !(personality(0xffffffff) & ADDR_NO_RANDOMIZE)) {
        LOG(ERROR) << "Error disabling address space randomization: " << strerror(errno);
        return false;
    }

    return true;
#else
    return false;
#endif
}

/*!
 * Enable address space randomization.
 * @return
 */
bool Debugger::enableASLR() {
#ifndef __arm__
    errno = 0;

    int orig = personality(0xffffffff);
    if (errno == 0 && (orig & ADDR_NO_RANDOMIZE)) {
        personality(orig & ~ADDR_NO_RANDOMIZE);
    }

    if (errno != 0 || (personality(0xffffffff) & ADDR_NO_RANDOMIZE)) {
        LOG(ERROR) << "Error enabling address space randomization: " << strerror(errno);
        return false;
    }

    return true;
#else
    return false;
#endif
}

/*!
 * Set tracing options on the debuggee so we get informed by thread
 * creation, destruction and exec.
 *
 * @param process
 * @return
 */
bool Debugger::initProcess(pid_t tid) {
    LOG(INFO) << "Setting debugger options.";
    int ptrace_opts = 0;

    // Have the child raise an event on exit.
    ptrace_opts |= PTRACE_O_TRACEEXIT;

    // Have the tracer trace threads which spawn in the inferior process.
    ptrace_opts |= PTRACE_O_TRACECLONE;

    // Have the tracer notify us before execve returns
    ptrace_opts |= PTRACE_O_TRACEEXEC;

    // NOTE: If we ever need to trace the debugee childs we need to
    // set the PTRACE_O_TRACEFORK and PTRACE_O_TRACEVFORK options.

    long ret = ptrace(PTRACE_SETOPTIONS, tid, 0, reinterpret_cast<void *>(ptrace_opts));
    if (ret == -1 && errno) {
        LOG(DEBUG) << strerror(errno) << " (" << tid << ")";
        return false;
    }

    return true;
}

/*!
 * Call mmap to allocate a memory region on the debuggee.
 *
 * @param size
 * @param permissions
 * @return
 */
uintptr_t Debugger::allocateMemory(size_t length, int permissions) {
    uintptr_t allocated_addr = -1;

    int prot = 0;
    if (permissions & Readable)
        prot |= PROT_READ;

    if (permissions & Writable)
        prot |= PROT_WRITE;

    if (permissions & Executable)
        prot |= PROT_EXEC;

    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    void *ret = 0;
    if (!Remote::call_mmap(this, &ret, 0, length, prot, flags, 0, 0)) {
        LOG(ERROR) << "Could not call mmap on the debuggee.";
        return -1;
    }

    // Check if mmap failed with MAP_FAILED
    allocated_addr = reinterpret_cast<uintptr_t>(ret);
    if (allocated_addr == INVALID_ADDRESS) {
        LOG(ERROR) << "mmap failed";
        return -1;
    }

    LOG(INFO) << "mmap allocated memory at " << ret;

    m_address_to_size[allocated_addr] = length;

    return allocated_addr;

}

/*!
 * Free the memory on the debuggee that was returned by 'allocateMemory'.
 * @param address
 */
void Debugger::freeMemory(uintptr_t address) {
    auto pos = m_address_to_size.find(address);

    if (pos != m_address_to_size.end()) {
        void *ret = 0;
        if (!Remote::call_munmap(this, &ret, reinterpret_cast<void *>(address), pos->second)) {
            LOG(ERROR) << "Could not call munmap on the debuggee.";
        }

        LOG(DEBUG) << "munmap returned " << ret;

        m_address_to_size.erase(pos);
    }
}

/*!
 * Load the library pointed by 'filename' and put the resulting handle in 'handle'.
 * This function assumes that the process is in stopped state and will leave it stopped.
 * @param filename
 * @param handle
 * @return
 */
bool Debugger::loadRemoteLibrary(string filename, void **handle) {
    // TODO: Keep track of 'memory' to release it later.
    // Allocate memory to hold the string.
    uintptr_t memory = getMemoryCache().AllocateMemory(filename.size() + 1, Readable | Writable);
    if (memory == INVALID_ADDRESS) {
        LOG(ERROR) << "Failed loading remote library, memory failed us.";
        return false;
    }

    // Copy the hook path to the process.
    if (!write_string(memory, filename)) {
        LOG(ERROR) << "Failed loading remote library, cannot write to memory.";
        getMemoryCache().DeallocateMemory(memory);
        return false;
    }

    // Call dlopen on the remote thread.
    if (!Remote::call_dlopen(this, handle, reinterpret_cast<char *>(memory),
            RTLD_NOW | RTLD_GLOBAL)) {
        LOG(ERROR) << "Failed loading remote library, could not call dlopen.";
        getMemoryCache().DeallocateMemory(memory);
        return false;
    }

    // Save our (filename, handle) tuple to be able to unload by library name.
    if (*handle) {
        LOG(DEBUG) << "Hook library handle value " << *handle;
        m_lib2handle.insert(make_pair(filename, *handle));
    }

    return *handle != 0;
}

/*!
 * Call dlclose on the remote library trying to unload. It will
 * not be unloaded if it had additional references from other places
 * or from aborted hook insertions.
 *
 * @param filename
 * @return
 */
bool Debugger::unLoadRemoteLibrary(string filename) {
    void *handle = m_lib2handle[filename];

    LOG(SEEME) << "HANDLE " << handle;

    void *ret = 0;
    if (!Remote::call_dlclose(this, &ret, handle)) {
        LOG(ERROR) << "Could not unload library " << filename;
        return false;
    }

    return ret == 0;
}
