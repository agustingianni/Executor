/*
 * Observer.cpp
 *
 *  Created on: Jul 22, 2013
 *      Author: anon
 */

#include "Debugger.h"
#include "EventHandler.h"
#include "Observer.h"
#include "Logging.h"
#include "Process.h"
#include "Assorted.h"
#include "RemoteCall.h"

#include <zmq.hpp>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <unistd.h>

#include <string>
#include <sstream>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

using namespace std;

boost::random::mt19937 gen;
boost::random::uniform_int_distribution<uint64_t> dist(0x1000000, 0x2000000);

/*!
 * Fill the general purpose registers with random values.
 * @param regs
 */
static void MagicFillGPR(Registers &regs) {
#ifdef __arm__
    regs.r0 = dist(gen);
    regs.r1 = dist(gen);
    regs.r2 = dist(gen);
    regs.r3 = dist(gen);
    regs.r4 = dist(gen);
    regs.r5 = dist(gen);
    regs.r6 = dist(gen);
    regs.r7 = dist(gen);
    regs.r8 = dist(gen);
    regs.r9 = dist(gen);
    regs.r10 = dist(gen);
    regs.r11 = dist(gen);
    regs.r12 = dist(gen);

    regs.sp = dist(gen);
    regs.lr = dist(gen);
    regs.pc = dist(gen);
#else
    regs.r8 = dist(gen);
    regs.r9 = dist(gen);
    regs.r10 = dist(gen);
    regs.r11 = dist(gen);
    regs.r12 = dist(gen);
    regs.r13 = dist(gen);
    regs.r14 = dist(gen);
    regs.r15 = dist(gen);
    regs.rax = dist(gen);
    regs.rbx = dist(gen);
    regs.rcx = dist(gen);
    regs.rdx = dist(gen);
    regs.rdi = dist(gen);
    regs.rsi = dist(gen);
    regs.rbp = dist(gen);
    regs.rsp = dist(gen);
    regs.rip = dist(gen);
#endif
}

Observer::Observer() {
    m_debugger = new Debugger();
}

#define REGSTR(ctx, regname) #regname "=" << ctx.regname << ","

/*!
 * Build a string that represents the values of all the values of the
 * context of a thread.
 *
 * @param context
 * @return
 */
static string RegistersToString(const Registers &context) {
    stringstream ss;

#ifdef __arm__
    ss << REGSTR(context, r0) << REGSTR(context, r1);
    ss << REGSTR(context, r2) << REGSTR(context, r3);
    ss << REGSTR(context, r4) << REGSTR(context, r5);
    ss << REGSTR(context, r6) << REGSTR(context, r7);
    ss << REGSTR(context, r8) << REGSTR(context, r9);
    ss << REGSTR(context, r10) << REGSTR(context, r11);
    ss << REGSTR(context, r12) << REGSTR(context, sp);
    ss << REGSTR(context, lr) << REGSTR(context, pc);
    ss << REGSTR(context, cpsr);
#else
    ss << REGSTR(context, r15) << REGSTR(context, r14);
    ss << REGSTR(context, r13) << REGSTR(context, r12);
    ss << REGSTR(context, rbp) << REGSTR(context, rbx);
    ss << REGSTR(context, r11) << REGSTR(context, r10);
    ss << REGSTR(context, r9) << REGSTR(context, r8);
    ss << REGSTR(context, rax) << REGSTR(context, rcx);
    ss << REGSTR(context, rdx) << REGSTR(context, rsi);
    ss << REGSTR(context, rdi) << REGSTR(context, rip);
    ss << REGSTR(context, eflags) << REGSTR(context, rsp);
#endif

    return ss.str();
}

/*!
 * Enter the observer loop. It will listen for connections
 * and will read instructions to be executed on the sandboxed process.
 *
 * @return
 */
bool Observer::loop() {
    pid_t child = fork();
    if (child == -1) {
        LOG(ERROR) << "Could not fork: " << strerror(errno);
        return false;
    }

    if (child == 0) {
        LOG(INFO) << "Sandbox entering busy loop";
        while (1)
            ;
        exit(-1);
    }

    LOG(INFO) << "Created child " << child << " as a sandbox";

    // Get a handle to the process and attach it.
    shared_ptr<Process> process = Process::getProcessByPid(child);

    if (!m_debugger->attach(process)) {
        LOG(ERROR) << "Could not observe process " << child;
        m_debugger->kill(child);
        return false;
    }

    const unsigned int stack_size = 1024 * 4;
    const unsigned int code_sandbox_size = 1024 * 4;

    // Allocate some memory to play in the remote process.
    uintptr_t code_addr = m_debugger->getMemoryCache().AllocateMemory(code_sandbox_size,
            Readable | Writable | Executable);
    if (code_addr == INVALID_ADDRESS) {
        LOG(ERROR) << "Could not allocate memory on the remote process";
        m_debugger->kill(child);
        return false;
    }

    uintptr_t stack_addr = m_debugger->getMemoryCache().AllocateMemory(stack_size,
            Readable | Writable);
    if (stack_addr == INVALID_ADDRESS) {
        LOG(ERROR) << "Could not allocate memory on the remote process";
        m_debugger->kill(child);
        return false;
    }

    LOG(INFO) << "Allocated code buffer @ " << (void *) code_addr;
    LOG(INFO) << "Allocated new stack   @ " << (void *) stack_addr;

    // Fill the memory with zeros.
    m_debugger->fill_memory(code_addr, 0x00, code_sandbox_size);
    m_debugger->fill_memory(stack_addr, 0x00, stack_size);

    // Get the original values so all the selectors and other stuff are valid.
    Registers original_regs, new_regs;
    m_debugger->getRegisters(process->pid(), &original_regs);

    LOG(INFO) << "Listening for incoming connections on *:4141";

    zmq::message_t request;
    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_REP);
    socket.bind("tcp://*:4141");

    int signo;
    siginfo_t siginfo;

    while (true) {
        LOG(INFO) << "";
        vector<void *> addresses;

        // Wait for next request from client.
        if (!socket.recv(&request)) {
            LOG(ERROR) << "Error receiving message";
            continue;
        }

        LOG(INFO) << "Received instruction from the host of size " << request.size();

        // Write the instruction at our code sandbox.
        if (!m_debugger->write_memory(code_addr,
                reinterpret_cast<const unsigned char *>(request.data()), request.size())) {
            LOG(ERROR) << "Could not write instruction to PC";

            string error("ERROR");
            zmq::message_t reply(error.size());
            memcpy((void *) reply.data(), error.c_str(), error.size());
            socket.send(reply);
            continue;
        }

        // Make a copy so we get all the selectors and stuff right.
        new_regs = original_regs;

        // Fill registers with random values.
        MagicFillGPR(new_regs);

        LOG(INFO) << "Flags: " << (void *) REGISTERS_FLAGS(original_regs);

        // We need a sane flags register.
        REGISTERS_FLAGS(new_regs) = REGISTERS_FLAGS(original_regs);

        // Point PC to the instruction we want to execute.
        REGISTERS_PC(new_regs) = code_addr;

        // TODO: Remove the need for stack reusage.
        // Build a new stack. Calls to mmap will need a stack.
        REGISTERS_SP(new_regs) = stack_addr;
        REGISTERS_BP(new_regs) = stack_addr;

        m_debugger->setRegisters(process->pid(), &new_regs);

        bool stop = false;

        while (!stop) {
            // Get the signal from the child. SIGTRAP means execution went smoothly.
            if (!m_debugger->singleStep(process->pid(), &signo)) {
                LOG(ERROR) << "Could not single stepp instruction.";

                string error("ERROR");
                zmq::message_t reply(error.size());
                memcpy((void *) reply.data(), error.c_str(), error.size());
                socket.send(reply);
                break;
            }

            if (!m_debugger->getSignalInformation(process->pid(), &siginfo)) {
                LOG(ERROR) << "Could not get signal details.";

                string error("ERROR");
                zmq::message_t reply(error.size());
                memcpy((void *) reply.data(), error.c_str(), error.size());
                socket.send(reply);
                break;
            }

            LOG(INFO) << "Signal: " << strsignal(signo) << " " << getpid();

            // If we get a segmentation violation we have to map that address and re-execute.
            if (signo == SIGSEGV) {
                if (siginfo.si_code == SEGV_MAPERR) {
                    void *addr;
                    bool ret = Remote::call_mmap(m_debugger, &addr,
                            System::AlignToPage(siginfo.si_addr), System::PageSize() * 2,
                            PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
                    if (!ret || addr == MAP_FAILED) {
                        LOG(ERROR) << "Could not mmap " << System::AlignToPage(siginfo.si_addr);
                        string error("ERROR");
                        zmq::message_t reply(error.size());
                        memcpy((void *) reply.data(), error.c_str(), error.size());
                        socket.send(reply);
                        break;
                    }

                    // Save the addres for later unmapping.
                    addresses.push_back(siginfo.si_addr);
                    LOG(INFO) << "Mapped address " << addr;
                } else {
                    void *addr;
                    bool ret = Remote::call_mprotect(m_debugger, &addr,
                            System::AlignToPage(siginfo.si_addr), System::PageSize() * 2,
                            PROT_READ | PROT_WRITE);
                    if (!ret || addr == MAP_FAILED) {
                        LOG(ERROR) << "Could not protect "
                                << System::AlignToPage(siginfo.si_addr);
                        string error("ERROR");
                        zmq::message_t reply(error.size());
                        memcpy((void *) reply.data(), error.c_str(), error.size());
                        socket.send(reply);
                        break;
                    }

                    addresses.push_back(siginfo.si_addr);
                    LOG(INFO) << "Protected address " << addr;
                }

            } else if (signo == SIGILL) {
                string error("ILLEGAL");
                zmq::message_t reply(error.size());
                memcpy((void *) reply.data(), error.c_str(), error.size());
                socket.send(reply);
                break;

            } else {
                stop = true;
            }
        }

        if (signo != SIGTRAP)
            continue;

        // Build a string that contains a simple serialized context.
        string response = RegistersToString(new_regs) + "\n";

        m_debugger->getRegisters(process->pid(), &new_regs);

        response += RegistersToString(new_regs) + "\n";

        // Unmap all the addresses we've mapped.
        for (auto addr = addresses.begin(); addr != addresses.end(); ++addr) {
            void *ret;
            if (!Remote::call_munmap(m_debugger, &ret, *addr, System::PageSize() * 2)) {
                LOG(ERROR) << "Failed unmapping address " << *addr;
                string error("ERROR");
                zmq::message_t reply(error.size());
                memcpy((void *) reply.data(), error.c_str(), error.size());
                socket.send(reply);
                continue;
            }

            stringstream ss;
            ss << *addr;
            response += "MEM:" + ss.str() + "\n";
        }

        // Send reply back to client
        zmq::message_t reply(response.size());
        memcpy((void *) reply.data(), response.c_str(), response.size());
        socket.send(reply);
    }

    m_debugger->kill(process->pid());

    return true;
}

int main(int argc, char **argv) {
    Observer observer;
    observer.loop();
}

