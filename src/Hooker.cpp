#include "Debugger.h"
#include "Logging.h"
#include "Assorted.h"
#include "RemoteAllocator.h"
#include <signal.h>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <cstddef>
#include <memory>
#include <boost/algorithm/string.hpp>

using namespace std;

class Hook {
    public:
        Hook(uintptr_t address, string handler_name, uintptr_t handler_address,
                vector<uint8_t> replaced, uintptr_t memory) :
                m_address(address), m_handler_name(handler_name), m_handler_address(
                        handler_address), m_replaced(replaced), m_memory(memory) {
        }

        uintptr_t getAddress() {
            return m_address;
        }

        string getHandlerName() {
            return m_handler_name;
        }

        uintptr_t getHandlerAddress() {
            return m_handler_address;
        }

        vector<uint8_t> getReplacedBytes() {
            return m_replaced;
        }

        size_t getReplacedSize() {
            return m_replaced.size();
        }

        uintptr_t getMemory() {
            return m_memory;
        }

    private:
        uintptr_t m_address;
        string m_handler_name;
        uintptr_t m_handler_address;
        vector<uint8_t> m_replaced;
        uintptr_t m_memory;
};

class Hooker {
        friend class Hook;
    public:
        Hooker(Debugger *debugger, std::string hook_lib);

        // Hook manipulating routines.
        shared_ptr<Hook> addHook(uintptr_t hooked_addr, string handler_name);
        bool delHook(shared_ptr<Hook> hook);
        bool initialize();
        bool destroy();

    private:
        Debugger *m_debugger;
        map<uintptr_t, shared_ptr<Hook> > m_hooks;
        std::string m_hook_lib;
        bool m_initialized;
};

Hooker::Hooker(Debugger *debugger, std::string hook_lib) :
        m_debugger(debugger), m_hook_lib(hook_lib), m_initialized(false) {
}

/*!
 * Initialize the hooking infrastructure by loading the hook library into the remote
 * process.
 * @return
 */
bool Hooker::initialize() {
    // Try to load a shared object into the process.
    void *handle = 0;
    if (!m_debugger->loadRemoteLibrary(m_hook_lib, &handle)) {
        LOG(ERROR) << "Could not load remote library " << m_hook_lib;
        return false;
    }

    m_initialized = true;
    return true;
}

/*!
 * Remove all hooks and unload the hook library.
 * @return
 */
bool Hooker::destroy() {
    m_debugger->stopAll();

    if (!m_initialized) {
        LOG(INFO) << "Hooked already destroyed";
        return true;
    }

    for (const auto& kv : m_hooks) {
        LOG(INFO) << "Deleting hook " << (void *) kv.first;
        delHook(kv.second);
    }

    // TODO: Unloading is making the remote process crash.
#if 0
    if (!m_debugger->unLoadRemoteLibrary(m_hook_lib)) {
        LOG(ERROR) << "Could not unload remote library " << m_hook_lib;
        return false;
    }
#endif

    m_initialized = false;
    return true;
}

shared_ptr<Hook> Hooker::addHook(uintptr_t hooked_addr, string handler_name) {
    size_t replaced_ins_size = 0;
    size_t n_ins = 0;
    string trampoline_jump;
    string trampoline_code;
    uintptr_t trampoline;

    shared_ptr<Hook> hook;
    if (!m_initialized) {
        LOG(ERROR) << "Hooker not initialized";
        return hook;
    }

    if (m_hooks.find(hooked_addr) != m_hooks.end()) {
        LOG(ERROR) << "Hook already exists at that location.";
        return hook;
    }

    uintptr_t scratch = 0;
    shared_ptr<Process> process = m_debugger->getLeaderProcess();

    // Find our hook library and resolve the handler.
    shared_ptr<Module> module = process->getModuleList().find(m_hook_lib);
    if (!module) {
        LOG(ERROR) << "Could not get a handle to " << m_hook_lib;
        return hook;
    }

    // Get the handler address.
    uintptr_t handler_addr = module->resolve(handler_name);
    if (handler_addr == INVALID_ADDRESS) {
        LOG(ERROR) << "Invalid handler name: " << handler_name;
        return hook;
    }

    LOG(SEEME) << "Handler " << handler_name << " at " << (void *) handler_addr;
    LOG(SEEME) << "Function to hook at " << (void *) hooked_addr;

    // Create a backup of the instructions that we will overwrite.
    unsigned char original_bytes[64];
    uintptr_t hooked_addr_aligned = hooked_addr;

#ifdef __arm__
    // The address is aligned to backup the right bytes from the function.
    hooked_addr_aligned = hooked_addr & 0xfffffffe;
    if (!m_debugger->read_memory(hooked_addr_aligned, original_bytes, sizeof(original_bytes))) {
        LOG(ERROR) << "Could not backup instructions replaced by the hook jump.";
        return hook;
    }

    // We decide the hook mode based on the instruction address.
    if (hooked_addr & 1) {
        LOG(INFO) << "Hooking THUMB code";
        // We replace two four byte instructions.
        replaced_ins_size = 4 * 2;

        // Save all the registers.
        // e9 2d 20 00    push    {sp}          ; Save the context
        // e9 2d 5f ff    push    {r0 ... r12, r14}
        trampoline_code.append("\x00\x20\x2d\xe9", 4);
        trampoline_code.append("\xff\x5f\x2d\xe9", 4);

        // Call the hook function and after that jump to the original instructions.
        // e1 a0 00 0d    mov r0, sp            ; The first argument to the hook is the Context structure.
        // e5 9f 80 0c    ldr r8, [pc, #12]     ; Address of the hook function
        // e1 2f ff 38    blx r8                ; Jump to the hook
        // e8 bd 5f ff    pop {r0, ... r12, r14}
        // e5 9d d0 00    ldr sp, [sp]
        // e2 8f f0 05    add pc, pc, #5        ; Skip 4 bytes to land into the 'saved' instructions in THUMB mode.
        // 41 42 43 44    .word   0x41424344    ; This will be the address of our hook function.
        trampoline_code.append("\x0d\x00\xa0\xe1", 4);
        trampoline_code.append("\x0c\x80\x9f\xe5", 4);
        trampoline_code.append("\x38\xff\x2f\xe1", 4);
        trampoline_code.append("\xff\x5f\xbd\xe8", 4);
        trampoline_code.append("\x00\xd0\x9d\xe5", 4);
        trampoline_code.append("\x05\xf0\x8f\xe2", 4);

        LOG(SEEME) << "Handle address " << (void *) handler_addr;

        // Address of the hook function.
        trampoline_code.append(reinterpret_cast<const char*>(&handler_addr), sizeof(handler_addr));

        // DEBUG BREAKPOINT_ARM = 0xe7 f0 01 f0
        trampoline_code.append("\xf0\x01\xf0\xe7", 4);

        // Original instructions that we've replaced.
        trampoline_code.append(reinterpret_cast<const char*>(original_bytes), replaced_ins_size);

        // Address of the original function but skipping the replaced bytes.
        scratch = hooked_addr + replaced_ins_size;
        // trampoline_code.append("\x04\xf0\x1f\xe5", 4); // 0xe51ff004 ldr   pc, [pc, #-4]
        trampoline_code.append("\xdf\xf8\x00\xf0", 4);  // ldr.w   pc, [pc]
        trampoline_code.append(reinterpret_cast<const char*>(&scratch), sizeof(scratch));

        // Address of the trampoline on the debuggee.
        trampoline = m_debugger->getMemoryCache().AllocateMemory(trampoline_code.size(),
                Readable | Writable | Executable);

        // Build the trampoline jump that will call 'trampoline_code' in ARM mode.
        //trampoline_jump.append("\xff\xf7\xfe\xbf", 4);  // DEBUG THUMB INFINITE LOOP
        trampoline_jump.append("\xdf\xf8\x00\xf0", 4);  // ldr.w   pc, [pc]
        trampoline_jump.append(reinterpret_cast<const char*>(&trampoline), sizeof(trampoline));

    } else {
        LOG(INFO) << "Hooking ARM code";

        // We replace two four byte instructions.
        replaced_ins_size = 4 * 2;

        // Save all the registers.
        // e9 2d 20 00    push    {sp}          ; Save the context
        // e9 2d 5f ff    push    {r0 ... r12, r14}
        trampoline_code.append("\x00\x20\x2d\xe9", 4);
        trampoline_code.append("\xff\x5f\x2d\xe9", 4);

        // Call the hook function and after that jump to the original instructions.
        // e1 a0 00 0d    mov r0, sp            ; The first argument to the hook is the Context structure.
        // e5 9f 80 0c    ldr r8, [pc, #12]     ; Address of the hook function
        // e1 2f ff 38    blx r8                ; Jump to the hook
        // e8 bd 5f ff    pop {r0, ... r12, r14}
        // e5 9d d0 00    ldr sp, [sp]
        // e2 8f f0 04    add pc, pc, #4        ; Skip 4 bytes to land into the 'saved' instructions.
        // 41 42 43 44    .word   0x41424344    ; This will be the address of our hook function.
        trampoline_code.append("\x0d\x00\xa0\xe1", 4);
        trampoline_code.append("\x0c\x80\x9f\xe5", 4);
        trampoline_code.append("\x38\xff\x2f\xe1", 4);
        trampoline_code.append("\xff\x5f\xbd\xe8", 4);
        trampoline_code.append("\x00\xd0\x9d\xe5", 4);
        trampoline_code.append("\x04\xf0\x8f\xe2", 4);

        LOG(SEEME) << "Handle address " << (void *) handler_addr;

        // Address of the hook function.
        trampoline_code.append(reinterpret_cast<const char*>(&handler_addr), sizeof(handler_addr));

        // DEBUG BREAKPOINT_ARM = 0xe7 f0 01 f0
        trampoline_code.append("\xf0\x01\xf0\xe7", 4);

        // Original instructions that we've replaced.
        trampoline_code.append(reinterpret_cast<const char*>(original_bytes), replaced_ins_size);

        // Address of the original function but skipping the replaced bytes.
        scratch = hooked_addr + replaced_ins_size;
        trampoline_code.append("\x04\xf0\x1f\xe5", 4); // 0xe51ff004 ldr   pc, [pc, #-4]
        trampoline_code.append(reinterpret_cast<const char*>(&scratch), sizeof(scratch));

        // Address of the trampoline on the debuggee.
        trampoline = m_debugger->getMemoryCache().AllocateMemory(trampoline_code.size(),
                Readable | Writable | Executable);

        // Build the trampoline jump that will call 'trampoline_code'
        trampoline_jump.append("\x04\xf0\x1f\xe5", 4); // 0xe51ff004 ldr   pc, [pc, #-4]
        trampoline_jump.append(reinterpret_cast<const char*>(&trampoline), sizeof(trampoline));
    }

#else
    if (!m_debugger->read_memory(hooked_addr, original_bytes, sizeof(original_bytes))) {
        LOG(ERROR) << "Could not backup instructions replaced by the hook jump.";
        return hook;
    }

    StringDisassembler dis(hooked_addr);
    vector<Instruction> res = dis.disassemble(original_bytes, sizeof(original_bytes), 0);

    const size_t hook_stub_size = 14;

    // Look for the smallest ammount of instructions to overwrite with a 5 byte jmp.
    for (auto ins = res.begin(); ins != res.end(); ++ins) {
        if (replaced_ins_size >= hook_stub_size) {
            LOG(INFO) << "Got enough instructions to replace.";
            break;
        }

        n_ins++;
        replaced_ins_size += ins->m_size;
        LOG(INFO) << (void *) hooked_addr << " " << ins->m_instruction;
    }

    LOG(INFO) << "Found " << n_ins << " instructions that use " << replaced_ins_size
    << " bytes";

    // Just in case I fucked up basic arithmetics.
    assert(replaced_ins_size >= hook_stub_size);

    // Save all the general purpose registers.
    trampoline_code.append("\x54\x50\x53\x51\x52\x56\x57\x55");
    trampoline_code.append("\x41\x50\x41\x51\x41\x52\x41\x53");
    trampoline_code.append("\x41\x54\x41\x55\x41\x56\x41\x57");

    // Save the RFLAGS (pushfq)
    trampoline_code.append("\x9c");

    // Push the first parameter to the hook function, our Context * (mov rdi,rsp)
    trampoline_code.append("\x48\x89\xe7");

    // Call our hook function (call [rip+2])
    trampoline_code.append("\xff\x15\x02\x00\x00\x00", 6);

    // Jump over the address of the hook function (jmp + 8)
    trampoline_code.append("\xeb\x08");

    // Address of the hook function
    trampoline_code.append(reinterpret_cast<const char*>(&handler_addr), sizeof(handler_addr));

    // Restore the RFLAGS (popfq)
    trampoline_code.append("\x9d");

    // Restore general purpose registers
    trampoline_code.append("\x41\x5f\x41\x5e\x41\x5d\x41\x5c");
    trampoline_code.append("\x41\x5b\x41\x5a\x41\x59\x41\x58");
    trampoline_code.append("\x5d\x5f\x5e\x5a\x59\x5b\x58\x5c");

    // Original instructions that we've replaced.
    trampoline_code.append(reinterpret_cast<const char*>(original_bytes), replaced_ins_size);

    // Call the original function (jmp QWORD PTR [rip+0x0])
    trampoline_code.append("\xff\x25\x00\x00\x00\x00", 6);

    // Address of the original function but skipping the replaced bytes.
    scratch = hooked_addr + replaced_ins_size;
    trampoline_code.append(reinterpret_cast<const char*>(&scratch), sizeof(scratch));

    // Address of the trampoline on the debuggee.
    trampoline = m_debugger->getMemoryCache().AllocateMemory(trampoline_code.size(),
            Readable | Writable | Executable);

    // Build the trampoline jump that will call 'trampoline_code'
    trampoline_jump.append("\xff\x25\x00\x00\x00\x00", 6);// jmp QWORD PTR [rip+0x0]
    trampoline_jump.append(reinterpret_cast<const char*>(&trampoline), sizeof(trampoline));

    // Check basic arithmetics, because fuck my brain.
    assert(trampoline_jump.size() <= replaced_ins_size);
    trampoline_jump.append(string(replaced_ins_size - trampoline_jump.size(), '\x90'));

#endif

    LOG(SEEME) << "Trampoline code size " << trampoline_code.size();
    LOG(SEEME) << "Trampoline at        " << (void *) trampoline;
    LOG(SEEME) << "Replaced bytes       " << replaced_ins_size;
    LOG(SEEME) << "Trampoline jmp size  " << trampoline_jump.size();

    // Make sure we got the size right.
    assert(trampoline_jump.size() == replaced_ins_size && "Invalid replaced ins size.");

    // Replace the original instructions with the trampoline jump.
    m_debugger->write_memory(hooked_addr_aligned,
            reinterpret_cast<const unsigned char *>(trampoline_jump.c_str()),
            trampoline_jump.size());

    // Add the code to the trampoline block.
    m_debugger->write_memory(trampoline,
            reinterpret_cast<const unsigned char *>(trampoline_code.c_str()),
            trampoline_code.size());

    // Create a hook and return it.
    vector<uint8_t> replaced = vector<uint8_t>(original_bytes, &original_bytes[replaced_ins_size]);
    hook.reset(new Hook(hooked_addr_aligned, handler_name, handler_addr, replaced, trampoline));

    // Keep track of the hook.
    m_hooks.insert(make_pair(hooked_addr_aligned, hook));

    return hook;
}

bool Hooker::delHook(shared_ptr<Hook> hook) {
    if (!m_initialized) {
        LOG(ERROR) << "Hooked not initialized";
        return false;
    }

    // Check if the hook exists.
    if (m_hooks.find(hook->getAddress()) == m_hooks.end()) {
        LOG(ERROR) << "Hook already removed or never present.";
        return false;
    }

    // TODO: Check that there is no thread with PC in [address : address + size]

    // Replace the jump to the trampoline.
    vector<uint8_t> replaced = hook->getReplacedBytes();
    m_debugger->write_memory(hook->getAddress(), &replaced[0], hook->getReplacedSize());

    // Return the memory to the debugee.
    if (!m_debugger->getMemoryCache().DeallocateMemory(hook->getMemory())) {
        LOG(ERROR) << "Could not free memory allocated for the trampoline.";
        return false;
    }

    LOG(INFO) << "Removed hook at " << (void *) hook->getAddress();

    return true;
}

static void showHelp(string &program_name) {
    cout << "\n" << program_name << " usage:\n" << endl;
    cout << "\t" << program_name << " [options]\n" << endl;
    cout << "Options:\n" << endl;
    cout << "\t" << "-l <path>\t\t\t\tHooking library [defaults to Hooks.so]." << endl;
    cout << "\t" << "-h <address>,<handler_name>\t\tHooks to install." << endl;
    cout << "\t" << "-a <pid|name>\t\t\t\tPid or process name to attach." << endl;
    cout << "\t" << "-e <path>\t\t\t\tBinary to execute." << endl;
}

int main(int argc, char **argv) {
    string program_name = boost::filesystem::basename(argv[0]);
    string hook_lib;
    vector<string> hooks;
    string attach_target;
    string exec_target;

    int c;
    while ((c = getopt(argc, argv, "l:h:a:e:")) != -1)
        switch (c) {
            case 'l':
                hook_lib = string(optarg);
                break;
            case 'h':
                hooks.push_back(string(optarg));
                break;
            case 'a':
                attach_target = string(optarg);
                break;
            case 'e':
                exec_target = string(optarg);
                break;
            case '?':
                showHelp(program_name);
                return -1;
            default:
                abort();
        }

    // Default to Hooks.so if no hook library is specified.
    if (hook_lib.empty()) {
        LOG(INFO) << "Defaulting to Hooks.so for hooks.";
        hook_lib = boost::filesystem::absolute("Hooks.so").native();
    }

    if (!boost::filesystem::exists(hook_lib)) {
        LOG(ERROR) << "Cannot find hook library " << hook_lib;
        showHelp(program_name);
        return -1;
    }

    // Check that we've some hooks.
    if (!hooks.size()) {
        LOG(INFO) << "No hooks specified, nothing to do here.";
        showHelp(program_name);
        return -1;
    }

    // Check that we have something to attach xor execute.
    if (attach_target.empty() && exec_target.empty()) {
        LOG(INFO) << "I either need a program to attach to xor a binary to run.";
        showHelp(program_name);
        return -1;
    }

    Debugger debugger;

    // Try to attach.
    if (!attach_target.empty()) {
        LOG(INFO) << "Trying to attach to: " << attach_target;

        // Get a reference to the process.
        shared_ptr<Process> process = Process::getProcess(attach_target);
        if (*process == Process::invalid()) {
            LOG(ERROR) << "Cannot get process simple";
            return -1;
        }

        // Attach to the process.
        if (!debugger.attach(process)) {
            LOG(ERROR) << "Cannot attach to process simple";
            return -1;
        }
    } else if (!exec_target.empty()) {
        LOG(INFO) << "Executing " << exec_target;
        debugger.execute(exec_target);
    }

    LOG(INFO) << "About to hook ...";

    // Place the hooks.
    Hooker hooker(&debugger, hook_lib);
    if (!hooker.initialize()) {
        LOG(ERROR) << "Could not initialize the hooker, aborting.";
        return -1;
    }

    for (const string &hook : hooks) {
        vector<string> tuple;
        boost::split(tuple, hook, boost::is_any_of(","));
        uintptr_t address;
        stringstream convert(tuple[0]);
        convert >> hex >> address;

        if (!hooker.addHook(address, tuple[1])) {
            LOG(ERROR) << "Could not add hook: " << hook;
        } else {
            LOG(INFO) << "Added hook: " << (void *) address;
        }
    }

    // debugger.loop();
    // hooker.destroy();
    debugger.detach();

    return 0;
}
