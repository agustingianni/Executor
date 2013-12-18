/*
 * Modules.cpp
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */

#include "Modules.h"
#include "Assorted.h"
#include "Logging.h"
#include <string>
#include <memory>
#include <fstream>
#include <sstream>
#include <cerrno>
#include <vector>
#include <boost/filesystem.hpp>
#include <dlfcn.h>
#include <stdint.h>

using namespace std;

/*!
 * Return the load address of a given module in the debugger address space.
 *
 * @param library
 * @return
 */
uintptr_t Module::GetModuleBaseAddress(string library) {
    ifstream input("/proc/self/maps");
    string line;
    uintptr_t base, end;
    char tmp;

    while (getline(input, line)) {
        if (line.find(library) == string::npos)
            continue;

        if (line.find("r-xp") == string::npos)
            continue;

        line.resize(line.find_first_of('-'));

        stringstream ss;
        ss << hex << line;
        ss >> base;
    }

    return base;
}

/*!
 * Return the address of function 'name' on the current process
 * after loading library 'library'.
 *
 * @param library
 * @param name
 * @return
 */
uintptr_t Module::resolve(std::string library, std::string name) {
    void *handle = dlopen(library.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        return -1;
    }

    // Resolve the address.
    void *function = dlsym(handle, name.c_str());
    if (!dlerror()) {
        dlclose(handle);
        return -1;
    }

    dlclose(handle);

    return reinterpret_cast<uintptr_t>(function);
}

/*!
 * Get the address of symbol 'name'.
 *
 * @param name
 * @return
 */
uintptr_t Module::resolve(string name) {
    uintptr_t offset = ELF::GetDynamicSymbolOffset(m_path.native(), name);

    // Try to resolve ourselves.
    if (offset && offset != INVALID_ADDRESS) {
        return m_base + offset;
    }

    // Make the dynamic loader resolve it for us.
    void *handle = dlopen(m_path.native().c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (handle) {
        uintptr_t address = -1;

        // Resolve the address.
        void *function = dlsym(handle, name.c_str());
        if (dlerror() == NULL) {
            // Get the base address of the library from proc fs.
            uintptr_t base = GetModuleBaseAddress(m_path.native());

            // Calculate the delta from the start of the library.
            address = m_base + (reinterpret_cast<uintptr_t>(function) - base);
        }

        dlclose(handle);
        return address;
    }

    return -1;
}

/*!
 * Add a module to the module list.
 *
 * @param module
 * @return
 */
bool ModuleList::add(shared_ptr<Module> module) {
    m_modules.push_back(module);
    return true;
}

/*!
 * Remove a module from the module list.
 *
 * @param module
 * @return
 */
bool ModuleList::del(shared_ptr<Module> module) {
    for (auto it = m_modules.begin(); it != m_modules.end(); ++it) {
        if (it->get() == module.get()) {
            m_modules.erase(it);
            return true;
        }
    }

    return false;
}

/*!
 * Find the module with name 'name'.
 *
 * @param name
 * @return
 */
shared_ptr<Module> ModuleList::find(string name) {
    shared_ptr<Module> found;

    for (auto module : m_modules) {
        if ((string::npos != module->name().find(name))
                || (string::npos != name.find(module->name()))) {
            found = module;
            break;
        }
    }

    return found;
}

/*!
 * Check if module 'name' is present.
 * @param name
 * @return
 */
bool ModuleList::exists(string name) {
    shared_ptr<Module> mod = find(name);
    return mod != 0;
}

