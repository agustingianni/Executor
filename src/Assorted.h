/*
 * Assorted.h
 *
 *  Created on: Jul 3, 2013
 *      Author: anon
 */

#ifndef ASSORTED_H_
#define ASSORTED_H_

#include "Debugger.h"
#include <sys/types.h>
#include <cstdint>
#include <string>

#define INVALID_ADDRESS ((uintptr_t) -1)

namespace ELF {
    uintptr_t GetDynamicSymbolOffset(std::string file_path, std::string symbol);
}

namespace Dump {
    void Context(Registers &regs);
    void Stack(Debugger &debugger, pid_t tid);
    bool AroundPC(Debugger &debugger, pid_t tid);
}

namespace System {
    long PageSize();
    uintptr_t AlignToPage(uintptr_t address);
    void *AlignToPage(void *address);
}

std::string StringToHex(const std::string &string_);

#endif /* ASSORTED_H_ */
