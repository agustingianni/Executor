/*
 * Disassembler.cpp
 *
 *  Created on: Jun 27, 2013
 *      Author: anon
 */

#include "Disassembler.h"
#include <udis86.h>
#include <string>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace std;

Disassembler::Disassembler(uint64_t pc, uint8_t mode) {
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, mode);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    ud_set_pc(&ud_obj, pc);
}

StringDisassembler::StringDisassembler(uint64_t pc, uint8_t mode) :
        Disassembler(pc, mode) {
}

/*!
 * Disassemble the given buffer up to size bytes or until 'n' (being the number of instructions
 * to disassemble is satisfied) reaches 0.
 *
 * @param buffer
 * @param size
 * @param n
 * @return
 */
vector<Instruction> StringDisassembler::disassemble(const unsigned char* buffer, size_t size,
        int n) {
    vector<Instruction> ret;
    ud_set_input_buffer(&ud_obj, buffer, size);

    int i = 0;
    while (ud_disassemble(&ud_obj)) {
        if (n == 0 || i++ < n) {
            const char *tmp = ud_insn_asm(&ud_obj);
            unsigned char *bytes = static_cast<unsigned char *>(malloc(ud_insn_len(&ud_obj)));
            memcpy(bytes, ud_insn_ptr(&ud_obj), ud_insn_len(&ud_obj));
            ret.push_back(Instruction(string(tmp), bytes, ud_insn_len(&ud_obj)));
        }
    }

    return ret;
}

Instruction Instruction::fromBytes(const char *buffer, size_t size) {
    StringDisassembler disassembler;
    std::vector<Instruction> ret = disassembler.disassemble((unsigned char *) buffer, size, 1);
    return ret.front();
}
