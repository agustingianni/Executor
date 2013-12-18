/*
 * Disassembler.h
 *
 *  Created on: Jun 27, 2013
 *      Author: anon
 */

#ifndef DISASSEMBLER_H_
#define DISASSEMBLER_H_

#include "Logging.h"
#include <udis86.h>
#include <string>
#include <vector>
#include <cstddef>

class StringDisassembler;

class Instruction {
    public:
        Instruction(std::string instruction, const unsigned char *bytes, size_t size) :
                m_instruction(instruction), m_bytes(bytes), m_size(size) {
        }

        std::string m_instruction;
        const unsigned char *m_bytes;
        size_t m_size;

        static Instruction fromBytes(const char *buffer, size_t size);
};

class Disassembler {
    public:
        Disassembler(uint64_t pc = 0, uint8_t mode = 64);
        ud_t ud_obj;
};

class StringDisassembler: public Disassembler {
    public:
        StringDisassembler(uint64_t pc = 0, uint8_t mode = 64);
        std::vector<Instruction> disassemble(const unsigned char* buffer, size_t size, int n = 0);

        static void print(const unsigned char *buffer, size_t size) {
            StringDisassembler dis(0, 64);
            std::vector<Instruction> res = dis.disassemble(buffer, size, 0);
            for (auto ins = res.begin(); ins != res.end(); ++ins) {
                LOG(INFO) << ins->m_instruction;
            }
        }

        static void print(const std::string &bytes) {
            StringDisassembler::print((const unsigned char *) bytes.c_str(), bytes.size());
        }
};

#endif /* DISASSEMBLER_H_ */
