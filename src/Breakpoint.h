/*
 * Breakpoint.h
 *
 *  Created on: Jun 28, 2013
 *      Author: anon
 */

#ifndef BREAKPOINT_H_
#define BREAKPOINT_H_

#include <cstdint>
#include <boost/function.hpp>

class Debugger;

class Breakpoint {
    public:
        typedef boost::function<bool (Debugger *)> handler_t;

        Breakpoint(uintptr_t address, handler_t handler) :
                m_handler(handler), m_address(address), m_replaced(false), m_hits(0), m_enabled(false) {
        }

        uint32_t hits() {
            return m_hits;
        }

        uintptr_t address() {
            return m_address;
        }

        bool enabled() {
            return m_enabled;
        }

        void enable() {
            m_enabled = true;
        }

        void disable() {
            m_enabled = false;
        }

        void setReplaced(uint32_t replaced) {
            m_replaced = replaced;
        }

        uint32_t getReplaced() {
            return m_replaced;
        }

        bool handle(Debugger *debugger) {
            return m_handler(debugger);
        }

        void hit() {
            m_hits++;
        }

    private:
        handler_t m_handler;
        uintptr_t m_address;
        uint32_t m_replaced;
        uint32_t m_hits;
        bool m_enabled;
};

#endif /* BREAKPOINT_H_ */
