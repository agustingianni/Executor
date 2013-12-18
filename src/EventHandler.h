/*
 * EventHandler.h
 *
 *  Created on: Jun 28, 2013
 *      Author: anon
 */

#ifndef EVENTHANDLER_H_
#define EVENTHANDLER_H_

#include "Debugger.h"

class EventHandler {
    public:
        explicit EventHandler(Debugger *debugger);
        virtual ~EventHandler();

        // Clients should be implementing this function.
        virtual bool handler(int signum);

    protected:
        Debugger *m_debugger;

    private:
        Debugger::connection_t m_connection;
};

#endif /* EVENTHANDLER_H_ */
