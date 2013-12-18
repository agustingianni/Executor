/*
 * EventHandler.cpp
 *
 *  Created on: Jun 28, 2013
 *      Author: anon
 */

#include "EventHandler.h"
#include "Debugger.h"
#include <boost/bind.hpp>

/*!
 * Create an event hanlder that will take care of events that
 * happen in the debugge process.
 * @param debugger
 */
EventHandler::EventHandler(Debugger *debugger) :
        m_debugger(debugger) {
    m_connection = m_debugger->connectHandler(
            boost::bind(&EventHandler::handler, this, _1));
}

EventHandler::~EventHandler() {
    m_debugger->disconnectHandler(m_connection);
}

/*!
 * Default event handler that does nothing. Client should implement it.
 * @param signum
 * @return
 */
bool EventHandler::handler(int signum) {
    return true;
}
