/*
 * Bugger.cpp
 *
 *  Created on: Aug 4, 2013
 *      Author: anon
 */

#include "Bugger.h"
#include "Debugger.h"
#include "Process.h"
#include "Logging.h"

#include <memory>

using namespace std;

Bugger::Bugger() {
}

int main(int argc, char **argv) {
    Debugger debugger;

    shared_ptr<Process> p = debugger.execute("hookme");
    if (*p == Process::invalid()) {
        LOG(ERROR) << "Exiting debugger.";
        return -1;
    }

    uintptr_t pc = 0;
    for (int i = 0; i < 10; i++) {
        debugger.getPC(p->pid(), &pc);
        cout << "pc: " << (void *) pc << endl;
        debugger.singleStep(p->pid());
    }

    debugger.loop();

    debugger.detach();
}
