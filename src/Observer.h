/*
 * Observer.h
 *
 *  Created on: Jul 23, 2013
 *      Author: anon
 */

#ifndef OBSERVER_H_
#define OBSERVER_H_

class Debugger;

class Observer {
    public:
        Observer();
        bool loop();

    private:
        Debugger *m_debugger;
};

#endif /* OBSERVER_H_ */
