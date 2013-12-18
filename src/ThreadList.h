/*
 * ThreadList.h
 *
 *  Created on: Jul 6, 2013
 *      Author: anon
 */

#ifndef THREADLIST_H_
#define THREADLIST_H_

#include <sys/types.h>
#include <map>
#include <memory>

class Process;

class Thread {
    public:
        Thread(std::shared_ptr<Process> process, pid_t tid) :
                m_tid(tid), m_process(process) {
        }

        ~Thread() {
            destroy();
        }

        static Thread invalid() {
            return Thread(0, -1);
        }

        void destroy();

        bool operator==(Thread const& rhs) const {
            return rhs.m_tid == m_tid;
        }

        bool operator!=(Thread const& rhs) const {
            return rhs.m_tid != m_tid;
        }

        pid_t tid() const {
            return m_tid;
        }

        std::shared_ptr<Process> process() {
            return m_process;
        }

    private:
        pid_t m_tid;
        std::shared_ptr<Process> m_process;
};

class ThreadList {
        friend class Process;
        friend class Debugger;

    public:
        ThreadList();
        ThreadList(std::shared_ptr<Process> process);
        ThreadList(const ThreadList &rhs);
        ~ThreadList();

        void clear();
        void destroy();
        void refresh();

        std::shared_ptr<Thread> getThreadByID(pid_t tid);
        void removeThreadByID(pid_t tid);

        void update(ThreadList &rhs);
        void addThread(const std::shared_ptr<Thread> &thread);
        void delThread(const std::shared_ptr<Thread> &thread);

        size_t size() {
            return m_threads.size();
        }

    private:
        std::shared_ptr<Process> m_process;

        typedef std::map<pid_t, std::shared_ptr<Thread> > threadmap_t;
        threadmap_t m_threads;
};

#endif /* THREADLIST_H_ */
