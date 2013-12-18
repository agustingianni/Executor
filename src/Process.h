/*
 * Process.h
 *
 *  Created on: Jul 2, 2013
 *      Author: anon
 */

#ifndef PROCESS_H_
#define PROCESS_H_

#include "ThreadList.h"
#include "Modules.h"
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <mutex>
#include <map>
#include <memory>
#include <boost/filesystem.hpp>

class Process: public std::enable_shared_from_this<Process> {
    public:
        static std::shared_ptr<Process> getProcess(std::string process);
        static std::shared_ptr<Process> getProcessByPid(pid_t pid);
        static std::shared_ptr<Process> getProcessByName(std::string name);

        static Process invalid() {
            return Process();
        }

        Process() :
                m_name("invalid"), m_pid(-1), m_proc(), m_thread_list() {
        }

        std::shared_ptr<Process> self() {
            return shared_from_this();
        }

        pid_t pid() const {
            return m_pid;
        }

        bool operator==(Process const& rhs) const {
            return rhs.m_pid == m_pid;
        }

        bool operator!=(Process const& rhs) const {
            return rhs.m_pid != m_pid;
        }

        ThreadList &getThreadList() {
            return m_thread_list;
        }

        ModuleList &getModuleList() {
            // TODO: This should not be done every time we call this.
            loadModuleList();
            return m_module_list;
        }

        size_t getNumberOfThreads() {
            return getThreadList().size();
        }

        bool loadModuleList();
        bool getThreads(std::map<pid_t, bool> &threads);
        void refreshThreadlist();

    private:
        // Process name and pid.
        std::string m_name;
        pid_t m_pid;

        // Path to /proc/<pid>/.
        boost::filesystem::path m_proc;

        // Collection of all the threads that comprise the process.
        ThreadList m_thread_list;

        // List of all the loaded modules.
        ModuleList m_module_list;
};

#endif /* PROCESS_H_ */
