/*
 * Process.cpp
 *
 *  Created on: Jul 2, 2013
 *      Author: anon
 */

#include "Process.h"
#include "Logging.h"
#include "MemoryRegion.h"
#include <sys/ptrace.h>
#include <string>
#include <cstddef>
#include <fstream>
#include <memory>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost::filesystem;
using namespace boost;

static bool is_integer(const string &str) {
    bool ret;
    try {
        lexical_cast<int>(str);
        ret = true;
    } catch (bad_lexical_cast &) {
        ret = false;
    }

    return ret;
}

void Process::refreshThreadlist() {
}

/*!
 * Return the list of threads present on /proc/<pid>/task
 * @return
 */
bool Process::getThreads(map<pid_t, bool> &threads) {
    LOG(INFO) << "Returning thread list";
    path tmp = m_proc / "task";

    LOG(DEBUG) << m_proc.native();
    bool tids_changed = false;

    directory_iterator end_itr; // default construction yields past-the-end
    for (directory_iterator itr(tmp); itr != end_itr; ++itr) {
        string string_pid = itr->path().filename().native();

        // Each new thread will have a directory inside the task proc entry.
        if (is_directory(itr->status()) && is_integer(string_pid)) {
            pid_t tid = lexical_cast<pid_t>(string_pid);
            auto it = threads.find(tid);
            if (it == threads.end()) {
                LOG(DEBUG) << "New thread " << tid << " found for process " << pid();
                threads.insert(make_pair(tid, false));
                tids_changed = true;
            }
        }
    }

    return tids_changed;
}

/*!
 * Populate the list of loaded modules.
 *
 * @return
 */
bool Process::loadModuleList() {
    LOG(INFO) << "Loading debugee modules";

    vector<MemoryRegion> maps = MemoryMapLoader::load(self());
    for (auto map = maps.begin(); map != maps.end(); ++map) {
        // Check that it is executable and it exists as a file.
        if (map->isExecutable() && exists(map->getPath())
                && !m_module_list.exists(map->getPath())) {
            LOG(INFO) << "Found library " << map->getPath() << " at "
                    << (void *) map->getStartAddress();

            boost::filesystem::path path(map->getPath());
            string name = path.filename().native();

            std::shared_ptr<Module> mod = make_shared<Module>(name, map->getStartAddress(),
                    map->getSize(), path);

            m_module_list.add(mod);
        }
    }

    return true;
}

std::shared_ptr<Process> Process::getProcess(string process) {
    try {
        return Process::getProcessByPid(lexical_cast<pid_t>(process));
    } catch (bad_lexical_cast &) {
        LOG(INFO) << "Resolving process pid of `" << process << "`";
    }

    return Process::getProcessByName(process);
}

std::shared_ptr<Process> Process::getProcessByPid(pid_t pid) {
    std::shared_ptr<Process> p = make_shared<Process>();
    p->m_pid = pid;
    p->m_proc = path("/proc");

    p->m_proc /= lexical_cast<string>(pid);
    if (!exists(p->m_proc)) {
        LOG(ERROR) << "PID " << pid << " does not exist.";
        return std::make_shared<Process>();
    }

    path tmp = p->m_proc / "cmdline";

    ifstream myfile(tmp.native());
    string line;
    getline(myfile, line);

    p->m_name = line;
    return p;
}

std::shared_ptr<Process> Process::getProcessByName(string name) {
    std::shared_ptr<Process> p = std::make_shared<Process>();
    vector<pid_t> pids;

    pid_t pid = -1;
    path proc("/proc");

    directory_iterator end_itr; // default construction yields past-the-end
    for (directory_iterator itr(proc); itr != end_itr; ++itr) {
        string string_pid = itr->path().filename().native();

        if (is_directory(itr->status()) && is_integer(string_pid)) {
            path tmp = itr->path() / "cmdline";

            ifstream myfile(tmp.native());
            string line;
            getline(myfile, line);

            // Skip threads.
            if (line.empty()) {
                continue;
            }

            // Just in case there is a zero.
            std::size_t found = line.find_first_of('\x00');
            if (found != std::string::npos) {
                line = line.substr(0, found);
            }

            found = line.find_first_of(' ');
            if (found != std::string::npos) {
                line = line.substr(0, found);
            }

            tmp = path(line);
            pid = lexical_cast<int>(string_pid);

            if (tmp.filename() == name) {
                pids.push_back(pid);
            }
        }
    }

    if (pids.size() == 0) {
        LOG(ERROR) << "Process " << name << " does not exist.";
        return std::make_shared<Process>();
    } else if (pids.size() > 1) {
        LOG(ERROR) << "Process " << name << " have " << pids.size() << " different processes.";
        return std::make_shared<Process>();
    } else {
        LOG(INFO) << "Found pid of process " << pids[0];
    }

    p->m_pid = pids.front();
    p->m_name = name;
    p->m_proc = "/proc" / lexical_cast<string>(p->m_pid);

    return p;
}
