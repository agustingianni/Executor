/*
 * ThreadList.cpp
 *
 *  Created on: Jul 6, 2013
 *      Author: anon
 */

#include "ThreadList.h"
#include "Process.h"
#include "Logging.h"

#include <memory>

using namespace std;

void Thread::destroy() {
    m_process->refreshThreadlist();
}

ThreadList::ThreadList() {
}

ThreadList::ThreadList(shared_ptr<Process> process) :
        m_process(process), m_threads() {
}

ThreadList::ThreadList(const ThreadList &rhs) :
        m_process(rhs.m_process), m_threads(rhs.m_threads) {
}

ThreadList::~ThreadList() {
    clear();
}

/*!
 * Clear the internal thread list.
 */
void ThreadList::clear() {
    m_threads.clear();
}

/*!
 * Refresh the thread list after an event.
 */
void ThreadList::refresh() {
    m_process->refreshThreadlist();
}

/*!
 * Destroy all threads.
 */
void ThreadList::destroy() {
    for (auto thread = m_threads.begin(); thread != m_threads.end(); ++thread) {
        thread->second->destroy();
    }
}

/*!
 * Return the thread with tid.
 * @param tid
 * @return
 */
shared_ptr<Thread> ThreadList::getThreadByID(pid_t tid) {
    auto it = m_threads.find(tid);
    if (it == m_threads.end()) {
        return make_shared<Thread>(Thread::invalid());
    }

    return it->second;
}

/*!
 * Remove thread.
 * @param tid
 */
void ThreadList::removeThreadByID(pid_t tid) {
    LOG(DEBUG) << "removeThreadByID: " << tid;
    m_threads.erase(tid);
}

void ThreadList::update(ThreadList &rhs) {

}

/*!
 * Add a thread to the list.
 * @param thread
 */
void ThreadList::addThread(const shared_ptr<Thread> &thread) {
    LOG(DEBUG) << "addThread: " << thread->tid();
    m_threads.insert(std::make_pair(thread->tid(), thread));
}

/*!
 * Remove a thread from the list.
 * @param thread
 */
void ThreadList::delThread(const shared_ptr<Thread> &thread) {
    LOG(DEBUG) << "delThread: " << thread->tid();
    m_threads.erase(thread->tid());
}
