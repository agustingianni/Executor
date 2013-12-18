/*
 * Modules.h
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */

#ifndef MODULES_H_
#define MODULES_H_

#include <string>
#include <vector>
#include <memory>
#include <cstddef>
#include <boost/filesystem.hpp>

class Module {
    public:
        Module(std::string name, uintptr_t base, size_t size, boost::filesystem::path path) :
                m_name(name), m_base(base), m_size(size), m_path(path) {
        }

        uintptr_t resolve(std::string name);
        static uintptr_t resolve(std::string library, std::string name);
        static uintptr_t GetModuleBaseAddress(std::string library);

        std::string name() {
            return m_name;
        }

        uintptr_t base() {
            return m_base;
        }

        size_t size() {
            return m_size;
        }

        boost::filesystem::path path() {
            return m_path;
        }

    private:
        std::string m_name;
        uintptr_t m_base;
        size_t m_size;
        boost::filesystem::path m_path;
};

class ModuleList {
    public:
        bool add(std::shared_ptr<Module> module);
        bool del(std::shared_ptr<Module> module);
        std::shared_ptr<Module> find(std::string name);
        bool exists(std::string name);

    private:
        std::vector<std::shared_ptr<Module> > m_modules;
};

#endif /* MODULES_H_ */
