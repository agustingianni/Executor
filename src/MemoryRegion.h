/*
 * MemoryRegion.h
 *
 *  Created on: Jul 2, 2013
 *      Author: anon
 */

#ifndef MEMORYREGION_H_
#define MEMORYREGION_H_

#include <string>
#include <array>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>

class Process;
class MemoryRegion;

class MemoryMapLoader {
    public:
        static std::vector<MemoryRegion> load(std::shared_ptr<Process> process);
};

class MemoryRegion {
        friend class MemoryMapLoader;

    public:
        enum MemoryPermissions {
            PERM_READ = 0x01,
            PERM_WRITE = 0x02,
            PERM_EXECUTE = 0x04,
            PERM_SHARED = 0x08,
            PERM_PRIVATE = 0x10
        };

        MemoryRegion() :
                m_perm(0), m_start(0), m_end(0), m_offset(0), m_major(0), m_minor(0), m_inode(0), m_path() {
        }

        uintptr_t getStartAddress() const {
            return m_start;
        }

        uintptr_t getEndAddress() const {
            return m_end;
        }

        size_t getSize() const {
            return m_end - m_start;
        }

        bool isReadable() const {
            return m_perm & PERM_READ;
        }

        bool isWriteable() const {
            return m_perm & PERM_WRITE;
        }

        bool isExecutable() const {
            return m_perm & PERM_EXECUTE;
        }

        bool isShared() const {
            return m_perm & PERM_SHARED;
        }

        bool isPrivate() const;

        int getPermissions() const {
            return m_perm;
        }

        uint32_t getOffset() const {
            return m_offset;
        }

        uint16_t getDeviceMajor() const {
            return m_major;
        }

        uint16_t getDeviceMinor() const {
            return m_minor;
        }

        uint32_t getInode() const {
            return m_inode;
        }

        const std::string& getPath() const {
            return m_path;
        }

    private:
        // Memory permissions
        int m_perm;

        uintptr_t m_start;
        uintptr_t m_end;
        uint32_t m_offset;
        uint16_t m_major;
        uint16_t m_minor;
        uint32_t m_inode;
        std::string m_path;
};

#endif /* MEMORYREGION_H_ */
