/*
 * RemoteAllocator.h
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */

#ifndef REMOTEALLOCATOR_H_
#define REMOTEALLOCATOR_H_

#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>

class Debugger;

// These classes were copied from the LLVM project
// You can read about them at llvm/tools/lldb/include/lldb/Target/Memory.h
// Copyright goes to the good folks at LLVM.

class AllocatedBlock {
    public:
        AllocatedBlock(uintptr_t addr, uint32_t byte_size, uint32_t permissions,
                uint32_t chunk_size);

        ~AllocatedBlock();

        uintptr_t ReserveBlock(uint32_t size);

        bool FreeBlock(uintptr_t addr);

        uintptr_t GetBaseAddress() const {
            return m_addr;
        }

        uint32_t GetByteSize() const {
            return m_byte_size;
        }

        uint32_t GetPermissions() const {
            return m_permissions;
        }

        uint32_t GetChunkSize() const {
            return m_chunk_size;
        }

        bool Contains(uintptr_t addr) const {
            return ((addr >= m_addr) && addr < (m_addr + m_byte_size));
        }

    protected:
        uint32_t TotalChunks() const {
            return m_byte_size / m_chunk_size;
        }

        uint32_t CalculateChunksNeededForSize(uint32_t size) const {
            return (size + m_chunk_size - 1) / m_chunk_size;
        }
        const uintptr_t m_addr;    // Base address of this block of memory
        const uint32_t m_byte_size;   // 4GB of chunk should be enough...
        const uint32_t m_permissions; // Permissions for this memory (logical OR of lldb::Permissions bits)
        const uint32_t m_chunk_size; // The size of chunks that the memory at m_addr is divied up into
        typedef std::map<uint32_t, uint32_t> OffsetToChunkSize;
        OffsetToChunkSize m_offset_to_chunk_size;
};

//----------------------------------------------------------------------
// A class that can track allocated memory and give out allocated memory
// without us having to make an allocate/deallocate call every time we
// need some memory in a process that is being debugged.
//----------------------------------------------------------------------
class AllocatedMemoryCache {
    public:
        //------------------------------------------------------------------
        // Constructors and Destructors
        //------------------------------------------------------------------
        AllocatedMemoryCache(Debugger *debugger);

        ~AllocatedMemoryCache();

        void
        Clear();

        uintptr_t
        AllocateMemory(size_t byte_size, uint32_t permissions);

        bool
        DeallocateMemory(uintptr_t ptr);

    private:
        std::shared_ptr<AllocatedBlock>
        AllocatePage(uint32_t byte_size, uint32_t permissions, uint32_t chunk_size);

        //------------------------------------------------------------------
        // Classes that inherit from MemoryCache can see and modify these
        //------------------------------------------------------------------
        Debugger *m_debugger;
        typedef std::multimap<uint32_t, std::shared_ptr<AllocatedBlock> > PermissionsToBlockMap;
        PermissionsToBlockMap m_memory_map;
};

#endif /* REMOTEALLOCATOR_H_ */
