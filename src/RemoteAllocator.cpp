/*
 * RemoteAllocator.cpp
 *
 *  Created on: Jul 7, 2013
 *      Author: anon
 */
#include "Assorted.h"
#include "RemoteAllocator.h"
#include "Debugger.h"

#include <memory>
#include <cstddef>

using namespace std;

// These classes were copied from the LLVM project
// You can read about them at llvm/tools/lldb/include/lldb/Target/Memory.h
// Copyright goes to the good folks at LLVM.

AllocatedBlock::AllocatedBlock(uintptr_t addr, uint32_t byte_size, uint32_t permissions,
        uint32_t chunk_size) :
        m_addr(addr), m_byte_size(byte_size), m_permissions(permissions), m_chunk_size(chunk_size), m_offset_to_chunk_size() {
    assert(byte_size > chunk_size);
}

AllocatedBlock::~AllocatedBlock() {
}

uintptr_t AllocatedBlock::ReserveBlock(uint32_t size) {
    uintptr_t addr = -1;
    if (size <= m_byte_size) {
        const uint32_t needed_chunks = CalculateChunksNeededForSize(size);

        if (m_offset_to_chunk_size.empty()) {
            m_offset_to_chunk_size[0] = needed_chunks;
            addr = m_addr;
        } else {
            uint32_t last_offset = 0;
            OffsetToChunkSize::const_iterator pos = m_offset_to_chunk_size.begin();
            OffsetToChunkSize::const_iterator end = m_offset_to_chunk_size.end();
            while (pos != end) {
                if (pos->first > last_offset) {
                    const uint32_t bytes_available = pos->first - last_offset;
                    const uint32_t num_chunks = CalculateChunksNeededForSize(bytes_available);
                    if (num_chunks >= needed_chunks) {
                        m_offset_to_chunk_size[last_offset] = needed_chunks;
                        addr = m_addr + last_offset;
                        break;
                    }
                }

                last_offset = pos->first + pos->second * m_chunk_size;

                if (++pos == end) {
                    // Last entry...
                    const uint32_t chunks_left = CalculateChunksNeededForSize(
                            m_byte_size - last_offset);
                    if (chunks_left >= needed_chunks) {
                        m_offset_to_chunk_size[last_offset] = needed_chunks;
                        addr = m_addr + last_offset;
                        break;
                    }
                }
            }
        }
    }

    return addr;
}

bool AllocatedBlock::FreeBlock(uintptr_t addr) {
    uint32_t offset = addr - m_addr;
    OffsetToChunkSize::iterator pos = m_offset_to_chunk_size.find(offset);
    bool success = false;
    if (pos != m_offset_to_chunk_size.end()) {
        m_offset_to_chunk_size.erase(pos);
        success = true;
    }

    return success;
}

AllocatedMemoryCache::AllocatedMemoryCache(Debugger *debugger) :
        m_debugger(debugger), m_memory_map() {
}

AllocatedMemoryCache::~AllocatedMemoryCache() {
}

void AllocatedMemoryCache::Clear() {
    PermissionsToBlockMap::iterator pos, end = m_memory_map.end();
    for (pos = m_memory_map.begin(); pos != end; ++pos) {
        m_debugger->freeMemory(pos->second->GetBaseAddress());
    }

    m_memory_map.clear();
}

shared_ptr<AllocatedBlock> AllocatedMemoryCache::AllocatePage(uint32_t byte_size,
        uint32_t permissions, uint32_t chunk_size) {
    shared_ptr<AllocatedBlock> block_sp;
    const size_t page_size = 4096;
    const size_t num_pages = (byte_size + page_size - 1) / page_size;
    const size_t page_byte_size = num_pages * page_size;

    uintptr_t addr = m_debugger->allocateMemory(page_byte_size, permissions);

    if (addr != INVALID_ADDRESS) {
        block_sp.reset(new AllocatedBlock(addr, page_byte_size, permissions, chunk_size));
        m_memory_map.insert(std::make_pair(permissions, block_sp));
    }

    return block_sp;
}

uintptr_t AllocatedMemoryCache::AllocateMemory(size_t byte_size, uint32_t permissions) {
    uintptr_t addr = -1;
    std::pair<PermissionsToBlockMap::iterator, PermissionsToBlockMap::iterator> range =
            m_memory_map.equal_range(permissions);

    for (PermissionsToBlockMap::iterator pos = range.first; pos != range.second; ++pos) {
        addr = (*pos).second->ReserveBlock(byte_size);
    }

    if (addr == INVALID_ADDRESS) {
        shared_ptr<AllocatedBlock> block_sp(AllocatePage(byte_size, permissions, 16));

        if (block_sp)
            addr = block_sp->ReserveBlock(byte_size);
    }

    return addr;
}

bool AllocatedMemoryCache::DeallocateMemory(uintptr_t addr) {
    PermissionsToBlockMap::iterator pos, end = m_memory_map.end();
    bool success = false;
    for (pos = m_memory_map.begin(); pos != end; ++pos) {
        if (pos->second->Contains(addr)) {
            success = pos->second->FreeBlock(addr);
            break;
        }
    }

    return success;
}

