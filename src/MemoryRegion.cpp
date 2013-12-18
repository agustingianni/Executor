/*
 * MemoryRegion.cpp
 *
 *  Created on: Jul 2, 2013
 *      Author: anon
 */

#include "MemoryRegion.h"
#include "Process.h"
#include "Logging.h"
#include <vector>
#include <cstdio>
#include <memory>
#include <boost/lexical_cast.hpp>

using namespace std;

vector<MemoryRegion> MemoryMapLoader::load(shared_ptr<Process> process) {
    vector<MemoryRegion> regions;
    string proc_path = string("/proc/") + boost::lexical_cast<string>(process->pid()) + "/maps";

    // Open the proc entry.
    FILE *fstream = fopen(proc_path.c_str(), "r");
    if (!fstream) {
        LOG(ERROR) << "Could not open " << proc_path << " to read process address space";
        return vector<MemoryRegion>();
    }

    char line[1024];
    char filename[1024 + 1];

    // Read all the lines.
    while (fgets(line, sizeof(line), fstream)) {
        // Drop the newline
        line[strlen(line) - 1] = 0x00;
        memset(static_cast<void *>(filename), 0x00, sizeof(filename));
        MemoryRegion m_current;

        char perms[4+1];

        int result = sscanf(line, "%lx-%lx %4s %x %hx:%hx %u %1024s\n", &m_current.m_start,
                &m_current.m_end, perms, &m_current.m_offset, &m_current.m_major,
                &m_current.m_minor, &m_current.m_inode, filename);

        // We should decode at least 7 fields of the line.
        if (result < 7) {
            LOG(ERROR) << "Could not parse the line correctly, skipping record";
            continue;
        }

        // Parse permissions.
        if (perms[0] == 'r') {
            m_current.m_perm |= MemoryRegion::MemoryPermissions::PERM_READ;
        }

        if (perms[1] == 'w') {
            m_current.m_perm |= MemoryRegion::MemoryPermissions::PERM_WRITE;
        }

        if (perms[2] == 'x') {
            m_current.m_perm |= MemoryRegion::MemoryPermissions::PERM_EXECUTE;
        }

        if (perms[3] == 's') {
            m_current.m_perm |= MemoryRegion::MemoryPermissions::PERM_SHARED;
        }

        if (perms[3] == 'p') {
            m_current.m_perm |= MemoryRegion::MemoryPermissions::PERM_PRIVATE;
        }

        m_current.m_path.assign(filename);
        regions.push_back(m_current);
    }

    fclose(fstream);
    return regions;
}

