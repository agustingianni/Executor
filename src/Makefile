CXX=clang++
CC=clang

#CXX=g++
#CC=gcc

CFLAGS=-c -Wall -std=c++11 -ggdb -Wno-int-to-pointer-cast
LDFLAGS=-ludis86 -lboost_signals -lboost_filesystem -lboost_system -lboost_program_options -lelf -lzmq

all: Hooker Hooks.so Observer Bugger

thread: tests/thread.c
	$(CC) $^ -o tests/$@ -Wall -ggdb -lpthread

# Build the Bugger binary.
OBJECTS=Bugger.o Debugger.o EventHandler.o Disassembler.o Breakpoint.o MemoryRegion.o Process.o Assorted.o ThreadList.o RemoteCall.o Modules.o RemoteAllocator.o
Bugger: $(OBJECTS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# Build the Hooker binary.
OBJECTS=Debugger.o EventHandler.o Hooker.o Disassembler.o Breakpoint.o MemoryRegion.o Process.o Assorted.o ThreadList.o RemoteCall.o Modules.o RemoteAllocator.o
Hooker: $(OBJECTS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# Build the Observer binary.
OBJECTS=Debugger.o EventHandler.o Disassembler.o Breakpoint.o MemoryRegion.o Process.o Assorted.o ThreadList.o RemoteCall.o Modules.o RemoteAllocator.o Observer.o
Observer: $(OBJECTS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# Build all the hooks defined by the user.
Hooks.so: Hooks.cpp
	$(CXX) $^ -o $@ -fPIC -shared -Wall -std=c++11 -ggdb

.cpp.o:
	$(CXX) $(CFLAGS) $< -o $@ -I .

clean:
	rm -rf *.o Hooker Observer Hooks.so Bugger
