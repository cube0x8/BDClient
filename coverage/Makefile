PIN_ROOT = $(CURDIR)/$(wildcard pin-*-gcc-linux)
CONFIG_ROOT = $(PIN_ROOT)/source/tools/Config
PIN = $(PIN_ROOT)/pin
DEBUG=1
CC=gcc

KIT = 1

include $(PIN_ROOT)/source/tools/Config/makefile.config

CXXFLAGS = -g -Wall -O0 -fno-stack-protector -march=native
CFLAGS = -g -O0 -Wall -DNDEBUG -fno-stack-protector -fPIC -march=native
LDFLAGS = -Wl,-O1

# I dont need these default targets
dir:
libs:
objects:
dlls:
apps:
libs:

tools: deepcover.so
	@echo \#!/bin/sh > pin
	@echo exec $(PIN_ROOT)/pin \$$\@ >> pin
	@chmod +x pin

OBJS = deepcover.o instrument.o tree.o edges.o modules_manager.o

tree.o: tree.c
	$(CC) $(COMP_OBJ) $@ $(CFLAGS) $<

deepcover.o: deepcover.cpp
	$(CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

modules_manager.o: modules_manager.cpp tree.o
	$(CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

instrument.o: instrument.cpp
	$(CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

edges.o: edges.cpp
	$(CXX) $(COMP_OBJ) $@ $(CXXFLAGS) $(TOOL_CXXFLAGS) $<

%.o : %.c
	$(CC) $(COMP_OBJ) $@ $(CFLAGS) $(TOOL_CFLAGS) $<

deepcover.so : $(OBJS)
	$(CXX) $(LINK_EXE) $@ $(LDFLAGS) $(TOOL_LDFLAGS) $(OBJS) $(MANAGE_BLOCKS) $(TOOL_LPATHS) $(TOOL_LIBS) -static-libgcc -static-libstdc++

coverage_parse_min: coverage_parse_min.c
	gcc $(CFLAGS) $(LDFLAGS) $(shell pkg-config glib-2.0 --cflags) -o $@ $< $(shell pkg-config glib-2.0 --libs)

clean:
	rm -f *.o deepcover.so core *.core pin *.log blocks.txt coverage.txt summary.txt
	rm -f coverage_parse_min
