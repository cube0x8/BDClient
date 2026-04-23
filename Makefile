INCLUDES = -I. -Ilog -Iinclude -Iintercept/ -Iintercept/include -Ipeloader -Ishmem_file_handling -Ithird_party/pe-parse/pe-parser-library/include
CFLAGS  = -DNDEBUG $(USER_DEFINED) -ggdb3 -fshort-wchar -Wno-multichar $(INCLUDES) -mstackrealign
CPPFLAGS= -D_GNU_SOURCE $(INCLUDES)
LDFLAGS = -lm -Wl,--dynamic-list=exports.lst -ldl
LDPELOADER  = -Wl,--whole-archive peloader/libpeloader.a
LDLIBS = $(LDPELOADER) -Wl,--no-whole-archive
INTERCEPT_LIBS = intercept/libhook.a intercept/libsubhook.a intercept/libZydis.a intercept/libZycore.a
TARGET_BUILD="all"
OBJECTS = bdlibrary.o log/log.o shmem_file_handling/module_ranges_shm.o allocation_tracker.o
HONGGFUZZ_EXTRA_OBJECTS = shmem_file_handling/shared_mem_file_handling.o
HONGGFUZZ_TARGET = fuzzers/honggfuzz_target/persistent-bdclient.cpp
HONGGFUZZ_DIR = "../../../honggfuzz"
PE_MUTATOR_DIR ?= "../../../libafl-pe-mutator"
PE_MUTATOR_HEADER_DIR = $(PE_MUTATOR_DIR)/crates/pe-mutator-capi/include
PE_MUTATOR_STATICLIB = $(PE_MUTATOR_DIR)/target/debug/libpe_mutator_capi.a
CC = gcc

ifdef PE_MUTATOR
CFLAGS += -DPE_MUTATOR
CPPFLAGS += -DPE_MUTATOR
INCLUDES += -I$(PE_MUTATOR_HEADER_DIR)
ADDITIONAL_TARGETS += pe-mutator-capi
LDLIBS += $(PE_MUTATOR_STATICLIB) -lpthread
endif

ifdef SHARED_MEM
CFLAGS += -DSHARED_MEM
ADDITIONAL_TARGETS += shmem_file_handling/shared_mem_file_handling.o
LDLIBS = $(LDPELOADER) -Wl,--no-whole-archive
OBJECTS +=  shmem_file_handling/shared_mem_file_handling.o
endif

ifdef FUZZ
CFLAGS += -DFUZZ
endif

ifdef LIBAFL_FUZZING
CFLAGS += -DLIBAFL_FUZZING
endif

ifdef HONGGFUZZ_FUZZING
CFLAGS += -DHONGGFUZZ_FUZZING
endif

HONGGFUZZ_CLANG = $(HONGGFUZZ_DIR)/hfuzz_cc/hfuzz-clang++

.PHONY: clean peloader intercept

DEBUG_CFLAGS   = -O0 -g

debug: CFLAGS := $(filter-out -DNDEBUG, $(CFLAGS))
debug: CFLAGS += $(DEBUG_CFLAGS)
debug: TARGET_BUILD = "debug"
debug: CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug
debug: bdclient_x64

honggfuzz_target_debug: CFLAGS := $(filter-out -DNDEBUG -DLIBAFL_FUZZING, $(CFLAGS))
honggfuzz_target_debug: CFLAGS += $(DEBUG_CFLAGS)
honggfuzz_target_debug: TARGET_BUILD = "debug"
honggfuzz_target_debug: CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug
honggfuzz_target_debug: FUZZ = 1
honggfuzz_target_debug: HONGGFUZZ_FUZZING = 1
honggfuzz_target_debug: CFLAGS += -DHONGGFUZZ_FUZZING
honggfuzz_target_debug: intercept $(OBJECTS) $(HONGGFUZZ_EXTRA_OBJECTS) $(HONGGFUZZ_TARGET)
	make -C $(HONGGFUZZ_DIR)
	$(HONGGFUZZ_CLANG) -g -rdynamic $(CFLAGS) $(INCLUDES) -o $@ $(HONGGFUZZ_TARGET) $(OBJECTS) $(HONGGFUZZ_EXTRA_OBJECTS) $(INTERCEPT_LIBS) $(LDLIBS) $(LDFLAGS) -lz -lpthread

intercept:
	cd intercept; mkdir -p build; cd build; cmake $(CMAKE_FLAGS) -DARCH:STRING=x64 -DZYDIS_BUILD_DOXYGEN=OFF -DZYDIS_BUILD_MAN=OFF ..; make
	cp intercept/build/libhook.a intercept/libhook.a
	cp intercept/build/zydis/libZydis.a intercept/libZydis.a
	cp intercept/build/zydis/zycore/libZycore.a intercept/libZycore.a
	cp intercept/build/subhook/libsubhook.a intercept/libsubhook.a

pe-parse:
	cd third_party/pe-parse; mkdir build; cd build; cmake $(CMAKE_FLAGS) ..; cmake --build .

pe-mutator-capi:
	cargo build -p pe-mutator-capi --manifest-path $(PE_MUTATOR_DIR)/Cargo.toml

allocation_tracker.o: allocation_tracker.c allocation_tracker.h
	$(CC) $(CFLAGS) -g -c -o $@ allocation_tracker.c

shmem_file_handling/shared_mem_file_handling.o: shmem_file_handling/shared_mem_file_handling.c
	gcc $(CFLAGS) -Ilog/ -g -c -fPIC $^ -o $@ $(LDFLAGS)

shmem_file_handling/module_ranges_shm.o: shmem_file_handling/module_ranges_shm.c
	gcc $(CFLAGS) -Ilog/ -g -c -fPIC $^ -o $@ $(LDFLAGS)

peloader_x64:
	make -C peloader $(TARGET_BUILD) ARCH=x64 SHARED_MEM=$(SHARED_MEM) FUZZ=$(FUZZ) HONGGFUZZ_FUZZING=$(HONGGFUZZ_FUZZING)

bdlibrary.o: peloader_x64
	$(CC)  $(CFLAGS) -g -c -o bdlibrary.o bdlibrary.c

bddeamon_x64: TARGET_BUILD = "debug"
bddeamon_x64: CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug
bddeamon_x64: CFLAGS += -g -fPIC
bddeamon_x64: bddeamon.o $(ADDITIONAL_TARGETS) $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

bdclient_x64: CMAKE_FLAGS += -DARCH:STRING=x64
bdclient_x64: $(ADDITIONAL_TARGETS) $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ bdclient.c $(OBJECTS) $(LDLIBS) $(LDFLAGS)

honggfuzz_target: FUZZ = 1
honggfuzz_target: HONGGFUZZ_FUZZING = 1
honggfuzz_target: CFLAGS := $(filter-out -DLIBAFL_FUZZING, $(CFLAGS))
honggfuzz_target: CFLAGS += -DHONGGFUZZ_FUZZING
honggfuzz_target: intercept $(OBJECTS) $(HONGGFUZZ_EXTRA_OBJECTS) $(HONGGFUZZ_TARGET)
	make -C $(HONGGFUZZ_DIR)
	$(HONGGFUZZ_CLANG) -g -rdynamic $(CFLAGS) $(INCLUDES) -o $@ $(HONGGFUZZ_TARGET) $(OBJECTS) $(HONGGFUZZ_EXTRA_OBJECTS) $(INTERCEPT_LIBS) $(LDLIBS) $(LDFLAGS) -lz -lpthread

clean:
	rm -rf a.out core *.o core.* vgcore.* gmon.out bdclient bdclient_x64 honggfuzz_target honggfuzz_target_debug libfuzzer_target bddeamon_x64 intercept/build intercept/*.a tests/build shmem_file_handling/*.o third_party/pe-parse/build log/log.o
	make -C peloader clean
	rm -rf faketemp
	rm -rf lib
