CFLAGS    	 = $(USER_DEFINED) -g -fPIC -ggdb3 -fshort-wchar -fno-omit-frame-pointer -Wno-multichar -I../include -I../log -mstackrealign -I../shmem_file_handling/
CPPFLAGS  	 = -D_GNU_SOURCE -I. -I../intercept/include -Wno-writable-strings -Wno-unused-value -Wno-deprecated -Wno-expansion-to-defined -Wno-return-type
LDFLAGS   	 = $(CFLAGS) -lm
ARCH	  	 = x64
OBJECT_FILES = winstrings.o pe_linker.o crt.o util.o extra.o file_mapping.o instrumentation.o
CC = gcc

RELEASE_CFLAGS 	 = -O3
RELEASE_CPPFLAGS = -DNDEBUG

ifeq ($(ARCH),x86)
	CFLAGS  += -m32
	LDFLAGS += -m32
else ifneq ($(ARCH),x64)
$(error Supported target architectures: x86 or x64)
endif

ifeq ($(SHARED_MEM),1)
	CFLAGS  += -DSHARED_MEM
endif

ifeq ($(HONGGFUZZ_FUZZING),1)
	CFLAGS  += -DHONGGFUZZ_FUZZING
endif

ifeq ($(ASAN),1)
	CFLAGS  += -fsanitize=address -Wunused-value -Wwritable-strings
endif

.PHONY: clean

# This glob matches all the winapi exports we provide.
WINAPI  = $(patsubst %.c,%.o,$(wildcard winapi/*.c))

TARGETS=libpeloader.a

all: CFLAGS += $(RELEASE_CFLAGS)
all: CPPFLAGS += $(RELEASE_CPPFLAGS)
all: $(TARGETS)

debug: $(TARGETS)

fuzz: $(TARGETS)

libpeloader.a: $(WINAPI) $(OBJECT_FILES)
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out winapi/*.o $(TARGETS)
