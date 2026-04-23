# BitDefender Windows engine porting to Linux
## Introduction

This repository contains a port of the BitDefender Windows engine to Linux using [loadlibrary](https://github.com/taviso/loadlibrary).

It is a research project focused on fuzzing and program analysis of the BitDefender engine in a Linux-hosted environment. The goal is to make the Windows engine easier to instrument, execute repeatedly, and integrate with external analysis tooling and fuzzing workflows. This codebase has also been used together with [LibAFL-BDCore-Fuzzer](https://github.com/cube0x8/LibAFL-BDCore-Fuzzer).

```
$ ./bdclient_x64 eicar.com
LoadModule(): The map file wasn't found, symbols wont be available
main(): Initializing the BitDefender core...
main(): BitDefender core initialized!
main(): Creating a core instance...
main(): Core instance created successfully!
main(): *** Running a scan... ***
MyScanCallback(): Threat Detected! C:\dummy/eicar.com (C:\dummy/eicar.com) => EICAR-Test-File (not a virus)
main(): Deleting the core instance...
main(): Core instance delete successfully.
```

## Setup
First of all, you need to download and install BitDefender on a Windows machine.
Then, locate the engine DLL (`bdcore.dll`) and the `Plugins` directory. Place `bdcore.dll` in `engine/x64`.

By default, `bdclient_x64` expects:

- the engine at `./engine/x64/bdcore.dll`
- the extracted BitDefender runtime tree under `./dummy`
- the plugins under `./dummy/Plugins`

The main build target is:

```bash
make bdclient_x64
```

The `Makefile` also exposes several build-time feature flags as environment variables:

- `SHARED_MEM=1`: enables the shared-memory file handling path used by some fuzzing workflows
- `FUZZ=1`: builds with fuzzing-oriented code paths enabled
- `LIBAFL_FUZZING=1`: enables the LibAFL-specific scanning path
- `HONGGFUZZ_FUZZING=1`: enables the Honggfuzz-specific build path
- `PE_MUTATOR=1`: links the PE mutator C API support and expects `PE_MUTATOR_DIR` to point to the mutator project
- `PE_MUTATOR_DIR=/path/to/libafl-pe-mutator`: overrides the default PE mutator location used by the `Makefile`

Examples:

```bash
make bdclient_x64
make bdclient_x64 SHARED_MEM=1 FUZZ=1
make bdclient_x64 FUZZ=1 LIBAFL_FUZZING=1
make honggfuzz_target FUZZ=1 HONGGFUZZ_FUZZING=1
```

`debug` builds are also available through:

```bash
make debug
make honggfuzz_target_debug
```

## Usage

The normal command line format is:

```bash
$ ./bdclient_x64 [OPTIONS] file1 file2 ...
```

Supported runtime switches:

- `--root-system-dir <dir>`: uses an alternate root directory for the runtime layout. With this switch, the loader looks for the engine at `<dir>/engine/x64/bdcore.dll` and the plugin tree at `<dir>/dummy/Plugins`
- `--loop <count>`: rescans the supplied input files in a loop using the same initialized core instance. This is useful for repeated execution and persistent-style fuzzing. Use `-1` for an unbounded loop

## Fuzzers

The `fuzzers/` directory contains integration targets and helpers for different fuzzing setups:

- `fuzzers/honggfuzz_target/persistent-bdclient.cpp`: a persistent Honggfuzz-oriented target with extra support for repeated execution, feedback collection, and trampoline-based instrumentation
- `fuzzers/honggfuzz_target/pe_mutator_ffmutate_wrapper.sh`: a helper wrapper to use with honggfuzz' `--ffmutate_cmd` CLI switch
- `fuzzers/wtf/fuzzer_bdcore.cc`: a WTF snapshot-based harness for running the engine with the WTF fuzzer
- `fuzzers/wtf/bdcore.h`: target-specific declarations used by the WTF harness
- [LibAFL-BDCore-Fuzzer](https://github.com/cube0x8/LibAFL-BDCore-Fuzzer): a LibAFL, snapshot-based, fuzzer that uses this harness 

## License

GPL2
