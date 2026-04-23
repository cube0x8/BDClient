// Axel '0vercl0k' Souchet - July 10 2021
#include "backend.h"
#include "bdcore.h"
#include "targets.h"
#include <fmt/format.h>

namespace fs = std::filesystem;

namespace BDCore {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("BDCore: ");
    fmt::print(Format, args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
  if (BufferSize < sizeof(uint32_t)) {
    return true;
  }

  struct _FILE_PARSING_STATE ParsingState;
  // read the original parsing structure from the snapshot memory
  if(!g_Backend->VirtReadStruct(Gva_t(g_Backend->Rax()), &ParsingState)) {
    DebugPrint("Failed to read bitbuf during testcase injection!");
    return false;
  }

  // modify the size of the file under scan
  ParsingState.EndOfFileOffset = BufferSize;

  // write the modified parsing struct back into the snapshot
  if (!g_Backend->VirtWriteStruct(Gva_t(g_Backend->Rax()), &ParsingState)) {
    DebugPrint("Failed to write parsing struct during testcase "
               "injection!");
  }
  // inject the fuzzed message data into the snapshot for this execution
  if (!g_Backend->VirtWrite(Gva_t((uint64_t)ParsingState.FileContent), Buffer, BufferSize, true)) {
    DebugPrint("Failed to write next testcase!");
    return false;
  }

  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &CpuState) {

  // stop execution if we reach the ret instruction in cab_initarc(...)
  if (!g_Backend->SetBreakpoint(Gva_t(0x023132561EFB), [](Backend_t *Backend) {
    DebugPrint("Reached function end\n");
    Backend->Stop(Ok_t());
  }))
  {
    return false;
  }

  // Instrument the Windows user-mode exception dispatcher to catch access violations
  //SetupUsermodeCrashDetectionHooks();

  return true;
}


bool Restore() { return true; }

//
// Register the target.
//

Target_t BDCore("BDCore", Init, InsertTestcase, Restore);

} // namespace BDCore