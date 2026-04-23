#ifndef BDLIBRARY_H
#define BDLIBRARY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SCAN_RESULT {
    DWORD Unknown1;
    char *TmpFileName;
    char *RealFileName;
    DWORD Unknown4;
    DWORD Flags;
    DWORD Unknown6;
    DWORD Unknown7;
    char *Signature;
} SCAN_RESULT;

#define EXE_UNPACK 0x19
#define ARCHIVE_UNPACK 0x1a
#define EMAIL_UNPACK 0x1b
#define HEURISTICS 0x21
#define REGISTER_CALLBACK 0x27
#define SCAN 0x37
#define ENABLE (void *)0x1
#define DISABLE (void *)0x0

extern bool SCAN_STARTED;

int InitializeCore(const char *root_dir, const char *plugin_dir);

void *CreateCoreNewInstance();

int DeleteCoreInstance(void *core_instance);

#if defined(LIBAFL_FUZZING) || defined(HONGGFUZZ_FUZZING)
int ScanFile(void *core_instance, uint8_t *buf, size_t size, char *file_path);
#else
int ScanFile(void *core_instance, char *file_path);
#endif

int SetScanCallBack(void *core_instance, int (*func)(void *, SCAN_RESULT *) __attribute__((ms_abi)));

int LoadModule(const char *engine_path);
void ResetScanState(void);

bool UnloadModule();

#ifdef __cplusplus
}
#endif

#endif //BDLIBRARY_H
