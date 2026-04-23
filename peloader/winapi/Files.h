#ifndef LOADLIBRARY_FILES_H
#define LOADLIBRARY_FILES_H

enum {
    CREATE_NEW          = 1,
    CREATE_ALWAYS       = 2,
    OPEN_EXISTING       = 3,
    OPEN_ALWAYS         = 4,
    TRUNCATE_EXISTING   = 5
};

union Size {
    int64_t size;
    struct {
        int32_t low;
        int32_t high;
    };
};

union Offset {
    int64_t offset;
    struct {
        int32_t low;
        int32_t high;
    };
};

#define FILE_TYPE_CHAR 0x0002
#define FILE_TYPE_DISK 0x0001
#define FILE_TYPE_PIPE 0x0003
#define FILE_TYPE_REMOTE 0x8000
#define FILE_TYPE_UNKNOWN 0x0000

#define ERROR_FILE_NOT_FOUND 2

#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16

#define INVALID_FILE_ATTRIBUTES -1;
#define MAX_PATH_LENGTH 255

#endif //LOADLIBRARY_FILES_H
