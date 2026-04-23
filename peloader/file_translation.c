#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "file_translation.h"
#include "winapi/Files.h"


void file_path_translation(char *original_file_path, char* translated_local_path) {
    size_t translated_local_path_size = MAX_PATH_LENGTH;
    size_t translated_file_path_length = strlen(kDummyPathA);
    size_t file_path_length = 0;

    // Copy the filepath first
    char *file_path = (char*) malloc(strlen(original_file_path) + 1);
    memset(file_path, 0, strlen(original_file_path) + 1);
    strncpy(file_path, original_file_path, strlen(original_file_path));

    // Translate path separator.
    while (strchr(file_path, '\\'))
        *strchr(file_path, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = file_path; *t; t++)
        *t = (char)tolower(*t);

    // Check if it is an absolute path
    char *absolute_path = strstr(file_path, "c:/");
    if (absolute_path != NULL) {
        file_path_length = strlen(file_path) - (file_path - absolute_path); // remove "c:\"
        file_path = &absolute_path[3];
    }

    // Check if it is relative
    else if (file_path[0] == '.' && file_path[1] == '\\') {
        file_path_length -= 1; // remove "c:\"
        file_path = &file_path[2];
    }
    else {
        file_path_length = strlen(file_path);
    }

    // Calculate the new length
    translated_file_path_length += file_path_length;
    translated_file_path_length += 1; // null terminator

    // Replace the path with a local dummy one
    char *new_filepath = (char*) malloc(translated_file_path_length);
    memset(new_filepath, 0, translated_file_path_length);
    strncpy(new_filepath, kDummyPathA, strlen(kDummyPathA));
    strncpy(&new_filepath[strlen(kDummyPathA)], file_path, strlen(file_path));

    if (translated_file_path_length > translated_local_path_size) {
        translated_local_path_size = translated_file_path_length;
        translated_local_path = realloc(translated_local_path, translated_local_path_size);
    }

    // Normalize the path
    memset(translated_local_path, 0, translated_local_path_size);
    realpath(new_filepath, translated_local_path);

    free(new_filepath);
}
