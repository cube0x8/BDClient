#include <search.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared_mem_file_handling.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

mmap_file g_mmap_file;


int new_mmap_buffer(uint8_t *data, size_t size, char *filename) {
    // Allocate memory for the data
    uint8_t *file_data = (uint8_t *)calloc(size, 1);
    if (file_data == NULL) {
        perror("new_mmap_buffer calloc");
        return -1;
    }
    memcpy(file_data, data, size);
    
    memset(&g_mmap_file, 0, sizeof(struct _mmap_file));
    strncpy(g_mmap_file.filename, filename, sizeof(g_mmap_file.filename));
    g_mmap_file.data = file_data;
    g_mmap_file.size = size;
    g_mmap_file.position = 0;

    return 0;
}


int new_mmap_file(char *filename) {
    // Check if the filename is valid
    if (filename == NULL || strlen(filename) == 0) {
        fprintf(stderr, "Invalid filename\n");
        return -1;
    }

    // Open the file
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    // Allocate memory for the data
    uint8_t *file_data = (uint8_t *)calloc(file_size, 1);
    if (file_data == NULL) {
        perror("malloc");
        fclose(file);
        return -1;
    }

    // Read the file data into memory
    if (fread(file_data, 1, file_size, file) != file_size) {
        perror("fread");
        free(file_data);
        fclose(file);
        return -1;
    }

    // Close the file
    fclose(file);

    // Initialize the _mmap_file struct
    memset(&g_mmap_file, 0, sizeof(struct _mmap_file));
    strncpy(g_mmap_file.filename, filename, sizeof(g_mmap_file.filename));
    g_mmap_file.data = file_data;
    g_mmap_file.size = file_size;
    g_mmap_file.position = 0;

    return 0; // Success
}

int delete_mmap_file() {
    // Free the data pointer
    if (g_mmap_file.data != NULL) {
        free(g_mmap_file.data);
        g_mmap_file.data = NULL;
    }

    // Reset the other fields
    memset(g_mmap_file.filename, 0, sizeof(g_mmap_file.filename));
    g_mmap_file.size = 0;
    g_mmap_file.position = 0;
}

int mmap_read(void *out_buffer, unsigned int n_bytes_to_read, unsigned int *n_bytes_read) {
    // Check if the file is valid and within bounds
    if (out_buffer == NULL || n_bytes_read == NULL) {
        perror("mmap_read: wrong parameters");
        return 0;
    }

    // Calculate the number of bytes that can be read without exceeding the file size
    int bytes_available = g_mmap_file.size - g_mmap_file.position;
    int bytes_to_read = n_bytes_to_read;
    if (bytes_to_read > bytes_available) {
        bytes_to_read = bytes_available;
    }

    // Copy data from the file to the user-supplied buffer
    memcpy(out_buffer, g_mmap_file.data + g_mmap_file.position, bytes_to_read);

    // Update the seek pointer and the number of bytes read
    g_mmap_file.position += bytes_to_read;
    *n_bytes_read = bytes_to_read;

    return 1;
}

int mmap_seek(int64_t offset, int method) {
    int64_t new_position;
    int ret_value;

    // Calculate the new position after seeking
    if (method == 0) {  // FILE_BEGIN
        new_position = offset;
    } else if (method == 1) {  // FILE_CURRENT
        new_position = g_mmap_file.position + offset;
    } else if (method == 2) {  // FILE_END
        new_position = g_mmap_file.size + offset; 
    }

    // Ensure the new position is within bounds
    if (new_position < 0) {
        // msdn: If a new file pointer is a negative value, the function fails, the file pointer is not moved, and the code returned by GetLastError is ERROR_NEGATIVE_SEEK.
        new_position = g_mmap_file.position;
        ret_value = -1;
    }

    // Update the position
    g_mmap_file.position = (size_t)new_position;
    ret_value = g_mmap_file.position;

    return ret_value;
}

#ifdef __cplusplus
}
#endif
