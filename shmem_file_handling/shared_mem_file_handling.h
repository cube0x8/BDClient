#define MIN(x, y) ((x) > (y) ? (y) : (x))
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

struct _mmap_file {
    char filename[255];
    void *data;
    size_t size;
    size_t position;
};


typedef struct _mmap_file mmap_file, *p_mmap_file;

#ifdef __cplusplus
extern "C" {
#endif

int new_mmap_buffer(uint8_t *data, size_t size, char *filename);
int new_mmap_file(char* filename);
int delete_mmap_file();
int mmap_read(void *out_buffer, unsigned int n_bytes_to_read, unsigned int *n_bytes_read);
int mmap_seek(int64_t offset, int method);

extern mmap_file g_mmap_file; 

#ifdef __cplusplus
}
#endif
