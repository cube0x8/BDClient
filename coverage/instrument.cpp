#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <search.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "pin.H"
#include "xed-interface.h"
#include "coverage.h"
#include "modules_manager.hpp"
#include "instrument.hpp"

#if defined(TARGET_IA32) && defined(TARGET_LINUX) && !defined(PIN_FAST_ANALYSIS_CALL)
# define PIN_FAST_ANALYSIS_CALL __attribute__((regparm(3)))
#else
# define PIN_FAST_ANALYSIS_CALL
#endif

#define COVERAGE_END "***COVERAGE_END***"
#define COVERAGE_START "***COVERAGE_START***"
#define TRACE_START "***TRACE_START***"
#define TRACE_END "***TRACE_END***"
#define EDGES_START "***EDGES_START***"
#define EDGES_END "***EDGES_END***"

module_coverage_result coverage_results = {
    .instructions= 0,
    .blockcount= 0,
    .totalinstructions= 0,
    .totalblocks = 0
};


VOID PIN_FAST_ANALYSIS_CALL InstrumentBasicBlock(ADDRINT address, UINT32 size, tree_t *blocks, char *module_name)
{
    void **data;

    execution_record_t *record, block = {
        .address = address,
        .size    = size,
        .count   = 0,
        .module_name = module_name,
    };

    // Do a slow btree lookup...
    if (tree_find(blocks, &block, &data)) {
        record = (execution_record_t *)*data;
    } else {
        // Create a new record to install
        record = (execution_record_t *)malloc(sizeof(execution_record_t));
        memcpy(record, &block, sizeof(execution_record_t));
        tree_add(blocks, record, &data);
    }

    record->count++;

    return;
}

static const char kCoverageReport[] = "coverage_stats.txt";
static const char kCoverageVariable[] = "COVERAGE_REPORT_FILE";

static const char kCoverageTrace[] = "COVERAGE_TRACE";


/*
unsigned instructions = 0;
unsigned blockcount = 0;
unsigned totalinstructions = 0;
unsigned totalblocks = 0;
*/

void calculate_block_stats(const void *v) {
    const execution_record_t *d = (execution_record_t *) v;
    coverage_results.blockcount++;
    coverage_results.instructions += d->size;
    coverage_results.totalblocks += d->count;
    coverage_results.totalinstructions += d->size * d->count;
}

size_t send_to_server(int clientSocket, const void *data, size_t data_length) {
    // Prepare coverage data as a string (modify as needed)
    char data_with_separator[1024] = { 0x0 };
    if (data_length >= sizeof(data_with_separator)) {
        printf("Cannot send data bigger than 1024 bytes. Exit.");
        exit(-1);
    }
    snprintf(data_with_separator, sizeof(data_with_separator), "%s\n", (const char *)data);
    return send(clientSocket, data_with_separator, strlen(data_with_separator), 0);
}

size_t write_to_file(FILE *output_file, const void *data, size_t data_length) {
    // Prepare coverage data as a string (modify as needed)
    char data_with_separator[1024] = { 0x0 };
    if (data_length >= sizeof(data_with_separator)) {
        printf("Cannot send data bigger than 1024 bytes. Exit.");
        exit(-1);
    }
    snprintf(data_with_separator, sizeof(data_with_separator), "%s\n", (const char *)data);
    size_t n_bytes_written = fwrite(data_with_separator, strlen(data_with_separator), 1, output_file);

    return n_bytes_written;
}

void store_coverage_stats_to_file() {
    FILE *output_file = fopen(getenv(kCoverageVariable)
                    ? getenv(kCoverageVariable)
                    : kCoverageReport, "a");

    // Send START
    write_to_file(output_file, COVERAGE_START, strlen(COVERAGE_START));
    // Send scanned filename 
    write_to_file(output_file, g_file_path, strlen(g_file_path));

    size_t module_set_size = ModuleSetSize();
    for (size_t i = 0; i < module_set_size; i++) {
        BitDefenderModule *module = FindModuleByIndex(i);

        tree_walk(module->Blocks, calculate_block_stats);

        // Start TRACE information
        write_to_file(output_file, TRACE_START, strlen(TRACE_START));

        // Prepare coverage data as a string
        char coverageData[1024] = { 0x0 };
        snprintf(coverageData, sizeof(coverageData), 
                "module_name=%s;instructions=%lu;blockcount=%lu;totalinstructions=%lu;totalblocks=%lu\n",
                module->ModuleName.c_str(), coverage_results.instructions, coverage_results.blockcount, coverage_results.totalinstructions, 
                coverage_results.totalblocks);
        
        // Send trace coverage data to the server
        write_to_file(output_file, coverageData, strlen(coverageData));

        // End TRACE information
        write_to_file(output_file, TRACE_END, strlen(TRACE_END));
        
        // Start Edges
        write_to_file(output_file, EDGES_START, strlen(EDGES_START));

        EDG_HASH_SET edge_set = module->EdgeSet;
        for (const auto& entry : edge_set) {
            EDGE edge = entry.first;
            COUNTER* counter_ptr = entry.second;

            BitDefenderModule *src_module = FindModuleByAddress(edge._src);
            BitDefenderModule *dst_module = FindModuleByAddress(edge._dst);
            BitDefenderModule *next_ins_module = FindModuleByAddress(edge._next_ins);
            char src[100] = { 0 };
            char dst[100] = { 0 };
            char next_ins[100] = { 0 };
            char src_module_name[50] = { 0 };
            char dst_module_name[50] = { 0 };
            char next_ins_module_name[50] = { 0 };
            ADDRINT src_module_start_addr;
            ADDRINT dst_module_start_addr;
            ADDRINT next_ins_module_start_addr;

            if (src_module == NULL) {
                strncpy(src_module_name, "jit_code", 9);
                src_module_start_addr = 0;
            } else {
                strncpy(src_module_name, (char *)(src_module->ModuleName.c_str()), 49);
                src_module_start_addr = src_module->Start;
            }

            if (dst_module == NULL) {
                strncpy(dst_module_name, "jit_code", 9);
                dst_module_start_addr = 0;
            } else {
                strncpy(dst_module_name, (char *)(dst_module->ModuleName.c_str()), 49);
                dst_module_start_addr = dst_module->Start;
            }

            if (next_ins_module == NULL) {
                strncpy(next_ins_module_name, "jit_code", 9);
                next_ins_module_start_addr = 0;
            } else {
                strncpy(next_ins_module_name, (char *)(next_ins_module->ModuleName.c_str()), 49);
                next_ins_module_start_addr = next_ins_module->Start;
            }

            snprintf(src, sizeof(src), "%s+%#lx", src_module_name, edge._src - src_module_start_addr);
            snprintf(dst, sizeof(dst), "%s+%#lx", dst_module_name, edge._dst - dst_module_start_addr);
            snprintf(next_ins, sizeof(next_ins), "%s+%#lx", next_ins_module_name, edge._next_ins - next_ins_module_start_addr);
            
            coverageData[1024] = { 0 };
            snprintf(coverageData, sizeof(coverageData),
                "src=%s;dst=%s;type=%s;next_ins=%s;count=%ld",
                src,
                dst,
                StringFromEtype(edge._type).c_str(),
                next_ins,
                counter_ptr->_count);

                // Send edges coverage data to the server
                write_to_file(output_file, coverageData, strlen(coverageData));
        }

        // End Edges
        write_to_file(output_file, EDGES_END, strlen(EDGES_END));

        coverage_results.instructions = 0;
        coverage_results.blockcount = 0;
        coverage_results.totalinstructions = 0;
        coverage_results.totalblocks = 0;
    }

    write_to_file(output_file, COVERAGE_END, strlen(COVERAGE_END));
    // Close the socket
    fclose(output_file);
}

void store_coverage_stats_socket() {
    int clientSocket;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    // Server address configuration
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345); // Replace with your server's port
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Replace with your server's IP

    // Connect to the server
    addr_size = sizeof(serverAddr);
    connect(clientSocket, (struct sockaddr *)&serverAddr, addr_size);

    // Send START
    send_to_server(clientSocket, COVERAGE_START, strlen(COVERAGE_START));
    // Send scanned filename 
    send_to_server(clientSocket, g_file_path, strlen(g_file_path));
    
    size_t module_set_size = ModuleSetSize();
    for (size_t i = 0; i < module_set_size; i++) {
        BitDefenderModule *module = FindModuleByIndex(i);

        tree_walk(module->Blocks, calculate_block_stats);

        // Start TRACE information
        send_to_server(clientSocket, TRACE_START, strlen(TRACE_START));

        // Prepare coverage data as a string
        char coverageData[1024] = { 0x0 };
        snprintf(coverageData, sizeof(coverageData), 
                "module_name=%s;instructions=%lu;blockcount=%lu;totalinstructions=%lu;totalblocks=%lu\n",
                module->ModuleName.c_str(), coverage_results.instructions, coverage_results.blockcount, coverage_results.totalinstructions, 
                coverage_results.totalblocks);
        
        // Send trace coverage data to the server
        send_to_server(clientSocket, coverageData, strlen(coverageData));

        // End TRACE information
        send_to_server(clientSocket, TRACE_END, strlen(TRACE_END));
        
        // Start Edges
        send_to_server(clientSocket, EDGES_START, strlen(EDGES_START));

        EDG_HASH_SET edge_set = module->EdgeSet;
        for (const auto& entry : edge_set) {
            EDGE edge = entry.first;
            COUNTER* counter_ptr = entry.second;
            
            coverageData[1024] = { 0 };
            snprintf(coverageData, sizeof(coverageData),
                "src=%p;dst=%p;type=%s;next_ins=%p;count=%ld",
                (void *) edge._src,
                (void *) edge._dst,
                StringFromEtype(edge._type).c_str(),
                (void *) edge._next_ins,
                counter_ptr->_count);

                // Send edges coverage data to the server
                send_to_server(clientSocket, coverageData, strlen(coverageData));
        }

        // End Edges
        send_to_server(clientSocket, EDGES_END, strlen(EDGES_END));

        coverage_results.instructions = 0;
        coverage_results.blockcount = 0;
        coverage_results.totalinstructions = 0;
        coverage_results.totalblocks = 0;
    }

    send_to_server(clientSocket, COVERAGE_END, strlen(COVERAGE_END));
    // Close the socket
    close(clientSocket);
}


/* VOID store_coverage_stats()
{
    output = fopen(getenv(kCoverageVariable)
                        ? getenv(kCoverageVariable)
                        : kCoverageReport, "a");

    if (getenv(kCoverageTrace)) {
        trace_output = fopen(getenv(kCoverageTrace), "w");
    }

    size_t module_set_size = ModuleSetSize();

    fprintf(output, "\n\n----- START -----\n");
    fprintf(output, "FILENAME: %s \n", g_file_path);

    for (size_t i = 0; i < module_set_size; i++) {
        BitDefenderModule *module = FindModuleByIndex(i);

        tree_walk(module->Blocks, calculate_block_stats);

        fprintf(output, "\n\n----- COVERAGE ANALYSIS -----\n");
        fprintf(output, "Unpacker module name: %s\n", module->ModuleName.c_str());
        fprintf(output, "%lu Unique Instructions Executed\n", coverage_results.instructions);
        fprintf(output, "%lu Unique Basic Blocks Executed\n", coverage_results.blockcount);
        fprintf(output, "%lu Total Instructions Executed\n", coverage_results.totalinstructions);
        fprintf(output, "%lu Total Basic Blocks Executed\n", coverage_results.totalblocks);

        coverage_results.instructions = 0;
        coverage_results.blockcount = 0;
        coverage_results.totalinstructions = 0;
        coverage_results.totalblocks = 0;
    }

    fprintf(output, "\n\n----- END -----\n");

    return;
} */

VOID InstrumentFiniCallback(INT32 code, VOID *v) {
/*     if (trace_output != NULL) {
        fclose(trace_output);
    }
    if (output != NULL) {
        fclose(output);
    } */
    return;
}
