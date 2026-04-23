#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "bdlibrary.h"

#define DAEMONIZE    0
#define DEFUALT_ROOT_SYSTEM_DIR "dummy"

int cl;

int WINAPI MyScanCallback(void *arg1, SCAN_RESULT *Result)
{
    if (Result == NULL)
        return 0;
    if (Result->Flags == 0 || Result->Flags == 0x40)
        LogMessage("%s (%s) => No threat detected!", Result->TmpFileName, Result->RealFileName);
    else if (Result->Flags == 0x240)
        return 0;
    else if (Result->Flags == 0x200000)
        LogMessage("An error occured. File unreadable?");
    else if (Result->Flags == 0x800040)
        LogMessage("Unpacking archive: %s", Result->RealFileName);
    else if (Result->Flags == 0x800240)
        LogMessage("Unpacking binary: %s", Result->RealFileName);
    else if (Result->Flags == 0x40)
        LogMessage("An error occured: %s", Result->RealFileName);
    else if (Result->Flags & 0x40000000)
        LogMessage("Threat Detected! %s (%s) => %s", Result->TmpFileName, Result->RealFileName, Result->Signature);
    else
        LogMessage("Unknown flag");
    return 0;
}

void sigalrm_handler(int signum) {
    printf("SIGALARM signal received\n");
    // This function will be called when SIGALRM is received
    write(cl, "[BDDEAMON_ERROR]: Sigalarm\n", 27);
    close(cl);
    
    exit(1); // Exit the program after handling the signal
}

static void daemonize(void) {
    pid_t pid, sid;

    /* already a daemon */
    if (getppid() == 1) return;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then we can exit the parent process. */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* At this point we are executing as the child process */

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory.  This prevents the current
       directory from being locked; hence not being able to remove it. */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Redirect standard files to /dev/null */
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}

int main(int argc, char *argv[]) {
    struct stat sb;
    int bdlib;

    /* socket server */
    char *socket_path = "/tmp/bdldr.sock", socket_buffer[1024];
    struct sockaddr addr2;
    
    struct sockaddr_un addr;
    int fd, rc = 1;
    char *ptr;

    bdlib = LoadModule("./engine/x64/bdcore.dll");
    if (bdlib == 0) {

        fprintf(stderr, "Initializing BD core ...\n");

        /* Init BD Core */
        int CoreInitializeResult = InitializeCore(DEFUALT_ROOT_SYSTEM_DIR, "Plugins");;
        if (CoreInitializeResult != 0)
            return -1;

        if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            perror("socket error");
            exit(EXIT_FAILURE);
        }
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
        unlink(socket_path);
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            perror("bind error");
            exit(EXIT_FAILURE);
        }
        if (listen(fd, 5) == -1) {
            perror("listen error");
            exit(EXIT_FAILURE);
        }
        chmod(socket_path, 0777);
        // fprintf(stderr, "Waiting for connections at %s\n", socket_path);

        /* Ignore SIGPIPE */
        signal(SIGPIPE, SIG_IGN);

#if DAEMONIZE
        fprintf(stderr, "Daemonizing ...\n");
        daemonize();
#endif

        fprintf(stderr, "Initializing BD core instance ...\n");
        void *BDCoreInstance = CreateCoreNewInstance();
        if (BDCoreInstance == NULL)
            return -1;

        fprintf(stderr, "Setting up scan callback ...\n");
        int SetScanCallBackResult = SetScanCallBack(BDCoreInstance, MyScanCallback);
        if (SetScanCallBackResult != 0)
            return -1;

        for (;;) {
            fprintf(stderr, "Waiting for connections at %s\n", socket_path);
            if ((cl = accept(fd, NULL, NULL)) == -1) {
                perror("accept error");
                continue;
            }
           
            /* Read only 1 command */
            rc = read(cl, socket_buffer, sizeof(socket_buffer));

            if (rc > 0) {
                if (strstr(socket_buffer, "SCAN ")) {
                    ptr = strchr(socket_buffer, '\n');
                    *ptr = 0x00;
                    ptr = strchr(socket_buffer, ' ') + 1;
                    /*
                    // Check file exists
                    if (stat(ptr, &sb) == -1) {
                        write(cl, "NO FILE", 7);
                        close(cl);
                        continue;
                    }
                    */
                        
                    fprintf(stderr, "[%d] Scanning %s ...\n", getpid(), ptr);

                    /* scan file */
                    /* handle hangs when fuzzing */
                    // alarm(300);
                    //printf("%s", ptr);
                    ScanFile(BDCoreInstance, ptr);
                    //alarm(0);
                    write(cl, "OUTPUT OK\n", 9);
                }
                else if (strstr(socket_buffer, "END")) {
                    write(cl, "OUTPUT OK: END command received. Exiting...\n", 44);
                    printf("Scan terminated by user. Exiting...\n");
                    break;
                }
            }
            close(cl);
        };
        DeleteCoreInstance(BDCoreInstance);
    } else {
        fprintf(stderr, "Error loading bdcore.so\n");
        return EXIT_FAILURE;
    }
    if (bdlib != 0) dlclose((void *)bdlib);
    return EXIT_SUCCESS;
}
