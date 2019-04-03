#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>

#include "args.h"
#include "file.h"
#include "macros.h"


forensic *data;
double start_time;
int fd_log = 0;

void sigint_handler(int signo) {
    printf("\nexecution stopped\n");
    signal_log(signo, "SIGINT");
    exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[]) {

    struct timeval start_time_struct;
    if (gettimeofday(&start_time_struct, NULL) == -1)  // TODO: use errno
        return EXIT_FAILURE;
    start_time = start_time_struct.tv_sec * 1000 + start_time_struct.tv_usec * 0.001;

    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fputs("an error occurred while setting a signal handler. \n", stderr);
        return EXIT_FAILURE;
    }

    data = create_forensic();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data)) {
        delete_forensic(data);
        return 1;
    }

    if (get_log(data) && get_logfile(data) != NULL) {
        fd_log = open(get_logfile(data), O_WRONLY | O_APPEND | O_CREAT, MODE);
    }


    int fd_out = STDOUT_FILENO;

    // TODO : check if file already exists
    if (get_output(data)) {
        fd_out = open(get_outfile(data), O_WRONLY | O_CREAT, MODE);
    }

    if (fd_out == -1) {
        delete_forensic(data);
        return 1;
    }
     
    analyse_target(get_target(data), fd_out);

    close(fd_out);          // TODO: use errno
    close(fd_log);
    delete_forensic(data);

    return 0;
}