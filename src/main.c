#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include<signal.h>

#include "args.h"
#include "file.h"
#include "macros.h"


forensic *data;


void sigint_handler(int signo){
    
    printf("\nO Brandao vai dar CTRL-C na gaja de BDAD :)\n");
    
    exit(0);

}


int main(int argc, char* argv[], char* envp[]) {

    // teste
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }


    data = create_forensic();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data)) {
        delete_forensic(data);
        return 1;
    }

    int fd_log = 0;
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