#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

#include "args.h"
#include "file.h"
#include "macros.h"


forensic *data;


int main(int argc, char* argv[], char* envp[]) {

    data = create_forensic();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data)) {
        delete_forensic(data);
        return 1;
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


    delete_forensic(data);

    return 0;
}