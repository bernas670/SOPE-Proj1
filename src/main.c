#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>

#include "args.h"
#include "file.h"
#include "macros.h"

 forensic *data;

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

    if (is_dir(get_target(data))) {
        
    }
    
    if (get_file_info(get_target(data), fd_out)) {
        delete_forensic(data);
        return 1;
    }
    


    printf("\nout: %s, file: %s\n", get_outfile(data), get_target(data));

    delete_forensic(data);

    return 0;
}