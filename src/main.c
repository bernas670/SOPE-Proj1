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

    if (is_dir(get_target(data))) {

        DIR *directory = opendir(get_target(data));

        if (directory == NULL) {
            delete_forensic(data);
            return 1;
        }

        struct dirent *ds;

        if (chdir(get_target(data)) == -1)
            return 1;

        while ((ds = readdir(directory)) != NULL) {     // TODO : use errno in case of error
            if (strcmp(ds->d_name, ".") == 0 || strcmp(ds->d_name, "..") == 0)
                continue;

            printf("%s\n", ds->d_name);
            
            if (get_file_info(ds->d_name, fd_out)) {
            delete_forensic(data);
            return 1;
            }  
            
        }

        
    }
    else {
        if (get_file_info(get_target(data), fd_out)) {
        delete_forensic(data);
        return 1;
        }
    }
    
    

    printf("\nout: %s, file: %s\n", get_outfile(data), get_target(data));

    delete_forensic(data);

    return 0;
}