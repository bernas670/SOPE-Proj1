#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "args.h"
#include "file.h"


int main(int argc, char* argv[], char* envp[]) {

    forensic *data = create_forensic();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data)) {
        delete_forensic(data);
        return 1;
    }

    struct stat file_stat;

    if (stat(get_target(data), &file_stat) == -1)       // use errno here (file doesnt exist)
        return 1;

    char buf[10];
    strmode(file_stat.st_mode, buf);
    printf("permissions : %s\n", buf);

    printf("%s,%d \n\n", get_target(data), (int) file_stat.st_size);

    printf("out: %s, file: %s \n", get_outfile(data), get_target(data));

    delete_forensic(data);

    return 0;
}