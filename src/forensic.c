#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "forensic.h"


int main(int argc, char* argv[], char* envp[]) {

    forensic_data *data = init_forensic_data();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data))
        return 1;

    printf("out: %s, file: %s \n", data->outfile, data->target);

    free_forensic_data(data);

    return 0;
}