#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "args.h"
#include "file.h"

 forensic *data;

int main(int argc, char* argv[], char* envp[]) {

    data = create_forensic();

    if (data == NULL)
        return 1;

    if (get_arguments(argc, argv, data)) {
        delete_forensic(data);
        return 1;
    }

    if (get_file_info(get_target(data), 0)) {
        delete_forensic(data);
        return 1;
    }


    printf("\nout: %s, file: %s\n", get_outfile(data), get_target(data));

    delete_forensic(data);

    return 0;
}