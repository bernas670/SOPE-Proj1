#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "forensic.h"


forensic_data* init_forensic_data() {
    forensic_data *ptr = malloc(sizeof(forensic_data));

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(forensic_data));

    return ptr;
}

void free_forensic_data(forensic_data *data) {
    free(data);
}


extern char *optarg; // used when parsing options that take a name as a parameter, contains a pointer to that parameter
extern int optind;   // current index into the main function's argument list


int get_arguments(int argc, char* argv[], forensic_data *data) {

    char opt;
    /* get command line arguments */
    while ((opt = getopt(argc, argv, "rh:o:v")) != -1) {
        switch (opt)
        {
            case 'r':
                if (data->recursive_flag == true) {
                    printf("-r is set multiple times\n");
                    return -1;
                }                
                data->recursive_flag = true;
                break;

            case 'h':
                if (data->hash_flag) {
                    printf("-h is set multiple times\n");
                    return -1;
                }
                data->hash_flag = true;
                
                char *ptr = strtok(optarg, ",");
                for (size_t i = 0; ; i++) {
                    if (i)
                        ptr = strtok(NULL, ",");

                    if (ptr == NULL)
                        break;

                    if (strcmp(ptr, "md5") == 0)
                        data->hash[0] = true;
                    else if (strcmp(ptr, "sha1") == 0)
                        data->hash[1] = true;
                    else if (strcmp(ptr, "sha256") == 0)
                        data->hash[2] = true;
                    else {
                        printf("'%s' is not a valid cryptographic hash\n", ptr);
                        return -1;
                    }
                }

                break;

            case 'o':
                if (data->output_flag) {
                    printf("-o is set multiple times\n");
                    return -1;
                }
                data->output_flag = true;
                data->outfile = strdup(optarg);
                break;

            case 'v':
                if (data->logfile_flag) {
                    printf("-v is set multiple times\n");
                    return -1;
                }
                data->logfile_flag = true;
                break;

            default:
                break;
        }
    }


    if (optind == argc) {
        if (data->recursive_flag)
            printf("missing target directory \n");
        else
            printf("missing target file \n");
        
        return 1;
    }

    while (optind <= argc) {
        printf("optind : %d, argc : %d \n", optind, argc);
        printf("%s \n", argv[optind]);
        if (data->target == 0) {
            data->target = strdup(argv[optind]);
        }
        else
            printf("invalid expression\n");
    }

    

    return 0;
}

