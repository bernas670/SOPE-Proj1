#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "args.h"

extern char *optarg; // used when parsing options that take a name as a parameter, contains a pointer to that parameter
extern int optind;   // current index into the main function's argument list


int get_arguments(int argc, char* argv[], forensic *data) {

    char opt;
    /* get command line arguments */
    while ((opt = getopt(argc, argv, "rh:o:v")) != -1) {
        switch (opt)
        {
            case 'r':
                if (get_recursive(data)) {
                    printf("-r is set multiple times\n");
                    return -1;
                }                
                set_recursive(data, true);
                break;

            case 'h':
                if (get_hash(data)) {
                    printf("-h is set multiple times\n");
                    return -1;
                }
                set_hash(data, true);
                
                char *ptr = strtok(optarg, ",");
                for (size_t i = 0; ; i++) {

                    if (ptr == NULL)
                        break;

                    if (strcmp(ptr, "md5") == 0)
                        set_md5(data, true);
                    else if (strcmp(ptr, "sha1") == 0)
                        set_sha1(data, true);
                    else if (strcmp(ptr, "sha256") == 0)
                        set_sha256(data, true);
                    else {
                        printf("'%s' is not a valid cryptographic hash\n", ptr);
                        return -1;
                    }

                    ptr = strtok(NULL, ",");
                }

                break;

            case 'o':
                if (get_output(data)) {
                    printf("-o is set multiple times\n");
                    return -1;
                }
                set_output(data, true);
                set_outfile(data, optarg);
                break;

            case 'v':
                if (get_logfile(data)) {
                    printf("-v is set multiple times\n");
                    return -1;
                }
                set_logfile(data, true);
                break;

            default:
                break;
        }
    }


    if (optind == argc) {
        printf("missing target file/directory \n");    
        return 1;
    }
    else {
        set_target(data, argv[optind]);
        optind++;
    }

    if (optind == argc)
        return 0;
    else {
        printf("too many arguments were parsed \n");
        return 1;
    }
}

