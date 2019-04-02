#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/wait.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <signal.h>

#include "file.h"
#include "macros.h"
#include "forensic.h"

extern forensic *data;

int issue_command(char* buf, size_t buf_size) {

       FILE* filep = popen(buf, "r"); //READ-ONLY

        if (filep == NULL)
            return 1;

        fread(buf,1, buf_size,filep);
        pclose(filep);
        return 0;      
}

// TODO : change permission string to "rwx|rwx|rwx"
void get_permissions(mode_t mode, char *buf) {
    const char chars[] = "rwxrwxrwx";
    for (size_t i = 0; i < 9; i++) {
        buf[i] = (mode & (1 << (8 - i))) ? chars[i] : '-';
    }
    buf[9] = '\0';
}

bool is_dir(char *path) {

    struct stat path_stat;

    if (stat(path, &path_stat) == -1)
        return false;

    return S_ISDIR(path_stat.st_mode);
}

int get_file_info(char *name, int out_fd) {

    struct stat file_stat;
    char output[PIPE_BUF];  // string that will be written to out_fd

    if (stat(name, &file_stat) == -1)   // use errno here (file doesnt exist)
        return 1;

    /* add file NAME to the output string */
    strcat(output, name);
    strcat(output, ",");

    char buf[PIPE_BUF];

    //using popen() inside issue_command
    strcpy(buf, "file --brief --preserve-date --print0 --print0 ");
    strcat(buf, name);
    
    if (issue_command(buf, sizeof(buf))) {
        return 1;
    }

    /* add file TYPE to the output string */
    strncat(output, buf, strlen(buf));
    strcat(output, ",");
    
    /* add file SIZE to the output string */
    sprintf(buf, "%ld,", (size_t) file_stat.st_size);
    strncat(output, buf, strlen(buf));

    /* add file PERMISSIONS to the output string */    
    get_permissions(file_stat.st_mode, buf);
    strncat(output, buf, strlen(buf));
    strcat(output, ",");

    /* get TIME OF LAST ACCESS */
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_atime)));
    strncat(output, buf, strlen(buf));
    strcat(output, ",");
    
    /* get TIME OF LAST MODIFICATION */
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_mtime)));
    strncat(output, buf, strlen(buf));
    strcat(output, ",");
    
    /* get TIME OF LAST ACCESS */
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_ctime)));
    strncat(output, buf, strlen(buf));
    
    // CRYPTOGRAPHY 
    if(get_hash(data)){

        if(get_md5(data)){

            strcpy(buf, "md5sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }
            
            strcat(output, ",");
            char *crypt = strtok(buf, " ");
            strcat(output, crypt);                      
        }

        if(get_sha1(data)){

            strcpy(buf, "sha1sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }

            strcat(output, ",");
            char *crypt = strtok(buf, " ");
            strcat(output, crypt);
        }

        if(get_sha256(data)){

            strcpy(buf, "sha256sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }
            
            strcat(output, ",");
            char *crypt = strtok(buf, " ");
            strcat(output, crypt);
        }
    }
    
    strcat(output, "\n");
    
    write(out_fd, output, strlen(output));

    return 0;
}


void sigint_handler_child(int signo) {
    exit(EXIT_SUCCESS);
}

int analyse_target(char *target, int out_fd) {

    if (!is_dir(target)) {
        get_file_info(target, out_fd);  // TODO : handle errors
        return 0;
    }

    DIR *dir = opendir(target);

    if (dir == NULL)
        return 1;

    struct dirent *ds;

    int num_child = 0;
    
    while ((ds = readdir(dir)) != NULL) {     // TODO : use errno in case of error

        if (!strcmp(ds->d_name, "."))
                continue;
        if (!strcmp(ds->d_name, ".."))
                continue;
        
        char path[500];
        strcpy(path, target);
        strcat(path, "/");
        strcat(path, ds->d_name);

        if (is_dir(path)) {
            num_child++;

            if (get_recursive(data)) {
                int child_pid = fork();

                if (child_pid == -1)
                    return -1;
                else if (child_pid == 0)
                {
                    if (signal(SIGINT, sigint_handler_child) == SIG_ERR) {
                        fputs("an error occurred while setting a signal handler. \n", stderr);
                        return EXIT_FAILURE;
                    }

                    analyse_target(path, out_fd);
                    exit(EXIT_SUCCESS);
                }
            }    
            continue;
        }

        get_file_info(path, out_fd);
    }

    while (num_child > 0) {
        wait(NULL);
        num_child--;
    }
        
    return 0;
}