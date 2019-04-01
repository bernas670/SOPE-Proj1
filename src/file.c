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

    if (stat(name, &file_stat) == -1)       // use errno here (file doesnt exist)
        return 1;

    write(out_fd, name, strlen(name));
    write(out_fd, ",", 1);

    char buf[PIPE_BUF];


    //using popen() inside issue_command
    strcpy(buf, "file --brief --preserve-date --print0 --print0 ");
    strcat(buf, name);
    
    if (issue_command(buf, sizeof(buf))) {
        return 1;
    }

    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);
    sprintf(buf, "%ld,", (size_t) file_stat.st_size);
    write(out_fd, buf, strlen(buf));

    get_permissions(file_stat.st_mode, buf);
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    // time of last access
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_atime)));
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);
    
    // time of last modification
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_mtime)));
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    // time of last status change
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_ctime)));
    write(out_fd, buf, strlen(buf));

    // CRYPTOGRAPHY 

    if(get_hash(data)){

        if(get_md5(data)){

            strcpy(buf, "md5sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }
            
            write(out_fd, ",", 1);
            char *crypt = strtok(buf, " ");
            write(out_fd, crypt, strlen(crypt));
            
        }

        if(get_sha1(data)){

            strcpy(buf, "sha1sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }
            
            write(out_fd, ",", 1);
            char *crypt = strtok(buf, " ");
            write(out_fd, crypt, strlen(crypt));
        }

        if(get_sha256(data)){

            strcpy(buf, "sha256sum ");
            strcat(buf, name);

            if (issue_command(buf, sizeof(buf))) {
               return 1;
            }
            
            write(out_fd, ",", 1);
            char *crypt = strtok(buf, " ");
            write(out_fd, crypt, strlen(crypt));
        }
    }
    
    write(out_fd, "\n", 1);
   
    return 0;
}


int analyse_target(char *target, int out_fd) {

    if (!is_dir(target)) {
        get_file_info(target, out_fd);  // TODO : handle errors
        return 0;
    }

    int child_pid = fork();

    if (child_pid == -1)
        return -1;
    else if (child_pid != 0) {
        return 0;
    }

    DIR *dir = opendir(target);

    if (dir == NULL)
        return 1;

    struct dirent *ds;

    if (chdir(target) == -1)
        return 1;

    while ((ds = readdir(dir)) != NULL) {     // TODO : use errno in case of error

        if (!strcmp(ds->d_name, "."))
                continue;
        if (!strcmp(ds->d_name, ".."))
                continue;

        analyse_target(ds->d_name, out_fd);
            
    }

    return 0;
}