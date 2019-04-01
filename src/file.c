#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/wait.h>
#include <string.h>
#include <limits.h>

#include "file.h"
#include "macros.h"
#include "forensic.h"

extern forensic *data;

int issue_command(char* buf){

       FILE* filep=popen(buf,"r"); //READ-ONLY

        if(filep==NULL){
            return 1;
        }

        
        fread(buf,1, 100,filep);
        
        pclose(filep);
        return 0;
            
}

void get_permissions(mode_t mode, char *buf) {
    const char chars[] = "rwxrwxrwx";
    for (size_t i = 0; i < 9; i++) {
        buf[i] = (mode & (1 << (8 - i))) ? chars[i] : '-';
    }
    buf[9] = '\0';
}

int get_file_info(char *name, int out_fd) {


    struct stat file_stat;

    if (stat(name, &file_stat) == -1)       // use errno here (file doesnt exist)
        return 1;

    write(out_fd, name, strlen(name));
    write(STDERR_FILENO, ",", 1);

    char buf[PIPE_BUF];

    //using popen() inside issue_command
    strcpy(buf, "file --brief --preserve-date --print0 --print0 ");
    strcat(buf, name);
    if(issue_command(buf)){
        return 1;
    }

    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    sprintf(buf, "%ld,", (size_t) file_stat.st_size);
    write(out_fd, buf, strlen(buf));

    get_permissions(file_stat.st_mode, buf);
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_atime)));
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);
    
    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_mtime)));
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    strftime(buf, sizeof(buf), "%FT%T", localtime(&(file_stat.st_ctime)));
    write(out_fd, buf, strlen(buf));
    write(out_fd, ",", 1);

    // CRYPTOGRAPHY 

    if(get_hash(data)){

        if(get_md5(data)){

            strcpy(buf, "md5sum ");
            strcat(buf, name);

            if(issue_command(buf)==1){
               return 1;
            }
        
            write(out_fd, buf, strlen(buf));
            write(out_fd, ",", 1);
            
        }

        if(get_sha1(data)){

            strcpy(buf, "sha1sum ");
            strcat(buf, name);

            if(issue_command(buf)==1){
               return 1;
            }
        
            write(out_fd, buf, strlen(buf));
            write(out_fd, ",", 1);
            
        }

        if(get_sha256(data)){

            strcpy(buf, "sha256sum ");
            strcat(buf, name);

            if(issue_command(buf)==1){
               return 1;
            }
        
            write(out_fd, buf, strlen(buf));
            write(out_fd, ",", 1);
            
        }
    }
    
   
    printf("\n");

    return 0;
}