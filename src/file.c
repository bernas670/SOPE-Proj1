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

void strmode(mode_t mode, char *buf) {
    const char chars[] = "rwxrwxrwx";
    for (size_t i = 0; i < 9; i++) {
        buf[i] = (mode & (1 << (8 - i))) ? chars[i] : '-';
    }
    buf[9] = '\0';
}

int get_file_info(char *name, int out_fd) {

    if (!out_fd)
        out_fd = STDOUT_FILENO;

    struct stat file_stat;

    if (stat(name, &file_stat) == -1)       // use errno here (file doesnt exist)
        return 1;

    write(out_fd, name, strlen(name));
    write(STDERR_FILENO, ",", 1);

    int fd[2];

    if (pipe(fd))
        return 1;

    char buf[PIPE_BUF];
    int buf_size;

    //int pid = getpid();
    int c_pid = fork();

    if (c_pid == -1) {
        return 1;
    }
    else if (c_pid == 0) {
        close(fd[READ]);
        dup2(fd[WRITE], STDOUT_FILENO);
        dup2(fd[WRITE], STDERR_FILENO);
        close(fd[WRITE]);
        
        execlp("file", "--brief", name, (char *) NULL); // use errno
        printf("failed exec!\n");
        return 1;
    }
    else {
        close(fd[WRITE]);
        buf_size = read(fd[READ], buf, sizeof(buf));
        wait(NULL);
    }

    write(out_fd, buf, buf_size);
    write(out_fd, ",", 1);
    sprintf(buf, "%ld,", (size_t) file_stat.st_size);
    write(out_fd, buf, strlen(buf));

    strmode(file_stat.st_mode, buf);
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

    // CRYPTOGRAPHY MISSING
    
   
    printf("\n");

    return 0;
}