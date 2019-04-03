#ifndef FILE_H
#define FILE_H

#include "stdbool.h"

void write_log(char* act);

void analize_log(char* name);

void signal_log(int signo, char *signame);

int issue_command(char* buf, size_t buf_size);

int file_info(char *name, int out_fd);

int analyse_target(char *target, int out_fd);


/**
 * @brief   Simple function that takes as an argument the name of a file and checks if it is a
 *          directory or not.
 * 
 * @param path      Name of the file
 * @return true     Returns true if the file is a directory
 * @return false    Returns false if the file is not a directory
 */
bool is_dir(char *path);


/**
 * @brief Get permissions of a file from the mode_t struct (part of the stat struct)
 * 
 * @param mode  Mode struct of the file
 * @param buf   Buffer where the permissions will be outputed to (needs to be at least 10 bytes long)
 */
void get_permissions(mode_t mode, char *buf);


#endif
