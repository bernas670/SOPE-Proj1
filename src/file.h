#ifndef FILE_H
#define FILE_H

int issue_command(char* buf, size_t buf_size);


int get_file_info(char *name, int out_fd);


/**
 * @brief Get permissions of a file from the mode_t struct (part of the stat struct)
 * 
 * @param mode  Mode struct of the file
 * @param buf   Buffer where the permissions will be outputed to (needs to be at least 10 bytes long)
 */
void get_permissions(mode_t mode, char *buf);


#endif
