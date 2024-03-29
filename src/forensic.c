#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


#include "forensic.h"

/**
 * @brief Struct that contains all the information parsed as a command line argument.
 */
struct st_forensic {
    bool recursive_flag;    /**< -r flag */
    bool hash_flag;         /**< -h flag */
    bool output_flag;       /**< -o flag */
    bool log_flag;          /**< -v flag */
    bool md5_flag;          /**< md5 flag */
    bool sha1_flag;         /**< sha1 flag */
    bool sha256_flag;       /**< sha256 flag */
    char *outfile;          /**< name of the CSV output file */
    char *logfile;          /**< name of the logfile */
    char *target;           /**< name of the file or starting directory that will be analysed */
    int pid;                /**< process id of the original process */
    int num_dir;            /**< number of directories analyzed */
    int num_file;           /**< number of files analyse */
};


forensic* create_forensic() {
    forensic *ptr = malloc(sizeof(forensic));

    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(forensic));

    ptr->pid = getpid();

    return ptr;
}

void delete_forensic(forensic *ptr) {
    free(ptr);
}


bool get_recursive(forensic *ptr) { return ptr->recursive_flag; }
void set_recursive(forensic *ptr, bool flag) { ptr->recursive_flag = flag; }

bool get_hash(forensic *ptr) { return ptr->hash_flag; }
void set_hash(forensic *ptr, bool flag) { ptr->hash_flag = flag; }

bool get_output(forensic *ptr) { return ptr->output_flag; }
void set_output(forensic *ptr, bool flag) { ptr->output_flag = flag; }

bool get_log(forensic *ptr) { return ptr->log_flag; }
void set_log(forensic *ptr, bool flag) { ptr->log_flag = flag; }

bool get_md5(forensic *ptr) { return ptr->md5_flag; }
void set_md5(forensic *ptr, bool flag) { ptr->md5_flag = flag; }

bool get_sha1(forensic *ptr) { return ptr->sha1_flag; }
void set_sha1(forensic *ptr, bool flag) { ptr->sha1_flag = flag; }

bool get_sha256(forensic *ptr) { return ptr->sha256_flag; }
void set_sha256(forensic *ptr, bool flag) { ptr->sha256_flag = flag; }

char *get_outfile(forensic *ptr) { return ptr->outfile; }
void set_outfile(forensic *ptr, char *filename) { ptr->outfile = strcat(strdup(filename), ".csv"); }

char *get_logfile(forensic *ptr) { return ptr->logfile; }
void set_logfile(forensic *ptr) { ptr->logfile = getenv("LOGFILENAME"); }

char *get_target(forensic *ptr) { return ptr->target; }
void set_target(forensic *ptr, char *targetname) { ptr->target = strdup(targetname); }

void increment_num_dir(forensic *ptr) { ptr->num_dir++; }
int get_num_dir(forensic *ptr) { return ptr->num_dir; }

void increment_num_file(forensic *ptr) { ptr->num_file++; }
int get_num_file(forensic *ptr) { return ptr->num_file; }

int get_pid(forensic *ptr) { return ptr->pid; }
