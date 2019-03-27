#include <stdbool.h>


typedef struct {
    bool recursive_flag, hash_flag, output_flag, logfile_flag;
    bool hash[3];               // 0: md5, 1: sha1, 2: sha256
    char *outfile, *target;     // outfile: CSV file, analyse: file/directory that will be analysed
} forensic_data;

forensic_data* init_forensic_data();
void free_forensic_data(forensic_data *data);

int get_arguments(int argc, char* argv[], forensic_data *data);


