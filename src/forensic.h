#include <stdbool.h>


struct st_forensic;
typedef struct st_forensic forensic;


/* CONSTRUCTOR */
forensic* create_forensic();
/* DESTRUCTOR */
void delete_forensic(forensic *data);


bool get_recursive(forensic *ptr);
void set_recursive(forensic *ptr, bool flag);

bool get_hash(forensic *ptr);
void set_hash(forensic *ptr, bool flag);

bool get_output(forensic *ptr);
void set_output(forensic *ptr, bool flag);

bool get_logfile(forensic *ptr);
void set_logfile(forensic *ptr, bool flag);

bool get_md5(forensic *ptr);
void set_md5(forensic *ptr, bool flag);

bool get_sha1(forensic *ptr);
void set_sha1(forensic *ptr, bool flag);

bool get_sha256(forensic *ptr);
void set_sha256(forensic *ptr, bool flag);

char *get_outfile(forensic *ptr);
void set_outfile(forensic *ptr, char *filename);

char *get_target(forensic *ptr);
void set_target(forensic *ptr, char *targetname);
