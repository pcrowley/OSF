#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

struct osf_control{
	unsigned int num_log_entries;//The number of entries to be kept in the log
	unsigned int num_db_entries;//The number of entries to be kept in the database
	unsigned int cur_db_entries;//Current number of entries loaded into database
	unsigned int next_log;//Next log to be written
	unsigned int missed_logs;//Number of logs missed due to the log being full
};

int main(int argc, char **argv){
	int fd;
	int size;
	struct stat pf_stat;
	struct osf_control *control_ptr;
	struct osf_control cur_control;
	    /* fetch size of proc file (used for mmap) */
    if (stat("/proc/osf_read", &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;
    fd = open("/proc/osf_read", O_RDONLY);
	        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
            }
            perror("open proc_file");
            return -1;
        }
	control_ptr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	        if (control_ptr == MAP_FAILED) {
            perror("mmap");
            close(fd);
        }
	memcpy(&cur_control, control_ptr, sizeof(struct osf_control));
	close(fd);
	printf("Max Log Entries: %u\n", cur_control.num_log_entries);
	printf("Max DB Entries:  %u\n", cur_control.num_db_entries);
	printf("Current DB Ent.: %u\n", cur_control.cur_db_entries);
	printf("Current Log:     %u\n", cur_control.next_log);
	printf("Missed Logs:     %u\n", cur_control.missed_logs);
	return 0;
}
