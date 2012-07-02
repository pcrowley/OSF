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

int control_read(){
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

int control_change(struct osf_control *new_control){
	int fd;
	int size;
	struct stat pf_stat;
	struct osf_control *control_ptr;
	struct osf_control cur_control;
	    /* fetch size of proc file (used for mmap) */
    if (stat("/proc/osf_change", &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;
    fd = open("/proc/osf_change", O_RDWR);
	        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
            }
            perror("open proc_file");
            return -1;
        }
	control_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	        if (control_ptr == MAP_FAILED) {
            perror("mmap");
            close(fd);
        }
	control_ptr->num_log_entries = new_control->num_log_entries;
	control_ptr->num_db_entries = new_control->num_db_entries;
	control_ptr->cur_db_entries = new_control->cur_db_entries;
	control_ptr->next_log = new_control->next_log;
	control_ptr->missed_logs = new_control->missed_logs;

	memcpy(&cur_control, control_ptr, sizeof(struct osf_control));
	close(fd);
	printf("Max Log Entries: %u\n", cur_control.num_log_entries);
	printf("Max DB Entries:  %u\n", cur_control.num_db_entries);
	printf("Current DB Ent.: %u\n", cur_control.cur_db_entries);
	printf("Current Log:     %u\n", cur_control.next_log);
	printf("Missed Logs:     %u\n", cur_control.missed_logs);
	return 0;
	return 0;
}

int usage(){
	printf("Usage:\n");
	printf("-l and -d are required, as new values\n");
	printf("are necessary to reinitialize the OSF\n");
	printf("Root is necessary for all options except\n");
	printf("-r.\n");
	printf("-h Prints this usage info\n");
	printf("-r Prints the current control info\n");
	printf("-w Suppresses warning described below\n");
	printf("-l [int] Sets the max log entries\n");
	printf("-d [int] Sets the max db entries\n");
	printf("*The following options will raise a\n");
	printf("*warning, do not use them except for\n");
	printf("*explicit testing purposes:\n");
	printf("-p [int] Sets the next log pointer\n");
	printf("-e [int] Sets the actual db size\n");
	printf("-m [int] Sets the missed log count\n");
	return 0;
}

int main(int argc, char **argv){
	char buffer[25];
	unsigned int temp_int;
	unsigned int i;
	short readFlag = 0;
	short logFlag = 0;
	short dbFlag = 0;
	short curLogFlag = 0;
	short curDbFlag = 0;
	short missLogFlag = 0;
	short suppressFlag = 0;
	short warningFlag = 0;
	struct osf_control new_control;	
	
	for(i=1 ; i < argc ; i++){
		if(strncmp(argv[i], "-r", 2) == 0){
			readFlag = 1;
			continue;		
		}
		if(strncmp(argv[i], "-w", 2) == 0){
			suppressFlag = 1;
			continue;		
		}
		if(strncmp(argv[i], "-h", 2) == 0){
			return usage();
		}
		if(strncmp(argv[i], "-l", 2) == 0){
			logFlag = 1;
			if(i + 1 >= argc){
				return usage();
			}
			new_control.num_log_entries = (unsigned int)atoi(argv[++i]);
			if(new_control.num_log_entries == 0){
				return usage();			
			}
			continue;
		}
		if(strncmp(argv[i], "-d", 2) == 0){
			dbFlag = 1;
			if(i + 1 >= argc){
				return usage();
			}
			new_control.num_db_entries = (unsigned int)atoi(argv[++i]);
			if(new_control.num_db_entries == 0){
				return usage();			
			}
			continue;
		}
		if(strncmp(argv[i], "-p", 2) == 0){
			warningFlag = 1;
			curLogFlag = 1;
			if(i + 1 >= argc){
				return usage();
			}
			new_control.next_log = (unsigned int)atoi(argv[++i]);
			if(new_control.next_log == 0){
				return usage();			
			}
			continue;
		}
		if(strncmp(argv[i], "-e", 2) == 0){
			warningFlag = 1;
			curDbFlag = 1;
			if(i + 1 >= argc){
				return usage();
			}
			new_control.cur_db_entries = (unsigned int)atoi(argv[++i]);
			if(new_control.cur_db_entries == 0){
				return usage();			
			}
			continue;
		}
		if(strncmp(argv[i], "-m", 2) == 0){
			warningFlag = 1;
			missLogFlag = 1;
			if(i + 1 >= argc){
				return usage();
			}
			new_control.missed_logs = (unsigned int)atoi(argv[++i]);
			if(new_control.missed_logs == 0){
				return usage();			
			}
			continue;
		}
		return usage();
	}
	if(readFlag == 1){
		return control_read();
	}
	if((warningFlag == 1) && (suppressFlag == 0)){
		printf("WARNING!\n");
		printf("Usage of -p, -e, or -m can cause OSF\n");
		printf("instabilities.  Do you wish to continue?\n");
		printf("[Y]es/[N]o: ");
		scanf("%s", buffer);
		if(buffer[0] != 'Y'){
			return 0;
		}
	}
	if((logFlag == 0) || (dbFlag == 0)){
		return usage();
	}
	if(curLogFlag == 0){
		new_control.next_log = 0;	
	}
	if(curDbFlag == 0){
		new_control.cur_db_entries = 0;
	}
	if(missLogFlag == 0){
		new_control.missed_logs = 0;	
	}

	return control_change(&new_control);
}
