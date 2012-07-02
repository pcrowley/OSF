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
#include <stdint.h>

struct osf_control{
	unsigned int num_log_entries;//The number of entries to be kept in the log
	unsigned int num_db_entries;//The number of entries to be kept in the database
	unsigned int cur_db_entries;//Current number of entries loaded into database
	unsigned int next_log;//Next log to be written
	unsigned int missed_logs;//Number of logs missed due to the log being full
};
//Type definitions for fixed-width data (userspace)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef	int8_t	 s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

struct osf_print{
	//Fingerprint info, 27 bytes
	u8		done;//Flag set to 1 if log is complete, 0 if empty
	u32		src_ip;//Source IP
	u32		dst_ip;//Destination IP
	u16		opt_hash;//Should never exceed 12800
	u32		quirks;//Set of 17 quirk flags.
	u8		opt_eol_pad;//Amount of bytes past EOL, 40 max
	u8		ip_opt_len;//Length of IP options
	u8		ip_version;//0=any, 4=IPv4, 6=IPv6
	u8		ttl;//Time to live
	u16		mss;//Max segment size, max 65535
	u16		win;//Window size, max 65535
	u8		win_type;//Window type, explained below
	u8		win_scale;//Window scaling, max 255
	u8		pay_class;//0 = any, 1 = No data, 2 = data
	u32		ts1;
	u32		ts2;
	u8		wildcards;//Set of wildcards for above values, see below
	u32		unix_time;//If this doesn't work, change to u64?
	char	os_type;
	char	os_class[5];
	char	os_name[20];
	char	os_flavor[20];
//Window type:
/*
	0=Wildcard.  The value for win can be anything.
	1=Direct value.  The value used for win is exact.
	2=Multiple of MSS.  Actual window is = win * mss.
	3=Multiple of MTU.  Actual window is = win * mtu.
	MTU should never come up.
	4=Multiple of a fixed value.  Actual window % win = 0.
*/
//Wildcards:
/*
	A set of flags for the values that can be wildarded,
	organized by bits:
	1=mss
	2=win_scale
*/
};

struct osf_print *database_user;
int user_size;

int control_read(struct osf_control *ret_control){
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
	memcpy(ret_control, control_ptr, sizeof(struct osf_control));
	close(fd);
	return 0;
}

int load_db_from_file(char *filename){
	int fd;
	int size;
	struct stat pf_stat;
	struct osf_print *database_map;
    if (stat(filename, &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;
	user_size = size;
	database_user = (struct osf_print*)malloc(size);
	if(database_user == ENOMEM){
		printf("Not enough memory\n");
		return -1;
	}
	fd = open(filename, O_RDONLY);
	if(fd < 0){
		printf("File IO error\n");
		return -1;
	}
	database_map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (database_map == MAP_FAILED) {
        perror("mmap");
        close(fd);
		return -1;
    }
	memcpy(database_user, database_map, size);
	close(fd);
	return 0;
}

int copy_db(struct osf_print *control_info){
	int fd;
	int size;
	int user_entries;
	struct stat pf_stat;
	struct osf_print *db_map;
	    /* fetch size of proc file (used for mmap) */
    if (stat("/proc/osf_db", &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;

    fd = open("/proc/osf_db", O_RDWR);
	        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
            }
            perror("open proc_file");
            return -1;
        }
	db_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	        if (db_map == MAP_FAILED) {
            perror("mmap");
            close(fd);
			return -1;
        }
	if(user_size > size){
		memcpy(db_map, database_user, size);
		printf("Warning:  Not enough memory allocated to\n");
		printf("database, only first %u entries copied.\n", size / sizeof(struct osf_print));	
		db_map->src_ip = size / sizeof(struct osf_print);
	}
	else{
		memcpy(db_map, database_user, user_size);
		db_map->src_ip = user_size / sizeof(struct osf_print);
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv){
	struct osf_control control_info;
	char *filename;
	if(control_read(&control_info) != 0){
		return -1;
	}
	if(argc != 2){
		return -1;
	}
	filename = argv[1];
	if(load_db_from_file(filename) != 0){
		return -1;
	}
	if(copy_db(&control_info) != 0){
		return -1;
	}
	printf("Database Loaded\n");
	return 0;
}
