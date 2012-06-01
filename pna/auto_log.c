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
int read_logs(char *filename){
	int i;
	int fd;
	int of;
	int size;
	struct stat pf_stat;
	struct osf_control cur_control;
	struct osf_print *log_map;
	//Get control info
	if(control_read(&cur_control) != 0){
		return -1;	
	}
	    /* fetch size of proc file (used for mmap) */
    if (stat("/proc/osf_log", &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;

	of = open(filename, O_WRONLY | O_CREAT);
	if(of < 0) {
		perror("Raw Output file error");
		return -1;	
	}
    fd = open("/proc/osf_log", O_RDWR);
	        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
            }
            perror("open proc_file");
			close(of);
            return -1;
        }
	log_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	        if (log_map == MAP_FAILED) {
            perror("mmap");
            close(fd);
			close(of);
			return -1;
        }
	for(i=0 ; i < cur_control.num_log_entries ; i++){
		if((log_map+i)->done == 0){
			continue;
		}
		if(write(of, (log_map+i), sizeof(struct osf_print)) < 0){
			close(fd);
			close(of);
			perror("???");			
			return -1;		
		}
		(log_map+i)->done = 0;
	}
	close(fd);
	fchmod(of, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	close(of);
	return 0;
}

int main(int argc, char **argv){
	if(argc != 2){
		return -1;
	}
	if(read_logs(argv[1]) != 0){
		return -1;
	}
	return 0;
}
