#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

struct count_info{
	unsigned long int total_count;
	unsigned long int non_ip_count;
	unsigned long int type_count[256];
};

int main(int argc, char **argv){
	int i;
	int fd;
	int size;
	struct stat pf_stat;
	struct count_info *count_ptr;
	struct count_info packet_counts;

	if(stat("/proc/pna/perf", &pf_stat) != 0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/perf", O_RDONLY);
	if(fd < 0){
		if(errno == EACCES){
		}
		perror("open proc_file");
		return -1;
	}
	count_ptr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if(count_ptr == MAP_FAILED){
		perror("mmap");
		close(fd);
	}
	printf("%u,", count_ptr->total_count);
	printf("%u,", count_ptr->non_ip_count);
	for(i=0 ; i < 256 ; i++){
		printf("%u,", count_ptr->type_count[i]);
	}
	printf(".\n");
	close(fd);
	return 0;
}
