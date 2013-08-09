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
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>

#include "fnv.h"

#define COPY_MAX_PACKETS 1000000
#define COPY_MAX_BYTES 100

struct copy_table {
	unsigned int start;
	unsigned int end;
	unsigned int skipped;
	char data[COPY_MAX_PACKETS][COPY_MAX_BYTES];
};

struct copy_table table;
struct copy_table table_dest;

int copy_logs(){
	int fd;
	int size;
	struct stat pf_stat;
	void *osf_map;
	if(stat("/proc/pna/copy", &pf_stat)!=0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/copy", O_RDWR);
	if(fd < 0){
		perror("open proc_file copy_logs\n");
		return -1;
	}
	osf_map = mmap(NULL, sizeof(struct copy_table), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(osf_map == MAP_FAILED){
		perror("mmap");
		close(fd);
		return -1;
	}
	memcpy(&table, osf_map, sizeof(struct copy_table));
	close(fd);
	munmap(osf_map, size);
	return 0;
}

int read_logs(char **argv){
	void *logs;
	int i,j;
	uint8_t temp;
	copy_logs();
	memcpy(&table_dest, &table, sizeof(struct copy_table));
	return 0;
}

int main(int argc, char **argv){
	int i;
	unsigned int a,b;
	unsigned long int total;
	FILE *fp;
	total = 0;
	i=0;
	//while(1==1){
		read_logs(argv);
		a = table_dest.start;
		b = table_dest.end;
		if(a <= b){
			total = total + b - a;
		}
		else{
			total = total + (COPY_MAX_PACKETS - a) + b;
		}
		i++;
		if(i >= 100){
		printf("%u\n", total);
		i = 0;
		}
	//}
	fp = fopen("table.out", "w");
	fwrite(&table_dest, sizeof(struct copy_table), 1, fp);
	fclose(fp);
	return 0;
}
