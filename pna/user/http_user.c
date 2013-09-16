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

#include "fnv.h"

unsigned int db_size;
unsigned int log_size;
unsigned int convert_size;

struct tm cur_date;

struct http_control{
	unsigned int num_ips;
	unsigned int num_logs;
	unsigned int num_db_entries;
	unsigned int cur_db_entries;
	unsigned int num_convert;
	unsigned int missed_logs;
};

struct http_print{
	uint32_t	db_entry;
	uint32_t	src_ip;
	uint32_t	dst_ip;
};

struct http_info{
	uint32_t	src_ip;
	uint32_t	table_index;
	uint32_t	current_log;
};

#define CONVERT_INDEX_MAX 100
#define CONVERT_HASH_MAX 997
#define TRANSITIONS_MAX 20
#define MAX_SUBSTRING 30

uint32_t http_hf_checksums[997] = { 0, 5400750, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 194456, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 195480, 0, 164664590, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 180672, 0, 0, 0, 1450854, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1354162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9266, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1302, 0, 0, 88044, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1341284, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1444004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2370, 0, 0, 0, 0, 0, 0, 0, 0, 164661914, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1345380, 0, 0, 10400, 0, 0, 0, 0, 0, 0, 176906, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2901720, 0, 0, 23384, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 310576, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2530, 5393310, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1348530, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2626, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5670, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2694, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 725554, 0, 0, 2732, 0, 0, 0, 0, 0, 0, 2695636, 0, 0, 0, 0, 0, 0, 0, 5401502, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 649248166, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5392558, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11774, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6418528, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2850, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20582970, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5107552, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20728566, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25213102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11944, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
uint8_t http_hf_convert[997] = { 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 2, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 21, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


struct http_sig{
	struct http_print print;
	uint8_t version;
	uint64_t inset;
	uint64_t outset;
	char hf_values[TRANSITIONS_MAX][MAX_SUBSTRING];
	uint8_t rule_table[TRANSITIONS_MAX][CONVERT_INDEX_MAX];
	uint8_t transition_table[TRANSITIONS_MAX][CONVERT_INDEX_MAX];
};

void clear_label(struct http_sig *sig){
	return;
}

void print_print(struct http_print *print){
	//Write Later
	return;
}
void print_sig(struct http_sig *sig){
	int i,j;
	printf("print: %u %u %u\n", sig->print.db_entry, sig->print.src_ip, sig->print.dst_ip);
	printf("version: %u\n", sig->version);
	printf("inset: %u\n", sig->inset);
	printf("outset: %u\n", sig->outset);
	printf("hf_values:\n");
	for(i=0 ; i < TRANSITIONS_MAX ; i++){
		for(j=0 ; j < MAX_SUBSTRING ; j++){
			printf("%c", sig->hf_values[i][j]);
		}
		printf("\n");
	}
	printf("rule_table:\n");
	for(i=0 ; i < TRANSITIONS_MAX ; i++){
		for(j=0 ; j < CONVERT_INDEX_MAX ; j++){
			printf("%u", sig->rule_table[i][j]);
		}
		printf("\n");
	}
	printf("transition_table:\n");
	for(i=0 ; i < TRANSITIONS_MAX ; i++){
		for(j=0 ; j < CONVERT_INDEX_MAX ; j++){
			printf("%u", sig->transition_table[i][j]);
		}
		printf("\n");
	}
	return;
}

void print_help(){
	printf("OSF User Help:\n");
	printf("Usage:  ./http_user <option> <option_args>\n");
	printf("Available Options:\n");
	printf("-p:Print OSF Debug Info\n");
	printf("-c <#IPs> <#Logs per IP> <#DB Entries> <#Convert Table>:Change control info\n");
	printf("-d <path/to/db/file>:Load new database file\n");
	printf("-r log_path db_path max_ips:Output log entries to file\n");
}

int parse_args(int argc, char **argv){
	if(argc == 1){
		return -1;
	}
	if(argv[1][0] != '-'){
		return -1;
	}
	if(argv[1][1] == 'p'){
		if(argc == 2){
			return 0;
		}
	}
	if(argv[1][1] == 'c'){
		if(argc == 6){
			return 1;
		}
	}
	if(argv[1][1] == 'd'){
		if(argc == 3){
			return 2;
		}
	}
	if(argv[1][1] == 'r'){
		if(argc == 5){
			return 3;
		}
	}
	return -1;
}

int print_control_info(){
	int fd;
	int size;
	struct stat pf_stat;
	struct http_control *control_ptr;
	struct http_control cur_control;
	if(stat("/proc/pna/http", &pf_stat) != 0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/http", O_RDONLY);
	if(fd < 0){
		perror("Error: Failed to open procfile\n");
		return -1;
	}
	control_ptr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if(control_ptr == MAP_FAILED){
		perror("Error: mmap failed to compelte\n");
		close(fd);
		return -1;
	}
	memcpy(&cur_control, control_ptr, sizeof(struct http_control));
	close(fd);
	printf("Max IPs: %u\n", cur_control.num_ips);
	printf("Max Logs Per IP: %u\n", cur_control.num_logs);
	printf("Max DB Entries: %u\n", cur_control.num_db_entries);
	printf("Convert Table Size: %u\n", cur_control.num_convert);
	printf("Current DB Entries: %u\n", cur_control.cur_db_entries);
	printf("Missed Logs: %u\n", cur_control.missed_logs);
	return 0;
}

int change_control_info(char **argv){
	struct http_control new_control;
	new_control.num_ips = (unsigned int)atoi(argv[2]);
	new_control.num_logs = (unsigned int)atoi(argv[3]);
	new_control.num_db_entries = (unsigned int)atoi(argv[4]);
	new_control.num_convert = (unsigned int)atoi(argv[5]);
	new_control.cur_db_entries = 0;
	new_control.missed_logs = 0;
	int fd;
	int size;
	struct stat pf_stat;
	struct http_control *control_ptr;
	struct http_control cur_control;

	if(stat("/proc/pna/http", &pf_stat) != 0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/http", O_RDWR);
	if(fd < 0){
		perror("Error: Failed to open procfile\n");
		return -1;
	}
	control_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(control_ptr == MAP_FAILED){
		perror("Error: mmap failed to complete\n");
		close(fd);
		return -1;
	}
	memcpy(control_ptr, &new_control, sizeof(struct http_control));
	munmap(control_ptr, size);
	close(fd);
	return 0;
}

struct http_sig *construct_list(char *filename){
	FILE *fp;
	char buffer[1000];
	char file_list[1000][1000];
	int lengths[1000];
	int colons;
	int i,j,k,l;
	int list_size=0;
	int cur_entry=0;
	uint64_t inset;
	uint64_t outset;
	uint32_t inset_checksums[100];
	uint32_t outset_checksums[100];
	uint32_t inset_question_marks[100];
	uint32_t checksum;
	char substrings[100][MAX_SUBSTRING];
	int substring_index=0;
	int num_hf = 0;
	uint32_t total;
	int state;
	unsigned int total_count=0;
	struct http_sig cur_sig;
	//Overall values necessary to compute all fields
	uint8_t hf_order[100];
	uint8_t hf_order_outset[100];
	uint8_t hf_length;
	uint8_t hf_value_flag[100];
	struct http_sig *ret;
	fp = fopen(filename, "r");
	if(fp == NULL){
		printf("File open error\n");
		printf("%s\n", filename);
		return NULL;
	}
	while(fgets(buffer, sizeof(buffer), fp) != NULL){
		for(i=0 ; i < 1000 ; i++){
			file_list[list_size][i] = buffer[i];
			if(buffer[i] == '\n'){
				break;
			}
		}
		lengths[list_size] = i;
		list_size = list_size + 1;
	}
	fclose(fp);
	db_size = list_size * sizeof(struct http_sig);
	ret = (struct http_sig *)malloc(db_size);
	memset(ret, 0, db_size);
	for(i=0 ; i < list_size ; i++){
		cur_sig.version = 0;
		cur_sig.inset = 0;
		cur_sig.outset = 0;
		for(j=0 ; j < TRANSITIONS_MAX ; j++){
			for(k=0 ; k < MAX_SUBSTRING ; k++){
				cur_sig.hf_values[j][k] = 0;
			}
			for(k=0 ; k < CONVERT_INDEX_MAX ; k++){
				cur_sig.rule_table[j][k] = 0;
				cur_sig.transition_table[j][k] = 0;
			}
		}
		switch(file_list[i][0]){
		case 'l'://label
			for(j=0 ; j < lengths[i] ; j++){
				if(colons >= 2){
					break;
				}
				if(file_list[i][j] == ':'){
					colons++;
				}
			}
			k=0;
			for( ; j < lengths[i] ; j++){
				//cur_sig.name[k] = file_list[i][j];
				k++;
			}
			//cur_sig.name[k] = '\0';
			break;
		case 's'://sig
			cur_sig.print.db_entry = total_count;
			total_count++;
			if(file_list[i][8] == '0'){
				cur_sig.version = 0;
			}
			else if(file_list[i][8] == '1'){
				cur_sig.version = 1;
			}
			else{
				cur_sig.version = 2;//wildcard since 2 is unused
			}
			//First, let's convert the inset and the outset.
			for(j=0 ; j < 100 ; j++){
				hf_value_flag[j] = 0;
				inset_checksums[j] = 0;
				outset_checksums[j] = 0;
				inset_question_marks[j] = 0;
				hf_order[j] = 0;
				hf_order_outset[j] = 0;
			}
			inset = 0;
			outset = 0;
			num_hf = 0;
			state = 0;
			checksum = 0;
			substring_index = 0;
			total = 0;
			for(j=10 ; j < lengths[i] ; j++){
				//Exit condition
				if(file_list[i][j] == ':'){
					break;
				}
				if(state == 0){
					//Default State, records question mark if there, otherwise falls to next state
					if(file_list[i][j] == '?'){
						inset_question_marks[num_hf] = 1;
					}
					else{
						state = 1;
					}
				}
				if(state == 1){
					//Calculates checksum
					//First, if we seen an '=' we know that we are moving to substring territory
					if(file_list[i][j] == '='){
						j++;
						state = 2;
					}
					else if(file_list[i][j] == ','){
						state = 3;
					}
					else if(file_list[i][j] != ' '){
						total = (total + file_list[i][j]) * 2;
					}
				}
				if(state == 2){
					//Ignoring equals and brackets, time to copy the substring
					if(file_list[i][j] == '['){
					}
					else if(file_list[i][j] == ']'){
						state = 3;
					}
					else{
						//Substring copy
						substrings[num_hf][substring_index] = file_list[i][j];
						substring_index++;
					}
				}
				if(state == 3){
					//Let's check to see if we just came from 2 and the next character is the comma
					if(file_list[i][j] == ']'){
						j++;
					}
					//We're done now, time to copy what we have for the inset
					inset_checksums[num_hf] = total;
					checksum = 0;
					if(substring_index > 0){
						hf_value_flag[num_hf] = substring_index;
					}
					substring_index = 0;
					total = 0;
					num_hf++;
					state = 0;
				}
			}
			//At this point, we have the headerfields, but not in the right form.  We have to convert the checksums to the array index values:
			for(k=0 ; k < num_hf ; k++){
				hf_order[k] = http_hf_convert[inset_checksums[k] % CONVERT_HASH_MAX];
				if(http_hf_checksums[inset_checksums[k] % CONVERT_HASH_MAX] != inset_checksums[k]){
					printf("Warning: Checksums do not match\n");
				}
			}
			hf_length = num_hf;
			//Now all we need is the outset, which will be calculated in almost the same way as the inset
			state = 0;
			checksum = 0;
			total = 0;
			num_hf = 0;
			for( ; j < lengths[i] ; j++){
				//Exit condition
				if(file_list[i][j] == ':'){
					break;
				}
				if(state == 0){
					//Default State, records question mark if there, otherwise falls to next state
					if(file_list[i][j] == '?'){
					}
					else{
						state = 1;
					}
				}
				if(state == 1){
					//Calculates checksum
					//First, if we seen an '=' we know that we are moving to substring territory
					if(file_list[i][j] == '='){
						j++;
						state = 2;
					}
					else if(file_list[i][j] == ','){
						state = 3;
					}
					else if(file_list[i][j] != ' '){
						total = (total + file_list[i][j]) * 2;
					}
				}
				if(state == 2){
					//Ignoring equals and brackets, time to copy the substring
					if(file_list[i][j] == '['){
					}
					else if(file_list[i][j] == ']'){
						state = 3;
					}
					else{
						//Substring copy
					}
				}
				if(state == 3){
					//Let's check to see if we just came from 2 and the next character is the comma
					if(file_list[i][j] == ']'){
						j++;
					}
					//We're done now, time to copy what we have for the inset
					outset_checksums[num_hf] = total;
					checksum = 0;
					total = 0;
					num_hf++;
					state = 0;
				}
			}
			//Same deal with converting the header fields to their proper form
			for(k=0 ; k < num_hf ; k++){
				hf_order_outset[k] = http_hf_convert[outset_checksums[num_hf] % CONVERT_HASH_MAX];
				if(http_hf_checksums[outset_checksums[k] % CONVERT_HASH_MAX] != outset_checksums[k]){
					printf("Warning: Checksums do not match(outset)\n");
				}
			}
			//Now, let's get the outset:
			for(k=0 ; k < num_hf ; k++){
				if(hf_order_outset[k] != 0){
					outset = outset | (1 << hf_order_outset[k]);
				}
			}
			//Now, for the inset:
			for(k=0 ; k < hf_length ; k++){
				if(hf_order[k] != 0){
					inset = inset | (1 << hf_order[k]);
				}
			}
			//At this point, we can build the transition table
			cur_sig.inset = inset;
			cur_sig.outset = outset;
			for(k=0 ; k < hf_length ; k++){
				for(l=0 ; l < hf_value_flag[k] ; l++){
					cur_sig.hf_values[k][l] = substrings[k][l];
				}
			}
			//All values are copied except rule_table and transition_table
			/*
			There are 4 rules:
			0-Stay where you are in the table
			1-Failure:Not a match
			2-Pass:Move to the spot in the table indicated by transition_table
			3-Conditional Pass:2, but only if the substring value matches
			*/
			for(j=0 ; j < TRANSITIONS_MAX ; j++){
				for(k=0 ; k < CONVERT_INDEX_MAX ; k++){
					cur_sig.rule_table[j][k] = 0;
					cur_sig.transition_table[j][k] = 0;
				}
			}
			for(j=0 ; j < TRANSITIONS_MAX ; j++){
				for(k=0 ; k < hf_length ; k++){
					if(hf_order[k] != 0){
						cur_sig.rule_table[j][hf_order[k]] = 1;
					}
				}
			}
			for(j=0 ; j < TRANSITIONS_MAX ; j++){
				for(k=0 ; k < num_hf ; k++){
					if(hf_order_outset[k] != 0){
						cur_sig.rule_table[j][hf_order_outset[k]] = 1;
					}
				}
			}
			//Failure conditions are now set, moving on to pass conditions
			for(j=0 ; j < hf_length ; j++){
				k = j;
				do{
					if(hf_order[k] == 0){
						break;
					}
					if(hf_value_flag[k] > 0){
						cur_sig.rule_table[j][hf_order[k]] = 3;
					}
					else{
						cur_sig.rule_table[j][hf_order[k]] = 2;
					}
					cur_sig.transition_table[j][hf_order[k]] = k+1;
					k++;
				}while(inset_question_marks[k-1] == 1);
			}
			//Transition Table complete, now to copy:
			//print_sig(&cur_sig);
			/*for(j=0 ; j < 100 ; j++){
				printf("%u", inset_question_marks[j]);
			}*/
			printf("\n");
			memcpy((void *)(ret+i), (void *)&cur_sig, sizeof(cur_sig));
		}
	}
	ret[0].print.src_ip = total_count;
	return ret;
}

int copy_database(struct http_sig *list){
	int fd;
	int size;
	int i;
	struct stat pf_stat;
	struct http_sig *db_map;
	if(stat("/proc/pna/http_db", &pf_stat)!=0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;

	fd = open("/proc/pna/http_db", O_RDWR);
	if(fd < 0){
		perror("open proc file, copy_database");
		return -1;
	}
	db_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(db_map == MAP_FAILED){
		perror("mmap");
		printf("MMAP failure\n");
		close(fd);
		return -1;
	}
	if(list[0].print.src_ip > size){
		memcpy(db_map, list, size);
	}
	else{
		memcpy(db_map, list, db_size);
	}
	return 0;
}

int load_database(char **argv){
	char *filename;
	struct http_sig *list;
	filename = argv[2];
	db_size = 0;
	list = construct_list(filename);
	if(list == NULL){
		return -1;
	}
	if(copy_database(list) == -1){
		free(list);
		return -1;
	}
	free(list);
	return 0;
}

int read_logs(char **argv){
	return 0;
}

void print_date(struct tm *cur_date){
	printf("%d-%d-%d %d:%d:%d\n", cur_date->tm_year+1900, cur_date->tm_mon+1, cur_date->tm_mday, cur_date->tm_hour, cur_date->tm_min, cur_date->tm_sec);
}

void get_cur_date(){
	time_t t = time(NULL);
	cur_date = *localtime(&t);
//	print_date(&cur_date);
}

int main(int argc, char **argv){
	int mode;
	get_cur_date();
	mode = parse_args(argc, argv);
	switch(mode){
		case 0:
			print_control_info();
			break;
		case 1:
			change_control_info(argv);
			break;
		case 2:
			load_database(argv);
			break;
		case 3:
			read_logs(argv);
			break;
		default:
			print_help();
			break;
	}
	return 0;
}
