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

//Option List
uint8_t opt_list[40];
uint8_t opt_list_size;
uint32_t opt_quirks;
uint8_t opt_eol_pad_temp;

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
	uint32_t	value;
	uint32_t	src_ip;
	char		name[20];
};

struct http_info{
	uint32_t	src_ip;
	uint32_t	table_index;
	uint32_t	current_log;
};

#define CONVERT_INDEX_MAX 150
#define CONVERT_HASH_MAX 1024
#define TRANSITIONS_MAX 20
struct http_sig{
	struct http_print print;
	uint8_t	version;
	uint64_t inset_a;
	uint64_t inset_b;
	uint64_t outset_a;
	uint64_t outset_b;
	u8	transition_table[TRANSITIONS_MAX][CONVERT_INDEX_MAX];
	char subvalues[CONVERT_INDEX_MAX][30];
	char uagent[20];//User agent or Server
	char name[30];//Label name
};

struct http_convert_entry{
	uint32_t checksum;
	uint32_t index;
	uint32_t next;
};


void clear_label(struct http_sig *sig){
	return;
}

void print_print(struct http_print *print){
	//Write Later
	return;
}
void print_sig(struct http_sig *sig){
	//Write Later
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
	return NULL;
}

struct http_convert_entry *construct_convert_list(char *filename){
	FILE *fp;
	char buffer[1000];
	int list_size = 0;
	int cur_entry =0;
	int i,j,k,l;
	char file_list[1000][1000];
	uint32_t checksum_list[1000];
	int lengths[1000];
	int colons=0;
	int skip_f=0;
	int bracket_f=0;
	int checksum_match = 0;
	uint32_t temp_checksum;
	struct http_convert_entry *ret;
	fp = fopen(filename, "r");
	if(fp == NULL){
		printf("File open error\n");
		printf("%s\n", filename);
		return NULL;
	}
	while(fgets(buffer, sizeof(buffer), fp!=NULL)){
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
	convert_size = list_size*sizeof(struct http_convert_entry);
	ret = (struct http_convert_entry *)malloc(CONVERT_HASH_MAX * sizeof(struct http_convert_entry));
	memset(ret, 0, sizeof(struct http_convert_entry) * CONVERT_HASH_MAX);
	for(i=0 ; i < list_size ; i++){
		if(file_list[i][0] != 's'){
			continue;
		}
		colons = 0;
		skip_f = 0;
		bracket_f = 0;
		temp_checksum = 0;
		for(j=10 ; j < lengths[i] ;j++){
			if(colons >= 2){
				break;
			}
			if(file_list[i][j] == ':'){
				colons = colons + 1;
				continue;
			}
			if(file_list[i][j] == ']'){
				bracket_f=0;
				continue;
			}
			if(file_list[i][j] == '['){
				bracket_f=1;
				continue;
			}
			if(bracket_f == 0 && file_list[i][j] == ','){
				skip_f = 0;
				checksum_match = 0;
				for(k=0 ; k < cur_entry ; k++){
					if(temp_checksum == checksum_list[k]){
						checksum_match=1;
						break;
					}
				}
				if(checksum_match == 0){
					checksum_list[cur_entry]=temp_checksum;
					cur_entry++;
				}
				temp_checksum = 0;
				continue;
			}
			if(file_list[i][j] == '?'){
				continue;
			}
			if(file_list[i][j] == '='){
				skip_f == 1;
				continue;
			}
			if(skip_f == 1){
				continue;
			}
			temp_checksum = (temp_checksum + file_list[i][j]) * 2;
		}
	}
	//Now to fill in the hash table:
	for(i=0 ; i < cur_entry ; i++){
		skip_f = 0;
		temp_checksum = checksum_list[i] % CONVERT_HASH_MAX;
		while(skip_f == 0){
			skip_f = 0;
			if(ret[temp_checksum].checksum == 0){
				ret[temp_checksum].checksum = checksum_list[i];
				ret[temp_checksum].index = i;
				skip_f = 1;
				continue;
			}
			else if(ret[temp_checksum].next != 0){
				temp_checksum = ret[temp_checksum].next;
			}
			else{
				for(j=1 ; j < CONVERT_HASH_MAX ; j++){
					//Starting at 1 on purpose
					if(ret[j].checksum == 0){
						break;
					}
				}
				ret[temp_checksum].next = j;
				temp_checksum = ret[temp_checksum].next;
			}
		}
	}
	return ret;
}

int copy_convert_list(struct http_convert_entry *list){
	int fd;
	int size;
	int i;
	struct stat pf_stat;
	struct http_convert_entry *convert_map;
	if(stat("/proc/pna/http_convert", &pf_stat)!=0){
		perror("stat http_convert");
		return -1;
	}
	size = pf_stat.st_size;

	fd = open("/proc/pna/http_convert", ORDWR);
	if(fd < 0){
		perror("open proc file, copy_convert_list");
		return -1;
	}
	convert_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(convert_map == MAP_FAILED){
		perror("mmap convert_list");
		printf("MMAP failure\n");
		close(fd);
		return -1;
	}
	memcpy(db_map, list, sizeof(struct http_convert_entry)*CONVERT_HASH_MAX);
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
	unsigned int total_count;
	struct http_sig cur_sig;
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
		switch(file_list[i][0]){
		case 'l'://list
				if(colons >= 2){
					break;
				}
				if(file_list[i][j] == ':'){
					colons++;
				}
			}
			k=0;
			for( ; j < lengths[i] ; j++){
				cur_sig.name[k] = file_list[i][j];
				k++;
			}
			cur_sig.name[k] = '\0';
			break;
		case 's'://sig
			if(file_list[i][8] == '0'){
				cur_sig.version = 0;
			}
			else if(file_list[i][8] == '1'){
				cur_sig.version = 1;
			}
			else{
				cur_sig.version = 2;//wildcard since 2 is unused
			}
		//XXX Continue Here	
		}
	}
	return ret;
}

int load_database(char **argv){
	char *filename;
	struct http_sig *list;
	struct http_convert_entry *convert_list;
	filename = argv[2];
	db_size = 0;
	convert_list = construct_convert_list(filename);
	if(convert_list == NULL){
		return -1;
	}
	if(copy_convert_list(convert_list) == -1){
		free(convert_list);
		return -1;
	}
	free(convert_list);
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
