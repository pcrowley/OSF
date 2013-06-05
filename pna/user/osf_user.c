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

struct tm cur_date;

struct osf_control{
	unsigned int num_ips;
	unsigned int num_logs;
	unsigned int num_db_entries;
	unsigned int cur_db_entries;
	unsigned int missed_logs;
};

struct osf_print{
	uint32_t	db_entry;
	uint32_t	src_ip;
	uint32_t	dst_ip;
	uint32_t	opt_hash;
	uint32_t	quirks;
	uint8_t		opt_eol_pad;
	uint8_t		ip_opt_len;
	uint8_t		ttl;
	uint16_t	mss;
	uint16_t	win;
	uint8_t		win_type;
	uint8_t		win_scale;
	uint8_t		pay_class;
};

struct osf_info{
	uint32_t	src_ip;
	uint32_t	table_index;
	uint32_t	current_log;
};

struct osf_sig{
	struct osf_print print;
	uint8_t	wildcards;
	uint8_t ack;
	uint32_t score;
	char os_type;
	char os_class[5];
	char os_name[20];
	char os_flavor[20];
};

void clear_label(struct osf_sig *sig){
	
}

//Using the FNV_32a hash
uint32_t compute_opt_hash(void *key, uint8_t len){
	return (uint32_t)fnv_32a_buf(key, len, FNV1_32A_INIT);
}

void print_print(struct osf_print *print){
	printf("\tdb_entry:    %u\n", print->db_entry);
	printf("\tsrc_ip:      %u\n", print->src_ip);
	printf("\tdst_ip:      %u\n", print->dst_ip);
	printf("\topt_hash:    %u\n", print->opt_hash);
	printf("\tquirks:      %u\n", print->quirks);
	printf("\topt_eol_pad: %u\n", print->opt_eol_pad);
	printf("\tip_opt_len:  %u\n", print->ip_opt_len);
	printf("\tttl:         %u\n", print->ttl);
	printf("\tmss:         %u\n", print->mss);
	printf("\twin:         %u\n", print->win);
	printf("\twin_type:    %u\n", print->win_type);
	printf("\twin_scale:   %u\n", print->win_scale);
	printf("\tpay_class:   %u\n", print->pay_class);
}
void print_sig(struct osf_sig *sig){
	printf("%c,%s,%s,%s:\n", sig->os_type, sig->os_class, sig->os_name, sig->os_flavor);
	print_print(&sig->print);
	printf("\twildcards:   %u\n", sig->wildcards);
}

char *parse_quirks(char *buffer){
	char b2[1000];
	int i;
	int first;
	first = 0;
	opt_quirks = 0;
	while(buffer[0] != ':'){
		if(first == 0){
			first = 1;
		}
		else{
			buffer = buffer + 1;
		}
		if(buffer[0] == 'd'){
			opt_quirks = opt_quirks | (1<<0);
			buffer = buffer + 2;
		}
		else if(buffer[0] == 'i' && buffer[2] == '+'){
			opt_quirks = opt_quirks | (1<<1);
			buffer = buffer + 3;
		}
		else if(buffer[0] == 'i' && buffer[2] == '-'){
			opt_quirks = opt_quirks | (1<<2);
			buffer = buffer + 3;
		}
		else if(buffer[0] == 'e' && buffer[1] == 'c'){
			opt_quirks = opt_quirks | (1<<3);
			buffer = buffer + 3;
		}
		else if(buffer[0] == '0'){
			opt_quirks = opt_quirks | (1<<4);
			buffer = buffer + 2;
		}
		else if(buffer[0] == 'f'){
			opt_quirks = opt_quirks | (1<<5);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 's'){
			opt_quirks = opt_quirks | (1<<6);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'a' && buffer[3] == '+'){
			opt_quirks = opt_quirks | (1<<7);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'a' && buffer[3] == '-'){
			opt_quirks = opt_quirks | (1<<8);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'u' && buffer[1] == 'p'){
			opt_quirks = opt_quirks | (1<<9);
			buffer = buffer + 5;
		}
		else if(buffer[0] == 'u' && buffer[1] == 'r'){
			opt_quirks = opt_quirks | (1<<10);
			buffer = buffer + 5;
		}
		else if(buffer[0] == 'p'){
			opt_quirks = opt_quirks | (1<<11);
			buffer = buffer + 6;
		}
		else if(buffer[0] == 't' && buffer[2] == '1'){
			opt_quirks = opt_quirks | (1<<12);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 't' && buffer[2] == '2'){
			opt_quirks = opt_quirks | (1<<13);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'o'){
			opt_quirks = opt_quirks | (1<<14);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'e' && buffer[1] == 'x'){
			opt_quirks = opt_quirks | (1<<15);
			buffer = buffer + 4;
		}
		else if(buffer[0] == 'b'){
			opt_quirks = opt_quirks | (1<<16);
			buffer = buffer + 3;
		}
	}
	buffer = buffer + 1;
	return buffer;
}

void clear_opt_list(){
	int i;
	for(i=0 ; i < 40 ; i++){
		opt_list[i] = 0;
	}
	opt_list_size = 0;
}

char *parse_options(char *buffer){
	char b2[1000];
	int i;
	int first;
	first = 0;
	while(buffer[0] != ':'){
		if(first == 0){
			first = 1;
		}
		else{
			buffer = buffer + 1;
		}
		if(buffer[0] == 'm'){
			opt_list[opt_list_size] = 2;
			buffer = buffer + 3;
		}
		else if(buffer[0] == 'n'){
			opt_list[opt_list_size] = 1;
			buffer = buffer + 3;
		}
		else if(buffer[0] == 'e'){
			buffer = buffer + 4;
			i=0;
			while(!(buffer[i] == ':' || buffer[i] == ',')){
				b2[i] = buffer[i];
				i++;
			}
			b2[i] = '\0';
			buffer = buffer + i;
			opt_list_size = opt_list_size + atoi(b2);
			opt_eol_pad_temp = atoi(b2);
		}
		else if(buffer[0] == 'w'){
			opt_list[opt_list_size] = 3;
			buffer = buffer + 2;
		}
		else if(buffer[0] == 's'){
			if(buffer[1] == 'o'){
				opt_list[opt_list_size] = 4;
				buffer = buffer + 3;
			}
			else if(buffer[1] == 'a'){
				opt_list[opt_list_size] = 5;
				buffer = buffer + 4;
			}
		}
		else if(buffer[0] == 't'){
			opt_list[opt_list_size] = 8;
			buffer = buffer + 2;
		}
		else if(buffer[0] == '?'){
			buffer = buffer + 1;
			i=0;
			while(!(buffer[i] == ':' || buffer[i] == ',')){
				b2[i] = buffer[i];
				i++;
			}
			b2[i] = '\0';
			buffer == buffer + i;
			opt_list[opt_list_size] = atoi(b2);
		}
		opt_list_size++;
	}
	buffer = buffer + 1;
	return buffer;

}

void print_help(){
	printf("OSF User Help:\n");
	printf("Usage:  ./osf_user <option> <option_args>\n");
	printf("Available Options:\n");
	printf("-p:Print OSF Debug Info\n");
	printf("-c <#IPs> <#Logs per IP> <#DB Entries>:Change control info\n");
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
		if(argc == 5){
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
	struct osf_control *control_ptr;
	struct osf_control cur_control;
	if(stat("/proc/pna/osf", &pf_stat) != 0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/osf", O_RDONLY);
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
	memcpy(&cur_control, control_ptr, sizeof(struct osf_control));
	close(fd);
	printf("Max IPs: %u\n", cur_control.num_ips);
	printf("Max Logs Per IP: %u\n", cur_control.num_logs);
	printf("Max DB Entries: %u\n", cur_control.num_db_entries);
	printf("Current DB Entries: %u\n", cur_control.cur_db_entries);
	printf("Missed Logs: %u\n", cur_control.missed_logs);
	return 0;
}

int change_control_info(char **argv){
	struct osf_control new_control;
	new_control.num_ips = (unsigned int)atoi(argv[2]);
	new_control.num_logs = (unsigned int)atoi(argv[3]);
	new_control.num_db_entries = (unsigned int)atoi(argv[4]);
	new_control.cur_db_entries = 0;
	new_control.missed_logs = 0;
	int fd;
	int size;
	struct stat pf_stat;
	struct osf_control *control_ptr;
	struct osf_control cur_control;

	if(stat("/proc/pna/osf", &pf_stat) != 0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/osf", O_RDWR);
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
	memcpy(control_ptr, &new_control, sizeof(struct osf_control));
	munmap(control_ptr, size);
	close(fd);
	return 0;
}


struct osf_sig *construct_list(char *filename){
	unsigned int total_count;
	unsigned int cur_entry;
	unsigned int offset;
	unsigned int i;
	struct osf_sig *ret;
	struct osf_sig cur_sig;
	FILE *fp;
	char buffer_mem[1000];
	char *buffer;
	char b2[100];
	total_count = 1;
	fp = fopen(filename, "r");
	if(fp == NULL){
		printf("File open error\n");
		printf("%s\n", filename);
		return NULL;
	}
	while(fgets(buffer_mem, sizeof(buffer_mem), fp)!=NULL){
		total_count++;
	}
	fclose(fp);
	db_size = total_count*sizeof(struct osf_sig);
	ret = (struct osf_sig *)malloc(total_count*sizeof(struct osf_sig));
	ret[0].print.db_entry = 0;
	ret[0].print.src_ip = 0;
	ret[0].print.dst_ip = 0;
	ret[0].print.opt_hash = 0;
	ret[0].print.quirks = 0;
	ret[0].print.opt_eol_pad = 0;
	ret[0].print.ip_opt_len = 0;
	ret[0].print.ttl = 0;
	ret[0].print.mss = 0;
	ret[0].print.win = 0;
	ret[0].print.win_type = 0;
	ret[0].print.win_scale = 0;
	ret[0].print.pay_class = 0;
	ret[0].wildcards = 0;
	ret[0].score = 10;
	clear_label(ret);
	ret[0].os_type = '?';
	strcpy(&ret[0].os_class, "unkn");
	strcpy(&ret[0].os_name, "Unknown");
	strcpy(&ret[0].os_flavor, "Unknown");
	
	//print_sig(ret);

	fp = fopen(filename, "r");
	if(fp == NULL){
		printf("File open error\n");
		return -1;
	}
	cur_entry = 1;
	while(fgets(buffer_mem, sizeof(buffer_mem), fp)!=NULL){
		offset = 0;
		buffer = buffer_mem;
		if(buffer[0] == '['){
			if(buffer[1] == 's'){
				cur_sig.ack = 0;
			}
			if(buffer[1] == 'a'){
				cur_sig.ack = 1;
			}
		}
		else if(buffer[0] == 'l'){
			clear_label(&cur_sig);
			offset = offset + 8;
			cur_sig.os_type = buffer[offset];
			offset = offset + 2;
			for(i=0 ; i<5 ; i++){
				if(buffer[offset+i] == ':'){
					break;
				}
				cur_sig.os_class[i] = buffer[offset+i];
			}
			cur_sig.os_class[i] = '\0';
			while(buffer[offset] != ':'){
				offset++;
			}
			offset++;
			for(i=0 ; i < 20 ; i++){
				if(buffer[offset+i] == ':'){
					break;
				}
				cur_sig.os_name[i] = buffer[offset+i];
			}
			cur_sig.os_name[i] = '\0';
			while(buffer[offset] != ':'){
				offset++;
			}
			offset++;
			for(i=0 ; i < 20 ; i++){
				if(buffer[offset+i] == '\n'){
					cur_sig.os_flavor[i] = '\0';
					break;
				}
				cur_sig.os_flavor[i] = buffer[offset+i];
			}
			cur_sig.os_flavor[i] = '\0';
			cur_sig.os_flavor[19] = '\0';
		}
		else if(buffer[0] == 's'){
			offset = offset + 10;
			cur_sig.wildcards = 0;
			cur_sig.score = 0;
			i=0;
			if(buffer[offset] == '*'){
				cur_sig.print.ttl = 0;
				cur_sig.wildcards = cur_sig.wildcards | 1 << 2;
				cur_sig.score++;
				while(buffer[offset] != ':'){
					offset++;
				}
				offset++;
			}
			else{
				while(buffer[offset] != ':'){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.ttl = atoi(b2);
				offset++;
			}
			i=0;
			if(buffer[offset] == '*'){
				cur_sig.print.ip_opt_len = 0;
				cur_sig.wildcards = cur_sig.wildcards | 1 << 3;
				cur_sig.score++;
				offset = offset + 2;
			}
			else{
				while(buffer[offset] != ':'){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.ip_opt_len = atoi(b2);
				offset++;
			}
			i=0;
			//MSS
			if(buffer[offset] == '*'){
				cur_sig.print.mss = 0;
				offset = offset + 2;
				cur_sig.wildcards = cur_sig.wildcards | 1;
				cur_sig.score++;
			}
			else{
				while(buffer[offset] != ':'){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.mss = atoi(b2);
				offset++;
			}
			i=0;
			//Window size/scale
			//3 Options, wildcard, multiple, or exact
			//First, test for wildcard
			if(buffer[offset] == '*'){
				cur_sig.print.win = 0;
				cur_sig.print.win_type = 0;//wildcard
				cur_sig.score++;
				offset = offset + 2;
			}
			else if(buffer[offset] == 'm'){
				offset = offset + 4;
				while(buffer[offset] != ','){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.win = atoi(b2);
				cur_sig.print.win_type = 1;//Multiple
				offset++;
			}
			else{
				while(buffer[offset] != ','){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.win = atoi(b2);
				cur_sig.print.win_type = 2;//Exact
				offset++;
			}
			i=0;
			//Window scale
			if(buffer[offset] == '*'){
				cur_sig.print.win_scale = 0;
				cur_sig.wildcards = cur_sig.wildcards | 2;
				cur_sig.score++;
				offset = offset+2;
			}
			else{
				while(buffer[offset] != ':'){
					b2[i] = buffer[offset];
					offset++;
					i++;
				}
				b2[i] = '\0';
				cur_sig.print.win_scale = atoi(b2);
				offset++;
			}
			//Option Parsing Now
			i=0;
			clear_opt_list();
			buffer = buffer + offset;
			opt_eol_pad_temp = 0;
			if(buffer[0] == '*'){
				cur_sig.print.opt_eol_pad = 0;
				cur_sig.print.opt_hash = 0;
				cur_sig.wildcards = cur_sig.wildcards | 1 << 4;
				cur_sig.score++;
				cur_sig.wildcards = cur_sig.wildcards | 1 << 5;
				cur_sig.score++;
				buffer = buffer + 2;

			}
			else{
				buffer = parse_options(buffer);
				cur_sig.print.opt_eol_pad = opt_eol_pad_temp;
				cur_sig.print.opt_hash = compute_opt_hash(opt_list, opt_list_size);
			}
			//Quirk Parsing Now
			if(buffer[0] == '*'){
				cur_sig.print.quirks = 0;
				cur_sig.wildcards = cur_sig.wildcards | 1 << 6;
				cur_sig.score++;
				buffer = buffer + 2;
			}
			else{
				buffer = parse_quirks(buffer);
				cur_sig.print.quirks = opt_quirks;
			}
			if(buffer[0] == '0'){
				cur_sig.print.pay_class = 0;
			}
			else{
				cur_sig.print.pay_class = 1;
			}
			//Update sig
			//ret[cur_entry];
			cur_sig.print.db_entry = cur_entry;
			memcpy(&ret[cur_entry], &cur_sig, sizeof(struct osf_sig));
			//print_sig(&ret[cur_entry]);
			cur_entry++;
		}

	}
	ret[cur_entry].print.db_entry = 0;
	return ret;
}

int copy_database(struct osf_sig *list){
	int fd;
	int size;
	int i;
	struct stat pf_stat;
	struct osf_sig *db_map;
	if(stat("/proc/pna/osf_db", &pf_stat)!=0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;

	fd = open("/proc/pna/osf_db", O_RDWR);
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
	list[0].print.dst_ip = db_size;
	if(db_size > size){
		memcpy(db_map, list, size);
	}
	else{
		memcpy(db_map, list, db_size);
	}
	close(fd);
	return 0;
}

int load_database(char **argv){
	char *filename;
	struct osf_sig *list;
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

void *copy_logs(unsigned int max_ips){
	int fd;
	int size;
	struct stat pf_stat;
	void *osf_map;
	void *test_copy;
	if(stat("/proc/pna/osf_log", &pf_stat)!=0){
		perror("stat");
		return -1;
	}
	size = pf_stat.st_size;
	fd = open("/proc/pna/osf_log", O_RDWR);
	if(fd < 0){
		perror("open proc_file copy_logs\n");
		return -1;
	}
	log_size = size;
	test_copy = malloc(size);
	osf_map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(osf_map == MAP_FAILED){
		perror("mmap");
		close(fd);
		return NULL;
	}
	memcpy(test_copy, osf_map, size);
	close(fd);
	munmap(osf_map, size);
	return test_copy;
}

int write_logs(char *filename, struct osf_sig *list, void *logs){
	//Actually write the info here
	FILE *fp;
	fp = fopen(filename, "w");
	if(fp == NULL){
		printf("File open error\n");
		printf("%s\n", filename);
		return -1;
	}
	fwrite(&cur_date, sizeof(struct tm), 1, fp);
	fwrite(&db_size, sizeof(unsigned int), 1, fp);
	fwrite(&log_size, sizeof(unsigned int), 1, fp);
	fwrite(list, 1, db_size, fp);
	fwrite(logs, 1, log_size, fp);
	fclose(fp);
	return 0;
}

int read_logs(char **argv){
	void *logs;
	int ret;
	struct osf_sig *list;
	unsigned int max_ips;
	int i;
	max_ips= atoi(argv[4]);
	db_size = 0;
	list = construct_list(argv[3]);
	if(list == NULL){
		return -1;
	}
	logs = copy_logs(max_ips);
	if(logs == NULL){
		return -1;
	}
	ret = write_logs(argv[2], list, logs);
	free(logs);
	free(list);
	return ret;
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
