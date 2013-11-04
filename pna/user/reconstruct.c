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
	uint8_t wildcards;
	uint8_t ack;
	uint32_t score;
	char os_type;
	char os_class[5];
	char os_name[20];
	char os_flavor[20];
};

void print_print(struct osf_print *print){
	printf("\tdb_entry:	%u\n", print->db_entry);
	printf("\tsrc_ip:	%u\n", print->src_ip);
	printf("\tdst_ip:	%u\n", print->dst_ip);
	printf("\topt_hash:	%u\n", print->opt_hash);
	printf("\tquirks:	%u\n", print->quirks);
	printf("\topt_eol_pad:	%u\n", print->opt_eol_pad);
	printf("\tip_opt_len:	%u\n", print->ip_opt_len);
	printf("\tttl:		%u\n", print->ttl);
	printf("\tmss:		%u\n", print->mss);
	printf("\twin:		%u\n", print->win);
	printf("\twin_type:	%u\n", print->win_type);
	printf("\twin_scale:	%u\n", print->win_scale);
	printf("\tpay_class:	%u\n", print->pay_class);
}

void print_sig(struct osf_sig *sig){
	uint8_t src1;
	uint8_t src2;
	uint8_t src3;
	uint8_t src4;
	uint8_t dst1;
	uint8_t dst2;
	uint8_t dst3;
	uint8_t dst4;
	char *ip_ptr;
	int i;
	ip_ptr = &sig->print.src_ip;
	src1 = ip_ptr[0];
	src2 = ip_ptr[1];
	src3 = ip_ptr[2];
	src4 = ip_ptr[3];
	ip_ptr = &sig->print.dst_ip;
	dst1 = ip_ptr[0];
	dst2 = ip_ptr[1];
	dst3 = ip_ptr[2];
	dst4 = ip_ptr[3];
	printf("%u;%u;%u;%u;%u;%u;%u;%u;%c;%s;%s;%s;%u;%u;%u;%u;%u;%u;%u;%u;%u;%u\n",
	src1, src2, src3, src4,
	dst1, dst2, dst3, dst4,
	sig->os_type, sig->os_class, sig->os_name, sig->os_flavor,
	sig->print.opt_hash,
	sig->print.quirks,
	sig->print.opt_eol_pad,
	sig->print.ip_opt_len,
	sig->print.ttl,
	sig->print.mss,
	sig->print.win,
	sig->print.win_type,
	sig->print.win_scale,
	sig->print.pay_class);
	//Old Print_sig
	/*printf("%c,%s,%s,%s:\n", sig->os_type, sig->os_class, sig->os_name, sig->os_flavor);
	print_print(&sig->print);
	printf("\twildcards:	%u\n", sig->wildcards);
	*/
}

void print_info(struct osf_info *info){
	printf("Info:\n");
	printf("\tsrc_ip:	%u\n", info->src_ip);
	printf("\ttable_index:	%u\n", info->table_index);
	printf("\tcurrent_log:	%u\n", info->current_log);
}

void print_date(struct tm *cur_date){
	printf("%d-%d-%d %d:%d:%d\n", cur_date->tm_year+1900, cur_date->tm_mon+1, cur_date->tm_mday, cur_date->tm_hour, cur_date->tm_min, cur_date->tm_sec);
}

void print_usage(){
	printf("Usage:\n");
	printf("reconstruct <raw_log_file> <logs_per_ip>\n");
}

void rand_ip(struct osf_sig *sig){
	uint32_t a;
	uint32_t b;
	a = (uint32_t)rand();
	b = (uint32_t)rand();
	sig->print.src_ip = a;
	sig->print.dst_ip = b;
}

int main(int argc, char **argv){
	FILE *fp;
	unsigned int log_size;
	unsigned int db_size;
	unsigned int entry_size;
	unsigned int num_logs;
	unsigned int logs_per_ip;
	unsigned int max_list;
	unsigned int i, j;
	unsigned int first;
	struct tm cur_date;
	struct osf_sig *list;
	struct osf_sig sig;
	struct osf_info cur_info;
	uint32_t key_dump;
	first = 0;
	if(argc != 3){
		print_usage();
		return -1;
	}
	fp = fopen(argv[1], "r");
	if(fp == NULL){
		printf("Could not open %s\n", argv[1]);
		return -1;
	}
	fread(&cur_date, sizeof(struct tm), 1, fp);
	print_date(&cur_date);
	fread(&db_size, sizeof(unsigned int), 1, fp);
	fread(&log_size, sizeof(unsigned int), 1, fp);
	entry_size = 4 + sizeof(struct osf_info) + sizeof(struct osf_print) * atoi(argv[2]);
	if(log_size % entry_size != 0){
		printf("You calculated something wrongly\n");
		return -1;
	}
	num_logs = log_size / entry_size;
	logs_per_ip = atoi(argv[2]);
	//Regenerate sig list
	list = (struct osf_sig *)malloc(db_size);
	fread(list, 1, db_size, fp);
	max_list = db_size / sizeof(struct osf_sig);
	/*for(j=0 ; j < 1000 ; j++){
		for(i=0 ; i < 180 ; i++){
			rand_ip(&list[i]);
			print_sig(&list[i]);
		}
	}
	return 0;
	for(i=0 ; i < num_logs ; i++){
		if(first == 0){
			first = 1;
		}
		else{
			fread(&key_dump, sizeof(uint32_t), 1, fp);//Get rid of first 4 bytes
		}
		fread(&cur_info, sizeof(struct osf_info), 1, fp);
		//print_info(&cur_info);
		for(j=0 ; j<logs_per_ip ; j++){
			fread(&sig.print, sizeof(struct osf_print), 1, fp);
			if(j < cur_info.current_log){
				if(sig.print.db_entry < max_list){
					sig.wildcards = list[sig.print.db_entry].wildcards;
					sig.ack = list[sig.print.db_entry].ack;
					sig.os_type = list[sig.print.db_entry].os_type;
					memcpy(&sig.os_class, &list[sig.print.db_entry].os_class, 5);
					memcpy(&sig.os_name, &list[sig.print.db_entry].os_name, 20);
					memcpy(&sig.os_flavor, &list[sig.print.db_entry].os_flavor, 20);
					print_sig(&sig);
				}
			}
		}
	}
	free(list);
	return 0;
}
