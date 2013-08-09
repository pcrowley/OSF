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
#include <math.h>
#include <float.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <pcap/pcap.h>
#include "fnv.h"

#define COPY_MAX_PACKETS 1000000
#define COPY_MAX_BYTES 100
#define OSF_FEATURES 61
#define NUM_TREES 1

#define DEBUG_F 0
#define DEBUG_F2 0

//Typedefs for easier access to fixed width
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct copy_table {
	unsigned int start;
	unsigned int end;
	unsigned int skipped;
	char data[COPY_MAX_PACKETS][COPY_MAX_BYTES];
};

unsigned int num_truths;
unsigned int *truths;
unsigned int num_ignore;
unsigned int *ignore;
struct copy_table table;
unsigned int num_packets;
unsigned int attribute_ranges[OSF_FEATURES];
struct tree_node **forest;
int pcap_count = -1;

int check_args(int argc, char **argv){
	//Looking for 1 filenames, the packet capture
	if(argc != 3) return 0;
	return 1;
}

void pcapHandle(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	u8 *ptr;
	int i;
	int ether_type;
	int ether_offset;
	struct iphdr *ip;
	ptr = (u8 *)packet;
	u8 temp;
	ether_type = ((int)(ptr[12]) << 8) | (int)ptr[13];
	if(ether_type == 0x0800){
		ether_offset = 14;
	}
	else{
		ether_offset = 18;
	}
	ptr += ether_offset;
	ip = (struct iphdr *)ptr;
	if(ptr[0] == 0){
		return;
	}
	if(ptr[9] == 6){
		pcap_count++;
	}
	else{
		return;
	}
	if(pcap_count >= COPY_MAX_PACKETS){
		return;
	}
	for(i=0 ; (i < ip->tot_len) && (i < COPY_MAX_BYTES) ; i++){
		temp = ptr[i];
		table.data[pcap_count][i] = 0;
		table.data[pcap_count][i] = temp;
	}
	return;
}

int load_files(char **argv){
	FILE *fp;
	char buffer[1000];
	char errbuf[PCAP_ERRBUF_SIZE];
	int i,j;
	int ether_type;
	int ether_offset;
	struct pcap_pkthdr header;
	struct iphdr *ip;
	pcap_t *handle;
	u_char *data_ptr;
	u8 *pkt_ptr;
	u8 temp;
	/*fp = fopen(argv[1], "r");
	if(fp == NULL){
		printf("Packet Open file open error\n");
		return 0;
	}
	fread(&table, sizeof(struct copy_table), 1, fp);
	fclose(fp);*/
	handle = pcap_open_offline(argv[1], errbuf);
	if(handle == NULL){
		printf("pcap Open error\n");
		return 0;
	}
	j=0;
	if(pcap_loop(handle, 0, pcapHandle, NULL) < 0) {
	}
	/*
		j++;
		pkt_ptr = (u8 *)data_ptr;
		ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
		ether_offset = 0;
		if(ether_type == 0x0800){
			ether_offset = 14;
		}
		else{
			ether_offset = 18;
		}
		pkt_ptr += ether_offset;
		ip = (struct iphdr *)pkt_ptr;
		for(i=0 ; (i < ip->tot_len) && (i < COPY_MAX_BYTES) ; i++){
			table.data[j][i] = pkt_ptr[i];
		}
		data_ptr = pcap_next(handle, &header);
	}
	*/
	fp = fopen(argv[2], "r");
	fgets(buffer, sizeof(buffer), fp);
	num_truths = atoi(buffer);
	truths = (unsigned int *)malloc(sizeof(unsigned int)*num_truths);
	for(i=0 ; i < num_truths ; i++){
		fgets(buffer, sizeof(buffer), fp);
		truths[i] = atoi(buffer);
	}
	fclose(fp);
	return 1;
}

void process_packets(){
	int i,j,k;
	int temp_max;
	int *syn_set;
	u8 flags;
	int count;
	for(i=0 ; i < COPY_MAX_PACKETS ; i++){
		if(table.data[i][0] == 0){
			break;
		}
	}
	temp_max = i;
	syn_set = (int *)malloc(sizeof(int)*temp_max);
	for(i=0 ; i < temp_max ; i++){
		flags = table.data[i][9];
		if(flags != 6){
			syn_set[i] = 0;
			continue;
		}
		flags = table.data[i][0];
		flags = flags >> 4;
		if(flags != 4){
			syn_set[i] = 0;
			continue;
		}
		count++;
		//33rd byte
		flags = table.data[i][33];
		flags = flags << 6;
		flags = flags >> 7;
		syn_set[i] = flags;
		//if(table.data[i][19] != 102){
		//	syn_set[i] = 0;
		//}
		if(syn_set[i]){
		}
	}
	j=0;
	flags = 0;
	for(i=0 ; i < temp_max ; i++){
		if(syn_set[i]){
			for( ; j < i ; j++){
				if(!syn_set[j]){
					break;
				}
			}
			if(i == j){
				continue;
			}
			syn_set[i] = 0;
			syn_set[j] = 1;
			for(k=0 ; k < COPY_MAX_BYTES ; k++){
				table.data[j][k] = 0;
			}
			memcpy(table.data[j], table.data[i], COPY_MAX_BYTES);
		}
	}
	for(i=0 ; i < temp_max ; i++){
		if(syn_set[i] == 0){
			break;
		}
	}
	num_packets = i;
	free(syn_set);
	return;
}

static unsigned int *extract_features(char data[COPY_MAX_BYTES]){
	unsigned int *features;
	int i,j,k,l;
	features = (unsigned int *)malloc(OSF_FEATURES*sizeof(unsigned int));
	//ECN
	u8 temp8;
	for(i=0 ; i < OSF_FEATURES ; i++){
		features[i] = 0;
	}
	if((data[1] & 3) != 0){
		features[0] = 1;
	}
	else{
		features[0] = 0;
	}
	//ID
	if((data[4] > 0) || (data[5] > 0)){
		features[1] = 1;
	}
	else{
		features[1] = 0; 
	}
	//IP_Flags
	temp8 = data[6];
	features[2] = temp8 >> 5;
	//Frag_off
	temp8 = data[6];
	if((((temp8 << 3) >> 3) > 0) || (temp8 > 0)){
		features[3] = 1;
	}
	else{
		features[3] = 0;
	}
	//TTL
	temp8 = data[8];
	features[4] = temp8;
	//TCP
	//Seq_num
	if((data[24] + data[25] + data[26] + data[27] ) > 0){
		features[5] = 1;
	}
	else{
		features[5] = 0;
	}
	features[5] = 0;
	//Ack_num
	if((data[28] + data[29] + data[30] + data[31] ) > 0){
		features[6] = 1;
	}
	else{
		features[6] = 0;
	}
	//TCP Flags
	if(data[32] & 1){
		features[7] = 1;
	}
	else{
		features[7] = 0;
	}
	if(data[32] & 2){
		features[8] = 1;
	}
	else{
		features[8] = 0;
	}
	if(data[32] & 4){
		features[9] = 1;
	}
	else{
		features[9] = 0;
	}
	if(data[32] & 8){
		features[10] = 1;
	}
	else{
		features[10] = 0;
	}
	if(data[32] & 16){
		features[11] = 1;
	}
	else{
		features[11] = 0;
	}
	if(data[32] & 32){
		features[12] = 1;
	}
	else{
		features[12] = 0;
	}
	//Window
	temp8 = data[34];
	features[13] = temp8;
	temp8 = data[35];
	features[13] = features[13] << 8;
	features[13] = features[13] + temp8;
	//Urgent Pointer
	if(data[38]+data[39] > 0){
		features[14] = 1;
	}
	else{
		features[14] = 0;
	}
	//TCP Options
	u8 temp8a, temp8b, temp8c, temp8d, temp8e;
	//Go back for 15
	k=15;//Feature location
	i=0;
	j=0;
	l=0;
	temp8e=0;
	temp8e=data[32];
	for(i=0 ; i < ((temp8e>>4)*4)-20 ; ){
		k++;
		j = i + 40;//Data location
		temp8 = data[j];
		features[k] = temp8;
		if(temp8 == 2){
			temp8a=data[j+2];
			features[56] = temp8a;
			features[56] = features[56]<<8;
			temp8a=data[j+3];
			features[56] = features[56] + temp8a;
			if(features[56] <=  100){
				features[60] = 0;
			}
			else if(features[13]%features[56] == 0){
				features[60] = features[13]/features[56];
				features[13] = 0;
			}
			else if(features[13]%(features[56]-12) == 0){
				features[60] = features[13]/(features[56]-12);
				features[13] = 0;
			}
			else{
				features[60] = 0;
			}
		}
		if(temp8 == 3){
			temp8a = data[j+2];
			features[57] = temp8a;
		}
		if(temp8 == 8){
			temp8a=data[j+2];
			temp8b=data[j+3];
			temp8c=data[j+4];
			temp8d=data[j+5];
			if((temp8a+temp8b+temp8c+temp8d) > 0){
				features[58] = 1;
			}
			else{
				features[58] = 0;
			}
			temp8a=data[j+6];
			temp8b=data[j+7];
			temp8c=data[j+8];
			temp8d=data[j+9];
			if((temp8a+temp8b+temp8c+temp8d) > 0){
				features[59] = 1;
			}
			else{
				features[59] = 0;
			}
			features[59] = 0;
		}
		if((temp8 == 0) || (temp8 == 1)){
			i++;
			continue;
		}
		if(temp8 == 4){
			i = i + 2;
			continue;
		}
		temp8a = data[j+1];
		i = i + temp8a;
	}
	features[15] = k-15;
	return features;
}

unsigned int **convert_to_features(){
	int i,j,k;
	int flag=0;
	unsigned int **ret;
	ret = (unsigned int **)malloc(sizeof(unsigned int *)*num_packets);
	k=0;
	for(i=0 ; i < num_packets ; i++){
		flag = 0;
		for(j=0 ; j < num_ignore ; j++){
			if(ignore[j] == i){
				flag=1;
			}
		}
		if(flag){
			continue;
		}
		ret[k]=extract_features(table.data[i]);
		k++;
	}
	return ret;
}

void generate_hashes(unsigned int **rf_feature){
	//This function will generate the Level 1 Hash Table.
	//We assume that each packet in our list is unique,
	//and represents a p0f specific match.
	int i, j, k, l;
	int *ignore_list;
	int total_ignore=0;
	u32 res;
	u32 *check;
	int collision_flag;
	ignore_list = (int *)malloc(sizeof(int)*num_packets);
	check = (u64 *)malloc(sizeof(int)*num_packets);
	for(i=0 ; i < num_packets ; i++){
		ignore_list[i] = 0;
		check[i] = 0;
		break;
	}
	for(i=0 ; i < num_packets ; i++){
		res = fnv_32a_buf((void *)rf_feature[i], OSF_FEATURES * sizeof(unsigned int), FNV1_32A_INIT);
		check[i] = res;
	}
	for(i=0 ; i < num_packets ; i++){
		for(j=i+1 ; j < num_packets ; j++){
			if(ignore_list[i]){
				break;
			}
			if(check[i] == check[j]){
				collision_flag = 0;
				for(k=0 ; k < OSF_FEATURES ; k++){
					if(rf_feature[i][k] != rf_feature[j][k]){
						collision_flag = 1;
						break;
					}
				}
				if(collision_flag){
					printf("Collision Detected!\n");
				}
				ignore_list[j] = 1;
				total_ignore++;
			}
		}
	}
	return;
	printf("%u\n", num_packets-total_ignore);
	for(i=0 ; i < num_packets ; i++){
		if(ignore_list[i]){
			continue;
		}
		printf("%u\n", check[i]);
	}
	for(i=0 ; i < num_packets ; i++){
		if(ignore_list[i]){
			continue;
		}
		printf("%u\n", truths[i]);
	}
	return;
}

void print_double_ips(unsigned int **rf_features){
	int i,j;
	FILE *fp1;
	FILE *fp2;
	u8 ip[8];
	fp1 = fopen("ip.a", "w");
	fp2 = fopen("ip.b", "w");
	for(i=0 ; i < num_packets ; i++){
		for(j=0 ; j < 8 ; j++){
			ip[j] = table.data[i][12+j];
		}
		fprintf(fp1, "%u.%u.%u.%u %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
		fprintf(fp2, "%u.%u.%u.%u %u.%u.%u.%u\n", ip[4], ip[5], ip[6], ip[7], ip[0], ip[1], ip[2], ip[3]);
	}
	fclose(fp1);
	fclose(fp2);
	return;
}

int main(int argc, char **argv){
	int i,j;
	unsigned int **rf_features;
	unsigned int *rf_ranges;
	if(!check_args(argc, argv)){
		printf("Takes 2 args, a pcap file and a truth file");
		printf("\n");
		return -1;
	}
	for(i=0 ; i < COPY_MAX_PACKETS ; i++){
		for(j=0 ; j < COPY_MAX_BYTES; j++){
			table.data[i][j] = 0;
		}
	}
	if(!load_files(argv)){
		printf("File Error\n");
		return -1;
	}
	process_packets();
	rf_features = convert_to_features();
	/*	
	for(i=0 ; i < num_packets ; i++){
		for(j=0 ; j < OSF_FEATURES ; j++){
			printf("%u", rf_features[i][j]);
			if(j == OSF_FEATURES - 1){
				printf("\n");
			}
			else{
				printf(",");
			}
		}
	}
	return 0;
	*/
	generate_hashes(rf_features);
	return 0;
}
