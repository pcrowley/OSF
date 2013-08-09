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

#include "forestlearn.h"

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
struct copy_table table;
unsigned int num_packets;
unsigned int attribute_ranges[OSF_FEATURES];
struct tree_node **forest;

int check_args(int argc, char **argv){
	//Looking for 3 filenames, the packet capture and the truth file
	if(argc != 4) return 0;
	return 1;
}

int load_files(char **argv){
	FILE *fp;
	char buffer[1000];
	int i;
	fp = fopen(argv[1], "r");
	if(fp == NULL){
		printf("Packet Open file open error\n");
		return 0;
	}
	fread(&table, sizeof(struct copy_table), 1, fp);
	fclose(fp);
	fp = fopen(argv[2], "r");
	if(fp == NULL){
		printf("Truth File file open error\n");
		return 0;
	}
	fgets(buffer, sizeof(buffer), fp);
	num_truths = atoi(buffer);
	truths = (unsigned int *)malloc(sizeof(unsigned int)*num_truths);
	for(i=0 ; i < num_truths ; i++){
		fgets(buffer, sizeof(buffer), fp);
		truths[i] = atoi(buffer);
	}
	fclose(fp);
	fp = fopen(argv[3], "r");
	if(fp == NULL){
		printf("Attribute range file open error\n");
		return 0;
	}
	for(i=0 ; i < OSF_FEATURES ; i++){
		fgets(buffer, sizeof(buffer), fp);
		attribute_ranges[i] = atoi(buffer);
	}
	fclose(fp);
	return 1;
}

void cleanup(){
	int i;
	for(i=0 ; i < NUM_TREES ; i++){
		if(forest[i] != NULL){
			free(forest[i]);
		}
	}
	free(forest);
	free(truths);
	return;
}

void process_packets(){
	int i,j,k;
	int temp_max;
	int *syn_set;
	u8 flags;
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
	printf("%d\n", i);
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
	features[2] = data[6] >> 5;
	//Frag_off
	if((((data[6] << 3) >> 3) > 0) || (data[7] > 0)){
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
			if(features[56] == 1){
				features[60] = 0;
			}
			else if((features[13]%features[56] == 0) && (features[56] != 1)){
				features[60] = features[13]/features[56];
				features[13] = 0;
			}
			else if((features[13]-12)%features[56] == 0){
				features[60] = (features[13]-12)/features[56];
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
		}
		if((temp8 == 0) || (temp8 == 1)){
			i++;
			continue;
		}
		temp8a = data[j+1];
		i = i + temp8a;
	}
	features[15] = k-15;
	return features;
}

unsigned int **convert_to_features(){
	int i,j;
	unsigned int **ret;
	ret = (unsigned int **)malloc(sizeof(unsigned int *)*num_packets);
	for(i=0 ; i < num_packets ; i++){

		ret[i]=extract_features(table.data[i]);
	}
	return ret;
}

int main(int argc, char **argv){
	int i,j;
	unsigned int **rf_features;
	unsigned int *rf_ranges;
	if(!check_args(argc, argv)){
		printf("Needs 3 Filenames, Packet capture, truth file, and ranges\n");
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
	rf_ranges = (unsigned int *)malloc(sizeof(unsigned int)*OSF_FEATURES);
	for(i=0 ; i < OSF_FEATURES ; i++){
		rf_ranges[i] = attribute_ranges[i];
	}
	//Let's convert the conflicting features now
	for(i=0 ; i < num_packets ; i++){
		break;
		if(rf_features[i][8] == 0){
			rf_features[i][8] = 1;
		}
		if(rf_features[i][8] > 255){
			rf_features[i][8] = 255;
		}
		if(truths[i] == 24){
			rf_features[i][57] = ((unsigned int)rand() % 250)+5;
		}
		if(truths[i] == 27){
			rf_features[i][57] = ((unsigned int)rand() % 240)+10;
		}
	}
	for(i=0 ; i < num_packets ; i++){
		for(j=0 ; j < OSF_FEATURES ; j++){
			if(j == OSF_FEATURES -1){
				printf("%u\n", rf_features[i][j]);
			}
			else{
				printf("%u,",  rf_features[i][j]);
			}
		}
	}
	return 0;
	forest = learn_forest(rf_features, OSF_FEATURES, num_packets, truths, rf_ranges, NUM_TREES, num_packets, OSF_FEATURES, RF_ENTROPY, NULL);
	return 0;
}
