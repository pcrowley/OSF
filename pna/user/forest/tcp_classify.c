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
#include "randomForest.h"
#include "pna_hashmap.h"
#include "fnv.h"

#define COPY_MAX_PACKETS 1000000
#define COPY_MAX_BYTES 100
#define OSF_FEATURES 61

#define DEBUG_F 1
#define DEBUG_F2 0
#define DEBUG_F3 0
#define DEBUG_F4 0
#define PPS_STATS 0

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

struct pna_hashmap *hashmap;

struct copy_table table;
struct copy_table table_dest;
unsigned int hash_size;
unsigned int total_trees;
unsigned int *tree_sizes;
struct tree_node **rf_forest;

unsigned int output_table[COPY_MAX_PACKETS];
unsigned int cur_output=0;

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
	return 0;
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
	if(temp8 <= 64){
		features[4] = 64;
	}
	else if(temp8 <= 128){
		features[4] = 128;
	}
	else{
		features[4] = 255;
	}
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

void write_results(struct forest_result *res){
	printf("%u\n", res[0].result);
	return;
}

int is_syn(char data[COPY_MAX_BYTES]){
	u8 temp;
	temp = data[9];
	if(temp != 6){
		return 0;
	}
	temp = data[33];
	if((temp & 2) != 2){
		return 0;
	}
	return 1;
}

void classify_packet(char data[COPY_MAX_BYTES]){
	//First, let's try the hash table:
	unsigned int *features;
	u32 value;
	unsigned int *hash_ptr=NULL;
	int i;
	if(!is_syn(data)){
		return;
	}
	features = extract_features(data);
	if(DEBUG_F3){
		for(i=0 ; i < OSF_FEATURES ; i++){
			printf("%u ", features[i]);
		}
		printf("\n");
	}
	value = fnv_32a_buf((void *)features, OSF_FEATURES * sizeof(unsigned int), FNV1_32A_INIT);
	if(DEBUG_F2){
		printf("%u\n", value);
	}
	hash_ptr = hashmap_get(hashmap, &value);
	if(hash_ptr == NULL){
		output_table[cur_output] = 0;
	}
	else{
		output_table[cur_output] = hash_ptr[1];
	}
	cur_output++;
	free(features);
	return;
}

void classify_table(){
	int i;
	cur_output = 0;
	if(table.start <= table.end){
		for(i=table.start ; i < table.end ; i++){
			classify_packet(table.data[i]);
		}
	}
	else{
		for(i=table.start ; i < COPY_MAX_PACKETS ; i++){
			classify_packet(table.data[i]);
		}
		for(i=0 ; i < table.end ; i++){
			classify_packet(table.data[i]);
		}
	}
	if(DEBUG_F){
		for(i=0 ; i < cur_output ; i++){
			printf("%u\n", output_table[i]);
		}
	}
	return;
}

void load_files(char **argv){
	FILE *fp;
	int i, j;
	int size;
	char buffer[1000];
	unsigned int *keys;
	unsigned int *values;
	unsigned int *test;
	//First, let's load the hash file:
	fp = fopen(argv[1], "r");
	fgets(buffer, sizeof(buffer), fp);
	size = atoi(buffer);
	keys = (unsigned int *)malloc(sizeof(unsigned int)*size);
	values = (unsigned int *)malloc(sizeof(unsigned int)*size);
	for(i=0 ; i < size ; i++){
		keys[i] = 0;
		values[i] = 0;
	}
	for(i=0 ; i < size ; i++){
		fgets(buffer, sizeof(buffer), fp);
		keys[i] = atoi(buffer);
	}
	for(i=0 ; i < size ; i++){
		fgets(buffer, sizeof(buffer), fp);
		values[i] = atoi(buffer);
	}
	hashmap = hashmap_create(size * 2, sizeof(unsigned int), sizeof(unsigned int));
	for(i=0 ; i < size ; i++){
		hashmap_put(hashmap, keys+i, values+i);
	}
	fclose(fp);
	free(keys);
	free(values);
	fp = fopen(argv[2], "r");
	fgets(buffer, sizeof(buffer), fp);
	total_trees = atoi(buffer);
	tree_sizes = (unsigned int *)malloc(sizeof(unsigned int)*total_trees);
	rf_forest = (struct tree_node **)malloc(sizeof(struct tree_node *)*total_trees);
	for(i=0 ; i < total_trees ; i++){
		fgets(buffer, sizeof(buffer), fp);
		tree_sizes[i] = atoi(buffer);
		rf_forest[i] = (struct tree_node *)malloc(sizeof(struct tree_node)*tree_sizes[i]);
		for(j=0 ; j < tree_sizes[i] ; j++){
			fscanf(fp, "%d %d %d %f %d %d", rf_forest[i][j].true_index, rf_forest[i][j].false_index, rf_forest[i][j].attr, rf_forest[i][j].value, rf_forest[i][j].done, rf_forest[i][j].result);
			rf_forest[i][j].true_index--;
			rf_forest[i][j].false_index--;
			rf_forest[i][j].attr--;
		}
	}
	for(i=0 ; i < total_trees ; i++){
		printf("Tree %d, size %u:\n", i, tree_sizes[i]);
		for(j=0 ; j < tree_sizes[i] ; j++){
			printf("%d %d %d %f %d %d\n", rf_forest[i][j].true_index, rf_forest[i][j].false_index, rf_forest[i][j].attr, rf_forest[i][j].value, rf_forest[i][j].done, rf_forest[i][j].result);
		}
	}
	return;
}

int main(int argc, char **argv){
	int i, j;
	unsigned int a,b;
	unsigned long int total;
	FILE *fp;
	total = 0;
	i=0;
	for(i=0 ; i < COPY_MAX_PACKETS ; i++){
		for(j=0 ; j < COPY_MAX_BYTES ; j++){
			table.data[i][j] = 0;
		}
	}
	if(argc != 3){
		//We need a hash file and a forest file
		printf("Check Args\n");
		return 0;
	}
	load_files(argv);
	while(1==1){
		read_logs(argv);
		a = table.start;
		b = table.end;
		if(a <= b){
			total = total + b - a;
		}
		else{
			total = total + (COPY_MAX_PACKETS - a) + b;
		}
		classify_table();
		i++;
		if(DEBUG_F || DEBUG_F2 || DEBUG_F3){
			break;
		}
		if(DEBUG_F4){
			printf("%u\n", table.skipped);
		}
		if(PPS_STATS){
			if(i % 10 == 0){
				printf("%u\n", total);
				i=0;
			}
		}
	}
	return 0;
}

