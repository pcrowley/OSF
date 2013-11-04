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
#include <signal.h>
#include <libsvm/svm.h>
#include "fnv.h"
#include "pna_hashmap.h"

#define HASHMAP_SIZE 10000
#define COPY_MAX_PACKETS 100000
#define COPY_MAX_BYTES 100
#define OSF_FEATURES 61

#define DEBUG_F1 0
#define DEBUG_F2 0
#define DEBUG_F3 1
//Throughput stages:
//0, Run normally
//1, Only Copy
//2, Copy + Hash
//3, Copy + Hash + SVM
#define THROUGHPUT_STAGE 0
#define STAT_TOTAL 1
#define SVM_NULL 0
#define VERBOSE_RUN 1
struct pna_hashmap *hashmap;
unsigned long int stat_total;



struct unknown_feature_table {
	unsigned int size;
	unsigned int features[COPY_MAX_PACKETS][OSF_FEATURES];
};

struct svm_model *model;

struct unknown_hash_table {
	unsigned int size;
	uint32_t ip[COPY_MAX_PACKETS];
	uint32_t key[COPY_MAX_PACKETS];
};

struct hash_result_table {
	unsigned int size;
	uint32_t ip[COPY_MAX_PACKETS];
	unsigned int class[COPY_MAX_PACKETS];
};

struct copy_table {
	unsigned int size;
	unsigned int skipped;
	char data[COPY_MAX_PACKETS][COPY_MAX_BYTES];
};

struct kernel_table {
	unsigned int start;
	unsigned int end;
	unsigned int skipped;
	char data[COPY_MAX_PACKETS][COPY_MAX_BYTES];
};

struct copy_table table;
struct unknown_feature_table uf_table;
struct unknown_hash_table uh_table;
struct hash_result_table hr_table;


void *fast_memcpy(void *__restrict b, const void *__restrict a, size_t n){
	char *s1 = b;
	const char *s2 = a;
	for(; 0<n; --n)*s1++ = *s2++;
	return b;
}

static unsigned int *extract_features(char data[COPY_MAX_BYTES], unsigned int features[OSF_FEATURES]){
	int i,j,k,l;
	features = (unsigned int *)malloc(OSF_FEATURES*sizeof(unsigned int));
	//ECN
	uint8_t temp8;
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
	uint8_t temp8a, temp8b, temp8c, temp8d, temp8e;
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
int copy_logs(){
	int fd;
	int size;
	unsigned int start;
	unsigned int end;
	struct stat pf_stat;
	struct kernel_table *osf_map;
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
	osf_map = (struct kernel_table *)mmap(NULL, sizeof(struct kernel_table), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(osf_map == MAP_FAILED){
		perror("mmap");
		close(fd);
		return -1;
	}
	start = osf_map->start;
	end = osf_map->end;
	table.skipped = osf_map->skipped;
	if(start == end){
		//No new packets
		table.size = 0;
		close(fd);
		munmap(osf_map, size);
		return 1;
	}
	else if(start < end){
		table.size = end - start;
		fast_memcpy(table.data[0], osf_map->data[start], table.size * COPY_MAX_BYTES);
	}
	else{
		table.size = (COPY_MAX_PACKETS - start) + end;
		fast_memcpy(table.data[0], osf_map->data[start], (COPY_MAX_PACKETS - start) * COPY_MAX_BYTES);
		fast_memcpy(table.data[COPY_MAX_PACKETS - start], osf_map->data[0], end * COPY_MAX_BYTES);
	}
	//memcpy(&table, osf_map, sizeof(struct copy_table));
	close(fd);
	munmap(osf_map, size);
	return 0;
}

uint32_t get_ip(char data[COPY_MAX_BYTES]){
	return (uint32_t)(data+12);
}

void hash_classify(char data[COPY_MAX_BYTES]){
	uint32_t value;
	unsigned int temp=-1;
	unsigned int *hash_ptr=NULL;
	if(DEBUG_F1){
		printf("Start extract_features\n");
	}
	extract_features(data, uf_table.features[uf_table.size]);
	if(DEBUG_F1){
		printf("End extract_features\n");
	}
	if(DEBUG_F1){
		printf("Start fnv_32a_buf\n");
	}
	value = fnv_32a_buf((void *)uf_table.features[uf_table.size], OSF_FEATURES * sizeof(unsigned int), FNV1_32A_INIT);
	if(DEBUG_F1){
		printf("End fnv_32a_buf\n");
	}
	//Critical Start
	if(DEBUG_F1){
		printf("Start hashmap_get\n");
	}
	hash_ptr = hashmap_get(hashmap, &value);
	if(DEBUG_F1){
		printf("End hashmap_get\n");
	}
	if(DEBUG_F2){
	}
	if(hash_ptr == NULL){	
		hashmap_put(hashmap, &value, &temp);
		uf_table.size++;
		uh_table.ip[uh_table.size] = get_ip(data);
		uh_table.key[uh_table.size] = value;
		uh_table.size++;
	}
	else if(hash_ptr[0] == -1){
		uh_table.ip[uh_table.size] = get_ip(data);
		uh_table.key[uh_table.size] = value;
		uh_table.size++;
	}
	else{
		hr_table.ip[hr_table.size] = get_ip(data);
		hr_table.class[hr_table.size] = hash_ptr[1];
		hr_table.size++;
	}
	//Critical End
}

void clear_tables(){
	uf_table.size=0;
	uh_table.size=0;
	hr_table.size=0;
}

void null_svm_classify(unsigned int features[OSF_FEATURES]){
	unsigned int key;
	unsigned int *value;
	key = fnv_32a_buf((void *)features, OSF_FEATURES * sizeof(unsigned int), FNV1_32A_INIT);
	value = hashmap_get(hashmap, &key);
	value[1] = 88;
	return;
}

void svm_classify(unsigned int features[OSF_FEATURES]){
	unsigned int key;
	unsigned int *value;
	unsigned int new_value;
	int i;
	int cur_index=0;
	struct svm_node sample[OSF_FEATURES+1];
	key = fnv_32a_buf((void *)features, OSF_FEATURES * sizeof(unsigned int), FNV1_32A_INIT);
	for(i=0 ; i < OSF_FEATURES ; i++){
		if(features[i] == 0){
			continue;
		}
		sample[cur_index].index = i;
		sample[cur_index].value = (double)features[i];
		cur_index++;
	}
	sample[cur_index].index = -1;
	new_value = (unsigned int)svm_predict(model, sample);
	value = hashmap_get(hashmap, &key);
	value[1] = new_value;
	return;
}

void memo_classify(uint32_t ip, uint32_t key){
	unsigned int *class;
	class = hashmap_get(hashmap, &key);
	if(DEBUG_F2){
		printf("Made it\n");
	}
	hr_table.ip[hr_table.size] = ip;
	hr_table.class[hr_table.size] = class[1];
	hr_table.size++;
}

void print_result(uint32_t ip, unsigned int class){
	uint8_t *temp;
	temp = &ip;
	printf("%u.%u.%u.%u %u\n", temp[0], temp[1], temp[2], temp[3], class);
}

void write_results(){
	int i;
	for(i=0 ; i < hr_table.size ; i++){
		if(DEBUG_F3){
			print_result(hr_table.ip[i], hr_table.class[i]);
		}
		else{
			//Write to disk
		}
	}
}

int read_logs(char **argv){
	void *logs;
	int i,j;
	uint8_t temp;
	int res;
	unsigned int **feature_list;
	if(DEBUG_F1){
		printf("Start copy_logs()\n");
	}
	res = copy_logs();//Copies all packets from PNA
	if(DEBUG_F1){
		printf("End copy_logs()\n");
	}
	if(THROUGHPUT_STAGE == 1){
		return 0;
	}
	if(res == -1){
		return -1;
	}
	else if(res == 1){
		return 0;
	}
	clear_tables();
	//Let's start the feature extraction process:
	for(i=0 ; i < table.size ; i++){
		if(DEBUG_F1){
			printf("Start hash_classify()\n");
		}
		hash_classify(table.data[i]);
		if(DEBUG_F1){
			printf("End hash_classify()\n");
		}
	}
	if(THROUGHPUT_STAGE == 2){
		return 0;
	}
	//Known features are done, let's go back and handle the unknown features
	for(i=0 ; i < uf_table.size ; i++){
		if(DEBUG_F1){
			printf("Start svm_classify()\n");
		}
		if(SVM_NULL){
			null_svm_classify(uf_table.features[i]);
		}
		else{
			svm_classify(uf_table.features[i]);
		}
		if(DEBUG_F1){
			printf("End svm_classify()\n");
		}
	}
	if(THROUGHPUT_STAGE == 3){
		return 0;
	}
	//Now that we know all unknowns, let's redo the unknown IP/hash pairs
	for(i=0 ; i < uh_table.size ; i++){
		memo_classify(uh_table.ip[i], uh_table.key[i]);
	}
	write_results();
	return 0;
}

void INThandler(int sig){
	signal(sig, SIG_IGN);
	if(STAT_TOTAL){
		printf("\n%u\n", stat_total);
	}
	exit(0);
}

void print_usage(){
	printf("Usage:\n");
	printf("ml_osc <svm_file>\n");
	return;
}

int check_args(int argc, char **argv){
	if(argc != 2){
		return 0;
	}
	return 1;
}

void load_files(int argc, char **argv){
	model = svm_load_model(argv[1]);
	if(model == NULL){
		printf("Model file error\n");
	}
}

int main(int argc, char **argv){
	int i;
	unsigned int a,b;
	FILE *fp;
	int first_run=1;
	if(check_args(argc, argv)){
		load_files(argc, argv);
	}
	else{
		print_usage();
		return 1;
	}
	stat_total = 0;
	i=0;
	signal(SIGINT, INThandler);
	hashmap = hashmap_create(HASHMAP_SIZE, sizeof(unsigned int), sizeof(unsigned int));
	while(1==1){
		if(DEBUG_F1){
			printf("Start\n");
		}
		read_logs(argv);
		if(DEBUG_F1){
			printf("End\n");
		}
		if(VERBOSE_RUN){
			if(table.size != 0){
				printf("%u\n", table.size);
			}
		}
		stat_total = stat_total + table.size;
	}
	fp = fopen("table.out", "w");
	fwrite(&table, sizeof(struct copy_table), 1, fp);
	fclose(fp);
	return 0;
}
