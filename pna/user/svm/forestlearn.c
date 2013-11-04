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

#define DEBUG_F		0
#define DEBUG_F2	1
#define DEBUG_F3	0
#define DEBUG_F4	0
#define DEBUG_F5	0

unsigned int depth;
unsigned int max_index;
unsigned int max_truth;
unsigned int *tree_sizes;
struct tree_node build_tree[MAX_NODES];


//Read-only args passed into learn_forest
unsigned int **features;
unsigned int num_features;
unsigned int num_samples;
unsigned int *truths;
unsigned int *ranges;
unsigned int num_trees;
unsigned int sub_sample_size;
unsigned int sub_attr_size;
unsigned int mode;
unsigned int *datatypes;

void nullify_forest(struct tree_node **forest){
	int i;
	for(i=0 ; i < num_trees ; i++){
		forest[i] == NULL;
	}
	return;
}

void get_max_truth(){
	int i;
	int max;
	max=0;
	for(i=0; i < num_samples ; i++){
		if(truths[i] > max){
			max = truths[i];
		}
	}
	max_truth = max;
	return;
}

void clear_build_tree(){
	u8 *ptr;
	int i;
	ptr = (u8 *)&build_tree;
	for(i=0 ; i < sizeof(build_tree) ; i++){
		ptr[i] = 0;
	}
	return;
}

double entropy(unsigned int *set, unsigned int num_set){
	int i;
	unsigned int *histogram;
	double sum=0.0;
	double a,b,p;
	histogram = (int *)malloc(sizeof(int)*max_truth+1);
	if(num_set == 0){
		printf("entropy() encountered emtpy set!\n");
		return (DBL_MAX / 2.0);
	}
	for(i=0 ; i < max_truth+1 ; i++){
		histogram[i] = 0;
	}
	for(i=0 ; i < num_set ; i++){
		histogram[truths[set[i]]]++;
	}
	for(i=0 ; i< max_truth+1 ; i++){
		b = (double)num_set;
		a = (double)histogram[i];
		if(histogram[i] == 0){
			continue;
		}
		p = a/b;
		sum = sum + (p * log2(p));
	}
	free(histogram);
	return (-1.0 * sum);
}

int pass_check(unsigned int *feat_sample, unsigned int attr, unsigned int value, unsigned int type){
	//Type: 0 means exact, 1 means less than or equal to
	if(type == 0){
		if(feat_sample[attr] == value){
			return 1;
		}
		else{
			return 0;
		}
	}
	else{
		if(feat_sample[attr] <= value){
			return 1;
		}
		else{
			return 0;
		}
	}
	return 0;
}

void split(unsigned int *qualify, unsigned int num_qualify, unsigned int *split_true, unsigned int *split_false, unsigned int *split_true_num, unsigned int *split_false_num, unsigned int attr, unsigned int value, unsigned int type){
	int true_num=0;
	int false_num=0;
	int i,j,k;
	if(DEBUG_F){
		printf("Splitting on: Attr-%u Value-%u Type -%u\n", attr, value, type);
	}
	for(i=0 ; i < num_qualify ; i++){
		if(DEBUG_F){
			printf("%d\n",qualify[i]);
		}
		if(pass_check(features[qualify[i]], attr, value, type)){
			split_true[true_num] = qualify[i];
			true_num++;
		}
		else{
			split_false[false_num] = qualify[i];
			false_num++;
		}
	}
	split_true_num[0] = true_num;
	split_false_num[0] = false_num;
	return;
}

double class_count(unsigned int *split, unsigned int num){
	int i;
	int sum=0;
	int max_class=-1;
	unsigned int *filter;
	for(i=0 ; i < num ; i++){
		if((int)truths[split[i]] > (int)max_class){
			max_class = (int)truths[split[i]];
		}
	}
	if(max_class == -1){
		return 0.0;
	}
	filter = (unsigned int *)malloc(sizeof(unsigned int)*(max_class+1));
	max_class++;
	for(i=0 ; i < max_class ; i++){
		filter[i] = 0;
	}
	for(i=0 ; i < num ; i++){
		filter[truths[split[i]]]++;
	}
	for(i=0 ; i < max_class ; i++){
		if(filter[i] > 0){
			sum++;
		}
	}
	free(filter);
	return (double)sum;
}

void best_split(unsigned int *qualify, unsigned int num_qualify, int *ret_attr, int *ret_value, int *ret_type){
	int *split_true;
	int *split_false;
	int split_true_num;
	int split_false_num;
	double min_entropy = DBL_MAX;
	double max_gain = 0.0;
	double temp;
	double temp1;
	double temp2;
	int min_entropy_type=-1;
	int min_entropy_attr=-1;
	int min_entropy_value=-1;
	unsigned int i,j,k;
	u8 temp8;
	if(DEBUG_F2){
		printf("Calculating Best Split...\n");
	}
	for(i=0 ; i < 2 ; i++){
		for(j=0 ; j < num_features ; j++){
			for(k=0 ; k < ranges[j] ; k++){
			if(DEBUG_F3){
				printf("%d %d %d %u\n", i, j, k, num_features);
			}
				split_true = (int *)malloc(sizeof(int)*num_qualify);
				split_false= (int *)malloc(sizeof(int)*num_qualify);
				split(qualify, num_qualify, split_true, split_false, &split_true_num, &split_false_num, j, k, i);
				if(DEBUG_F){
					printf("split_true_num %d\n", split_true_num);
					printf("split_false_num %d\n", split_false_num);
				}
				if(split_true_num == 0 || split_false_num == 0){
					free(split_true);
					free(split_false);
					continue;
				}
				//temp1 = class_count(split_true, split_true_num);
				//temp2 = class_count(split_false, split_false_num);
				temp1 = entropy(split_true, split_true_num);
				temp2 = entropy(split_false, split_false_num);
				temp = entropy(qualify, num_qualify) - (temp1*((double)split_true_num/(double)num_qualify)+temp2*((double)split_false_num/(double)num_qualify));
				
				//temp = split_true_num - split_false_num;
				if(temp < 0){
					temp = temp * -1.0;
				}
				
				if((split_true_num == 0) || (split_false_num == 0)){
					temp = -1.0;
				}
				
				if(temp >= max_gain){
					max_gain = temp;
					min_entropy_type = i;
					min_entropy_attr = j;
					min_entropy_value = k;
				}
				free(split_true);
				free(split_false);
			}
		}
	}
	if(min_entropy_type == -1 || min_entropy_attr == -1 || min_entropy_value == -1){
		printf("Something went horribly wrong in best_split()\n");
		for(i=1 ; i < num_qualify ; i++){
			truths[qualify[i]] = truths[qualify[0]];
		}
		return;
		for(i=0 ; i < num_qualify ; i++){
			printf("%u\n", truths[qualify[i]]);
			for(j=0 ; j < num_features ; j++){
				printf("%u ", features[qualify[i]][j]);
			}
			printf("\n");
		}
		ret_attr[0]=0;
		ret_value[0]=0;
		ret_type[0]=0;
		return;
	}
	ret_attr[0]=min_entropy_attr;
	ret_value[0]=min_entropy_value;
	ret_type[0]=min_entropy_type;
	return;
}

void learn_node(unsigned int *qualify, unsigned int num_qualify, unsigned int my_index){
	unsigned int split_attr;
	unsigned int split_value;
	unsigned int split_type;
	int *split_true;
	int *split_false;
	int split_true_num;
	int split_false_num;
	int i;
	if(DEBUG_F){
		printf("New Node: %u\n", max_index);
	}
	if(DEBUG_F2){
		printf("Depth %u\n", depth);
		printf("Num_qualify %d\n", num_qualify);
	}
	depth++;
	if(num_qualify == 0){
		build_tree[max_index].result = 0;
		build_tree[max_index].done_flag = 1;
		depth--;
		return;
	}
	//if(entropy(qualify, num_qualify) == 0.0){
	if(class_count(qualify, num_qualify) <= 1.0){
		build_tree[max_index].result = truths[qualify[0]];
		build_tree[max_index].done_flag = 1;
		depth--;
		return;
	}
	if(num_qualify == 1){
		build_tree[max_index].result = truths[qualify[0]];
		build_tree[max_index].done_flag = 1;
		depth--;
		return;
	}
	best_split(qualify, num_qualify, &split_attr, &split_value, &split_type);
	if(split_attr == -1){
		build_tree[max_index].result = truths[qualify[0]];
		build_tree[max_index].done_flag = 1;
		depth--;
		return;
	}
	build_tree[max_index].attribute_index = split_attr;
	build_tree[max_index].values = split_value;
	build_tree[max_index].type = split_type;
	split_true=(int *)malloc(sizeof(int)*num_qualify);
	split_false=(int *)malloc(sizeof(int)*num_qualify);
	split(qualify, num_qualify, split_true, split_false, &split_true_num, &split_false_num, split_attr, split_value, split_type);
	max_index++;
	build_tree[my_index].true_dest = max_index;
	learn_node(split_true, split_true_num, max_index);
	free(split_true);
	max_index++;
	build_tree[my_index].false_dest = max_index;
	learn_node(split_false, split_false_num, max_index);
	free(split_false);
	depth--;
	return;
}

struct tree_node *learn_tree(){
	unsigned int *qualify;//Packets that make it to a particular node
	unsigned int num_qualify;
	int i,j;
	struct tree_node *ret;
	depth=0;
	qualify = (int *)malloc(sizeof(unsigned int) * num_samples);
	j=0;
	for(i=0 ; i < num_samples ; i++){
			qualify[j++] = i;
	}
	num_qualify = j;
	learn_node(qualify, num_qualify, max_index);
	free(qualify);
	ret = (struct tree_node *)malloc(sizeof(struct tree_node) * (max_index+1));
	memcpy(ret, &build_tree, sizeof(struct tree_node)*(max_index+1));
	return ret;
}

struct tree_node **learn_forest(
	unsigned int **rf_features,
	unsigned int rf_num_features,
	unsigned int rf_num_samples,
	unsigned int *rf_truths,
	unsigned int *rf_ranges,
	unsigned int rf_num_trees,
	unsigned int rf_sub_sample_size,
	unsigned int rf_sub_attr_size,
	unsigned int rf_mode, //Either RF_GINI or RF_ENTROPY
	unsigned int *rf_datatypes //For each feature, cast as double or int
){
	int i;
	struct tree_node **forest;
	features = rf_features;
	num_features = rf_num_features;
	num_samples = rf_num_samples;
	truths = rf_truths;
	num_trees = rf_num_trees;
	ranges = rf_ranges;
	sub_sample_size = rf_sub_sample_size;
	sub_attr_size = rf_sub_attr_size;
	mode = rf_mode;
	datatypes = rf_datatypes;
	mode = RF_ENTROPY;//Not implemented yet
	datatypes = NULL;//Not implemented yet
	depth=0;
	get_max_truth();
	forest = (struct tree_node **)malloc(sizeof(struct tree_node *) * num_trees);
	tree_sizes = (unsigned int *)malloc(sizeof(unsigned int) * num_trees);
	nullify_forest(forest);
	for(i=0 ; i < num_trees ; i++){
		clear_build_tree();
		max_index = 0;
		forest[i] = learn_tree();
		tree_sizes[i] = max_index+1;
	}
	write_forest(forest);
	free(forest);
	free(tree_sizes);
	return;
}

void write_forest(struct tree_node **forest){
	int i,j,k,l;
	unsigned int size;
	FILE *fp;
	struct forest_result *res;
	fp = fopen("forest.out", "w");
	//Format of forest file:
	//1 unsigned int = NUM_TREES
	//NUM_TREES unsigned int = Size of each tree
	//Tree Data
	if(fp == NULL){
		printf("forest.out cannot be opened for writing\n");
		return;
	}
	size = num_trees;
	fwrite(&size, sizeof(unsigned int), 1, fp);
	for(i=0 ; i < num_trees ; i++){
		size = tree_sizes[i];
		fwrite(&size, sizeof(unsigned int), 1, fp);
	}
	for(i=0 ; i < num_trees ; i++){
		fwrite(forest[i], sizeof(struct tree_node), tree_sizes[i], fp);
	}
	if(DEBUG_F2){
		for(i=0 ; i < num_trees ; i++){
			for(j=0 ; j < tree_sizes[i] ; j++){
				printf("%u %u %u %u %u %u %u\n", forest[i][j].attribute_index, forest[i][j].values, forest[i][j].type, forest[i][j].true_dest, forest[i][j].false_dest, forest[i][j].result, forest[i][j].done_flag);
			}
		}
	}
	for(i=0 ; i < num_samples ; i++){
		res = forest_classify(features[i], num_features, forest, num_trees, tree_sizes); 
		if(DEBUG_F2){
		printf("%u\n", res->result);
		}
		free(res);
	}
	fclose(fp);
	return;
}

struct tree_node **load_forest(char *filename, unsigned int *rf_num_trees, unsigned int **rf_num_nodes){
	FILE *fp;
	int i, j;
	struct tree_node **ret;
	struct tree_node **forest;
	fp = fopen(filename, "r");
	fread(rf_num_trees, sizeof(unsigned int), 1, fp);
	*rf_num_nodes = (unsigned int *)malloc(sizeof(unsigned int)*(rf_num_trees[0]));
	fread(*rf_num_nodes, sizeof(unsigned int), rf_num_trees[0], fp);
	ret = (struct tree_node **)malloc(sizeof(struct tree_node *)*rf_num_trees[0]);
	for(i=0 ; i < rf_num_trees[0] ; i++){
		ret[i] = (struct tree_node *)malloc(sizeof(struct tree_node)*(*rf_num_nodes[i]));
		fread(ret[i], sizeof(struct tree_node), rf_num_nodes[i], fp);
	}
	fclose(fp);
	return ret;
}

unsigned int tree_classify(unsigned int *feat_sample, unsigned int rf_features, struct tree_node *tree, unsigned int rf_tree_size){
	int i=0;
	i=0;
	if(DEBUG_F5){
		for(i=0 ; i < rf_features ; i++){
			printf("%u ", feat_sample[i]);
		}
		printf("\n");
	}
	i=0;
	while(!tree[i].done_flag){
		if(DEBUG_F5){
			printf("Node %d: Attr-%u ", i, tree[i].attribute_index);
			if(tree[i].type == 0){
				printf("== ");
			}
			else{
				printf("<= ");
			}
			printf("%u Sample is %u\n", tree[i].values, feat_sample[tree[i].attribute_index]);
		}
		if(tree[i].type == 0){
			if(feat_sample[tree[i].attribute_index] == tree[i].values){
				i = tree[i].true_dest;
			}
			else{
				i = tree[i].false_dest;
			}
		}
		else{
			if(feat_sample[tree[i].attribute_index] <= tree[i].values){
				i = tree[i].true_dest;
			}
			else{
				i = tree[i].false_dest;
			}
		}
		if(i >= rf_tree_size){
			printf("Error in tree_classify()\n");
			printf("Index %d\n", i);
			for(i=0 ; i < rf_tree_size ; i++){
				printf("%u %u %u %u %u %u %u\n", tree[i].attribute_index, tree[i].values, tree[i].type, tree[i].true_dest, tree[i].false_dest, tree[i].result, tree[i].done_flag);	
			}
			return 0;
		}
	}
	if(DEBUG_F4){
		printf("%d\n", i);
	}
	return tree[i].result;
}

struct forest_result *forest_classify(unsigned int *feat_sample, unsigned int rf_features, struct tree_node **forest, unsigned int rf_num_trees, unsigned int *rf_num_nodes){
	struct forest_result *ret;
	int i;
	unsigned int max_class=0;
	unsigned int max_vote=0;
	unsigned int max_index=0;
	unsigned int *histogram;
	ret = (struct forest_result*)malloc(sizeof(struct forest_result));
	ret->num_trees = rf_num_trees;
	if(rf_num_trees == 1){
		ret->result =  tree_classify(feat_sample, rf_features, forest[0], rf_num_nodes[0]);
		ret->votes = (unsigned int *)malloc(sizeof(unsigned int));
		return ret;
	}
	ret->votes = (unsigned int *)malloc(sizeof(unsigned int) * rf_num_trees);
	for(i=0 ; i < rf_num_trees ; i++){
		ret->votes[i] = tree_classify(feat_sample, rf_features, forest[i], rf_num_nodes[i]);
		if(ret->votes[i] > max_class){
			max_class = ret->votes[i];
		}
	}
	histogram = (unsigned int *)malloc(sizeof(unsigned int)*(max_class + 1));
	for(i=0 ; i < max_class ; i++){
		histogram[i] = 0;
	}
	for(i=0 ; i < rf_num_trees ; i++){
		histogram[ret->votes[i]]++;
	}
	for(i=0 ; i < max_class ; i++){
		if(histogram[i] > max_vote){
			max_vote = histogram[i];
			max_index = i;
		}
	}
	ret->result = max_index;
	return ret;
}
