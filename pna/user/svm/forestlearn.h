#ifndef __FORESTLEARN_H__
#define __FORESTLEARN_H__

#define RF_GINI 1
#define RF_ENTROPY 0
#define MAX_NODES 100000

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct tree_node {
	unsigned int attribute_index;
	unsigned int values;
	unsigned int type;
	unsigned int true_dest;
	unsigned int false_dest;
	unsigned int result;
	unsigned int done_flag;
};

struct forest_result {
	unsigned int result;
	unsigned int num_trees;
	unsigned int *votes;
};

void write_forest(struct tree_node **forest);

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
	);

struct forest_result *forest_classify(unsigned int *feat_sample, unsigned int rf_features, struct tree_node **forest, unsigned int rf_num_trees, unsigned int *rf_num_nodes);

struct tree_node **load_forest(char *filename, unsigned int *rf_num_trees, unsigned int **rf_num_nodes);

#endif
