#ifndef __RANDOMFOREST_H__
#define __RANDOMFOREST_H__


struct tree_node{
	int true_index;
	int false_index;
	int attr;
	double value;
	int done;
	int result;
};

struct forest_result{
	int result;
	double percent;
};

struct forest_result rf_classify(struct tree_node **forest, int num_trees, int *num_nodes, int max_class, unsigned int *features, unsigned int num_features);

#endif
