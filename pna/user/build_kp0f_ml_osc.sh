rm -vf copy_user perf_read reconstruct osf_user
gcc -w -o copy_user copy_user.c
gcc -w -o reconstruct reconstruct.c
gcc -w -o perf_read pna_perfmon_read.c
gcc -w -o osf_user osf_user.c hash_32a.c
