rm -vf perf_read reconstruct http_user
gcc -w -o reconstruct reconstruct.c
gcc -w -o perf_read pna_perfmon_read.c
gcc -w -o http_user http_user.c hash_32a.c
