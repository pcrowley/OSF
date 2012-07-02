log_num=1
exit_flag=0
case "$1" in
2)	
	log_int=$4
	log_cur=$log_int
	while (($exit_flag == 0)); do
	log_cur=$(($log_cur - 1))
	sleep 1
	if (($log_cur == 0));
	then
		log_cur=$log_int
		sudo bin/log_read "logs/raw/raw"$log_num".log" 2> read.log
		log_num=$(($log_num + 1))
		if (grep -qi "stat" read.log);
		then
			rm read.log
			exit_flag=1
		fi
	fi
	done
;;
3)	
	cap_int=$2
	cap_cur=$cap_int
	cap_num=$(bin/calculate_capacity $3 $5);
	while (($exit_flag == 0)); do
	cap_cur=$(($cap_cur - 1))
	sleep 1
	if (($cap_cur == 0));
	then
		cap_cur=$cap_int
		bin/control_read > control.log
		if (grep -qi "stat" control.log);
		then
			rm control.log
			exit_flag=1
			break
		fi
		cur_log=$(grep "Current Log" control.log);
		cur_log=${cur_log:17}
		if (($cur_log >= $cap_num));
		then
			sudo bin/log_read "logs/raw"$log_num".log" 2> read.log
			log_num=$(($log_num + 1))
			if (grep -qi "stat" read.log);
			then
				rm read.log
				exit_flag=1
				break
			fi
		fi
	fi
	done
;;
4)	
	log_int=$4
	log_cur=$log_int
	cap_int=$2
	cap_cur=$cap_int
	cap_num=$(bin/calculate_capacity $3 $5);
	while (($exit_flag == 0)); do
	cap_cur=$(($cap_cur - 1))
	log_cur=$(($log_cur - 1))
	sleep 1
	if (($log_cur == 0));
	then
		log_cur=$log_int
		sudo bin/log_read "logs/raw"$log_num".log" 2> read.log
		log_num=$(($log_num + 1))
		if (grep -qi "stat" read.log);
		then
			rm read.log
			exit_flag=1
			break
		fi
		if (($cap_cur == 0));
		then
			log_cur=$log_int
		fi
		continue
	fi
	if (($cap_cur == 0));
	then
		cap_cur=$cap_int
		bin/control_read > control.log
		if (grep -qi "stat" control.log);
		then
			rm control.log
			exit_flag=1
			break
		fi
		cur_log=$(grep "Current Log" control.log);
		cur_log=${$cur_log:19}
		if (($cur_log >= $cap_num));
		then
			sudo bin/log_read "logs/raw/raw"$log_num".log" 2> read.log
			log_num=$(($log_num + 1))
			if (grep -qi "stat" read.log);
			then
				rm read.log
				exit_flag=1
				break
			fi
		fi
	fi
	done
;;
*)	exit 0
esac

