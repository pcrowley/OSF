echo "Starting OSF"
if (/sbin/lsmod|grep -q pna);
then
	echo "pna loaded"
else
	echo "Error: pna not loaded"
	exit
fi

if [ -f etc/osf_config ];
then
	echo "etc/osf_config found"
else
	echo "Error: etc/osf_config not found"
	exit
fi

if [ -f fpdb/p0f.fp ];
then
	echo "fpdb/p0f.fp found"
else
	echo "Error: fpdb/p0f.fp not found"
	exit
fi

if (grep -q Max_log_entries etc/osf_config);
then
	log=$(grep Max_log_entries etc/osf_config)
	log=${log:25}
	echo "Max log entries" $log
else
	echo "osf_config missing Max_log_entries"
	exit
fi

if (grep -q Max_db_entries etc/osf_config);
then
	db=$(grep Max_db_entries etc/osf_config)
	db=${db:25}
	echo "Max db entries" $db
else
	echo "osf_config missing Max_db_entries"
	exit
fi

if (grep -q Autolog_mode etc/osf_config);
then
	mode=$(grep Autolog_mode etc/osf_config)
	mode=${mode:25}
	echo "Autolog mode" $mode
else
	echo "osf_config missing Autolog_mode"
	exit
fi

if (grep -q Capacity_poll_time etc/osf_config);
then
	ctime=$(grep Capacity_poll_time etc/osf_config)
	ctime=${ctime:25}
	echo "Capacity poll time" $ctime
else
	echo "osf_config missing Capacity_poll_time"
	exit
fi

if (grep -q Capacity_percentage etc/osf_config);
then
	cper=$(grep Capacity_percentage etc/osf_config);
	cper=${cper:25}
	echo "Capacity percentage" $cper
else
	echo "osf_config missing Capacity_percentage"
	exit
fi

if (grep -q Log_dump_wait_time etc/osf_config);
then
	ltime=$(grep Log_dump_wait_time etc/osf_config);
	ltime=${ltime:25}
	echo "Log dump wait time" $ltime
else
	echo "osf_config missing Log_dump_wait_time"
fi

cd fpdb
../bin/p0f_convert p0f.fp >/dev/null
cd ..
sudo bin/osf_control -l $log -d $db
sudo bin/db_load fpdb/tcp.osf
nohup bin/autolog $mode $ctime $cper $ltime $log $db &
