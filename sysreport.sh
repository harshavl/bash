#! /bin/bash
#
# Description: Function of the script is to collect platform and database info.
#
# Date        Name            Description
# ----        ----            -----------
# 
# 
#######################################################################
#set -x

log="sysreport.sh.log"
wd=$PWD
TEMP=/data/storage/tmp
DATE=`/bin/date -u +%G%m%d%k%M%S | /usr/bin/tr -d ' '`
ROOT=$TEMP/sysreport-$DATE
MAINROOT=$TEMP/sysreport-$DATE
DISTRO_DIR=$ROOT/DistroInfo
HW_DIR=$ROOT/HardwareInfo
RUNTIMEINFO_DIR=$ROOT/RuntimeInfo
PLATFORM_DIR=$ROOT/PlatformInfo
BLADE_DIR=$ROOT/Blade_Info

#trap "{ /bin/rm -rf $ROOT ; exit ; }" EXIT
mkdir -p $BLADE_DIR
mkdir -p $DISTRO_DIR 
#mkdir -p $RUNTIMEINFO_DIR 
mkdir $PLATFORM_DIR || exit 1
export PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
VER=`/bin/uname -r`
mkdir -p $TEMP
ROOT=$DISTRO_DIR
ROOT=$RUNTIMEINFO_DIR
ROOT=$PLATFORM_DIR

if [ -z "$BOOTUP" ]; then
  if [ -f /etc/sysconfig/init ]; then
      . /etc/sysconfig/init
  else
    BOOTUP=serial
    RES_COL=60
    MOVE_TO_COL="echo -en \\033[300C\\033[$[${COLUMNS}-${RES_COL}]D"
    SETCOLOR_SUCCESS="echo -en \\033[1;32m"
    SETCOLOR_FAILURE="echo -en \\033[1;31m"
    SETCOLOR_WARNING="echo -en \\033[1;33m"
    SETCOLOR_NORMAL="echo -en \\033[0;39m"
    LOGLEVEL=1
  fi
fi

# Functions Start

function usage {
  echo 
  echo "  it's a utility that gathers information about a system's 
hardware and configuration. The information can then be used for 
diagnostic purposes and debugging." 
  echo
  echo
  exit 0
}


collect_distro_info(){
	echo "=== Distro version ==="
	if ls /etc/TEST-release &>/dev/null ;
	then
		/bin/cat /etc/TEST-release  >>$DISTRO_DIR/TEST-release
	fi
	echo
	echo "=== Exports version ==="
	if ls /usr/*/exports/exports-version &>/dev/null ;
	then
		/bin/cat /usr/*/exports/exports-version >$DISTRO_DIR/exports-version
	fi
}

collect_app_info(){
	echo
	echo "=== Software version and checksums ==="
	if ls /usr/*/current/software_version &>/dev/null;
	then
		/bin/cat /usr/*/current/software_version
	fi
	echo 
	if ls /usr/*/current/checksums &>/dev/null;
	then
		/bin/cat /usr/*/current/checksums >$ROOT/application_checksums
	fi
 }

dump_db(){


	echo "=== dump database mnode_cm_data ==="
#	echo "Enter DB password (Press ENTER ) "
#	read -s sqlpasswd

	sqlpasswd=`/usr/*/current/bin/TESTcrypt d `
#	/usr/local/bin/mysqldump -uroot -p$sqlpasswd --add-drop-database --routines --databases mnode_cm_data >$ROOT/full_dump_cm.sql

	/usr/local/mysql/bin/mysqldump -p$sqlpasswd ccps > $ROOT/full_dump_cm.sql
	if [ $? -eq 0 ];
	then
		echo_success
	else
		echo_failure
	fi
	

}

dump_plt_db() {

  sqlpasswd=`/usr/*/current/bin/TESTcrypt d`
  echo "=== dump platform database tables to $ROOT/platform-db-dump.sql ==="
  #echo "Enter DB platform password"
  #read -s db_password

  /usr/local/mysql/bin/mysqldump -uroot -p$sqlpasswd --add-drop-database --routines mnode_cm_data  activeAlarm alarmThreshold AuditComponent AuditProfile AuditResult blade_port_map call_trace_config call_trace_id call_trace_user component contact correlationId cps_managed_tables criticalPGSet dbMonMgr dbUpdateResult DMOConfig dm_supported_exch_mapping emsAccessControl emsTrLog eventDefinition eventGeneral externalNodeMon ext_ip ext_ip_intf ext_route ext_route_ProtGrp_map FaultGroup FaultGroupManagedObjectMap FaultRule FaultSensorEvent filterpolicy  FMResource fqdn_local fqdn_local_ext_ip_map GatewayFacility genericParamDef geo_fsync_dir geo_fsync_remote JobTable location LogCategoryProfile LogConfig ManagedObjects MCMConfig nat ObjectHealth OnDemandAudit OvldApp OvldAppRes OvldComponent OvldDiskInfo OvldDropAction OvldInterface OvldSystem peExtLinkMon perfMonConfig perfMonObjects perfMonThresholds platform PMConfig  product program programSecurity prot_grp restartpolicy rmExtIpPing SEConfig service_pool service_pool_ip_map sharedDisk shelf  SMConfig SMMonInterface snmpConfig SoftwareInstallLog softwareUpgrade solution svcpkg sw_bundle sw_bundle_program_map SystemAudit SystemBackup systemSecurity system_shutdown ThrottleSettings tmmCsvFilePushing tmmFileDir tmmGeneral tmmTableFilenameMap trapResend virtualService > $MAINROOT/platform-db-dump.sql

   if [ $? -eq 0 ];
   then
      echo "successly dump platform database"
   else
      echo "failed to dump platform database"
   fi
}

full_db_dump(){
	echo "=== full database dump to $ROOT/full_db_dump.sql ==="
	echo "=== Please be await this take few minutes ==="
    sqlpasswd=`/usr/*/current/bin/TESTcrypt d `

	/usr/local/mysql/bin/mysqldump -p$sqlpasswd  --databases `mysql -p$sqlpasswd -BN -e "SELECT GROUP_CONCAT(schema_name SEPARATOR ' ') FROM information_schema.schemata WHERE schema_name NOT IN ('mysql','performance_schema','information_schema');"` --routines --triggers > $MAINROOT/full_db_dump.sql

	if [ $? -eq 0 ]
	then
		echo "Database dump success "
	else
		echo "Database dump sucess "
	fi

}

fixupfile() {
   if [ -f $2 ] ; then
      /bin/sed -e$1 $2 > $2.newfile
      /bin/mv $2.newfile $2
   fi
   return 0
}

getpartinfo() {
  # Get fdisk -l output from all disks/partitionable raid devices from /proc/partitions
  raiddevs=`cat /proc/partitions | egrep -v "^major|^$" | awk '{print $4}' | grep \/ | egrep -v "p[0123456789]$"`
  disks=`cat /proc/partitions | egrep -v "^major|^$" | awk '{print $4}' | grep -v / | egrep -v "[0123456789]$"`
  echo "=== fdisk -l output ==="
  for d in $raiddevs $disks ; do
    echo "<----  Disk: /dev/${d}  ---->"
    echo ""
    fdisk -l /dev/${d} 2>&1
    echo ""
    echo "<----    END     ---->"
    done
}

getpciinfo() {
( echo "lspci"
  echo
  lspci
  echo
  echo "lspci -n"
  echo
  lspci -n
  echo
  echo "lspci -nv"
  echo
  lspci -nv
  echo 
  echo "lspci -nvv"
  echo
  lspci -nvv ) 2>&1
}

getipmiutilinfo() {

( echo "ipmiutil sensor"
  echo 
  ipmiutil sensor
  echo 
  echo "ipmiutil health"
  echo 
  ipmiutil health
  echo 
  echo "ipmiutil alarms"
  echo 
  ipmiutil alarms
  echo 
  echo "ipmiutil fru"
  echo 
  ipmiutil fru
  echo 
  echo "ipmiutil getevt"
  echo 
  ipmiutil getevt
  echo 
  echo "ipmiutil sel"
  echo 
  ipmiutil sel
  echo 
  echo "ipmiutil wdt"
  echo 
  ipmiutil wdt
  echo 

) 2>&1 

}

getethtoolinfo() {

( for int in `echo eth0 eth1 eth2 eth3 eth4 eth5`
  do
  	echo 
  	echo "ethtool"
  	echo 
  	ethtool $int
  	echo 
  	echo "ethtool -i"
  	echo 
  	ethtool -i $int
  	echo 
  done
) 2>&1 

}

#
# Added MC, TC, and SC

catiffile() {


  if [ -d $1 ]; then
	if [ "$2" = "RM" -o "$2" = "MP" -o "$2" = "DM" -o "$2" = "MC" -o "$2" = "TC" -o "$2" = "SC" ];
	then
		cp_cmd="cp --parents"
	else
		cp_cmd="cp -x --parents"
	fi
    $cp_cmd -R $1 $ROOT 2>>$MAINROOT/$log
    find $ROOT/$1 -type b -o -type c | xargs rm -f 2>/dev/null || :
    echo -n $STATUS
    echo_success
    return 1
  fi
  if [ -f $1 ]; then
    cp --parents $1 $ROOT 2>>$MAINROOT/$log
    echo -n $STATUS
    echo_success
    return 1
  fi

  return 0
}

catifproc() {

	echo $1 |grep "/proc"
	if [ $? -eq 0 ]; then
		fil=`find $1 -type f`
		for f in $fil
		do
			mkdir -p $ROOT/`dirname $f`
			cat $f >$ROOT/$f
		done
    	echo -n $STATUS
    	echo_success
    	return 1
	fi
  	return 0
}

catifexec() {
  if [[ -x $1 ]]; then
    echo -n $STATUS
    echo "$*" >> $ROOT/`basename $1`
    $* >> $ROOT/`basename $1` 2>&1
    echo_success
    return 1
  fi
  return 0
}


echo_success() {
  [ "$BOOTUP" = "color" ] && $MOVE_TO_COL
  echo -n "[  "
  [ "$BOOTUP" = "color" ] && $SETCOLOR_SUCCESS
  echo -n "OK"
  [ "$BOOTUP" = "color" ] && $SETCOLOR_NORMAL
  echo "  ]"
  return 0
}

echo_failure() {
  [ "$BOOTUP" = "color" ] && $MOVE_TO_COL
  echo -n "["
  [ "$BOOTUP" = "color" ] && $SETCOLOR_FAILURE
  echo -n "FAILED"
  [ "$BOOTUP" = "color" ] && $SETCOLOR_NORMAL
  echo "]"
  return 1
}

echo_passed() {
  [ "$BOOTUP" = "color" ] && $MOVE_TO_COL
  echo -n "["
  [ "$BOOTUP" = "color" ] && $SETCOLOR_WARNING
  echo -n "PASSED"
  [ "$BOOTUP" = "color" ] && $SETCOLOR_NORMAL
  echo "]"
  return 1
}


function dataCollection() {

#
# Collecting Distro Info
#

echo "Collecting distro info:"
collect_distro_info > $ROOT/distro_info
echo_success

STATUS="Collecting information about chkconfig --list:"
catifexec "/sbin/chkconfig" "--list"

if [[ -d /etc/rc.d ]];
then
	STATUS="Collecting information about /etc/rc.d:"
	catiffile "/etc/rc.d"
	ls /etc/rc.d/rc*.d/ > $ROOT/etc/rc.d/ls-output 2>/dev/null
fi

if [[ -x /bin/rpm ]] || [[ -x /usr/bin/rpm ]]; 
then
  echo "Collecting information about currently installed packages:"
  echo -n "This may take several minutes...."
  rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}\n" > $ROOT/installed-rpms
  echo_success
fi

STATUS="Getting bootloader information:"
[ -e /boot ] && ls -alR /boot > $ROOT/ls-boot 2>&1

if [ -d /boot/grub -a -f /boot/grub/grub.conf -a -f /boot/grub/device.map ]; then
  STATUS="Collecting information about the boot process (grub.conf):"
  catiffile "/boot/grub/grub.conf"
  STATUS="Collecting information about the boot process (grub.map):"
  catiffile "/boot/grub/device.map"
fi

STATUS="Collecting init configuration:"
catiffile "/etc/inittab"

STATUS="Gathering sysctl -p information:"
sysctl -p > $ROOT/sysctl-p 2>&1

STATUS="Gathering ntp configuration (/etc/ntp.conf):"
catiffile "/etc/ntp.conf"

STATUS="Collecting configuration file"
catiffile "/etc/my.cnf"

STATUS="Gathering ntp configuration (/etc/ntp/step-tickers):"
catiffile "/etc/ntp/step-tickers"

STATUS="Gathering ntp configuration (/etc/ntp/ntpservers):"
catiffile "/etc/ntp/ntpservers"

STATUS="Gathering IP information (/sbin/ifconfig):"
catifexec "/sbin/ifconfig" "-a"

STATUS="Gathering IP information (/sbin/ip a):"
catifexec "/sbin/ip" "a"

STATUS="Checking network routes:"
catifexec "/sbin/route" "-n"

STATUS="Collecting information about system authentication (pam):"
catiffile "/etc/pam.d"

echo
echo "Getting information about the kernel."
echo
STATUS="Getting kernel version:"
catifexec "/bin/uname" "-a"

STATUS="Checking module information:"
catifexec "/sbin/lsmod"

STATUS="Collecting information from /etc/fstab:"
catiffile "/etc/fstab"

STATUS="Collecting disk partition information:"
getpartinfo > $ROOT/fdisk-l

STATUS="Checking mounted file systems (mount) "
catifexec "/bin/mount"

STATUS="Collecting LVM information:"
catifexec "/usr/sbin/vgdisplay" "-vv"

STATUS="Collecting Ethernet infomation"
catifexec "/usr/dmesg | grep eth"
catifexec "/sbib/ifconfig -s -a"

# iptables
STATUS="Getting iptables information:"
if [ -f /etc/sysconfig/iptables-config ] ; then
   catiffile "/etc/sysconfig/iptables-config"
fi
STATUS="Getting iptables information (filter):"
catifexec "/sbin/iptables" "-t filter -nvL"
STATUS="Getting iptables information (mangle):"
catifexec "/sbin/iptables" "-t mangle -nvL"
STATUS="Getting iptables information (nat):"
catifexec "/sbin/iptables" "-t nat -nvL"

# ssh
STATUS="Getting ssh configuration (ssh_config)"
catiffile "/etc/ssh/ssh_config"
STATUS="Getting sshd configuration (sshd_config)"
catiffile "/etc/ssh/sshd_config"

# named
STATUS="Collecting information about the nameserver (/etc/named.conf)"
catiffile "/etc/named.conf"
STATUS="Collecting information about the nameserver (/etc/named.TESTenir1.zone)"
catiffile "/etc/named.TESTenir1.zone"
catiffile "/var/named/"

STATUS="Gathering information about your partitions:"

catifproc "/proc/partitions"

# nfs
STATUS="Collecting information about the NFS:"
catiffile "/etc/exports"

STATUS="Getting /etc/securetty:"
catiffile "/etc/securetty"

STATUS="Getting ulimit info:"
catiffile "/etc/security/limits.conf"

STATUS="Collecting information from dmesg:"
catiffile "/var/log/dmesg"


file_size=`du -hk /var/log/messages|awk '{print $1}'`
STATUS="Collecting information (/var/log/messages size ${file_size}k)"
if [ $file_size -gt 512000 ];
then
        echo "/var/log/messages is bigger than 512000k ( ${file_size}k ), skip it."     
else
	if [ -f /var/log/messages ];
	then
        for x in `/bin/ls /var/log/messages` ; do
                STATUS="Collecting messages files ($x)"
                catiffile "$x"
        done
	fi
fi

file_size=`du -hk /var/log/secure|awk '{print $1}'` 2>/dev/null
STATUS="Collecting information (/var/log/secure size ${file_size}k)"

if [[ $file_size -gt 1024000 ]];
then
        echo "/var/log/secure is bigger than 1024000k ( ${file_size}k ), skip it."
else
        catiffile "/var/log/secure"
fi

#
# Collecting Runtime Info
#

echo
echo "Collecting Runtime information..."
echo

STATUS="Getting the date:"
catifexec "/bin/date"

STATUS="Checking your systems current uptime and load average:"
catifexec "/usr/bin/uptime"

STATUS="Checking available memory:"
catifexec "/usr/bin/free"

STATUS="Checking free disk space:"
catifexec "/bin/df" "-ah"

STATUS="Checking currently running processes:"
catifexec "/bin/ps" "-e -o euser,pid,ppid,tty,%cpu,%mem,rss,vsz,start_time,time,state,wchan,cmd"

STATUS="Checking current process tree:"
catifexec "/usr/bin/pstree"

STATUS="Collecting IPC-related information:"
catifexec "/usr/bin/ipcs" "-a"

if [ -x /usr/sbin/lsof ] ; then
  STATUS="Lists information about files opened (lsof)"
  catifexec "/usr/sbin/lsof" "-b +M -n -l"
fi

if [ -x /usr/bin/ipcs ];
then
  STATUS="Collecting interprocess communication facilities status"
  catifexec "/usr/bin/ipcs" "-u"
  catifexec "/usr/bin/ipcs" "-l"
fi

STATUS="Gathering sysctl -a information:"
sysctl -a > $ROOT/sysctl-a 2>&1

STATUS="Gathering sysctl information (/proc/sys):"
catifproc "/proc/sys" $1

STATUS="Gathering information about your filesystems:"
catifproc "/proc/filesystems"

STATUS="Gathering information about your system stat:"
catifproc "/proc/stat"

STATUS="Getting kernel command line"
catifproc "/proc/cmdline"

STATUS="Gathering information about your CPU:"
catifproc "/proc/cpuinfo"

STATUS="Gathering information about your Ram:"
catifproc "/proc/meminfo"

STATUS="Gathering information about your ioports:"
catifproc "/proc/ioports"

STATUS="Gathering information about your interrupts:"
catifproc "/proc/interrupts"

STATUS="Gathering information about your devices (/proc/devices):"
catifproc "/proc/devices"

#STATUS="Gathering information about your bus:"
#getpciinfo > $ROOT/lspci
#catiffile "/proc/bus" $1

STATUS="Gathering info on udev configuration:"
catiffile "/etc/udev/rules.d/"

STATUS="Checking mounted file systems (/proc/mounts)"
catifproc "/proc/mounts"

STATUS="Getting information about the hardware."
catifexec "/usr/sbin/dmidecode"

echo "Gathering information about hardware using ipmiutil"
getipmiutilinfo > $ROOT/ipmiutilinfo
echo_success

echo "Gathering information eth ports using ethtool"
getethtoolinfo > $ROOT/ethtoolinfo
echo_success


version=`cat /etc/TEST-release`


if [[ $version =~ "wrlinux_4_0" ]] || [[ $version =~ "wrlinux_4_3" ]] || [[ $version =~ "rhel_6.2" ]]
then
	catiffile "/etc/ha.d"
	cp  "/var/lib/heartbeat/cores/*" $ROOT 2>>$MAINROOT/heartbeat_info 
fi

if [[ $version =~ "rhel_7.1" ]]
then
	pcs=`pcs status`
	echo $pcs >> $ROOT/pcs_status
elif [[ $version =~ "wrlinux_6_0" ]]
then
	crm=`crm status`
	echo $crm >> $ROOT/crm_status

fi

}

function run_mcli(){
	slot=$1
	atcaversion=`ssh $slot "uname -a"`
	if [[ $atcaversion =~ "ATCA7240" ]] || [[ $atcaversion =~ "ATCA-7240" ]]
	then
		version="ATCA-7240"
		cmd_eth="base-ethernet"
		cmd_port="ATCA-7240-Base"
		sleep_cmd=30
	elif [[ $atcaversion =~ "ATCA7220" ]] || [[ $atcaversion =~ "ATCA-7220" ]]
	then
		version="ATCA-7220"
		cmd_eth="eth"
		cmd_port="ATCA-7220-Eth"
		sleep_cmd=300
	fi
	echo "Enter RM card password"
	read -s rm_password
	echo "Please wait collecting RM card info"
	$wd/mcli.exp $slot $version $cmd_eth $cmd_port root $rm_password $sleep_cmd >> $BLADE_DIR/"$RM.log"
}

function collectCardsInfo(){

	slot=$1
	card=$2

	/usr/bin/ssh $slot "mkdir -p /tmp/audit" </dev/null
	/usr/bin/scp get_cardinfo.sh $slot:/tmp/audit
	/usr/bin/ssh $slot /tmp/audit/get_cardinfo.sh $card  </dev/null
	/usr/bin/scp $slot:/tmp/audit/$card.tar.gz $BLADE_DIR </dev/null

}

function collect_readShm(){


verify_readShm=`/usr/IMS/current/bin/readShm`

if [[ $? -eq 0 ]]
then
	count=`/usr/IMS/current/bin/readShm | wc -l`
	#atca=`cat /etc/TEST-release`
	/usr/IMS/current/bin/readShm | grep -A$count  "Card Status" | awk '{ if(NR > 2) print $0}' | awk '{ print $1 "\t" $6}' | while read line
	do
		slot=`echo $line | awk '{ print $1}' `
		card=` echo $line | awk '{ print $2} ' `
		
		ping -c1 -w1 -q $slot &>/dev/null
		if [ $? -eq 0 ]
		then
			#Collect cards information
			if [[ $card != "AM" ]]
			then
				echo "Collecting shelf slot:$slot and card:$card information"
				collectCardsInfo $slot $card
			fi

		else
			echo "Slot:$slot is not pingable "
		fi

	done
fi

}

function collectMRF() {

#
# Collecting MRF Application Info
#
	STATUS="Collecting xms info"
	if [ -d /var/log/xms ];
	then
	catiffile "/var/log/xms" 
	echo_success
	fi	

	STATUS="Collecting log messages"
	catiffile "/var/log/messages" 2>/dev/null
	echo_success

	STATUS="Collecting upgrade logs"
	if [[ -f /etc/xms/upgrade/upgrade.log ]]
	then
	catifile "/etc/xms/upgrade/upgrade.log"
	echo_success
	fi

	STATUS="Collecting dialogic logs"
	catiffile "/usr/dialogic/log"
	echo_success
	
	STATUS="Collecting xms information"
	catifproc "ps -leaf | grep xms"
	echo_success

	STATUS="Collecting MRF License file "
	catiffile "/etc/xms/license/active/XMS2x__host_tri_00505686c2d9.lic"
	echo_success

}

function collectCCPF(){

#
#Collect CCPF information
#

	STATUS="Collecting var logs"
	if [ -d /var/log ]
	then
	catiffile "/var/log"
	echo_success
	fi

	STATUS="Collecting  audit logs"
	catiffile "/var/log/audit"
	echo_success

	STATUS="Collecting Console logs"
	catiffile "/var/log/ConsoleKit"
	echo_success

	STATUS="Collecting operational logs"
	if [[ -f /opt/VZ_CCPS/logs/operational.log ]]
	then
		catiffile "/opt/VZ_CCPS/logs/operational.log"
	fi
	echo_success

	STATUS="Collecting functional logs"
	if [[ -f /opt/VZ_CCPS/logs/functional.log ]]
	then
		catiffile "/opt/VZ_CCPS/logs/functional.log"
	fi
	echo_success	

	dump_db

}


function collectProductInfo() {

	host=`hostname | awk -F. '{ print $1 }' `
	am_slot=`/usr/IMS/current/bin/readShm | grep AM | grep ACTIVE |  awk -F' ' '{ print $1 }' `
	am=` /usr/IMS/current/bin/readShm | grep AM | grep ACTIVE | awk -F' ' '{ print $6 }' `

	if [[ $host -eq $am_slot ]] && [[ $am -eq "AM" ]]
	then
		echo "collecting AM card info:"
		STATUS="Collecting readShm information"
       		catifexec "/usr/IMS/current/bin/readShm"
	
		collect_readShm
		dump_plt_db	
		full_db_dump
		dataCollection
		if [[ `dmidecode |grep -i prod |grep -i -c atca` -gt 0 ]] 2>/dev/null
		then

			shelf_id=`cat /etc/shelf.cfg | grep shelf |awk '{print $2}'`
			echo "Getting the RM Card mcli output"
			for card in `echo ${shelf_id}-17 ${shelf_id}-18`
			do
        		ping -w 5 $card
        		if [ $? -eq 0 ]; then
				run_mcli $card
        		else
                		echo "Card:$card is not pingable"
        		fi  
			done
	
	
			echo "Collecting znyx/SE card information "	
			#Getting znyx/SE card reports.
	
			for card in `echo ${shelf_id}-7 ${shelf_id}-8 ${shelf_id}-7-fabric ${shelf_id}-8-fabric`
			do
			ping -w 5 $card 
			if [ $? -eq 0 ]; then
				echo "Enter SE card password"
				read -s se_password
				echo "Please wait collecting SE cards info"
				$wd/znyx-logs.exp $card root $se_password >>$BLADE_DIR/"SE_$card.log"
			else
				echo "Card:$card is not pingable"
			fi
			done
	fi

else
	mrf_product=`ps -eaf | grep -c /usr/bin/xmserver `

	if [[ $mrf_product -gt 1 ]]
	then
		echo "Collecting MRF Product information"
		collectMRF
		dataCollection

	elif [[ -d /opt/VZ_CCPS ]]
	then
		echo "Collecting CCPF product information"
		collectCCPF
		dataCollection
	else
		echo "Collecting Hostname:$hostname information"
		dataCollection
	fi
fi
}

# Functions End

# Main

if [ $UID != 0 ]; then
  echo "You must be root to use this utility"
  exit 1
fi

#if ( ! mkdir $ROOT >& /dev/null ) ; then
#  echo "Cannot make temp dir"
#  exit 1
#fi

collectProductInfo

#
# Distro Files Report

distro_files="distro_info uname iptables ifconfig route lsmod ls-boot ls-tftpboot mount proc/partitions sysctl-p chkconfig installed-rpms"

echo "Generating the Distro Report"
for file in $distro_files
do
	echo "###################################################################################################" >> $MAINROOT/sysReport
	if [[ -f $DISTRO_DIR/$file ]]
	then
		cat $DISTRO_DIR/$file >> $MAINROOT/sysReport
		echo "###################################################################################################" >> $MAINROOT/sysReport
	fi
done	

#
# Comparing with the Standard setup's sysReport
#
#echo 
#echo "Comparing the sysreport withe standard sysReport"
#echo 

#if [[ -f $wd/sysReport.std ]]
#then
#	diff -y $wd/sysReport.std $MAINROOT/sysReport |more
#else
#	echo "To compare sysreport with the standard sysReport.Please copy the standard sysReport in the $wd directory "
#fi
#echo 
echo "Creating the sysReport TGZ"
#
ROOT=$TEMP/sysreport-$DATE
cd $TEMP
/bin/echo
HOSTNM=`/bin/hostname`
NAME=$HOSTNM.$DATE
/bin/rm -Rf $NAME
/bin/mv $ROOT $NAME
/bin/tar cvf $NAME.tar $NAME
if [ -x /usr/bin/bzip2 ]; then
  /usr/bin/bzip2 $NAME.tar
  SUFFIX="tar.bz2"
else 
  /bin/gzip -9 $NAME.tar
  SUFFIX="tar.gz"
fi

/bin/rm -Rf $NAME
echo
/bin/ls -l $TEMP/${NAME}.${SUFFIX}
echo
echo "Done"

