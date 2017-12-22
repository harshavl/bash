

card=$1
#slot=$2


log="sysreport.sh.log"
cur_dir=`/bin/pwd`
host=`/bin/hostname`

#temp=$cur_dir/$host
temp=/tmp/audit/$card

date=`/bin/date -u +%G%m%d%k%M%S | /usr/bin/tr -d ' '`
#root=$temp/sysreport-$date
distro_dir=$temp/DistroInfo
hw_dir=$temp/HardwareInfo
runtime_dir=$temp/RuntimeInfo
platform_dir=$temp/PlatformInfo
root=$temp
#/bin/mkdir -p $temp 
/bin/mkdir -p $root 

echo $root

#mkdir -p $distro_dir 
#mkdir -p $hw_dir 
#mkdir -p $runtime_dir
#mkdir -p $platform_dir
export PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
ver=`/bin/uname -r`
#root=$distro_dir
#root=$runtime_dir
#root=$platform_dir

catiffile() {


  if [ -d $1 ]; then
        if [ "$2" = "RM" -o "$2" = "MP" -o "$2" = "DM" -o "$2" = "MC" -o "$2" = "TC" -o "$2" = "SC" ];
        then
                cp_cmd="cp --parents"
        else
                cp_cmd="cp -x --parents"
        fi
    $cp_cmd -R $1 $root 2>>$root/$log
    find $root/$1 -type b -o -type c | xargs rm -f 2>/dev/null || :
   # echo -n $STATUS
   # echo_success
    return 1
  fi
  if [ -f $1 ]; then
    cp --parents $1 $ROOT 2>>$MAINROOT/$log
   # echo -n $STATUS
   # echo_success
    return 1
  fi

  return 0
}

collect_distro_info(){
        echo "=== Distro version ==="
        if ls /etc/TEST-release &>/dev/null ;
        then
                /bin/cat /etc/TEST-release
        fi
        echo
        echo "=== Exports version ==="
        if ls /usr/*/exports/exports-version &>/dev/null ;
        then
                /bin/cat /usr/*/exports/exports-version
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
                /bin/cat /usr/*/current/checksums >$root/application_checksums
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

catifproc() {

        echo $1 |grep "/proc"
        if [ $? -eq 0 ]; then
                fil=`find $1 -type f`
                for f in $fil
                do
                        mkdir -p $root/`dirname $f`
                        cat $f >$root/$f
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
    echo "$*" >> $root/`basename $1`
    $* >> $root/`basename $1` 2>&1
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


#if ( ! mkdir $root >& /dev/null ) ; then
#  echo "Cannot make temp dir"
#  exit 1
#fi

#
# Collecting Distro Info
#

function dataCollection() {

echo "Collecting distro info:"
collect_distro_info > $root/distro_info
echo_success

STATUS="Collecting information about chkconfig --list:"
catifexec "/sbin/chkconfig" "--list"

if [ -d /etc/rc.d ];
then
        STATUS="Collecting information about /etc/rc.d:"
        catiffile "/etc/rc.d"
        ls /etc/rc.d/rc*.d/ > $root/etc/rc.d/ls-output
fi

if [ -x /bin/rpm ] || [ -x /usr/bin/rpm ];
then
  echo "Collecting information about currently installed packages:"
  echo -n "This may take several minutes...."
  rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}\n" > $root/installed-rpms
  echo_success
fi

STATUS="Getting bootloader information:"
[ -e /boot ] && ls -alR /boot > $root/ls-boot 2>&1

if [ -d /boot/grub -a -f /boot/grub/grub.conf -a -f /boot/grub/device.map ]; then
  STATUS="Collecting information about the boot process (grub.conf):"
  catiffile "/boot/grub/grub.conf"
  STATUS="Collecting information about the boot process (grub.map):"
  catiffile "/boot/grub/device.map"
fi

STATUS="Collecting init configuration:"
catiffile "/etc/inittab"

STATUS="Gathering sysctl -p information:"
sysctl -p > $root/sysctl-p 2>&1

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
getpartinfo > $root/fdisk-l

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
if [[ $file_size -gt 512000 ]];
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

file_size=`du -hk /var/log/secure|awk '{print $1}'`
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
sysctl -a > $root/sysctl-a 2>&1

STATUS="Gathering sysctl information (/proc/sys):"
catifproc "/proc/sys" 

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
#getpciinfo > $root/lspci
#catiffile "/proc/bus" $1

STATUS="Gathering info on udev configuration:"
catiffile "/etc/udev/rules.d/"

STATUS="Checking mounted file systems (/proc/mounts)"
catifproc "/proc/mounts"

STATUS="Getting information about the hardware."
catifexec "/usr/sbin/dmidecode"
echo "Gathering information about hardware using ipmiutil"
getipmiutilinfo > $root/ipmiutilinfo

echo "Gathering information eth ports using ethtool"
getethtoolinfo > $root/ethtoolinfo

cat "/usr/*/exports/blade.cfg" >$root/blade_info 2>/dev/null
'ls -alR /tftpboot/' >$root/tftp_boot 2>/dev/null


}


dataCollection

cd /tmp/audit/$card
tar -czvf ../$card.tar.gz * 

#
# Distro Files Report

#distro_files="distro_info uname iptables ifconfig route lsmod ls-boot ls-tftpboot mount proc/partitions sysctl-p chkconfig installed-rpms"

#echo "Generating the Distro Report"
#for file in $distro_files
#do
#	touch $distro_dir/$file
#        echo "###################################################################################################" >> $MAINROOT/sysReport
#        if [[ -f $distro_dir/$file ]]
#        then
#                cat $distro_dir/$file >> $root/sysReport
#                echo "###################################################################################################" >> $MAINROOT/sysReport
#        fi
#done

