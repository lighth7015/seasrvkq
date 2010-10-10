#!/bin/sh
#
# A script to send message to SEA Sender from FreeBSD command line.
# (c) Vadim Goncharov <vadim_nuclight@mail.ru>, 2010.
#
# Covered by BSD license.   

# default values
id=0
user=`whoami`
comp=`hostname -s`
server=kernblitz.nuclight.avtf.net
pflags=0

onebyte()
{
	printf "\\\\%o" $1
}

htons()
{
	lo=$(($1 % 256))
	hi=$(($1 / 256))
	printf "\\\\%o\\\\%o" $hi $lo
}

htonl()
{
	lo=$(($1 % 65536))
	hi=$(($1 / 65536))
	htons $hi
	htons $lo
}

hton3()
{
	lo=$(($1 % 65536))
	hi=$(($1 / 65536))
	onebyte $hi
	htons $lo
}

getflen()
{
	if [ -f "$1" -a -r "$1" ]; then
		len=`/usr/bin/stat -f %z $1`
		if [ $? -eq 0 ]; then
			echo $len
			return 0
		fi
	fi
	echo "Can't get size of file $1!"
	exit 1
}

usage()
{
	cat << EOH
Usage: $0 [-s srv] [-d id] [-u user] [-c comp] -m file [-r file] [-b file]

   -s	Server address to connect to (default is $server)
   -d	Destination user ID, defaults to 0 (entire group)
   -u	Our (sender) user name, defaults to your Unix login
   -c	Our computer name, defaults to this machine hostname
   -m	File name with plain text of message to send
   -r	File name of RTF-formatted version of message to send
   -b	Any (binary) file attached to message

All files must be regular to be able to know file size. Formatted versions
are understood by clients with protocol version 101 and later (BlastCore 0.4
and later). The total limit is 64 Kb for version 101 and older clients
(BlastCore 0.4 and older), and 16 Mb for protocol version 102 and later.
EOH
}

args=`getopt b:c:d:m:p:r:s:h $*`
if [ $? -ne 0 ]; then
	usage
	exit 2
fi
set -- $args
for i; do
	case "$i" in
		-d)
			id=$2; shift;
			if [ -z "$id" -o "$id" -lt 0 -o "$id" -gt 65535 ]; then
				echo "Invalid ID, must be between 0 and 65535"
				exit 1
			fi
			shift;;
		-p)
			pflags=$2; shift;
			if [ -z "$pflags" -o "$pflags" -lt 0 -o "$pflags" -gt 255 ]; then
				echo "Invalid prio/flags, must be between 0 and 255"
				exit 1
			fi
			shift;;
		-u)
			user=$2; shift;
			shift;;
		-c)
			comp=$2; shift;
			shift;;
		-m)
			msgfile=$2; shift;
			msgfilelen=`getflen $msgfile`
			if [ "$msgfilelen" -gt 65535 ]; then
				echo "Message file too big!"
				exit 1
			fi
			shift;;
		-r)
			rtffile=$2; shift;
			rtffilelen=`getflen $rtffile`
			shift;;
		-b)
			binfile=$2; shift;
			binfilelen=`getflen $binfile`
			fname=`basename "$binfile"`
			fnamelen=`expr -- "$fname" : ".*"`
			ftime=`/usr/bin/stat -f %m $binfile`
			shift;;
		-s)
			server=$2; shift;
			shift;;
		-h)
			usage
			exit 2;;
	esac
done

if [ -z "$msgfile" ]; then
	echo "File with message text required. For help run $0 -h"
	exit 2
fi

# get string lengths
userlen=`expr -- "$user" : ".*"`
complen=`expr -- "$comp" : ".*"`

totalcmdlen=$(($msgfilelen + 7))	# with header
[ -n "$rtffile" ] && totalcmdlen=$(($totalcmdlen + 1 + $rtffilelen))
if [ -n "$binfile" ]; then
	# \0 + "FILE" + 4 bytes UnixTime + 1 byte name len + name + data
	totalcmdlen=$(($totalcmdlen + 1 + 4 + 4 + 1 + $fnamelen + $binfilelen))
fi

# protocol limit...
if [ $totalcmdlen -gt 16777215 ]; then	# 2^24 -1
	echo "Total size of message exceeds 16 Mb!"
	exit 1
fi

# protocol version 102 - what will see older clients?
if [ $totalcmdlen -le 65535 ]; then
	# we fit to 64K, behave as old client
	msglen=$(($totalcmdlen - 7))
else
	# first try to send both plain and RTF
	msglen=$(($msgfilelen + 1 + $rtffilelen))
	if [ $msglen -gt 65535 ]; then
		msglen=$msgfilelen
	fi
fi

# begin output to server
{
	# first we login as our user and comp...
	# e.g '\0\0\5' '\1' '\1' 'a' '\1' 'b' for 'a[b]'
	cmdlen=$((1 + 1 + $userlen + 1 + $complen))
	printf "`hton3 $cmdlen`\1`onebyte $userlen`$user`onebyte $complen`$comp"
	sleep 1

	# now we need to enable protocol version 102, if message is long enough
	if [ $totalcmdlen -gt 65535 ]; then
		# send cmd #4: len '\4' fak room infolen info versionbyte
		cmdlen=$((1 + 1 + 5 + 1 + 0 + 1))
		# 5 byte room, space-padded, zero info
		printf "`hton3 $cmdlen`\4\001"
		printf "666  \0\146"
		# join also the printers group
		printf "\0\0\1\17"
		sleep 1
	fi

	# now actually send msg, headers first
	printf "`hton3 $totalcmdlen`\2`htons $id``onebyte $pflags`\0`htons $msglen`"
	cat $msgfile

	# add RTF part, if present
	if [ -n "$rtffile" ]; then
		printf '\0'
		cat $rtffile
	fi

	# send attached file, if present
	if [ -n "$binfile" ]; then
		# \0 + "FILE" + 4 bytes UnixTime + 1 byte name len + name + data
		printf "\0FILE`htonl $ftime``onebyte $fnamelen`$fname"
		cat $binfile
	fi
	
	# all done, final wait to settle, to receive from server, etc.
	sleep 15
}| nc $server 8732 | hd
