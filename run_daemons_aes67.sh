#!/bin/bash
# Start all daemons

if [ "$1" == "-h" ]; then
        echo "Usage: $0 <network interface>"
        echo "   eg: $0 eth1"
        echo ""
        echo "If you are using IGB, call \"sudo ./run_igb.sh\" before running this script."
        echo ""
        exit
fi

#nic=$1
nic=ens2

if [ "$nic" == "" ]; then
        echo "Please enter network interface name as parameter. For example:"
        echo "sudo $0 eth1"
        echo ""
        echo "If you are using IGB, call \"sudo ./run_igb.sh\" before running this script."
        echo ""
        exit -1
fi

echo "Starting daemons on "$nic
daemons/mrpd/mrpd -mvs -i $nic &
daemons/maap/linux/build/maap_daemon -i $nic -d /dev/null
daemons/shaper/shaper_daemon -d &

adir=lib/avtp_pipeline/build/bin
(cd $adir; ./openavb_avdecc -I $nic aes67_talker.ini,ifname=igb:$nic aes67_listener.ini,ifname=igb:$nic &)
