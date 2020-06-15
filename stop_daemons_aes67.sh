#!/bin/bash
# Stop all daemons

killall shaper_daemon
killall maap_daemon
killall mrpd
killall openavb_avdecc
rm -f /dev/shm/igb_sem

