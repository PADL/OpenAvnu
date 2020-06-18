#  AVB to AES67 Bridge

Luke Howard  
PADL Software Pty Ltd  
lukeh@padl.com  

## Abstract

The AVB to AES67 is a work in progress / proof of concept attempt at providing a transparent(-ish) bridge between the Audio Video Bridging and AES67 protocols.

**The bridge is not yet ready for production use.** In my testing, which admittedly involved proprietary endpoints in a fairly complex network configuration and PTP topology, I had difficulty synchronizing all the media clocks. I'm hoping this is simply a configuration or implementation issue, rather than a fundamental design one!

## Background

AVB and AES67 are abstractly similar protocols for transporting audio information over a network. They both involve sending (typically via multicast) timestamped audio packets at regular intervals, referenced to a common PTP clock. Very few endpoints support both protocols, so in a mixed environment a degree of interoperability can be desirable.

The principal difference between the two protocols is that AVB operates at Layer 2 (using the Audio Video Transport Protocol, or AVTP) and AES67 at Layer 3 (using RTP). AVB uses a PTP profile that also operates at Layer 2 (802.1AS), with specific constraints; AES67 uses PTPv2 over UDP. PTP time is distributed hierarchically with a single (but floating) grandmaster. AES67 derives the media clock directly from the PTP time, whereas AVB cross-stamps an explicit media clock stream with the PTP time.

Both AVTP and RTP packets can carry PCM audio (at least, 16-bit and 24-bit) at a variety of sampling rates. Audio encoding is similar; differences are in how the packets are referenced backed to the common clock. The 61883-6 format used by older AVB implementations has some unusual quirks, in that audio frames may cross packet boundaries, and that it is the frames rather than the packets that are timestamped (in other words, the AVTP timestamp may not refer to the first sample in the packet). The newer AVTP Audio Format (AAF) simplifies this and saves on bandwidth (by not using 32-bit sample words), but not all equipment supports it.

RTP timestamps packets with the media clock (which with the addition of an offset, maps directly to PTP time), whereas AVTP timestamps packet with the PTP time, from which the media clock can be recovered. Both packet formats use 32-bit wrapping timestamps, so the receiver needs the current time to set the most significant bits.

## Bridge

Having established this, it should be possible to bridge between the two protocols without re-clocking the audio as long as all endpoints share a common PTP clock domain (and media clock, in the case of AVB). The bridge only uses the PTP time for determining the media clock offset, otherwise it can operate quasi-asynchronously (of course, it cannot miss a deadline, and ideally it will send packets at a fixed interval). One current limitation is that AES67 must be the AVB media clock master: if the AVB is running the media clock, it would need to run at exactly the frequency (relative to the PTP clock), and use a statically configurable offset against the PTP time. 

The bridge requires a PTP boundary clock (BC) that can handle multiple profiles of PTP simultaneously: the Linux PTP project (`ptp4l`) is one such implementation. I extended it to support multiple PTP ports over a single interface; this allows a common physical hardware clock (PHC) to be used across both profiles of PTP. This is useful for testing. A practical deployment would likely use separate networks for AVB and AES67. A stable clock would be best implemented with a multi-port NIC with a single PHC; I'm not aware of any that also support multiple hardware queues and hardware timestamping. (An alternative is a bunch of Intel i210s that have their clock SDP pins tied together, with `ts2phc`.)

The AES to AES67 Bridge is implemented as an interface module for the OpenAvnu AVTP pipeline (originally the EAVB stack from Symphony Teleca Corporation, now Harman). Whilst it does require some configuration, it is flexible, easily to debug, and also implements the discovery components of AVB (AVDECC).

The test environment consisted of an Avid S3 (AVB endpoint) and Avid MTRX in AES67 mode (AES67 endpoint). The MTRX was configured as the clock master. A Mac Pro running Ubuntu 20.04 (with the low latency kernel) and an Intel i210 Ethernet card served as the bridge. The network switch was an Extreme Networks X460-48p in AVB mode. All devices were on the same network (notwithstanding AVB VLAN reservations).

## Configuration

The following configuration notes mostly apply to my test environment and will need to be adapted for different conditions.

### MTRX

The MTRX must have a Dante card installed and needs to be put into AES67 mode (which will require a reboot). Multicast AES67 streams need to be created explicitly; write down the stream name as you will need this to configure the bridge.

### S3

The S3 can be accessed via telnet and FTP using the username `root` with no password.

You will need to configure the S3 to allow it to slave from the AVB media clock. Edit the file `/opt/etc/avdecc_layout.xml` and add the following lines:

```
<sync_avb>
        <name>AVB</name>
</sync_avb>
```

after the `<sync_internal>` definition. You should also change the index of the active sync source from 0 to 1. (This can be done manually with `avbd -s 1`. It is also suggested to comment out the default presentation time offset of 2ms; it will default to 750us. (This is best done using FTP to copy the file to a local machine for editing. After replacing, remove `/opt/etc/avdecc_layout.out.xml` and reboot.)

You can validate PTP configuration with the following command:

```
# switchd2 -p
ST:SLAVE:MC:0x001dc1fffe106c16:LC:0x000496fffe51eaa5:SR:2:AD:-1ns:RMS:3.74166ns
priority1:250
P0:RR:4.35171e-06:PD:331ns
P6:RR:0:PD:0ns
CRR:4.35171e-06
```

The first line indicates the grandmaster clock ID and the closest master clock ID, respectively. The other values appear to indicate the phase difference, priority, path delay and frequency difference.

Sometimes I see an issue where it flaps between the `LISTENING` and `SLAVE` states. Restarting `ptp4l` seems to help fix this. You can turn up PTP debugging with `switchd2 -d PTP 9`. Logs are written to `/var/log/messages`.

The AVB configuration can also be validated by typing `cat /proc/avb`.

### Linux PTP

You will need the [lukeh/avb](https://github.com/PADL/linuxptp/tree/lukeh/avb) branch of Linux PTP as it supports the shared memory interface used by the Intel PTP daemon which it replaces. (A future version of the bridge should eliminate this dependency by communicating with `ptp4l` using the management interface, but this was the quickest approach for now.) It also supports running multiple PTP ports (with different protocols) on a single interface, which can be useful for testing.

It should be possible to run the boundary clock on a separate machine, but you will still need to run a local PTP daemon so that the grandmaster clock information is correctly reported over AVDECC and SDP for session setup.

A sample configuration file can be found in `configs/avb-BC.cfg`. Be sure to update it for your Ethernet interface name. It should already be configured appropriately for the AES67 and 802.1AS profiles but, some tweaking may be required. Before proceeding make sure that all endpoints are locked to the same PTP grandmaster. (This can be validated from the respective controller applications or sometimes the device themselves.)

### ExtremeXOS

Configuring ExtremeXOS for AVB is, in theory, as simple as installing the AVB license and typing `enable avb`. [This document](https://support.biamp.com/Tesira/AVB/Enabling_AVB_on_Extreme_Networks_switches) from biamp has more information. Interestingly I didn't find it necessary to disable IGMP snooping. With 802.1AS enabled on the switch, it won't function as a PTPv2 (UDP) boundary clock (it may function as a transparent clock but apparently this isn't guaranteed). But disabling peer-to-peer can actually be advantageous for audio as it reduces jitter.

If you are running AVB and AES67 over the same interface, you should reduce the AVB bandwidth to, say, 50% to leave sufficient bandwidth for RTP. On ExtremeXOS this can be done with the command `configure msrp ports all traffic-class A delta-bandwidth 50`.

### AES67 Bridge

Bridge configuration files live in `lib/avtp_pipeline/platform/Linux/intf_aes67/aes67_{listener,talker.ini}` and are installed into the `build/bin` directory. You will need to be comfortable editing configuration files and, most likely, running code under the debugger to use it.

It is important to configure the _packing factor_, or ratio of RTP to AVTP packets, correctly. With a default Class A AVTP transmission interval of 8000pps, the packet duration is 125us. RTP will typically use an interval of 1000pps (packet duration 1ms). Thus the packing factor `map_nv_packing_factor` should be set to 8 in both talker and listener, although the bridge will attempt to determine it itself. Having the RTP packet duration being shorter than the AVTP one (fractional packing factor) is not supported. A 1:1 ratio (packing factor of one) should in theory work, but it hasn't been tested. Dante devices in AES67 mode default to a packet time of 1ms which I don't believe is configurable, at least not without Dante Domain Manager.

#### Talker

The AVB talker _receives_ AES67, and sends AVB. Configuration options are described below.

##### intf_nv_audio_rate

The sampling frequency in samples per second, e.g. 48000. I have not tested other frequencies and it is likely that sample rates that do not have a base rate of this frequency will not work.

##### intf_nv_audio_bit_depth

The bit depth; only 16 and 24 are supported. This can also take the special value `am824` to select the RTP payload format for transparent transport of AES3 audio data defined by RAVENNA. The latter setting is only valid with the 61883-6 mapper.

##### intf_nv_audio_channels

The number of audio channels. The number of audio channels, bit depth and packet duration determine the packet size. In scaling the number of audio channels be sure not to exceed the UDP or Ethernet frame size.

##### intf_nv_aes67_ifname

The interface to use for AES67. This need not be the same as the AVB interface, but its PHC and the PHC of the AVB interface _must_ be synchronised to the PTP clock. It may be simplest to use the same interface as for AVB as they will share a PHC. 

##### intf_nv_aes67_session_name

The name of the AES67 session advertised by the Session Description Protocol (SDP). This will be something like `Avid-MTRX : 32`. Received SAP advertisements will be logged by `openavb_host`.

##### intf_nv_aes67_pto_usec

This is the presentation time offset in microseconds. Calculate it by adding the RTP and AVTP transit intervals. A PTO of 2500us with a transit time of 1250us is a good starting point.

#### Listener

The listener _receives_ AVB, and sends AES67. It is configured similarly to the talker. Additional options that are not present on the talker are detailed below:

##### intf_nv_aes67_multicast_address

The multicast IP address to which to send RTP packets.

##### intf_nv_aes67_hwtstamp

A boolean value which can be used to disable hardware timestamping on outgoing RTP packets. This must be disabled if the AES67 interface does not share a PHC with the AVB one, as the offset information from the latter is used to resolve a PTP time to a local one. (This can be fixed eventually by querying `ptp4l` using the management interface, which would allow retrieving the offsets for the correct clock port.)

##### intf_nv_aes67_socket_priority

The socket priority for outgoing RTP packets. Only useful if you have mapped priorities to traffic classes, and traffic classes to queues, using `tc qdisc`.

## Testing

The `run_daemons.sh` script in the top-level directory can be used to start the MRP, MAAP and traffic shaper daemons; however, comment out the gPTP daemon (`daemon_cl`) line as it is not used.

You can then start the `openavb_avdecc` and `openavb_host` daemons, with the following arguments:

```
# ./openavb_avdecc -I ens2 aes67_talker.ini,ifname=igb:ens2 aes67_listener.ini,ifname=igb:ens2 &
# chrt --fifo 99 ./openavb_host -I ens2 aes67_talker.ini,ifname=igb:ens2 aes67_listener.ini,ifname=igb:ens2 &
```

You will probably want to run at least `openavb_host` in the foreground for debugging (indeed, you will probably want to run it under the debugger, given the current state of the code).

You can then create the necessary patches on the AVB side using an AVDECC controller (on macOS, launch `avbutil` from the command line and type `controller`), and on the AES67 side using Dante Controller.
