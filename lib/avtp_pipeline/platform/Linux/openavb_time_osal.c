/*************************************************************************************************************
Copyright (c) 2012-2015, Symphony Teleca Corporation, a Harman International Industries, Incorporated company
Copyright (c) 2016-2017, Harman International Industries, Incorporated
All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS LISTED "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS LISTED BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
Attributions: The inih library portion of the source code is licensed from 
Brush Technology and Ben Hoyt - Copyright (c) 2009, Brush Technology and Copyright (c) 2009, Ben Hoyt. 
Complete license and copyright information can be found at 
https://github.com/benhoyt/inih/commit/74d2ca064fb293bc60a77b0bd068075b293cf175.
*************************************************************************************************************/

#include <inttypes.h>
#include <linux/ptp_clock.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "avb_gptp.h"

#include "openavb_platform.h"
#include "openavb_time_osal.h"
#include "openavb_trace.h"

#define	AVB_LOG_COMPONENT	"osalTime"
#include "openavb_pub.h"
#include "openavb_log.h"

static pthread_mutex_t gOSALTimeInitMutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK()         pthread_mutex_lock(&gOSALTimeInitMutex)
#define UNLOCK()       pthread_mutex_unlock(&gOSALTimeInitMutex)

#ifdef PTP_CLOCK_DIRECT
/*
 * Experimental support to get the wall time directly from the PTP clock
 */
#ifndef CLOCKFD
#define CLOCKFD                 3
#endif
#ifndef FD_TO_CLOCKID
#define FD_TO_CLOCKID(fd)       ((~(clockid_t) (fd) << 3) | CLOCKFD)
#endif
#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

static int gPtpClockFd = -1;
static clockid_t gPtpClockId = CLOCK_INVALID;

static bool gPtpClockIdInit(const char *ifname)
{
	int fd;
	char phcName[16];
	struct ethtool_ts_info tsInfo;
	struct ifreq ifr;

	memset(&tsInfo, 0, sizeof(tsInfo));
	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0)
		return FALSE;

	tsInfo.cmd = ETHTOOL_GET_TS_INFO;

	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
	ifr.ifr_data = (caddr_t)&tsInfo;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
		close(fd);
		return FALSE;
	}

	if (tsInfo.so_timestamping) {
		struct timespec phcTime;

		snprintf(phcName, sizeof(phcName), "/dev/ptp%d", tsInfo.phc_index);
		gPtpClockFd = open(phcName, O_RDONLY);
		if (gPtpClockFd >= 0) {
			if (clock_gettime(FD_TO_CLOCKID(gPtpClockFd), &phcTime) == 0) {
				gPtpClockId = FD_TO_CLOCKID(gPtpClockFd);
			} else {
				AVB_LOGF_WARNING("Failed to get PTP time from clock %d: %s", gPtpClockId, strerror(errno));
			}
		}
	}

	close(fd);

	return gPtpClockId != CLOCK_INVALID;
}
#endif /* PTP_CLOCK_DIRECT */

static bool bInitialized = FALSE;
static int gPtpShmFd = -1;
static char *gPtpMmap = NULL;
gPtpTimeData gPtpTD;

static bool x_timeInit(const char *ifname) {
	AVB_TRACE_ENTRY(AVB_TRACE_TIME);

#ifdef PTP_CLOCK_DIRECT
	if (!gPtpClockIdInit(ifname)) {
		AVB_LOG_ERROR("GPTP PHC init failed");
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return FALSE;
	}
	AVB_LOGF_INFO("Local PTP clock ID = %d", gPtpClockId);
#endif

	if (gptpinit(&gPtpShmFd, &gPtpMmap) < 0) {
		AVB_LOG_ERROR("GPTP init failed");
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return FALSE;
	}

	if (gptpgetdata(gPtpMmap, &gPtpTD) < 0) {
		AVB_LOG_ERROR("GPTP data fetch failed");
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return FALSE;
	}

#ifdef PTP_CLOCK_DIRECT
	AVB_LOGF_INFO("local_time = %" PRIu64, gPtpTD.local_time);
	AVB_LOGF_INFO("ml_phoffset = %" PRId64, gPtpTD.ml_phoffset);
	AVB_LOGF_INFO("ml_freqffset = %Lf", gPtpTD.ml_freqoffset);
#else
	AVB_LOGF_INFO("local_time = %" PRIu64, gPtpTD.local_time);
	AVB_LOGF_INFO("ml_phoffset = %" PRId64 ", ls_phoffset = %" PRId64, gPtpTD.ml_phoffset, gPtpTD.ls_phoffset);
	AVB_LOGF_INFO("ml_freqffset = %Lf, ls_freqoffset = %Lf", gPtpTD.ml_freqoffset, gPtpTD.ls_freqoffset);
#endif

	AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return TRUE;
}

static bool x_getPTPTime(U64 *timeNsec) {
	AVB_TRACE_ENTRY(AVB_TRACE_TIME);

	if (gptpgetdata(gPtpMmap, &gPtpTD) < 0) {
		AVB_LOG_ERROR("GPTP data fetch failed");
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return FALSE;
	}

	uint64_t now_local = 0;
	uint64_t update_8021as;
	int64_t delta_8021as;
	int64_t delta_local;
#ifdef PTP_CLOCK_DIRECT
	struct timespec getTime;

	if (clock_gettime(gPtpClockId, &getTime) == 0)
#else
	if (gptplocaltime(&gPtpTD, &now_local))
#endif
	{
#ifdef PTP_CLOCK_DIRECT
		now_local = (((U64)getTime.tv_sec * (U64)NANOSECONDS_PER_SECOND) + (U64)getTime.tv_nsec);
#endif
		update_8021as = gPtpTD.local_time - gPtpTD.ml_phoffset;
		delta_local = now_local - gPtpTD.local_time;
		delta_8021as = gPtpTD.ml_freqoffset * delta_local;
		*timeNsec = update_8021as + delta_8021as;

		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return TRUE;
	}

	AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return FALSE;
}

bool osalAVBTimeInit(const char *ifname) {
	AVB_TRACE_ENTRY(AVB_TRACE_TIME);

	LOCK();
	if (!bInitialized) {
		if (x_timeInit(ifname))
		    bInitialized = TRUE;
	}
	UNLOCK();

        AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return bInitialized;
}

bool osalAVBTimeClose(void) {
	AVB_TRACE_ENTRY(AVB_TRACE_TIME);

#ifdef PTP_CLOCK_DIRECT
	LOCK();
	if (gPtpClockFd != -1) {
		close(gPtpClockFd);
		gPtpClockFd = -1;
		gPtpClockId = CLOCK_INVALID;
	}
	UNLOCK();
#endif
	gptpdeinit(&gPtpShmFd, &gPtpMmap);

	AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return TRUE;
}

bool osalClockGettime(openavb_clockId_t openavbClockId, struct timespec *getTime)
{
	clockid_t clockId = CLOCK_MONOTONIC;

	AVB_TRACE_ENTRY(AVB_TRACE_TIME);
	switch (openavbClockId) {
	case OPENAVB_CLOCK_REALTIME:
		clockId = CLOCK_REALTIME;
		break;
	case OPENAVB_CLOCK_MONOTONIC:
		clockId = CLOCK_MONOTONIC;
		break;
	case OPENAVB_TIMER_CLOCK:
		clockId = CLOCK_MONOTONIC;
		break;
	case OPENAVB_CLOCK_WALLTIME: {
		U64 timeNsec;
		if (!x_getPTPTime(&timeNsec)) {
			AVB_TRACE_EXIT(AVB_TRACE_TIME);
			return FALSE;
		}
		getTime->tv_sec = timeNsec / NANOSECONDS_PER_SECOND;
		getTime->tv_nsec = timeNsec % NANOSECONDS_PER_SECOND;
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return TRUE;
	}
	default:
		clockId = (clockid_t)openavbClockId;
		break;
	}

	if (!clock_gettime(clockId, getTime)) {
	    AVB_TRACE_EXIT(AVB_TRACE_TIME);
	    return TRUE;
	}

	AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return FALSE;
}

bool osalClockGettime64(openavb_clockId_t openavbClockId, U64 *timeNsec)
{
	clockid_t clockId = CLOCK_MONOTONIC;

	AVB_TRACE_ENTRY(AVB_TRACE_TIME);

	switch (openavbClockId) {
	case OPENAVB_CLOCK_REALTIME:
		clockId = CLOCK_REALTIME;
		break;
	case OPENAVB_CLOCK_MONOTONIC:
		clockId = CLOCK_MONOTONIC;
		break;
	case OPENAVB_TIMER_CLOCK:
		clockId = CLOCK_MONOTONIC;
		break;
	case OPENAVB_CLOCK_WALLTIME:
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return x_getPTPTime(timeNsec);
	default:
		clockId = (clockid_t)openavbClockId;
		break;
	}
	struct timespec getTime;
	if (!clock_gettime(clockId, &getTime)) {
		*timeNsec = ((U64)getTime.tv_sec * (U64)NANOSECONDS_PER_SECOND) + (U64)getTime.tv_nsec;
		AVB_TRACE_EXIT(AVB_TRACE_TIME);
		return TRUE;
	}
	AVB_TRACE_EXIT(AVB_TRACE_TIME);
	return FALSE;
}

