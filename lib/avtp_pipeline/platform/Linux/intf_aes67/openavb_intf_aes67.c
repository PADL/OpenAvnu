/*
 * Copyright (c) 2020, PADL Software Pty Ltd
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS LISTED "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS LISTED BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>

#include "openavb_types_pub.h"
#include "openavb_trace_pub.h"
#include "openavb_mediaq_pub.h"
#include "openavb_map_uncmp_audio_pub.h"
#include "openavb_map_aaf_audio_pub.h"
#include "openavb_intf_pub.h"
#include "openavb_list.h"
#include "openavb_grandmaster_osal_pub.h"
#include "avb_gptp.h"

#define AVB_LOG_LEVEL AVB_LOG_LEVEL_DEBUG
#define AVB_LOG_COMPONENT    "AES67 Interface"

#include "mast.h"
#include "openavb_log_pub.h"

#ifndef CLOCKFD
#define CLOCKFD			3
#endif
#ifndef FD_TO_CLOCKID
#define FD_TO_CLOCKID(fd)	((~(clockid_t) (fd) << 3) | CLOCKFD)
#endif
#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define SDP_CACHE_DIRECTORY		    "/var/run/aes67"
#define SAP_ANNOUNCER_THREAD_INTERVAL_SEC   30
#define RTP_DSCP_VALUE			    34
#define RTP_LOG_INTERVAL		    4000

/* analyze incoming RTP packet timestamps */
//#define RTP_DEBUG_TS			    1

extern gPtpTimeData gPtpTD;

static openavb_list_t gSapRemoteAdvertisements;
static pthread_mutex_t gSapRemoteAdvertisementsLock = PTHREAD_MUTEX_INITIALIZER;

static openavb_list_t gSapLocalAdvertisements;
static pthread_mutex_t gSapLocalAdvertisementsLock = PTHREAD_MUTEX_INITIALIZER;

static pthread_t gSapMonitorThread;
static pthread_t gSapAnnouncerThread;
static pthread_once_t gAES67InitializeOnce = PTHREAD_ONCE_INIT;

static char *gAES67SapInterfaceName;
static pthread_mutex_t gAES67SapInterfaceLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gAES67SapInterfaceCondition = PTHREAD_COND_INITIALIZER;

static size_t gAES67InstanceCount;

typedef struct {
    /* configuration items */
    char *interfaceName;
    char *multicastAddress;
    char *sessionName;
    bool hwtsEnabled;
    int socketPriority;
    int dscpValue;
    double packetTimeUSec;
    avb_audio_rate_t audioRate;
    avb_audio_bit_depth_t audioBitDepth;
    avb_audio_channels_t audioChannels;

    /* pointer to current SDP session description */
    openavb_list_node_t sessionDescription;

    /* clocking */
    char ptpGmId[24];
    uint8_t ptpDomain;
    int ptpClockFd;
    clockid_t ptpClockId;
    uint64_t mediaClock;

    /* current RTP state */
    mast_rtp_sequence_state_t sequenceState;
    uint32_t packingFactor;
    mast_socket_t rtpSocket;

    /* statistics, other stuff */
    avb_role_t avbRole;
    unsigned int randomSeed;
    uint64_t invocationCount;
    uint64_t rtpPacketCount;
    uint32_t ssrcIdentifier;

    uint64_t lastPacketTime; /* reused by RTP_DEBUG_TS */
    double audioRateRecovered;

#ifdef RTP_DEBUG_TS
    double rtpPacketRate;
#endif
} aes67_pvt_data_t;

typedef enum {
    AES67_SDP_CACHE_LOCAL,
    AES67_SDP_CACHE_REMOTE
} aes67_sdp_cache_t;

static size_t
rtpPacketFrames(aes67_pvt_data_t *pPvtData);

static bool
setSocketHwTs(mast_socket_t *sock, bool tx);

static void
waitUntilInterfaceConfigured(void)
{
    pthread_mutex_lock(&gAES67SapInterfaceLock);
    while (gAES67SapInterfaceName == NULL) {
	pthread_cond_wait(&gAES67SapInterfaceCondition, &gAES67SapInterfaceLock);
    }
    pthread_mutex_unlock(&gAES67SapInterfaceLock);
}

static void
sockaddrStorageToString(struct sockaddr_storage *ss, char *buffer, size_t length)
{
    if (ss->ss_family == AF_INET)
	inet_ntop(AF_INET, &(((struct sockaddr_in *)ss)->sin_addr), buffer, length);
    else if (ss->ss_family == AF_INET6)
	inet_ntop(AF_INET6,  &(((struct sockaddr_in6 *)ss)->sin6_addr), buffer, length);
    else
	snprintf(buffer, length, "<unknown-address-family>");
}

static size_t
sockaddrStorageLength(struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET)
	return sizeof(struct sockaddr_in);
    else if (ss->ss_family == AF_INET6)
	return sizeof(struct sockaddr_in6);
    else
	return 0;
}

static openavb_list_t
sessionDescriptionList(aes67_sdp_cache_t sap)
{
    return sap == AES67_SDP_CACHE_LOCAL ? gSapLocalAdvertisements : gSapRemoteAdvertisements;
}

static mast_sdp_t *
sessionDescriptionFromNode(openavb_list_node_t node)
{
    assert(node != NULL);

    return (mast_sdp_t *)((int64_t *)openavbListData(node) + 1);
}

static void
sessionDescriptionNodeMarkInvalid(openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);

    while (!__sync_val_compare_and_swap(&sdp->payload_type, sdp->payload_type, 0))
	;
}

static bool
sessionDescriptionIsValid(openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);

    return !!sdp->payload_type;
}

static void
sessionDescriptionNodeRetain(aes67_sdp_cache_t sdpCache, openavb_list_node_t node)
{
    int64_t *count = (int64_t *)openavbListData(node);
    __sync_add_and_fetch(count, 1);
}

static void
sessionDescriptionNodeRelease(aes67_sdp_cache_t sdpCache, openavb_list_node_t *pNode)
{
    openavb_list_node_t node = *pNode;
    openavb_list_t list = sessionDescriptionList(sdpCache);
    int64_t *count;

    if (node == NULL)
	return;

    count = (int64_t *)openavbListData(node);

    if (__sync_sub_and_fetch(count, 1) == 0) {
	mast_sdp_t *sdp = sessionDescriptionFromNode(node);

	AVB_LOGF_DEBUG("Purging session %s from %s cache", sdp->session_id,
		       sdpCache == AES67_SDP_CACHE_LOCAL ? "local" : "remote");
	openavbListDelete(list, node);
    }

    *pNode = NULL;
}

static int
sessionDescriptionListLock(aes67_sdp_cache_t sdpCache)
{
    pthread_mutex_t *lock = (sdpCache == AES67_SDP_CACHE_LOCAL) ?
	&gSapLocalAdvertisementsLock : &gSapRemoteAdvertisementsLock;

    return pthread_mutex_lock(lock);
}

static int
sessionDescriptionListUnlock(aes67_sdp_cache_t sdpCache)
{
    pthread_mutex_t *lock = (sdpCache == AES67_SDP_CACHE_LOCAL) ?
	&gSapLocalAdvertisementsLock : &gSapRemoteAdvertisementsLock;

    return pthread_mutex_unlock(lock);
}

static const char *
sessionDescriptionPersistentCacheDir(aes67_sdp_cache_t sdpCache)
{
    return sdpCache == AES67_SDP_CACHE_LOCAL ?
	SDP_CACHE_DIRECTORY "/local" : SDP_CACHE_DIRECTORY "/remote";
}

static void
sessionDescriptionPath(aes67_sdp_cache_t sdpCache, char *buffer, size_t bufsiz, openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);

    snprintf(buffer, bufsiz, "%s/%s.sdp",
	     sessionDescriptionPersistentCacheDir(sdpCache), sdp->session_id);
}

static bool
sessionDescriptionNodeUnpersist(aes67_sdp_cache_t sdpCache, openavb_list_node_t node)
{
    char path[PATH_MAX];

    sessionDescriptionPath(sdpCache, path, sizeof(path), node);

    return unlink(path) == 0;
}

static bool
sessionDescriptionNodePersist(aes67_sdp_cache_t sdpCache, openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);
    FILE *fp;
    char path[PATH_MAX];

    sessionDescriptionPath(sdpCache, path, sizeof(path), node);
    fp = fopen(path, "w");
    if (fp == NULL) {
	AVB_LOGF_INFO("Failed to open %s for writing: %s", path, strerror(errno));
	return false;
    }

    if (fwrite(sdp, 1, sizeof(*sdp), fp) != sizeof(*sdp)) {
	AVB_LOGF_INFO("Failed to write to %s: %s", path, strerror(errno));
	fclose(fp);
	return false;
    }

    fclose(fp);

    return true;
}

static openavb_list_node_t
sessionDescriptionNodeNew(aes67_sdp_cache_t sdpCache)
{
    openavb_list_t list = sessionDescriptionList(sdpCache);
    openavb_list_node_t node;

    node = openavbListNew(list, sizeof(int64_t) + sizeof(mast_sdp_t));
    sessionDescriptionNodeRetain(sdpCache, node); /* list RC */
    sessionDescriptionNodeRetain(sdpCache, node); /* caller RC */

    return node;
}

/* returns a node that must be released, caller must acquire lock */
static openavb_list_node_t
findSessionDescriptionNode(aes67_sdp_cache_t sdpCache,
			   const char *sessionName)
{
    openavb_list_t list = sessionDescriptionList(sdpCache);
    openavb_list_node_t node;

    if (sessionName == NULL)
	return NULL;

    for (node = openavbListIterFirst(list);
	 node != NULL;
	 node = openavbListIterNext(list)) {
	mast_sdp_t *sdp;

	if (!sessionDescriptionIsValid(node))
	    continue; /* skip invalid */

	sdp = sessionDescriptionFromNode(node);

	if (sessionName && strcmp(sdp->session_name, sessionName) == 0)
	    break;
    }

    if (node)
	sessionDescriptionNodeRetain(sdpCache, node);

    return node;
}

void
dumpSessionDescriptions(aes67_sdp_cache_t sdpCache)
{
    openavb_list_t list = sessionDescriptionList(sdpCache);
    openavb_list_node_t node;

    for (node = openavbListIterFirst(list);
	 node != NULL;
	 node = openavbListIterNext(list)) {
	mast_sdp_t *sdp;

	sessionDescriptionNodeRetain(sdpCache, node);
	sdp = sessionDescriptionFromNode(node);
	AVB_LOGF_DEBUG("SDP %s cache: %s - %s/%s [%s/%d/%d]",
		       sdpCache == AES67_SDP_CACHE_LOCAL ? "local" : "remote",
		       sdp->session_name,
		       sdp->address, sdp->port,
		       mast_encoding_name(sdp->encoding), sdp->sample_rate, sdp->channel_count);
	sessionDescriptionNodeRelease(sdpCache, &node);
    }
}

static void
sessionDescriptionPersistentCacheMkdirs(aes67_sdp_cache_t sdpCache)
{
    (void) mkdir(SDP_CACHE_DIRECTORY, 0755);
    (void) mkdir(sessionDescriptionPersistentCacheDir(sdpCache), 0755);
}

static void
sessionDescriptionCachePrime(aes67_sdp_cache_t sdpCache)
{
    DIR *dirp;
    struct dirent *dp;
    const char *cacheDir = sessionDescriptionPersistentCacheDir(sdpCache);

    dirp = opendir(cacheDir);
    if (dirp == NULL) {
	int err = errno;

	AVB_LOGF_INFO("Failed to open directory %s: %s", cacheDir, strerror(err));
	if (err == ENOENT)
	    sessionDescriptionPersistentCacheMkdirs(sdpCache);
	return;
    }

    sessionDescriptionListLock(sdpCache); // {

    while ((dp = readdir(dirp)) != NULL) {
	FILE *fp;
	mast_sdp_t sdp;
	openavb_list_node_t node;
	char path[PATH_MAX];
	size_t len = strlen(dp->d_name);
	struct stat sb;

	if (len < 4 || strcmp(&dp->d_name[len - 4], ".sdp") != 0)
	    continue;

	snprintf(path, sizeof(path), "%s/%s", cacheDir, dp->d_name);

	if (stat(path, &sb) != 0 || sb.st_size != sizeof(sdp))
	    continue;

	fp = fopen(path, "r");
	if (fp == NULL) {
	    AVB_LOGF_INFO("Failed to open %s for reading: %s", path, strerror(errno));
	    continue;
	}

	if (fread(&sdp, 1, sizeof(sdp), fp) != sizeof(sdp)) {
	    AVB_LOGF_INFO("Failed to read from %s: %s", path, strerror(errno));
	    fclose(fp);
	    continue;
	}

	node = sessionDescriptionNodeNew(sdpCache);
	memcpy(sessionDescriptionFromNode(node), &sdp, sizeof(sdp));
	AVB_LOGF_DEBUG("Restored %s AES67 session ID %s",
		       sdpCache == AES67_SDP_CACHE_LOCAL ? "local" : "remote", sdp.session_id);
	sessionDescriptionNodeRelease(AES67_SDP_CACHE_LOCAL, &node);
	fclose(fp);
    }

    sessionDescriptionListUnlock(sdpCache); // }

    closedir(dirp);
}

static bool
sessionDescriptionIsLocal(mast_socket_t *sock, mast_sdp_t *sdp)
{
    char srcAddress[256];

    sockaddrStorageToString(&sock->src_addr, srcAddress, sizeof(srcAddress));

    return strcmp(srcAddress, sdp->session_origin) == 0;
}

static void
receiveSapPacket(mast_socket_t *sock)
{
    int res;
    ssize_t packetLen;
    uint8_t packet[2048];
    mast_sap_t sap;
    mast_sdp_t sdp;
    openavb_list_node_t node;

    packetLen = mast_socket_recv(sock, packet, sizeof(packet));
    if (packetLen < 0)
	return;

    res = mast_sap_parse(packet, packetLen, &sap);
    if (res == 0)
	res = mast_sap_parse(packet, packetLen, &sap);
    if (res == 0)
	res = mast_sdp_parse_string(sap.sdp, &sdp);
    /* ignore reflected packets because we joined our own multicast group */
    if (res != 0 || sessionDescriptionIsLocal(sock, &sdp))
	return;

    AVB_LOGF_INFO(
        "SAP %s: %s <%s> - %s/%s [%s/%d/%d]",
        sap.message_type == MAST_SAP_MESSAGE_ANNOUNCE ? "ANNOUNCE" : "DELETE",
	sdp.session_name, sdp.session_id,
        sdp.address, sdp.port,
        mast_encoding_name(sdp.encoding), sdp.sample_rate, sdp.channel_count);

    sessionDescriptionListLock(AES67_SDP_CACHE_REMOTE); // {

    node = findSessionDescriptionNode(AES67_SDP_CACHE_REMOTE, sdp.session_name);
    if (sap.message_type == MAST_SAP_MESSAGE_ANNOUNCE) {
	bool bSessionDidChange = true;

	if (node) {
	    mast_sdp_t *sdp2 = sessionDescriptionFromNode(node);

	    /*
	     * Only payload_type can be updated without acquiring the lock, so for remote
	     * announcements we mark the node as invalid and create a new one so the fast
	     * path in the RTP receiver doesn't need to acquire the lock.
	     *
	     * The RTP sender only updates its session description before becoming an AVB
	     * listener, so it can acquire the lock and thus work directly with the node.
	     */
	    if (memcmp(&sdp, sdp2, sizeof(*sdp2)) != 0) {
		AVB_LOGF_DEBUG("Updating SAP session %s <%s>", sdp2->session_name, sdp2->session_id);
		sessionDescriptionNodeMarkInvalid(node);
	    } else
		bSessionDidChange = false;
	}

	if (bSessionDidChange) {
	    openavb_list_node_t node2;

	    node2 = sessionDescriptionNodeNew(AES67_SDP_CACHE_REMOTE);
	    memcpy(sessionDescriptionFromNode(node2), &sdp, sizeof(sdp));
	    AVB_LOGF_DEBUG("Caching SAP session %s <%s>", sdp.session_name, sdp.session_id);
	    sessionDescriptionNodePersist(AES67_SDP_CACHE_REMOTE, node2);
	    sessionDescriptionNodeRelease(AES67_SDP_CACHE_REMOTE, &node2);
	}
    } else if (sap.message_type == MAST_SAP_MESSAGE_DELETE) {
	AVB_LOGF_DEBUG("Removing SAP session %s <%s>", sdp.session_name, sdp.session_id);
	sessionDescriptionNodeUnpersist(AES67_SDP_CACHE_REMOTE, node);
	sessionDescriptionNodeMarkInvalid(node);
    }

    if (node)
	sessionDescriptionNodeRelease(AES67_SDP_CACHE_REMOTE, &node);

    sessionDescriptionListUnlock(AES67_SDP_CACHE_REMOTE); // }
}

static void *
openavbIntfAES67SapMonitorThread(void *unused)
{
    int res;
    mast_socket_t sock;

    waitUntilInterfaceConfigured();

    sock.fd = -1;

    AVB_LOG_INFO("SAP monitor thread starting");

    sessionDescriptionCachePrime(AES67_SDP_CACHE_REMOTE);

    do {
	if (sock.fd == -1) {
	    res = mast_socket_open_recv(&sock, MAST_SAP_ADDRESS_LOCAL,
					MAST_SAP_PORT, gAES67SapInterfaceName);
	    if (res) {
		AVB_LOGF_WARNING("Failed to open SAP monitor socket: %s; sleeping", strerror(errno));
		sleep(SAP_ANNOUNCER_THREAD_INTERVAL_SEC);
		continue;
	    }
	}
	receiveSapPacket(&sock);
    } while (gAES67InstanceCount);

    mast_socket_close(&sock);

    return NULL;
}

static bool
sdpToString(mast_sdp_t *sdp, char *buffer, size_t buflen)
{
    int res;
    int ip6Origin = strchr(sdp->session_origin, ':') != NULL;
    int ip6Address = strchr(sdp->address, ':') != NULL;
    char domainSuffix[64] = "";

    if (sdp->ptp_domain != 0)
	snprintf(domainSuffix, sizeof(domainSuffix), ":%u", sdp->ptp_domain);

    if (sdp->payload_type == 0) {
	res = snprintf(buffer, buflen,
		       "v=0\r\n"
		       "o=- %s %s IN %s %s\r\n",
		       sdp->session_id, sdp->session_id, ip6Origin ? "IP6" : "IP4", sdp->session_origin);
    } else {
	res = snprintf(buffer, buflen,
		       "v=0\r\n"
		       "o=- %s %s IN %s %s\r\n"
		       "s=%s\r\n"
		       "c=IN %s %s\r\n"
		       "t=0 0\r\n"
		       "a=keywds:AVB\r\n"
		       "m=audio %s RTP/AVP %d\r\n"
		       "i=%s\r\n"
		       "a=recvonly\r\n"
		       "a=rtpmap:%d L%d/%d/%d\r\n"
		       "a=ptime:%f\r\n"
		       "a=ts-refclk:ptp=IEEE1588-2008:%s%s\r\n"
		       "a=mediaclk:direct=%lu\r\n",
		       /* o= */ sdp->session_id, sdp->session_id, ip6Origin ? "IP6" : "IP4", sdp->session_origin,
		       /* s= */ sdp->session_name,
		       /* c= */ ip6Address ? "IP6" : "IP4", sdp->address,
		       /* m= */ sdp->port, sdp->payload_type,
		       /* i= */ sdp->information,
		       /* a=rtpmap */ sdp->payload_type, sdp->sample_size, sdp->sample_rate, sdp->channel_count,
		       /* a=ptime */ sdp->packet_duration,
		       /* a=ts-refclk */ sdp->ptp_gmid, domainSuffix,
		       /* a=mediaclk */ sdp->clock_offset);
    }

    if (res >= buflen)
	return false;

    return true;
}

static bool
getLocalPtpClockGrandmaster(char ptp_gmid[24], uint8_t *domain)
{
    uint8_t gmid[8];

    if (!osalAVBGrandmasterGetCurrent(gmid, domain))
	return false;

    snprintf(ptp_gmid, 24, "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X",
	gmid[0], gmid[1], gmid[2], gmid[3],
	gmid[4], gmid[5], gmid[6], gmid[7]);

    return true;
}

static void *
openavbIntfAES67SapAnnouncerThread(void *unused)
{
    char buffer[1024];
    int res;
    mast_socket_t sock;
    openavb_list_t list;

    sock.fd = -1;

    waitUntilInterfaceConfigured();
    sessionDescriptionCachePrime(AES67_SDP_CACHE_LOCAL);

    list = sessionDescriptionList(AES67_SDP_CACHE_LOCAL);

    do {
	openavb_list_node_t node;

	if (sock.fd == -1) {
	    res = mast_socket_open_send(&sock, MAST_SAP_ADDRESS_LOCAL,
					MAST_SAP_PORT, gAES67SapInterfaceName);
	    if (res < 0) {
		AVB_LOGF_WARNING("Failed to open SAP announcer socket: %s; sleeping", strerror(errno));
		sleep(SAP_ANNOUNCER_THREAD_INTERVAL_SEC);
	    }
	}

	sessionDescriptionListLock(AES67_SDP_CACHE_LOCAL); // {

	for (node = openavbListIterFirst(list);
	     node;
	     node = openavbListIterNext(list)) {
	    mast_sdp_t *sdp = sessionDescriptionFromNode(node);
	    uint8_t message_type;
	    struct sockaddr_storage *ss = &sock.src_addr;

	    if (sessionDescriptionIsValid(node))
		message_type = MAST_SAP_MESSAGE_ANNOUNCE;
	    else
		message_type = MAST_SAP_MESSAGE_DELETE;

	    /* set session_origin to our address */
	    sockaddrStorageToString(ss, sdp->session_origin, sizeof(sdp->session_origin));

	    if (!sdpToString(sdp, buffer, sizeof(buffer)))
		continue;

	    AVB_LOGF_DEBUG("Sending SAP %s for session %s <%s>",
			   message_type == MAST_SAP_MESSAGE_ANNOUNCE ? "announcement" : "deletion",
			   sdp->session_name, sdp->session_id);

	    mast_sap_send_sdp_string(&sock, buffer, message_type);

	    if (message_type == MAST_SAP_MESSAGE_DELETE) {
		sessionDescriptionNodeUnpersist(AES67_SDP_CACHE_LOCAL, node);
		sessionDescriptionNodeRelease(AES67_SDP_CACHE_LOCAL, &node);
	    }
	}

	sessionDescriptionListUnlock(AES67_SDP_CACHE_LOCAL); // }

	/* XXX add correct announce time bandwidth modulation */
	sleep(SAP_ANNOUNCER_THREAD_INTERVAL_SEC);
    } while (gAES67InstanceCount);

    mast_socket_close(&sock);

    return NULL;
}

/*
 * Calculate a PTP time from an absolute (64-bit) media clock.
 */
static void
mediaClockToPtpTimeNS(aes67_pvt_data_t *pPvtData,
		      uint64_t mediaClock,
		      uint64_t *ptpTimeNS)
{
    *ptpTimeNS = mediaClock * (NANOSECONDS_PER_SECOND / 100) / (pPvtData->audioRate / 100);
}

/*
 * Calculate an absolute (64-bit) media clock from a PTP time.
 */
static void
ptpTimeNSToMediaClock(aes67_pvt_data_t *pPvtData,
		      uint64_t ptpTimeNS,
		      uint64_t *mediaClock)
{
    *mediaClock = round(1.0 * ptpTimeNS * (pPvtData->audioRateRecovered / 100) / (NANOSECONDS_PER_SECOND / 100));
}

static void
rtpInitializeMediaClock(aes67_pvt_data_t *pPvtData, mast_sdp_t *sdp)
{
    uint64_t currentPtpTimeNS;

    pPvtData->audioRateRecovered = pPvtData->audioRate;

    CLOCK_GETTIME64(OPENAVB_CLOCK_WALLTIME, &currentPtpTimeNS);
    ptpTimeNSToMediaClock(pPvtData, currentPtpTimeNS, &pPvtData->mediaClock);

    /*
     * Leave clock offset as zero for listeners, for SMPTE ST 2110 interop.
     */

    AVB_LOGF_DEBUG("%s media clock at %ld.%ld is %lu offset 0x%08x",
		   pPvtData->avbRole == AVB_ROLE_TALKER ? "Remote" : "Local",
		   currentPtpTimeNS / NANOSECONDS_PER_SECOND,
		   currentPtpTimeNS % NANOSECONDS_PER_SECOND,
		   pPvtData->mediaClock, sdp->clock_offset);
}

static bool
sessionDescriptionGrandmasterChangedFromCurrentConfig(aes67_pvt_data_t *pPvtData, openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);

    return memcmp(sdp->ptp_gmid, pPvtData->ptpGmId, sizeof(pPvtData->ptpGmId)) != 0 ||
	sdp->ptp_domain != pPvtData->ptpDomain;
}


/*
 * Returns true if the session description in node is different from our current
 * configuration in bit depth, sample rate or channel count.
 *
 * This is used on the talker side (RTP receiver) to dynamically update the local
 * configuration and mapper with a new session description. This is the only case
 * in which we log a warning message.
 *
 * On the listener side (RTP sender), it is used to flush cached session descriptions
 * to avoid sending SAP advertisements for a stale configuration.
 */
static bool
sessionDescriptionChangedFromCurrentConfig(aes67_pvt_data_t *pPvtData, openavb_list_node_t node)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(node);
    avb_audio_bit_depth_t audioBitDepth = 0;
    bool bConfigurationChanged = false;
    bool bLogChanges = (pPvtData->avbRole == AVB_ROLE_TALKER);

    switch (sdp->encoding) {
    case MAST_ENCODING_L16:
	audioBitDepth = AVB_AUDIO_BIT_DEPTH_16BIT;
	break;
    case MAST_ENCODING_L24:
	audioBitDepth = AVB_AUDIO_BIT_DEPTH_24BIT;
	break;
    case MAST_ENCODING_L32:
	audioBitDepth = AVB_AUDIO_BIT_DEPTH_32BIT;
	break;
    case MAST_ENCODING_AM824:
	audioBitDepth = AVB_AUDIO_BIT_DEPTH_AM824;
	break;
    default:
	break;
    }

    if (audioBitDepth != pPvtData->audioBitDepth) {
	if (bLogChanges) {
	    AVB_LOGF_INFO("Audio bit depth mismatch: configured for %u bits but session is %u; reconfiguring mapper",
			  pPvtData->audioBitDepth, audioBitDepth);
	}
	bConfigurationChanged = true;
    } else if (sdp->sample_rate != pPvtData->audioRate) {
	if (bLogChanges) {
	    AVB_LOGF_INFO("Sample rate mismatch: configured for %u but session is %u; reconfiguring mapper",
			  pPvtData->audioRate, sdp->sample_rate);
	}
	bConfigurationChanged = true;
    } else if (sdp->channel_count != pPvtData->audioChannels) {
	if (bLogChanges) {
	    AVB_LOGF_INFO("Channel count mismatch: configured for %u but session is %u; reconfiguring mapper",
			  pPvtData->audioChannels, sdp->channel_count);
	}
	bConfigurationChanged = true;
    } else if (sessionDescriptionGrandmasterChangedFromCurrentConfig(pPvtData, node)) {
	char ptpGmId[24];
	uint8_t ptpDomain;

	/* refresh local GM ID */
	if (getLocalPtpClockGrandmaster(ptpGmId, &ptpDomain)) {
	    memcpy(pPvtData->ptpGmId, ptpGmId, sizeof(ptpGmId));
	    pPvtData->ptpDomain = ptpDomain;
	}

	if (bLogChanges && sessionDescriptionGrandmasterChangedFromCurrentConfig(pPvtData, node)) {
	    AVB_LOGF_WARNING("PTP grandmaster clock mismatch: local is %s:%u but stream is %s:%u",
			     pPvtData->ptpGmId, pPvtData->ptpDomain,
			     sdp->ptp_gmid, sdp->ptp_domain);
	}
    }

    return bConfigurationChanged;
}

static openavb_list_node_t
prepareForAnnouncement(aes67_pvt_data_t *pPvtData)
{
    uint64_t sessionID;
    openavb_list_node_t node;
    mast_sdp_t *sdp;

    /*
     * Invalidate any cached SDP session information. Otherwise, recycle it.
     */
    node = findSessionDescriptionNode(AES67_SDP_CACHE_LOCAL,
				      pPvtData->sessionName);
    if (node) {
	if (sessionDescriptionChangedFromCurrentConfig(pPvtData, node)) {
	    sessionDescriptionNodeMarkInvalid(node);
	    sessionDescriptionNodeRelease(AES67_SDP_CACHE_LOCAL, &node);
	}
    }

    if (node == NULL)
	node = sessionDescriptionNodeNew(AES67_SDP_CACHE_LOCAL);

    sdp = sessionDescriptionFromNode(node);

    /*
     * If it is a new session, then generate a "random" session ID and
     * payload type.
     */
    if (!sessionDescriptionIsValid(node)) {
	CLOCK_GETTIME64(OPENAVB_CLOCK_REALTIME, &sessionID);
	sessionID &= 0xffffffff;
	snprintf(sdp->session_id, sizeof(sdp->session_id), "%lu", sessionID);

	sdp->payload_type = 96 + (rand_r(&pPvtData->randomSeed) % 32);
    }

    return node;
}

static bool
sapMakeAnnouncement(aes67_pvt_data_t *pPvtData)
{
    openavb_list_node_t node;
    mast_sdp_t *sdp;

    if (!getLocalPtpClockGrandmaster(pPvtData->ptpGmId, &pPvtData->ptpDomain))
	return false;

    sessionDescriptionListLock(AES67_SDP_CACHE_LOCAL); // {

    node = prepareForAnnouncement(pPvtData);
    sdp = sessionDescriptionFromNode(node);
    rtpInitializeMediaClock(pPvtData, sdp);

    /*
     * Prime the session information from the local listener configuration.
     */
    snprintf(sdp->address, sizeof(sdp->address), "%s", pPvtData->multicastAddress);
    snprintf(sdp->port, sizeof(sdp->port), MAST_DEFAULT_PORT);

    if (pPvtData->sessionName == NULL)
	snprintf(sdp->session_name, sizeof(sdp->session_name), "AVB session : %.200s", sdp->session_id);
    else
	snprintf(sdp->session_name, sizeof(sdp->session_name), "%s", pPvtData->sessionName);
    snprintf(sdp->information, sizeof(sdp->information), "%d channels", pPvtData->audioChannels);

    switch (pPvtData->audioBitDepth) {
    case AVB_AUDIO_BIT_DEPTH_16BIT:
	mast_sdp_set_encoding(sdp, MAST_ENCODING_L16);
	break;
    case AVB_AUDIO_BIT_DEPTH_24BIT:
	mast_sdp_set_encoding(sdp, MAST_ENCODING_L24);
	break;
    case AVB_AUDIO_BIT_DEPTH_32BIT:
	mast_sdp_set_encoding(sdp, MAST_ENCODING_L32);
	break;
    case AVB_AUDIO_BIT_DEPTH_AM824:
	mast_sdp_set_encoding(sdp, MAST_ENCODING_AM824);
	break;
    default:
	return false;
    }
    sdp->sample_rate = pPvtData->audioRate;
    sdp->channel_count = pPvtData->audioChannels;
    sdp->packet_duration = pPvtData->packetTimeUSec / MICROSECONDS_PER_MSEC * 1.0;

    memcpy(sdp->ptp_gmid, pPvtData->ptpGmId, sizeof(pPvtData->ptpGmId));
    sdp->ptp_domain = pPvtData->ptpDomain;

    sessionDescriptionNodePersist(AES67_SDP_CACHE_LOCAL, node);

    sessionDescriptionListUnlock(AES67_SDP_CACHE_LOCAL); // }

    sessionDescriptionNodeRelease(AES67_SDP_CACHE_LOCAL, &pPvtData->sessionDescription);
    pPvtData->sessionDescription = node;
    pPvtData->ssrcIdentifier = strtoul(sdp->session_id, NULL, 10); /* XXX */

    return true;
}

static media_q_pub_map_uncmp_audio_info_t *
uncompressedAudioPubMapInfo(media_q_t *pMediaQ)
{
    if (strcmp(pMediaQ->pMediaQDataFormat, MapUncmpAudioMediaQDataFormat) == 0
	|| strcmp(pMediaQ->pMediaQDataFormat, MapAVTPAudioMediaQDataFormat) == 0)
	return (media_q_pub_map_uncmp_audio_info_t *)pMediaQ->pPubMapInfo;
    else
	return NULL;
}

/*
 * The transmission interval is the AVTP packet frequency in Hz.
 */
static uint32_t
getAvtpTransmissionInterval(media_q_t *pMediaQ)
{
    uint32_t txInterval = 0;
    extern U32 openavbMapUncmpAudioTransmitIntervalCB(media_q_t *pMediaQ);
    extern U32 openavbMapAVTPAudioTransmitIntervalCB(media_q_t *pMediaQ);

    if (strcmp(pMediaQ->pMediaQDataFormat, MapUncmpAudioMediaQDataFormat) == 0)
	txInterval = openavbMapUncmpAudioTransmitIntervalCB(pMediaQ);
    else if (strcmp(pMediaQ->pMediaQDataFormat, MapAVTPAudioMediaQDataFormat) == 0)
	txInterval = openavbMapAVTPAudioTransmitIntervalCB(pMediaQ);

    if (txInterval == 0)
	txInterval = 4000; /* Class B */

    return txInterval;
}

static double
getAvtpTranmissionDurationUSec(media_q_t *pMediaQ)
{
    uint32_t txDuration = getAvtpTransmissionInterval(pMediaQ);

    return MICROSECONDS_PER_SECOND * 1.0 / txDuration;
}

static bool
getRtpAbsoluteMediaClock(aes67_pvt_data_t *pPvtData,
			 uint32_t rtpTimestamp,
			 uint64_t *pMediaClock)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(pPvtData->sessionDescription);
    uint64_t mediaClock, delta;
    bool bCanUpdate = true;

    /* Basic algorithm derived from GStreamer */
    mediaClock = (rtpTimestamp - sdp->clock_offset) & 0xffffffff;
    mediaClock += pPvtData->mediaClock & 0xffffffff00000000;

    if (mediaClock < pPvtData->mediaClock) {
	delta = pPvtData->mediaClock - mediaClock;
	if (delta > 0xffffffff)
	    mediaClock += 1ULL << 32;
    } else {
	delta = mediaClock - pPvtData->mediaClock;
	if (delta > 0xffffffff) {
	    if (mediaClock < 1ULL << 32)
		mediaClock = 0;
	    else
		mediaClock -= 1ULL << 32;
	    bCanUpdate = false;
	}
    }

    *pMediaClock = mediaClock;

    return bCanUpdate;
}

/*
 * Update the ratio between the RTP and AVTP packet durations, known as the packing
 * factor.
 */
static bool
updatePackingFactorIntf(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;

    pPvtData->packingFactor = round(1.0 * pPvtData->packetTimeUSec / getAvtpTranmissionDurationUSec(pMediaQ));

    if (pPvtData->packingFactor == 0) {
	AVB_LOGF_ERROR("RTP packet duration (%fus) cannot be shorter than AVTP packet duration (%fus)",
		       pPvtData->packetTimeUSec, pPvtData->packetTimeUSec);
	pPvtData->packingFactor = 1;
    }

    return pPvtData->packingFactor > 0;
}

/*
 * Reset the packing factor and optionally the mapping configuration, after the local
 * sample rate, bit depth and audio channel count changed.
 */
static bool
notifyConfigurationChanged(media_q_t *pMediaQ, bool bReconfigureMapper)
{
    extern U32 openavbMapUncmpAudioGenInitCB(media_q_t *pMediaQ);
    extern U32 openavbMapAVTPAudioGenInitCB(media_q_t *pMediaQ);
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    media_q_pub_map_uncmp_audio_info_t *pPubMapUncmpAudioInfo = uncompressedAudioPubMapInfo(pMediaQ);

    if (pPubMapUncmpAudioInfo == NULL)
	return false;

    pPubMapUncmpAudioInfo->audioType = AVB_AUDIO_TYPE_INT;
    pPubMapUncmpAudioInfo->audioEndian = AVB_AUDIO_ENDIAN_BIG;
    pPubMapUncmpAudioInfo->audioRate = pPvtData->audioRate;
    pPubMapUncmpAudioInfo->audioBitDepth = pPvtData->audioBitDepth;
    pPubMapUncmpAudioInfo->audioChannels = pPvtData->audioChannels;

    /* default packet time allows for 48 frames per packet */
    if (pPvtData->packetTimeUSec == 0)
	pPvtData->packetTimeUSec = MICROSECONDS_PER_MSEC * 1.0 * AVB_AUDIO_RATE_48KHZ / pPvtData->audioRate;

    if (bReconfigureMapper) {
	if (strcmp(pMediaQ->pMediaQDataFormat, MapUncmpAudioMediaQDataFormat) == 0)
	    openavbMapUncmpAudioGenInitCB(pMediaQ);
	else if (strcmp(pMediaQ->pMediaQDataFormat, MapAVTPAudioMediaQDataFormat) == 0)
	    openavbMapAVTPAudioGenInitCB(pMediaQ);
    }

    return updatePackingFactorIntf(pMediaQ);
}

/*
 * Release the session description pointer if it is no longer valid, and look in
 * the session description cache for one matching the session name specified in
 * the configuration file.
 */
static bool
refreshSessionDescription(aes67_pvt_data_t *pPvtData)
{
    bool bDidChange = false;

    if (pPvtData->sessionDescription &&
	!sessionDescriptionIsValid(pPvtData->sessionDescription))
	sessionDescriptionNodeRelease(AES67_SDP_CACHE_REMOTE, &pPvtData->sessionDescription);

    if (pPvtData->sessionDescription == NULL) {
	sessionDescriptionListLock(AES67_SDP_CACHE_REMOTE); // {
	pPvtData->sessionDescription = findSessionDescriptionNode(AES67_SDP_CACHE_REMOTE,
								  pPvtData->sessionName);
	sessionDescriptionListUnlock(AES67_SDP_CACHE_REMOTE); // }

	if (pPvtData->sessionDescription == NULL)
	    return NULL;

	bDidChange = true;
    }

    return bDidChange;
}

/*
 * Update the subscription to an RTP sender, used by the AVB talker (RTP receiver).
 */
static bool
refreshSubscription(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    bool bSessionChanged = refreshSessionDescription(pPvtData);
    mast_sdp_t *sdp;

    if (pPvtData->sessionDescription == NULL)
	return false;

    sdp = sessionDescriptionFromNode(pPvtData->sessionDescription);

    if (bSessionChanged) {
	bool bConfigurationChanged =
	    sessionDescriptionChangedFromCurrentConfig(pPvtData, pPvtData->sessionDescription);

	mast_socket_close(&pPvtData->rtpSocket);

	if (bConfigurationChanged)
#if 0
	    /* XXX we would also need to notify AVDECC */
	    notifyConfigurationChanged(pMediaQ, true);
#else
	    return false;
#endif

	rtpInitializeMediaClock(pPvtData, sdp);

	pPvtData->packetTimeUSec = sdp->packet_duration * MICROSECONDS_PER_MSEC;
	if (!updatePackingFactorIntf(pMediaQ))
	    return false;
    }

    if (pPvtData->rtpSocket.fd < 0) {
	/* open socket */
	int res;

	pPvtData->rtpPacketCount = 0;

	res = mast_socket_open_recv(&pPvtData->rtpSocket, sdp->address,
				    sdp->port, pPvtData->interfaceName);
	if (res) {
	    AVB_LOGF_ERROR("Failed to open RTP receive socket to %s:%d: %s",
			   sdp->address, sdp->port, strerror(errno));
	    return false;
	} else {
	    AVB_LOGF_VERBOSE("Opened RTP receive socket to %s:%d",
			     sdp->address, sdp->port);
	}

#ifdef RTP_DEBUG_TS
	if (!setSocketHwTs(&pPvtData->rtpSocket, false)) {
	    AVB_LOGF_WARNING("Failed to set RTP receive socket HW timestamping: %s",
			     strerror(errno));
	}
#endif
    }

    return true;
}

static void
openavbIntfAES67CfgCB(media_q_t *pMediaQ, const char *name, const char *value)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    char *pEnd = NULL;
    int32_t val;
    media_q_pub_map_uncmp_audio_info_t *pPubMapUncmpAudioInfo = uncompressedAudioPubMapInfo(pMediaQ);

    AVB_TRACE_ENTRY(AVB_TRACE_INTF);

    pPvtData = pMediaQ->pPvtIntfInfo;
    if (pPvtData == NULL) {
	AVB_LOG_ERROR("Private interface module data not allocated.");
	return;
    }

    if (strcmp(name, "intf_nv_aes67_ifname") == 0) {
	/* XXX global */
	pthread_mutex_lock(&gAES67SapInterfaceLock);
	if (gAES67SapInterfaceName)
	    free(gAES67SapInterfaceName);
	gAES67SapInterfaceName = strdup(value);
	pthread_cond_broadcast(&gAES67SapInterfaceCondition);
	pthread_mutex_unlock(&gAES67SapInterfaceLock);

	if (pPvtData->interfaceName)
	    free(pPvtData->interfaceName);
	pPvtData->interfaceName = strdup(value);
    } else if (strcmp(name, "intf_nv_aes67_session_name") == 0) {
	if (pPvtData->sessionName)
	    free(pPvtData->sessionName);
	pPvtData->sessionName = strdup(value);
    } else if (strcmp(name, "intf_nv_aes67_multicast_address") == 0) {
	if (pPvtData->multicastAddress)
	    free(pPvtData->multicastAddress);
	pPvtData->multicastAddress = strdup(value);
    } else if (strcmp(name, "intf_nv_audio_rate") == 0) {
	val = strtoul(value, &pEnd, 10);

	if (val >= AVB_AUDIO_RATE_44_1KHZ && val <= AVB_AUDIO_RATE_96KHZ)
	    pPvtData->audioRate = val;
    } else if (strcmp(name, "intf_nv_audio_bit_depth") == 0) {
	if (strcasecmp(value, "am824") == 0) {
	    pPvtData->audioBitDepth = AVB_AUDIO_BIT_DEPTH_AM824;
	} else {
	    val = strtoul(value, &pEnd, 10);

	    if (val >= AVB_AUDIO_BIT_DEPTH_16BIT && val <= AVB_AUDIO_BIT_DEPTH_32BIT)
		pPvtData->audioBitDepth = val;
	}
    } else if (strcmp(name, "intf_nv_audio_channels") == 0) {
	val = strtoul(value, &pEnd, 10);

	if (val >= AVB_AUDIO_CHANNELS_1 && val <= AVB_AUDIO_CHANNELS_8)
	    pPvtData->audioChannels = val;
    } else if (strcmp(name, "intf_nv_aes67_ptime_usec") == 0) {
	val = strtoul(value, &pEnd, 10);

	pPvtData->packetTimeUSec = val;
    } else if (strcmp(name, "intf_nv_aes67_pto_usec") == 0) {
	val = strtol(value, &pEnd, 10);

	if (pPubMapUncmpAudioInfo)
	    pPubMapUncmpAudioInfo->presentationLatencyUSec = val;
    } else if (strcmp(name, "intf_nv_aes67_hwtstamp") == 0) {
	val = strtoul(value, &pEnd, 10);

	pPvtData->hwtsEnabled = !!val;
    } else if (strcmp(name, "intf_nv_aes67_dscp") == 0) {
	val = strtoul(value, &pEnd, 10);

	pPvtData->dscpValue = val;
    } else if (strcmp(name, "intf_nv_aes67_socket_priority") == 0) {
	val = strtoul(value, &pEnd, 10);

	pPvtData->socketPriority = val;
    }

    if (pEnd && *pEnd) {
	AVB_LOGF_WARNING("Extraneous non-digit characters in %s: %s", name, value);
    }

    notifyConfigurationChanged(pMediaQ, false);

    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
openavbIntfAES67GenInitCB(media_q_t *pMediaQ)
{
    AVB_TRACE_ENTRY(AVB_TRACE_INTF);
    __sync_add_and_fetch(&gAES67InstanceCount, 1);
    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
openavbIntfAES67TxInitCB(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF);
    AVB_LOGF_DEBUG("Initializing talker on queue %p", pMediaQ);
    getLocalPtpClockGrandmaster(pPvtData->ptpGmId, &pPvtData->ptpDomain);
    pPvtData->avbRole = AVB_ROLE_TALKER;

    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
rtpTracePacket(aes67_pvt_data_t *pPvtData,
	       int32_t presentationLatencyUSec,
	       mast_rtp_packet_t *rtpPacket,
	       uint64_t rtpTimestampNS)
{
    int64_t presentationLatencyNS = presentationLatencyUSec * NANOSECONDS_PER_USEC;
    uint64_t nowNS, presentationTimeNS;
    uint64_t rtpDeltaNS, presentationDeltaNS;
    bool bRtpTimeInFuture, bPresentationTimeInFuture;

    CLOCK_GETTIME64(OPENAVB_CLOCK_WALLTIME, &nowNS);

    /*
     * rtpTimestampNS is the timestamp extracted from the media queue item's
     * AVTP time. On RTP ingress (AVTP egress), this time is the RTP timestamp;
     * the presentation latency will be added by the mapper to calculate the
     * presentation time. (We don't have visibility into the transit time.)
     *
     * On AVTP ingress (RTP egress), the mapper has subtracted the presentation
     * latency from the packet timestamp, so we need to add it back in order to
     * log the presentation time.
     *
     * Relative to the current PTP time, the presentation time should be in the
     * future and the RTP time in the past, both sufficiently distant in order
     * to compensate for the transit time on either side of the protocol bridge.
     */
    presentationTimeNS = rtpTimestampNS + presentationLatencyNS;

    bRtpTimeInFuture = rtpTimestampNS > nowNS;
    rtpDeltaNS = bRtpTimeInFuture ? rtpTimestampNS - nowNS : nowNS - rtpTimestampNS;

    bPresentationTimeInFuture = presentationTimeNS > nowNS;
    presentationDeltaNS = bPresentationTimeInFuture ? presentationTimeNS - nowNS : nowNS - presentationTimeNS;

    AVB_LOGF_DEBUG("%s: len %u pay %u seq %u ts 0x%08x "
		   "rtp %lu.%lu pres %u/0x%08x/%lu.%lu now %lu.%lu "
		   "%s by %ldus pto %dus %s by %ldus",
		   pPvtData->avbRole == AVB_ROLE_TALKER ? "R->A" : "A->R",
		   rtpPacket->length, rtpPacket->payload_type,
		   rtpPacket->sequence, rtpPacket->timestamp,
		   rtpTimestampNS / NANOSECONDS_PER_SECOND,
		   rtpTimestampNS % NANOSECONDS_PER_SECOND,
		   presentationTimeNS & 0xffffffff,
		   presentationTimeNS & 0xffffffff,
		   presentationTimeNS / NANOSECONDS_PER_SECOND,
		   presentationTimeNS % NANOSECONDS_PER_SECOND,
		   nowNS / NANOSECONDS_PER_SECOND,
		   nowNS % NANOSECONDS_PER_SECOND,
		   bRtpTimeInFuture ? "RTP>NOW" : "rtp<now",
		   rtpDeltaNS / NANOSECONDS_PER_USEC,
		   presentationLatencyUSec,
		   bPresentationTimeInFuture ? "pres>now" : "PRES<NOW",
		   presentationDeltaNS / NANOSECONDS_PER_USEC);
}

/*
 * Number of bytes consumed by a single RTP frame (i.e. in a single
 * increment of the RTP media clock)
 */
static inline uint32_t
rtpFrameSize(aes67_pvt_data_t *pPvtData)
{
    uint32_t frameSize;

    frameSize = (pPvtData->audioBitDepth == AVB_AUDIO_BIT_DEPTH_AM824) ? 4 : pPvtData->audioBitDepth / 8;
    frameSize *= pPvtData->audioChannels;

    return frameSize;
}

/*
 * Add a received RTP packet to the media queue, to be mapped to an AVTP packet.
 */
static bool
pushRtpPacketToMediaQ(mast_rtp_packet_t *rtpPacket, media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    media_q_pub_map_uncmp_audio_info_t *pPubMapUncmpAudioInfo = uncompressedAudioPubMapInfo(pMediaQ);
    uint64_t mediaClock;
    bool updateMediaClock, firstFrame = true;

    updateMediaClock = getRtpAbsoluteMediaClock(pPvtData, rtpPacket->timestamp, &mediaClock);

    while (rtpPacket->payload_length != 0) {
	uint64_t timestampNS;
	media_q_item_t *pMediaQItem;
	size_t mediaQByteCount;
	size_t frameCount;

	pMediaQItem = openavbMediaQHeadLock(pMediaQ);
	if (pMediaQItem == NULL)
	    return true;

	if (pMediaQItem->itemSize < pPubMapUncmpAudioInfo->itemSize) {
	    AVB_LOG_ERROR("Media queue item not large enough for samples");
	    return false;
	}

	mediaQByteCount = rtpPacket->payload_length;
	if (mediaQByteCount > pMediaQItem->itemSize)
	    mediaQByteCount = pMediaQItem->itemSize;

	memcpy(pMediaQItem->pPubData, rtpPacket->payload, mediaQByteCount);
	pMediaQItem->dataLen = mediaQByteCount;

	rtpPacket->payload += mediaQByteCount;
	rtpPacket->payload_length -= mediaQByteCount;

	mediaClockToPtpTimeNS(pPvtData, mediaClock, &timestampNS);
	openavbAvtpTimeSetToTimestampNS(pMediaQItem->pAvtpTime, timestampNS);

	if (firstFrame) {
	    /* the mapper will add the presentation latency to the AVTP time, so log that */
	    IF_LOG_INTERVAL(RTP_LOG_INTERVAL) {
		rtpTracePacket(pPvtData, pPubMapUncmpAudioInfo->presentationLatencyUSec,
			       rtpPacket, timestampNS);
	    }
	    firstFrame = false;
	}

	if (mediaQByteCount != pMediaQItem->itemSize)
	    AVB_LOG_WARNING("Non-integral RTP packets will be truncated, check packing configuration");

	openavbMediaQHeadPush(pMediaQ);

	assert((mediaQByteCount % rtpFrameSize(pPvtData)) == 0);
	frameCount = mediaQByteCount / rtpFrameSize(pPvtData);

	mediaClock += frameCount;
    }

    if (updateMediaClock)
	pPvtData->mediaClock = mediaClock;

    return true;
}

/*
 * Returns the number of sample frames in a packet, at the currently configured
 * sample rate and RTP packet duration.
 */
static size_t
rtpPacketFrames(aes67_pvt_data_t *pPvtData)
{
    return pPvtData->audioRate * (1.0 * pPvtData->packetTimeUSec / MICROSECONDS_PER_SECOND);
}

/*
 * Returns the RTP payload size in bytes we will generate or expect to receive.
 */
static size_t
rtpPacketPayloadSize(aes67_pvt_data_t *pPvtData)
{
    return rtpPacketFrames(pPvtData) * rtpFrameSize(pPvtData);
}

#ifdef RTP_DEBUG_TS
/*
 * Just some debugging for checking the rate at which RTP packets are arriving
 * is sufficient to satisfy the AVB stream. Should be disabled by default as it
 * involves an extra system call per packet.
 */
static void
rtpDebugTSUpdate(aes67_pvt_data_t *pPvtData)
{
    struct timespec ts;
    uint64_t packetTime;
    double intervalNS, packetRate;

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    if (ioctl(pPvtData->rtpSocket.fd, SIOCGSTAMPNS, &ts) != 0)
	return;

    packetTime = ts.tv_sec * NANOSECONDS_PER_SECOND + ts.tv_nsec;

    if (pPvtData->lastPacketTime == 0) {
	intervalNS = pPvtData->packetTimeUSec * NANOSECONDS_PER_USEC;
	pPvtData->rtpPacketRate = 1.0 / (pPvtData->packetTimeUSec / MICROSECONDS_PER_SECOND);
    } else {
	intervalNS = 1.0 * (packetTime - pPvtData->lastPacketTime);
    }

    packetRate = 1.0 / (intervalNS / NANOSECONDS_PER_SECOND);
    pPvtData->rtpPacketRate = (15.0 * pPvtData->rtpPacketRate + packetRate) / 16.0;

    IF_LOG_INTERVAL(RTP_LOG_INTERVAL) {
	AVB_LOGF_DEBUG("RTP sender rate is %fHz, time since last RTP packet %fus, delta %fus, effective Fs %uHz",
		       pPvtData->rtpPacketRate,
		       intervalNS / NANOSECONDS_PER_USEC,
		       intervalNS / NANOSECONDS_PER_USEC - pPvtData->packetTimeUSec,
		       (unsigned)pPvtData->rtpPacketRate * rtpPacketFrames(pPvtData));
    }

    pPvtData->lastPacketTime = packetTime;
}
#endif

static bool
openavbIntfAES67TxCB(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    mast_rtp_packet_t rtpPacket;
    mast_sdp_t *sdp;
    bool res;
    size_t rtpExpectedPayloadLength;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF_DETAIL);

    if (pMediaQ == NULL) {
	AVB_LOG_DEBUG("No media queue");
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    }

    if (!refreshSubscription(pMediaQ)) {
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    }

    sdp = sessionDescriptionFromNode(pPvtData->sessionDescription);

    /*
     * This is automatically computed from the ratio of the AVB transmit time
     * to the AES67 packet time. It is required to not overrun the media queue
     * with RTP packets as the AVB transmit time will typically be smaller than
     * the AES67 equivalent.
     */
    if ((pPvtData->invocationCount++ % pPvtData->packingFactor) != 0) {
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return true;
    } else if (mast_rtp_recv(&pPvtData->rtpSocket, &rtpPacket) < 0) {
	AVB_LOG_INFO("Failed to receive RTP packet");
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    } else if (rtpPacket.version != RTP_VERSION) {
	AVB_LOGF_INFO("Invalid RTP packet version, got %d expected %d",
		      rtpPacket.version, RTP_VERSION);
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    } else if (rtpPacket.payload_type != sdp->payload_type) {
	AVB_LOGF_INFO("Invalid RTP packet payload type, got %d expected %d",
		      rtpPacket.payload_type, sdp->payload_type);
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    } else if ((rtpPacket.payload_length % rtpFrameSize(pPvtData)) != 0) {
	AVB_LOGF_INFO("RTP packet of length %d bytes is truncated, must be a multiple of %d",
		      rtpPacket.payload_length, getAvtpTranmissionDurationUSec(pMediaQ));
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    }

#ifdef RTP_DEBUG_TS
    rtpDebugTSUpdate(pPvtData);
#endif

    if (pPvtData->rtpPacketCount == 0) {
	char destAddress[NI_MAXHOST];

	sockaddrStorageToString(&pPvtData->rtpSocket.dest_addr, destAddress, sizeof(destAddress));

	AVB_LOGF_INFO("Starting RTP receiver stream: payload type %d from %s",
		      rtpPacket.payload_type, destAddress);

	mast_rtp_init_sequence(&pPvtData->sequenceState, rtpPacket.sequence);
	pPvtData->sequenceState.max_seq = rtpPacket.sequence - 1;
	pPvtData->sequenceState.probation = RTP_MIN_SEQUENTIAL;
	pPvtData->ssrcIdentifier = rtpPacket.ssrc;
    } else if (rtpPacket.ssrc != pPvtData->ssrcIdentifier) {
	AVB_LOGF_DEBUG("RTP SSRC changed, got %u expected %u", rtpPacket.ssrc, pPvtData->ssrcIdentifier);
    }

    rtpExpectedPayloadLength = rtpPacketPayloadSize(pPvtData);

    if (pPvtData->packetTimeUSec == 0) {
	/* if SDP lacked ptime, calculate based on first packet */
	pPvtData->packetTimeUSec = 1.0 * rtpPacket.payload_length / rtpFrameSize(pPvtData) /
				   (pPvtData->audioRate * MICROSECONDS_PER_SECOND);
	if (!updatePackingFactorIntf(pMediaQ))
	    return false;

    } else if (rtpPacket.payload_length != rtpExpectedPayloadLength) {
	AVB_LOGF_DEBUG("RTP packet too %s, got %u expected %u bytes",
		       rtpPacket.payload_length > rtpExpectedPayloadLength ? "long" : "short",
		       rtpPacket.payload_length, rtpExpectedPayloadLength);
    }

    if (mast_rtp_update_sequence(&pPvtData->sequenceState, rtpPacket.sequence)) {
	res = pushRtpPacketToMediaQ(&rtpPacket, pMediaQ);
    } else {
	if (pPvtData->sequenceState.probation == 0)
	    AVB_LOGF_DEBUG("Out of sequence RTP packet, got %d expected %d",
			   rtpPacket.sequence, pPvtData->sequenceState.max_seq);
	res = false;
    }

    pPvtData->rtpPacketCount++;

    AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);

    return res;
}

static bool
setSocketHwTs(mast_socket_t *sock, bool tx)
{
    int tsFlags = SOF_TIMESTAMPING_RAW_HARDWARE;

    if (tx)
	tsFlags |= SOF_TIMESTAMPING_TX_HARDWARE;
    else
	tsFlags |= SOF_TIMESTAMPING_RX_HARDWARE;

    /* NB: we are assuming the PTP daemon or something has enabled HWTS for the interface */
    return setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMPING,
		      &tsFlags, sizeof(tsFlags)) == 0;
}

static bool
setSocketDscpValue(mast_socket_t *sock, int dscpValue)
{
    int level, option, tos = 0;
    socklen_t len = sizeof(tos);

    if (sock->src_addr.ss_family == AF_INET) {
	level = IPPROTO_IP;
	option = IP_TOS;
    } else if (sock->src_addr.ss_family == AF_INET6) {
	level = IPPROTO_IPV6;
	option = IPV6_TCLASS;
    } else {
	return false;
    }

    if (getsockopt(sock->fd, level, option, &tos, &len) != 0)
	tos = 0;

    tos &= ~(0xFC);
    tos |= dscpValue << 2;

    return setsockopt(sock->fd, level, option, &tos, sizeof(tos)) == 0;
}

static bool
setSocketDontFragment(mast_socket_t *sock, bool dfValue)
{
    int level, option, df = dfValue ? IP_PMTUDISC_DO : IP_PMTUDISC_WANT;

    if (sock->src_addr.ss_family == AF_INET) {
	level = IPPROTO_IP;
	option = IP_MTU_DISCOVER;
    } else if (sock->src_addr.ss_family == AF_INET6) {
	level = IPPROTO_IPV6;
	option = IPV6_MTU_DISCOVER;
    } else {
	return false;
    }

    return setsockopt(sock->fd, level, option, &df, sizeof(df)) == 0;
}

static bool
openRtpSendSocket(aes67_pvt_data_t *pPvtData)
{
    pPvtData->rtpPacketCount = 0;

    if (pPvtData->interfaceName == NULL) {
	AVB_LOG_ERROR("No AES67 interface specified, cannot open socket");
	goto error;
    } else if (rtpPacketPayloadSize(pPvtData) > RTP_MAX_PAYLOAD) {
	AVB_LOG_ERROR("Current configuration would exceed RTP maximum payload size");
	goto error;
    }

    assert(pPvtData->rtpSocket.fd == -1);

    if (mast_socket_open_send(&pPvtData->rtpSocket, pPvtData->multicastAddress,
			       MAST_DEFAULT_PORT, pPvtData->interfaceName) != 0) {
	AVB_LOGF_WARNING("Failed to open RTP send socket: %s", strerror(errno));
	goto error;
    }

    if (!setSocketDontFragment(&pPvtData->rtpSocket, true)) {
	AVB_LOGF_WARNING("Failed to set RTP send socket MTU discovery: %s", strerror(errno));
	goto error;
    }

    if (!setSocketDscpValue(&pPvtData->rtpSocket, pPvtData->dscpValue)) {
	AVB_LOGF_WARNING("Failed to set RTP send socket DSCP value: %s", strerror(errno));
	goto error;
    }

    if (pPvtData->socketPriority != -1) {
	if (setsockopt(pPvtData->rtpSocket.fd, SOL_SOCKET, SO_PRIORITY,
		       &pPvtData->socketPriority, sizeof(pPvtData->socketPriority)) != 0) {
	    AVB_LOGF_WARNING("Failed to set RTP send socket priority: %s", strerror(errno));
	    goto error;
	}
    }

    if (setsockopt(pPvtData->rtpSocket.fd, SOL_SOCKET, SO_BINDTODEVICE,
		   pPvtData->interfaceName, strlen(pPvtData->interfaceName)) != 0) {
	AVB_LOGF_WARNING("Failed to set RTP send socket interface affinity: %s", strerror(errno));
	goto error;
    }

    if (pPvtData->hwtsEnabled) {
	struct ethtool_ts_info tsInfo;
	struct ifreq ifr;

	memset(&tsInfo, 0, sizeof(tsInfo));
	memset(&ifr, 0, sizeof(ifr));
	tsInfo.cmd = ETHTOOL_GET_TS_INFO;
	strncpy(ifr.ifr_name, pPvtData->interfaceName, IFNAMSIZ - 1);
	ifr.ifr_data = (caddr_t)&tsInfo;

	if (!setSocketHwTs(&pPvtData->rtpSocket, true)) {
	    AVB_LOGF_WARNING("Failed to set RTP send socket HW timestamping: %s",
			     strerror(errno));
	    goto error;
	}

	if (ioctl(pPvtData->rtpSocket.fd, SIOCETHTOOL, &ifr) != 0) {
	    AVB_LOGF_WARNING("Failed to query time stamping information for interface %s: %s",
			     pPvtData->interfaceName, strerror(errno));
	    goto error;
	}

	assert(pPvtData->ptpClockFd == -1);
	pPvtData->ptpClockFd = -1;
	pPvtData->ptpClockId = CLOCK_INVALID;

	if (tsInfo.so_timestamping) {
	    char phcName[16];

	    snprintf(phcName, sizeof(phcName), "/dev/ptp%d", tsInfo.phc_index);
	    pPvtData->ptpClockFd = open(phcName, O_RDONLY);
	    if (pPvtData->ptpClockFd >= 0) {
		pPvtData->ptpClockId = FD_TO_CLOCKID(pPvtData->ptpClockFd);
		AVB_LOGF_DEBUG("Using PTP clock /dev/ptp%d", tsInfo.phc_index);
	    }
	}

	if (pPvtData->ptpClockId != CLOCK_INVALID) {
	    struct sock_txtime txtime;

	    txtime.clockid = pPvtData->ptpClockId;
	    txtime.flags = 0;

	    if (setsockopt(pPvtData->rtpSocket.fd, SOL_SOCKET, SO_TXTIME,
			   &txtime, sizeof(txtime)) != 0) {
		AVB_LOGF_WARNING("Failed to enable timestamping on RTP send socket: %s", strerror(errno));
		goto error;
	    }
	}
    }

    pPvtData->sequenceState.max_seq = rand_r(&pPvtData->randomSeed) % 0xffff;

    return true;

error:
    mast_socket_close(&pPvtData->rtpSocket);
    return false;
}

static void
openavbIntfAES67RxInitCB(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF);

    AVB_LOGF_DEBUG("Initializing listener  queue %p", pMediaQ);
    pPvtData->avbRole = AVB_ROLE_LISTENER;

    /* open multicast RTP socket */
    if (openRtpSendSocket(pPvtData))
	sapMakeAnnouncement(pPvtData);

    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
initRtpPacketHeader(aes67_pvt_data_t *pPvtData,
		    uint64_t mediaClock,
		    mast_rtp_packet_t *rtpPacket)
{
    mast_sdp_t *sdp = sessionDescriptionFromNode(pPvtData->sessionDescription);

    assert(sdp != NULL);

    rtpPacket->version = RTP_VERSION;
    rtpPacket->padding = 0;
    rtpPacket->extension = 0;
    rtpPacket->csrc_count = 0;
    rtpPacket->marker = 0;
    rtpPacket->payload_type = sdp->payload_type;

    rtpPacket->sequence = pPvtData->sequenceState.max_seq++;
    rtpPacket->timestamp = (mediaClock + sdp->clock_offset) & 0xffffffff;
    rtpPacket->ssrc = pPvtData->ssrcIdentifier;
}

static void
encodeRtpPacketHeader(mast_rtp_packet_t *rtpPacket)
{
    uint16_t sequenceNumber = htons(rtpPacket->sequence);
    uint32_t timestamp = htonl(rtpPacket->timestamp);
    uint32_t ssrc = htonl(rtpPacket->ssrc);

    rtpPacket->length = RTP_HEADER_LENGTH + rtpPacket->payload_length;

#define bitShift(byte, mask, shift) ((byte & mask) << shift)

    rtpPacket->buffer[0] = bitShift(rtpPacket->version, 0x02, 6) |
			   bitShift(rtpPacket->padding, 0x01, 5) |
			   bitShift(rtpPacket->extension, 0x01, 4) |
			   bitShift(rtpPacket->csrc_count, 0x0F, 0);
    rtpPacket->buffer[1] = bitShift(rtpPacket->marker, 0x01, 7) |
			   bitShift(rtpPacket->payload_type, 0x7F, 0);
    memcpy(&rtpPacket->buffer[2], &sequenceNumber, 2);
    memcpy(&rtpPacket->buffer[4], &timestamp, 4);
    memcpy(&rtpPacket->buffer[8], &ssrc, 4);
}

/*
 * Prepare and send an RTP packet; the caller is expected to have filled in
 * the payload.
 */
static bool
sendRtpPacket(aes67_pvt_data_t *pPvtData,
	      uint64_t mediaClock,
	      mast_rtp_packet_t *rtpPacket,
	      uint64_t avtpTimestampNS,
	      int32_t presentationLatencyUSec)
{
    char control[CMSG_SPACE(sizeof(uint64_t))];
    struct iovec iov;
    struct msghdr msgHeader;
    ssize_t bytesSent;
    char srcAddress[NI_MAXHOST], destAddress[NI_MAXHOST];

    assert(RTP_HEADER_LENGTH + rtpPacket->payload_length <= sizeof(rtpPacket->buffer));

    if (pPvtData->rtpPacketCount == 0) {
	mast_sdp_t *sdp = sessionDescriptionFromNode(pPvtData->sessionDescription);

	sockaddrStorageToString(&pPvtData->rtpSocket.src_addr, srcAddress, sizeof(srcAddress));
	sockaddrStorageToString(&pPvtData->rtpSocket.dest_addr, destAddress, sizeof(destAddress));

	AVB_LOGF_INFO("Starting RTP sender stream: payload type %d from %s to %s",
		      sdp->payload_type, srcAddress, destAddress);
    }

    initRtpPacketHeader(pPvtData, mediaClock, rtpPacket);
    encodeRtpPacketHeader(rtpPacket);

    rtpPacket->length = RTP_HEADER_LENGTH + rtpPacket->payload_length;

    iov.iov_base = rtpPacket->buffer;
    iov.iov_len = rtpPacket->length;

    memset(&msgHeader, 0, sizeof(msgHeader));
    msgHeader.msg_name = &pPvtData->rtpSocket.dest_addr;
    msgHeader.msg_namelen = sockaddrStorageLength(&pPvtData->rtpSocket.dest_addr);
    msgHeader.msg_iov = &iov;
    msgHeader.msg_iovlen = 1;

    if (pPvtData->ptpClockId != CLOCK_INVALID) {
	struct cmsghdr *cMsgHeader;

	memset(&control, 0, sizeof(control));
	msgHeader.msg_control = control;
	msgHeader.msg_controllen = sizeof(control);

	cMsgHeader = CMSG_FIRSTHDR(&msgHeader);
	cMsgHeader->cmsg_level = SOL_SOCKET;
	cMsgHeader->cmsg_type = SCM_TXTIME;
	cMsgHeader->cmsg_len = CMSG_LEN(sizeof(avtpTimestampNS));

	/* compensate for drift between PHC and PTP clock */
	gptpmaster2local(&gPtpTD, avtpTimestampNS, (uint64_t *)CMSG_DATA(cMsgHeader));
    }

    bytesSent = sendmsg(pPvtData->rtpSocket.fd, &msgHeader, 0);
    if (bytesSent < 0) {
	int error = errno;

	sockaddrStorageToString(&pPvtData->rtpSocket.src_addr, srcAddress, sizeof(srcAddress));
	sockaddrStorageToString(&pPvtData->rtpSocket.dest_addr, destAddress, sizeof(destAddress));

	AVB_LOGF_ERROR("Failed to send RTP packet from %s to %s: %s",
		       srcAddress, destAddress, strerror(error));
    } else {
	pPvtData->rtpPacketCount++;
    }

    IF_LOG_INTERVAL(RTP_LOG_INTERVAL) {
	rtpTracePacket(pPvtData, presentationLatencyUSec, rtpPacket, avtpTimestampNS);
    }

    return bytesSent == rtpPacket->length;
}

static void
recoverMediaClock(media_q_t *pMediaQ,
		  media_q_item_t *pMediaQItem,
		  uint64_t *pAvtpTimestampNS,
		  uint64_t *pMediaClock)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    int32_t frameCount = pMediaQItem->dataLen / rtpFrameSize(pPvtData);
    double effectiveRate, interval;

    assert(pPvtData->audioRateRecovered != 0);

    *pAvtpTimestampNS = openavbAvtpTimeGetAvtpTimeNS(pMediaQItem->pAvtpTime);

    if (pPvtData->lastPacketTime == 0)
	interval = getAvtpTranmissionDurationUSec(pMediaQ) * pPvtData->packingFactor *
		   NANOSECONDS_PER_USEC;
    else
	interval = 1.0 * (*pAvtpTimestampNS - pPvtData->lastPacketTime);

    effectiveRate = 1.0 * frameCount / interval * NANOSECONDS_PER_SECOND;
    pPvtData->audioRateRecovered = (15.0 * pPvtData->audioRateRecovered + effectiveRate) / 16.0;

    ptpTimeNSToMediaClock(pPvtData, *pAvtpTimestampNS, pMediaClock);
    pPvtData->lastPacketTime = *pAvtpTimestampNS;

    IF_LOG_INTERVAL(RTP_LOG_INTERVAL) {
	AVB_LOGF_DEBUG("Talker rate is %fHz based on media queue interval %ldns (frames %d)",
		       pPvtData->audioRateRecovered, effectiveRate, (long)interval,
		       *pMediaClock - pPvtData->mediaClock);
    }
}

/*
 * Process received AVTP frames into a new RTP packet to be sent. The packing
 * factor should be configured so that this function is called once per RTP
 * packet.
 */
static void
processMediaQItemRtpPacket(media_q_t *pMediaQ, media_q_item_t *pMediaQItem)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    media_q_pub_map_uncmp_audio_info_t *pPubMapUncmpAudioInfo = uncompressedAudioPubMapInfo(pMediaQ);
    int32_t presentationLatencyUSec = pPubMapUncmpAudioInfo ? pPubMapUncmpAudioInfo->presentationLatencyUSec : 0;
    size_t rtpPacketSize = rtpPacketPayloadSize(pPvtData);
    size_t mediaQIndex = 0;
    uint8_t *pMediaQData = pMediaQItem->pPubData;
    uint64_t timestampNS, mediaClock;
    size_t packetCount = 0;

    recoverMediaClock(pMediaQ, pMediaQItem, &timestampNS, &mediaClock);

    while (mediaQIndex < pMediaQItem->dataLen) {
	mast_rtp_packet_t rtpPacket;

	memset(&rtpPacket, 0, sizeof(rtpPacket));
	rtpPacket.payload = &rtpPacket.buffer[RTP_HEADER_LENGTH];

	rtpPacket.payload_length = pMediaQItem->dataLen;
	if (rtpPacket.payload_length > rtpPacketSize)
	    rtpPacket.payload_length = rtpPacketSize;

	memcpy(rtpPacket.payload, &pMediaQData[mediaQIndex], rtpPacket.payload_length);
	mediaQIndex += rtpPacket.payload_length;

	rtpPacket.payload_length = rtpPacket.payload_length;
	sendRtpPacket(pPvtData, mediaClock, &rtpPacket, timestampNS, presentationLatencyUSec);
	packetCount++;

	assert((rtpPacket.payload_length % rtpFrameSize(pPvtData)) == 0);
	mediaClock += rtpPacket.payload_length / rtpFrameSize(pPvtData);
    }

    if (packetCount > 1) {
	AVB_LOGF_INFO("Sent multiple (%d) RTP packets in a single invocation; "
		      "suggest setting map_nv_packing_factor to %u",
		      packetCount, pPvtData->packingFactor);
    }

    pPvtData->mediaClock = mediaClock;
}

static bool
openavbIntfAES67RxCB(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
    media_q_item_t *pMediaQItem;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF_DETAIL);

    if (pPvtData->rtpSocket.fd < 0) {
	AVB_LOG_ERROR("In receive callback with no RTP send socket initialized");
	AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);
	return false;
    }

    pPvtData->invocationCount++;

    while ((pMediaQItem = openavbMediaQTailLock(pMediaQ, true)) != NULL) {
	processMediaQItemRtpPacket(pMediaQ, pMediaQItem);
	openavbMediaQTailPull(pMediaQ);
    }

    AVB_TRACE_EXIT(AVB_TRACE_INTF_DETAIL);

    return true;
}

static void
openavbIntfAES67EndCB(media_q_t *pMediaQ)
{
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF);
    if (pPvtData->avbRole == AVB_ROLE_LISTENER)
	sessionDescriptionNodeRelease(AES67_SDP_CACHE_LOCAL, &pPvtData->sessionDescription);
    else
	sessionDescriptionNodeRelease(AES67_SDP_CACHE_REMOTE, &pPvtData->sessionDescription);
    mast_socket_close(&pPvtData->rtpSocket);
    if (pPvtData->ptpClockFd != -1) {
	close(pPvtData->ptpClockFd);
	pPvtData->ptpClockFd = -1;
	pPvtData->ptpClockId = CLOCK_INVALID;
    }
    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
openavbIntfAES67GenEndCB(media_q_t *pMediaQ)
{
    void *retval;
    aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;

    AVB_TRACE_ENTRY(AVB_TRACE_INTF);

    free(pPvtData->interfaceName);
    free(pPvtData->sessionName);
    free(pPvtData->multicastAddress);

    if (__sync_sub_and_fetch(&gAES67InstanceCount, 1) == 0) {
	pthread_cancel(gSapMonitorThread);
	pthread_join(gSapMonitorThread, &retval);

	pthread_cancel(gSapAnnouncerThread);
	pthread_join(gSapAnnouncerThread, &retval);
    }

    AVB_TRACE_EXIT(AVB_TRACE_INTF);
}

static void
aes67InitializeGlobals(void)
{
    int res;
    pthread_attr_t attr;

    gSapRemoteAdvertisements = openavbListNewList();
    gSapLocalAdvertisements = openavbListNewList();

    res = pthread_attr_init(&attr);
    if (res == 0)
	res = pthread_create(&gSapMonitorThread, &attr, openavbIntfAES67SapMonitorThread, NULL);
    if (res == 0)
	res = pthread_create(&gSapAnnouncerThread, &attr, openavbIntfAES67SapAnnouncerThread, NULL);
}

extern DLL_EXPORT bool
openavbIntfAES67Initialize(media_q_t *pMediaQ, openavb_intf_cb_t *pIntfCB)
{
    AVB_TRACE_ENTRY(AVB_TRACE_INTF);

    pthread_once(&gAES67InitializeOnce, aes67InitializeGlobals);

    osalAVBGrandmasterInit();

    if (pMediaQ) {
        pMediaQ->pPvtIntfInfo = calloc(1, sizeof(aes67_pvt_data_t));
        if (pMediaQ->pPvtIntfInfo == NULL) {
            AVB_LOG_ERROR("Unable to allocate memory for AES67 interface module.");
            return false;
        }

	aes67_pvt_data_t *pPvtData = pMediaQ->pPvtIntfInfo;
	pPvtData->rtpSocket.fd = -1;
	pPvtData->audioRate = AVB_AUDIO_RATE_48KHZ;
	pPvtData->audioChannels = AVB_AUDIO_CHANNELS_8;
	pPvtData->audioBitDepth = AVB_AUDIO_BIT_DEPTH_24BIT;
	pPvtData->ptpClockFd = -1;
	pPvtData->ptpClockId = CLOCK_INVALID;
	pPvtData->avbRole = AVB_ROLE_UNDEFINED;
	pPvtData->randomSeed = 1;
	pPvtData->hwtsEnabled = true;
	pPvtData->dscpValue = RTP_DSCP_VALUE;
	pPvtData->socketPriority = -1;

        pIntfCB->intf_cfg_cb = openavbIntfAES67CfgCB;
        pIntfCB->intf_gen_init_cb = openavbIntfAES67GenInitCB;
        pIntfCB->intf_tx_init_cb = openavbIntfAES67TxInitCB;
        pIntfCB->intf_tx_cb = openavbIntfAES67TxCB;
        pIntfCB->intf_rx_init_cb = openavbIntfAES67RxInitCB;
        pIntfCB->intf_rx_cb = openavbIntfAES67RxCB;
        pIntfCB->intf_end_cb = openavbIntfAES67EndCB;
        pIntfCB->intf_gen_end_cb = openavbIntfAES67GenEndCB;
    }

    AVB_TRACE_EXIT(AVB_TRACE_INTF);

    return true;
}
