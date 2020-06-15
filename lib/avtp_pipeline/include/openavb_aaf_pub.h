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

/*
 * MODULE SUMMARY : AAF Audio Types Public
 */

#ifndef AVB_AAF_PUB_H
#define AVB_AAF_PUB_H 1

typedef enum {
	AAF_RATE_UNSPEC = 0,
	AAF_RATE_8K,
	AAF_RATE_16K,
	AAF_RATE_32K,
	AAF_RATE_44K1,
	AAF_RATE_48K,
	AAF_RATE_88K2,
	AAF_RATE_96K,
	AAF_RATE_176K4,
	AAF_RATE_192K,
	AAF_RATE_24K,
} aaf_nominal_sample_rate_t;

typedef enum {
	AAF_FORMAT_UNSPEC = 0,
	AAF_FORMAT_FLOAT_32,
	AAF_FORMAT_INT_32,
	AAF_FORMAT_INT_24,
	AAF_FORMAT_INT_16,
	AAF_FORMAT_AES3_32, // AVDECC_TODO:  Implement this
} aaf_sample_format_t;

typedef enum {
	AAF_STATIC_CHANNELS_LAYOUT      = 0,
	AAF_MONO_CHANNELS_LAYOUT        = 1,
	AAF_STEREO_CHANNELS_LAYOUT      = 2,
	AAF_5_1_CHANNELS_LAYOUT         = 3,
	AAF_7_1_CHANNELS_LAYOUT         = 4,
	AAF_MAX_CHANNELS_LAYOUT         = 15,
} aaf_automotive_channels_layout_t;

typedef enum {
	// Disabled - timestamp is valid in every avtp packet
	TS_SPARSE_MODE_DISABLED         = 0,
	// Enabled - timestamp is valid in every 8th avtp packet
	TS_SPARSE_MODE_ENABLED          = 1
} avb_audio_sparse_mode_t;

#endif // AVB_AAF_PUB_H
