/*
 * Copyright (c) 2018  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * Definitions of TLDK version numbers
 * Follows DPDK version convention.
 */

#ifndef _TLE_VERSION_H_
#define _TLE_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

/**
 * Major version/year number i.e. the yy in yy.mm.z
 */
#define TLE_VER_YEAR 18

/**
 * Minor version/month number i.e. the mm in yy.mm.z
 */
#define TLE_VER_MONTH 2

/**
 * Patch level number i.e. the z in yy.mm.z
 */
#define TLE_VER_MINOR 0

/**
 * Patch release number
 *   0-15 = release candidates
 *   16   = release
 */
#define TLE_VER_RELEASE 16

/**
 * Macro to compute a version number usable for comparisons
 */
#define TLE_VERSION_NUM(a, b, c, d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))

/**
 * All version numbers in one to compare with RTE_VERSION_NUM()
 */
#define TLE_VERSION TLE_VERSION_NUM( \
			TLE_VER_YEAR, \
			TLE_VER_MONTH, \
			TLE_VER_MINOR, \
			TLE_VER_RELEASE)

static const char * const tle_version = "TLDK "
#if (TLE_VER_YEAR < 10)
			"0"
#endif
			RTE_STR(TLE_VER_YEAR) "."
#if (TLE_VER_MONTH < 10)
			"0"
#endif
			RTE_STR(TLE_VER_MONTH) "."
			RTE_STR(TLE_VER_MINOR)
#if (TLE_VER_RELEASE < 16)
			"rc-" RTE_STR(TLE_VER_RELEASE)
#endif
			"";

#ifdef __cplusplus
}
#endif

#endif /* _TLE_VERSION_H_ */
