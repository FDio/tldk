/*
 * Copyright (c) 2016  Intel Corporation.
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

#ifndef DPDK_LEGACY_H_
#define DPDK_LEGACY_H_

#include <rte_version.h>

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
typedef uint32_t dpdk_lpm6_idx_t;
#else
typedef uint8_t dpdk_lpm6_idx_t;
#endif

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
typedef uint16_t dpdk_port_t;
#else
typedef uint8_t dpdk_port_t;
#endif

#endif /* DPDK_LEGACY_H_ */
