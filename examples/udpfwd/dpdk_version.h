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

#ifndef DPDK_VERSION_H_
#define DPDK_VERSION_H_

#include <rte_version.h>

#ifdef RTE_VER_MAJOR
#if RTE_VER_MAJOR >= 16 && RTE_VER_MINOR >= 4
#define DPDK_VERSION_GE_1604
#endif
#elif defined(RTE_VER_YEAR)
#if RTE_VER_YEAR >= 16 && RTE_VER_MONTH >= 4
#define DPDK_VERSION_GE_1604
#endif
#else
#error "RTE_VER_MAJOR and RTE_VER_YEAR are undefined!"
#endif

#endif /* DPDK_VERSION_H_ */
