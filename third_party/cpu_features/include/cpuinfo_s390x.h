// Copyright 2022 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef CPU_FEATURES_INCLUDE_CPUINFO_S390X_H_
#define CPU_FEATURES_INCLUDE_CPUINFO_S390X_H_

#include "cpu_features_macros.h"
#include "cpu_features_cache_info.h"
#include "internal/hwcaps.h"

CPU_FEATURES_START_CPP_NAMESPACE

typedef struct {
  int esan3 : 1;
  int zarch : 1;
  int stfle : 1;
  int msa : 1;
  int ldisp : 1;
  int eimm : 1;
  int dfp : 1;
  int edat : 1;
  int etf3eh : 1;
  int highgprs : 1;
  int te : 1;
  int vx : 1;
  int vxd : 1;
  int vxe : 1;
  int gs : 1;
  int vxe2 : 1;
  int vxp : 1;
  int sort : 1;
  int dflt : 1;
  int vxp2 : 1;
  int nnpa : 1;
  int pcimio : 1;
  int sie : 1;
  // Make sure to update S390XFeaturesEnum below if you add a field here.
} S390XFeatures;

typedef struct {
  S390XFeatures features;
} S390XInfo;

// This function is guaranteed to be malloc, memset and memcpy free.
S390XInfo GetS390XInfo(void);

typedef struct {
  char platform[64];  // 0 terminated string
  char machine[64];   // 0 terminated string
  char num_processors[64];       // 0 terminated string
  PlatformType type;
} S390XPlatformStrings;

S390XPlatformStrings GetS390XPlatformStrings(void);

////////////////////////////////////////////////////////////////////////////////
// Introspection functions

typedef enum {
  S390X_ESAN3,        /* instructions named N3, "backported" to esa-mode */
  S390X_ZARCH,        /* z/Architecture mode active */
  S390X_STFLE,        /*  */
  S390X_MSA,          /* message-security assist */
  S390X_LDISP,        /* long-displacement */
  S390X_EIMM,          /* extended-immediate */
  S390X_DFP,          /* decimal floating point & perform floating point
                         operation */
  S390X_EDAT,         /* huge page support */
  S390X_ETF3EH,       /*  */
  S390X_HIGHGPRS,     /* 64-bit register support for 31-bit processes */
  S390X_TE,           /* transactional execution */
  S390X_VX,           /* vector extension */
  S390X_VXD,          /*  */
  S390X_VXE,          /*  */
  S390X_GS,           /* guarded storage */
  S390X_VXE2,         /*  */
  S390X_VXP,          /*  */
  S390X_SORT,         /*  */
  S390X_DFLT,         /*  */
  S390X_VXP2,         /*  */
  S390X_NNPA,         /*  */
  S390X_PCIMIO,       /*  */
  S390X_SIE,          /* virtualization support */
  S390X_LAST_,
} S390XFeaturesEnum;

int GetS390XFeaturesEnumValue(const S390XFeatures* features, S390XFeaturesEnum value);

const char* GetS390XFeaturesEnumName(S390XFeaturesEnum);

CPU_FEATURES_END_CPP_NAMESPACE

#if !defined(CPU_FEATURES_ARCH_S390X)
  #error Including cpuinfo_s390x.h from a non-s390x target.
#endif

#endif  // CPU_FEATURES_INCLUDE_CPUINFO_S390X_H_
