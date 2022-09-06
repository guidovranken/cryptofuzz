// Copyright 2022 IBM.
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

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "cpuinfo_s390x.h"
#include "internal/bit_utils.h"
#include "internal/filesystem.h"
#include "internal/stack_line_reader.h"
#include "internal/string_view.h"
#include "internal/unix_features_aggregator.h"

DECLARE_SETTER(S390XFeatures, esan3)
DECLARE_SETTER(S390XFeatures, zarch)
DECLARE_SETTER(S390XFeatures, stfle)
DECLARE_SETTER(S390XFeatures, msa)
DECLARE_SETTER(S390XFeatures, ldisp)
DECLARE_SETTER(S390XFeatures, eimm)
DECLARE_SETTER(S390XFeatures, dfp)
DECLARE_SETTER(S390XFeatures, edat)
DECLARE_SETTER(S390XFeatures, etf3eh)
DECLARE_SETTER(S390XFeatures, highgprs)
DECLARE_SETTER(S390XFeatures, te)
DECLARE_SETTER(S390XFeatures, vx)
DECLARE_SETTER(S390XFeatures, vxd)
DECLARE_SETTER(S390XFeatures, vxe)
DECLARE_SETTER(S390XFeatures, gs)
DECLARE_SETTER(S390XFeatures, vxe2)
DECLARE_SETTER(S390XFeatures, vxp)
DECLARE_SETTER(S390XFeatures, sort)
DECLARE_SETTER(S390XFeatures, dflt)
DECLARE_SETTER(S390XFeatures, vxp2)
DECLARE_SETTER(S390XFeatures, nnpa)
DECLARE_SETTER(S390XFeatures, pcimio)
DECLARE_SETTER(S390XFeatures, sie)

static const CapabilityConfig kConfigs[] = {
  [S390X_ESAN3] = {{HWCAP_S390_ESAN3, 0}, "esan3", &set_esan3},
  [S390X_ZARCH] = {{HWCAP_S390_ZARCH, 0}, "zarch", &set_zarch},
  [S390X_STFLE] = {{HWCAP_S390_STFLE, 0}, "stfle", &set_stfle},
  [S390X_MSA] = {{HWCAP_S390_MSA, 0}, "msa", &set_msa},
  [S390X_LDISP] = {{HWCAP_S390_LDISP, 0}, "ldisp", &set_ldisp},
  [S390X_EIMM] = {{HWCAP_S390_EIMM, 0}, "eimm", &set_eimm},
  [S390X_DFP] = {{HWCAP_S390_DFP, 0}, "dfp", &set_dfp},
  [S390X_EDAT] = {{HWCAP_S390_HPAGE, 0}, "edat", &set_edat},
  [S390X_ETF3EH] = {{HWCAP_S390_ETF3EH, 0}, "etf3eh", &set_etf3eh},
  [S390X_HIGHGPRS] = {{HWCAP_S390_HIGH_GPRS, 0}, "highgprs", &set_highgprs},
  [S390X_TE] = {{HWCAP_S390_TE, 0}, "te", &set_te},
  [S390X_VX] = {{HWCAP_S390_VXRS, 0}, "vx", &set_vx},
  [S390X_VXD] = {{HWCAP_S390_VXRS_BCD, 0}, "vxd", &set_vxd},
  [S390X_VXE] = {{HWCAP_S390_VXRS_EXT, 0}, "vxe", &set_vxe},
  [S390X_GS] = {{HWCAP_S390_GS, 0}, "gs", &set_gs},
  [S390X_VXE2] = {{HWCAP_S390_VXRS_EXT2, 0}, "vxe2", &set_vxe2},
  [S390X_VXP] = {{HWCAP_S390_VXRS_PDE, 0}, "vxp", &set_vxp},
  [S390X_SORT] = {{HWCAP_S390_SORT, 0}, "sort", &set_sort},
  [S390X_DFLT] = {{HWCAP_S390_DFLT, 0}, "dflt", &set_dflt},
  [S390X_VXP2] = {{HWCAP_S390_VXRS_PDE2, 0}, "vxp2", &set_vxp2},
  [S390X_NNPA] = {{HWCAP_S390_NNPA, 0}, "nnpa", &set_nnpa},
  [S390X_PCIMIO] = {{HWCAP_S390_PCI_MIO, 0}, "pcimio", &set_pcimio},
  [S390X_SIE] = {{HWCAP_S390_SIE, 0}, "sie", &set_sie},
};
static const size_t kConfigsSize = sizeof(kConfigs) / sizeof(CapabilityConfig);

static bool HandleS390XLine(const LineResult result,
                          S390XPlatformStrings* const strings) {
  StringView line = result.line;
  StringView key, value;
  if (CpuFeatures_StringView_GetAttributeKeyValue(line, &key, &value)) {
    if (CpuFeatures_StringView_HasWord(key, "processors")) {
      CpuFeatures_StringView_CopyString(value, strings->num_processors,
                                        sizeof(strings->platform));
    } else if (CpuFeatures_StringView_IsEquals(key, str("machine"))) {
      CpuFeatures_StringView_CopyString(value, strings->machine,
                                        sizeof(strings->platform));
    }
  }
  return !result.eof;
}

static void FillProcCpuInfoData(S390XPlatformStrings* const strings) {
  const int fd = CpuFeatures_OpenFile("/proc/cpuinfo");
  if (fd >= 0) {
    StackLineReader reader;
    StackLineReader_Initialize(&reader, fd);
    for (;;) {
      if (!HandleS390XLine(StackLineReader_NextLine(&reader), strings)) {
        break;
      }
    }
    CpuFeatures_CloseFile(fd);
  }
}

static const S390XInfo kEmptyS390XInfo;

S390XInfo GetS390XInfo(void) {
  S390XInfo info = kEmptyS390XInfo;

  CpuFeatures_OverrideFromHwCaps(kConfigsSize, kConfigs,
                                 CpuFeatures_GetHardwareCapabilities(),
                                 &info.features);
  return info;
}

static const S390XPlatformStrings kEmptyS390XPlatformStrings;

S390XPlatformStrings GetS390XPlatformStrings(void) {
  S390XPlatformStrings strings = kEmptyS390XPlatformStrings;

  FillProcCpuInfoData(&strings);
  strings.type = CpuFeatures_GetPlatformType();
  return strings;
}

////////////////////////////////////////////////////////////////////////////////
// Introspection functions

int GetS390XFeaturesEnumValue(const S390XFeatures* features,
                            S390XFeaturesEnum value) {
  switch (value) {
    case S390X_ESAN3:
      return features->esan3;
    case S390X_ZARCH:
      return features->zarch;
    case S390X_STFLE:
      return features->stfle;
    case S390X_MSA:
      return features->msa;
    case S390X_LDISP:
      return features->ldisp;
    case S390X_EIMM:
      return features->eimm;
    case S390X_DFP:
      return features->dfp;
    case S390X_EDAT:
      return features->edat;
    case S390X_ETF3EH:
      return features->etf3eh;
    case S390X_HIGHGPRS:
      return features->highgprs;
    case S390X_TE:
      return features->te;
    case S390X_VX:
      return features->vx;
    case S390X_VXD:
      return features->vxd;
    case S390X_VXE:
      return features->vxe;
    case S390X_GS:
      return features->gs;
    case S390X_VXE2:
      return features->vxe2;
    case S390X_VXP:
      return features->vxp;
    case S390X_SORT:
      return features->sort;
    case S390X_DFLT:
      return features->dflt;
    case S390X_VXP2:
      return features->vxp2;
    case S390X_NNPA:
      return features->nnpa;
    case S390X_PCIMIO:
      return features->pcimio;
    case S390X_SIE:
      return features->sie;
    case S390X_LAST_:
      break;
  }
  return false;
}

/* Have used the same names as glibc  */
const char* GetS390XFeaturesEnumName(S390XFeaturesEnum value) {
  if(value >= kConfigsSize)
    return "unknown feature";
  return kConfigs[value].proc_cpuinfo_flag;
}
