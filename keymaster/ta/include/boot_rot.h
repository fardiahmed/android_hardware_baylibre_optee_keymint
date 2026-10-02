/* SPDX-License-Identifier: Apache-2.0 */
/* Verified boot root of trust from OP-TEE's boot_rot PTA, set by the bootloader after AVB */
#ifndef BOOT_ROT_H
#define BOOT_ROT_H

#include <tee_internal_api.h>
#include "ta_ca_defs.h"

/* TEE_ERROR_ITEM_NOT_FOUND when the bootloader did not set it */
TEE_Result TA_get_boot_rot(avb_root_of_trust_t *out);

#endif /* BOOT_ROT_H */
