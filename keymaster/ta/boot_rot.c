// SPDX-License-Identifier: Apache-2.0
/* Verified boot root of trust from OP-TEE's boot_rot PTA, set by the bootloader after AVB */

#include <pta_boot_rot.h>
#include <tee_internal_api.h>

#include "boot_rot.h"

TEE_Result TA_get_boot_rot(avb_root_of_trust_t *out)
{
	const TEE_UUID uuid = PTA_BOOT_ROT_UUID;
	uint32_t ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param params[TEE_NUM_PARAMS];
	struct pta_boot_rot rot;
	TEE_Result res;

	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, NULL);
	if (res != TEE_SUCCESS)
		return res;
	TEE_MemFill(params, 0, sizeof(params));
	params[0].memref.buffer = &rot;
	params[0].memref.size = sizeof(rot);
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, PTA_BOOT_ROT_CMD_GET,
				  ptypes, params, NULL);
	TEE_CloseTASession(sess);
	if (res != TEE_SUCCESS)
		return res;

	TEE_MemFill(out, 0, sizeof(*out));
	TEE_MemMove(out->verified_boot_key, rot.verified_boot_key,
		    sizeof(out->verified_boot_key));
	TEE_MemMove(out->verified_boot_hash, rot.verified_boot_hash,
		    sizeof(out->verified_boot_hash));
	out->device_locked = rot.device_locked;
	out->verified_boot_state = rot.verified_boot_state;
	return TEE_SUCCESS;
}
