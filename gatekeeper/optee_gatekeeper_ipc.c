/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "OpteeGateKeeper"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <log/log.h>

#include <tee_client_api.h>

#include <gatekeeper_ipc.h>
#include "optee_gatekeeper_ipc.h"

static bool inUse = false;
static TEEC_Context ctx;
static TEEC_Session sess;

int optee_gatekeeper_connect() {
    TEEC_Result res;
    TEEC_UUID uuid = TA_GATEKEEPER_UUID;
    uint32_t err_origin;

    if (inUse) {
        ALOGE("Is already connected");
        return false;
    }

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_InitializeContext failed with code 0x%x", res);
        return false;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
                           NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_Opensession failed with code 0x%x origin 0x%x",
              res, err_origin);
        return false;
    }

    inUse = true;

    return true;
}

int optee_gatekeeper_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t *out,
                          uint32_t *out_size) {
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = in;
    op.params[0].tmpref.size = in_size;

    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size = *out_size;

    uint32_t err_origin;
    TEEC_Result res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_InvokeCommand failed with code 0x%08x origin 0x%08x",
              res, err_origin);
        if (res == TEEC_ERROR_TARGET_DEAD) {
            optee_gatekeeper_disconnect();
            optee_gatekeeper_connect();
        }
        return -EINVAL;
    }

    return 0;
}

void optee_gatekeeper_disconnect() {
    if (inUse) {
        TEEC_FinalizeContext(&ctx);
        TEEC_CloseSession(&sess);
    }

    inUse = false;
}
