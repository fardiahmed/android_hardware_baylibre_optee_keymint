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

#ifndef TA_GATEKEEPER_H
#define TA_GATEKEEPER_H

#include "gatekeeper.h"
#include "gatekeeper_messages.h"
#include <compiler.h>
#include <stdint.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#define AUTH_KEY_OFFSET 4
#define HW_AUTH_TOKEN_VERSION 0

/*
 * Please keep password_handle_t structure consistent with its counterpart
 * which defined in system/gatekeeper/include/gatekeeper/password_handle.h
 */

#define HANDLE_VERSION 2

// Android Gatekeeper structures
typedef uint64_t secure_id_t;
// Security constants
#define SECURE_KEY_SIZE             32
#define MAX_FAILED_ATTEMPTS 5
#define THROTTLE_FACTOR             30  // seconds per failure
#define KEY_DERIVATION_ROUNDS       100
#define PASSWORD_LIFECYCLE_SEC      (90 * 24 * 60 * 60)  // 90 days in seconds

typedef enum {
  HW_AUTH_NONE = 0,
  HW_AUTH_PASSWORD = 1 << 0,
  HW_AUTH_FINGERPRINT = 1 << 1,
  // Additional entries should be powers of 2.
  HW_AUTH_ANY = (int)((uint32_t)~0U)
} hw_authenticator_type_t;

/*
 * Please keep this variable consistent with TA_UUID variable that
 * is defined in Keymaster Android.mk file
 */
#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
	                { 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

/*
 * Please keep this define consistent with KM_GET_AUTHTOKEN_KEY constant that
 * is defined in Keymaster
 */
#define KM_GET_AUTHTOKEN_KEY 0x10000
#endif /* TA_GATEKEEPER_H */
