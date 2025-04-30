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

#ifndef GATEKEEPER_IPC_H
#define GATEKEEPER_IPC_H

#include <stdint.h>
#include <string.h>

/*
 * Please keep this define consistent with TA_UUID variable that defined
 * in Android.mk file
 */
#define TA_GATEKEEPER_UUID { 0x4d573443, 0x6a56, 0x4272, \
		{ 0xac, 0x6f, 0x24, 0x25, 0xaf, 0x9e, 0xf9, 0xbb} }

/*
 * GateKeeper command identifier
 */
typedef enum {
	GK_ENROLL,
	GK_VERIFY,
	GK_DELETE_USER,
	GK_DELETE_ALL_USERS,
} gatekeeper_command_t;

/*
 * GateKeeper messages error codes
 */
typedef enum {
	ERROR_NONE = 0,
	ERROR_INVALID,
	ERROR_RETRY,
	ERROR_UNKNOWN,
} gatekeeper_error_t;

/*
 * GateKeeper message size
 */

constexpr const uint32_t SEND_BUF_SIZE = 8192;
constexpr const uint32_t RECV_BUF_SIZE = 8192;
#define GATEKEEPER_MAX_BUFFER_LENGTH (RECV_BUF_SIZE-sizeof(uint32_t))
		
struct gatekeeper_message {
    uint32_t cmd;
    uint8_t payload[0];
};

#endif /* GATEKEEPER_IPC_H */
