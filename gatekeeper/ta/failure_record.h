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

#ifndef FAILURE_RECORD_H
#define FAILURE_RECORD_H

#include <stdint.h>
#include <stdbool.h>
#include "ta_gatekeeper.h"

#define HMAC_SHA256_KEY_SIZE_BYTE 32
#define HMAC_SHA256_KEY_SIZE_BIT (8 * HMAC_SHA256_KEY_SIZE_BYTE)

struct __attribute__((packed)) mem_failure_record_t {
  gatekeeper_failure_record_t failure_record;
  uint32_t uid;
};

/*
 * Checks if the gatekeeper implementation is hardware-backed
 * @param dev Pointer to the gatekeeper device
 * @return true if the implementation is hardware-backed, false otherwise
 */
bool is_hardware_backed(gatekeeper_device_t *dev);

/*
 * Initialize secure keys for the TA
 */
TEE_Result init_secure_keys(void);

/*
 * Writes an authentication failure record to secure storage
 * @param dev Pointer to the gatekeeper device
 * @param uid User ID for Android user
 * @param record Pointer to the failure record to be written
 * @param secure Flag indicating whether to use secure storage
 * @return true on success, false on failure
 */
bool WriteFailureRecord(gatekeeper_device_t *dev, uint32_t uid,
                        gatekeeper_failure_record_t *record, bool secure);

/*
 * Retrieves an authentication failure record from secure storage
 * @param dev Pointer to the gatekeeper device
 * @param uid User ID for Android user
 * @param user_id Secure identifier for the user
 * @param record Pointer where the retrieved failure record will be stored
 * @param secure Flag indicating whether to use secure storage
 * @return true on success, false if record not found or error
 */
bool GetFailureRecord(gatekeeper_device_t *dev, uint32_t uid,
                      gatekeeper_secure_id_t user_id,
                      gatekeeper_failure_record_t *record, bool secure);

/*
 * Removes an authentication failure record from secure storage
 * @param dev Pointer to the gatekeeper device
 * @param uid User ID for Android user
 * @param user_id Secure identifier for the user
 * @param secure Flag indicating whether to use secure storage
 * @return true on success, false on failure
 */
bool ClearFailureRecord(gatekeeper_device_t * dev, uint32_t uid,
                        gatekeeper_secure_id_t user_id, bool secure);

/*
 * Retrieves the master key used for password hashing
 * @param dev Pointer to the gatekeeper device
 * @param password_key Pointer to be updated with the key buffer
 * @param length Pointer to be updated with the key length
 */
void GetMasterKey(gatekeeper_device_t *dev, const uint8_t **password_key, uint32_t *length);

/*
 * @return current secure timestamp
 */
uint64_t GetTimestamp(gatekeeper_device_t *dev);

/*
 * Secure storage ID generation with protection against directory traversal
 */
void generate_storage_id(char *storage_id, size_t size, secure_id_t user_id);

/*
 * Delete a user from secure storage
 */
gatekeeper_error_t delete_user(gatekeeper_device_t *dev, secure_id_t user_id);

/*
 * Delete all users from secure storage
 */
gatekeeper_error_t delete_all_users(gatekeeper_device_t *dev);

/*
 * Add user to registry for tracking
 */
TEE_Result add_user_to_registry(secure_id_t user_id);

/*
 * Remove user from registry
 */
TEE_Result remove_user_from_registry(secure_id_t user_id);

#endif /* FAILURE_RECORD_H */
