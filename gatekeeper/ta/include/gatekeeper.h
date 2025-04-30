/*
 * Copyright 2023 The Android Open Source Project
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

#ifndef GATEKEEPER_C_H_
#define GATEKEEPER_C_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
typedef enum {
    ERROR_NONE = 0,
    ERROR_INVALID = 1,
    ERROR_RETRY = 2,
    ERROR_UNKNOWN = 3,
    ERROR_MEMORY_ALLOCATION_FAILED = 4,
    ERROR_NOT_IMPLEMENTED = 5,
} gatekeeper_error_t;

/* Handle flags */
#define GATEKEEPER_HANDLE_FLAG_THROTTLE_SECURE 1

/* Handle versions */
#define GATEKEEPER_HANDLE_VERSION         2
#define GATEKEEPER_HANDLE_VERSION_THROTTLE 2

/* Time constants */
#define GATEKEEPER_DAY_IN_MS (1000 * 60 * 60 * 24)

/* Type definitions */
typedef uint64_t gatekeeper_secure_id_t;
typedef uint64_t gatekeeper_salt_t;

/* Buffer struct to replace SizedBuffer */
typedef struct {
    uint8_t *buffer;
    uint32_t length;
} gatekeeper_buffer_t;

/* Password handle structure */
typedef struct __attribute__ ((__packed__)) {
    // fields included in signature
    uint8_t version;
    gatekeeper_secure_id_t user_id;
    uint64_t flags;

    // fields not included in signature
    gatekeeper_salt_t salt;
    uint8_t signature[32];

    bool hardware_backed;
} gatekeeper_password_handle_t;

/* Failure record structure */
typedef struct __attribute__((packed)) {
    uint64_t secure_user_id;
    uint64_t last_checked_timestamp;
    uint32_t failure_counter;
} gatekeeper_failure_record_t;

/* Hardware auth token structure */
typedef struct __attribute__ ((packed)) {
    uint8_t version;
    uint64_t challenge;
    uint64_t user_id;
    uint64_t authenticator_id;
    uint32_t authenticator_type;
    uint64_t timestamp;
    uint8_t hmac[32];
} gatekeeper_hw_auth_token_t;

/* Message structures */
typedef struct __attribute__((packed)) {
  gatekeeper_error_t error;
  uint32_t user_id;
  uint32_t retry_timeout;
} gatekeeper_message_t;

typedef struct {
    gatekeeper_message_t base;
    uint64_t challenge;
    gatekeeper_buffer_t password_handle;
    gatekeeper_buffer_t provided_password;
} gatekeeper_verify_request_t;

typedef struct {
    gatekeeper_message_t base;
    gatekeeper_buffer_t auth_token;
    bool request_reenroll;
} gatekeeper_verify_response_t;

typedef struct {
    gatekeeper_message_t base;
    gatekeeper_buffer_t password_handle;
    gatekeeper_buffer_t enrolled_password;
    gatekeeper_buffer_t provided_password;
} gatekeeper_enroll_request_t;

typedef struct {
    gatekeeper_message_t base;
    gatekeeper_buffer_t enrolled_password_handle;
} gatekeeper_enroll_response_t;

typedef struct {
    gatekeeper_message_t base;
} gatekeeper_delete_user_request_t;

typedef struct {
    gatekeeper_message_t base;
} gatekeeper_delete_user_response_t;

typedef struct {
    gatekeeper_message_t base;
} gatekeeper_delete_all_users_request_t;

typedef struct {
    gatekeeper_message_t base;
} gatekeeper_delete_all_users_response_t;

/*
 * GateKeeper implementation structure.
 * This replaces the C++ abstract class with function pointers to implement
 * the platform-specific methods.
 */
typedef struct gatekeeper_device gatekeeper_device_t;

struct gatekeeper_device {
    /* Implementation data field */
    void *impl;

    /* Platform-specific implementation methods */
    bool (*get_auth_token_key)(gatekeeper_device_t *dev, const uint8_t **auth_token_key, uint32_t *length);
    void (*get_password_key)(gatekeeper_device_t *dev, const uint8_t **password_key, uint32_t *length);
    void (*compute_password_signature)(gatekeeper_device_t *dev,
                                      uint8_t *signature, uint32_t signature_length,
                                      const uint8_t *key, uint32_t key_length,
                                      const uint8_t *password, uint32_t password_length,
                                      gatekeeper_salt_t salt);
    void (*get_random)(gatekeeper_device_t *dev, void *random, uint32_t requested_size);
    void (*compute_signature)(gatekeeper_device_t *dev,
                             uint8_t *signature, uint32_t signature_length,
                             const uint8_t *key, uint32_t key_length,
                             const uint8_t *message, const uint32_t length);
    uint64_t (*get_milliseconds_since_boot)(gatekeeper_device_t *dev);
    gatekeeper_error_t (*remove_user)(gatekeeper_device_t *dev,
                                      gatekeeper_secure_id_t uid);
    gatekeeper_error_t (*remove_all_users)(gatekeeper_device_t *dev);
    bool (*get_failure_record)(gatekeeper_device_t *dev, uint32_t uid, gatekeeper_secure_id_t user_id,
                             gatekeeper_failure_record_t *record, bool secure);
    bool (*clear_failure_record)(gatekeeper_device_t *dev, uint32_t uid, gatekeeper_secure_id_t user_id, bool secure);
    bool (*write_failure_record)(gatekeeper_device_t *dev, uint32_t uid, gatekeeper_failure_record_t *record, bool secure);
    bool (*is_hardware_backed)(gatekeeper_device_t *dev);
};

/* Buffer manipulation functions */
void gatekeeper_buffer_init(gatekeeper_buffer_t *buffer);
void gatekeeper_buffer_free(gatekeeper_buffer_t *buffer);
bool gatekeeper_buffer_allocate(gatekeeper_buffer_t *buffer, uint32_t length);
bool gatekeeper_buffer_copy(gatekeeper_buffer_t *dest, const gatekeeper_buffer_t *src);
bool gatekeeper_buffer_is_valid(const gatekeeper_buffer_t *buffer);

/* Main GateKeeper interface functions */
void gatekeeper_enroll(gatekeeper_device_t *dev,
                     const gatekeeper_enroll_request_t *request,
                     gatekeeper_enroll_response_t *response);

void gatekeeper_verify(gatekeeper_device_t *dev,
                     const gatekeeper_verify_request_t *request,
                     gatekeeper_verify_response_t *response);

void gatekeeper_delete_user(gatekeeper_device_t *dev,
                          const gatekeeper_delete_user_request_t *request,
                          gatekeeper_delete_user_response_t *response);

void gatekeeper_delete_all_users(gatekeeper_device_t *dev,
                               const gatekeeper_delete_all_users_request_t *request,
                               gatekeeper_delete_all_users_response_t *response);

/* Helper functions */
bool gatekeeper_create_password_handle(gatekeeper_device_t *dev,
                                     gatekeeper_buffer_t *password_handle_buffer,
                                     gatekeeper_salt_t salt,
                                     gatekeeper_secure_id_t user_id,
                                     uint64_t flags,
                                     uint8_t handle_version,
                                     const gatekeeper_buffer_t *password);

bool gatekeeper_do_verify(gatekeeper_device_t *dev,
                        const gatekeeper_password_handle_t *expected_handle,
                        const gatekeeper_buffer_t *password);

gatekeeper_error_t gatekeeper_mint_auth_token(gatekeeper_device_t *dev,
                                            gatekeeper_buffer_t *auth_token,
                                            uint64_t timestamp,
                                            gatekeeper_secure_id_t user_id,
                                            gatekeeper_secure_id_t authenticator_id,
                                            uint64_t challenge);

uint32_t gatekeeper_compute_retry_timeout(const gatekeeper_failure_record_t *record);

bool gatekeeper_throttle_request(gatekeeper_device_t *dev,
                               uint32_t uid,
                               uint64_t timestamp,
                               gatekeeper_failure_record_t *record,
                               bool secure,
                               gatekeeper_message_t *response);

bool gatekeeper_increment_failure_record(gatekeeper_device_t *dev,
                                       uint32_t uid,
                                       gatekeeper_secure_id_t user_id,
                                       uint64_t timestamp,
                                       gatekeeper_failure_record_t *record,
                                       bool secure);

/* Message serialization/deserialization */
uint32_t gatekeeper_message_get_serialized_size(const gatekeeper_message_t *message);
uint32_t gatekeeper_message_serialize(const gatekeeper_message_t *message, uint8_t *payload, const uint8_t *end);
gatekeeper_error_t gatekeeper_message_deserialize(gatekeeper_message_t *message, const uint8_t *payload, const uint8_t *end);
void gatekeeper_message_set_retry_timeout(gatekeeper_message_t *message, uint32_t retry_timeout);

#ifdef __cplusplus
}
#endif

#endif /* GATEKEEPER_C_H_ */
