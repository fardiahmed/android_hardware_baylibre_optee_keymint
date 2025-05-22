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
#include "gatekeeper.h"
#include <stddef.h>
#include <utee_defines.h>


/* Buffer manipulation functions */
void gatekeeper_buffer_init(gatekeeper_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    /* Check for invalid memory addresses (safety check) */
    if (buffer->buffer != NULL) {
        /* Check if the buffer contains a suspiciously high address */
        uintptr_t buffer_addr = (uintptr_t)buffer->buffer;
        if (buffer_addr > 0x1000000000ULL) { /* Very high address - likely invalid */
            /* Skip freeing the invalid buffer and just reset to NULL */
            buffer->buffer = NULL;
            buffer->length = 0;
            return;
        }

        gatekeeper_buffer_free(buffer);
    } else if (buffer->length != 0) {
        /* Just reset length to 0 since buffer is NULL */
        buffer->length = 0;
    }

    /* Initialize to NULL/0 */
    buffer->buffer = NULL;
    buffer->length = 0;
}

void gatekeeper_buffer_free(gatekeeper_buffer_t *buffer) {
    if (!buffer) {
        return;
    }

    /* Validate the state */
    if (buffer->length > 0 && !buffer->buffer) {
        buffer->length = 0;
    }

    /* Check for suspicious buffer address */
    if (buffer->buffer != NULL) {
        uintptr_t buffer_addr = (uintptr_t)buffer->buffer;
        if (buffer_addr > 0x1000000000ULL) { /* Very high address - likely invalid */
            /* Reset to NULL/0 without attempting to free the suspicious pointer */
            buffer->buffer = NULL;
            buffer->length = 0;
            return;
        }
    }

    /* Check for suspiciously large lengths */
    if (buffer->length > 10 * 1024 * 1024) { /* 10MB is definitely wrong */
        buffer->length = 0;
    }

    if (buffer->buffer) {
        if (buffer->length > 0) {
            /* Safely zero memory */
            memset(buffer->buffer, 0, buffer->length);
        }

        free(buffer->buffer);
        buffer->buffer = NULL;
        buffer->length = 0;
    } else {
        /* Reset length for consistency */
        if (buffer->length != 0) {
            buffer->length = 0;
        }
    }
}

bool gatekeeper_buffer_allocate(gatekeeper_buffer_t *buffer, uint32_t length) {
    if (!buffer) {
        return false;
    }

    /* Free any existing buffer */
    gatekeeper_buffer_free(buffer);

    /* Verify buffer was properly freed */
    if (buffer->buffer != NULL || buffer->length != 0) {
        return false;
    }

    /* Handle zero-length request */
    if (length == 0) {
        return true;
    }

    /* Perform the allocation */
    buffer->buffer = (uint8_t*)malloc(length);

    if (!buffer->buffer) {
        return false;
    }

    /* Set length and return success */
    buffer->length = length;

    /* Zero out the memory for security */
    memset(buffer->buffer, 0, length);

    return true;
}

bool gatekeeper_buffer_copy(gatekeeper_buffer_t *dest, const gatekeeper_buffer_t *src) {
    if (!dest || !src) {
        return false;
    }

    /* Check for empty source buffer */
    if (!src->buffer || src->length == 0) {
        /* Free destination */
        gatekeeper_buffer_free(dest);
        return true;
    }

    /* Allocate destination buffer */
    if (!gatekeeper_buffer_allocate(dest, src->length)) {
        return false;
    }

    /* Verify destination was properly allocated */
    if (!dest->buffer || dest->length != src->length) {
        gatekeeper_buffer_free(dest);
        return false;
    }

    /* Perform copy */
    memcpy(dest->buffer, src->buffer, src->length);

    return true;
}


bool gatekeeper_buffer_is_valid(const gatekeeper_buffer_t *buffer) {
    return buffer && buffer->buffer && buffer->length > 0;
}

/* Message functions */
/* Serial header structure - must match the C++ serial_header_t exactly */
struct __attribute__((__packed__)) gatekeeper_serial_header {
    uint32_t error;
    uint32_t user_id;
};

uint32_t gatekeeper_message_get_serialized_size(const gatekeeper_message_t *message) {
    if (!message) return 0;

    /* Base message size is the packed serial header */
    uint32_t size = sizeof(struct gatekeeper_serial_header);

    /* Add retry_timeout field for error cases */
    if (message->error == ERROR_RETRY) {
        size += sizeof(uint32_t);
    }

    return size;
}

uint32_t gatekeeper_message_serialize(const gatekeeper_message_t *message, uint8_t *payload, const uint8_t *end) {
    if (!message || !payload || !end) return 0;

    /* Store original position to calculate bytes written at the end */
    uint8_t *start_payload = payload;

    /* Ensure we have enough space for the header */
    if (payload + sizeof(struct gatekeeper_serial_header) > end) {
        return 0;
    }

    /* Create and write the header */
    struct gatekeeper_serial_header header;
    header.error = message->error;
    header.user_id = message->user_id;

    /* Use a direct copy of the packed structure */
    memcpy(payload, &header, sizeof(header));
    payload += sizeof(header);

    /* For retry errors, write retry timeout */
    if (message->error == ERROR_RETRY) {
        if (payload + sizeof(uint32_t) > end) {
            return 0;
        }
        uint32_t timeout = message->retry_timeout;
        memcpy(payload, &timeout, sizeof(uint32_t));
        payload += sizeof(uint32_t);
    }

    /* Return the number of bytes written */
    return (uint32_t)(payload - start_payload);
}

gatekeeper_error_t gatekeeper_message_deserialize(gatekeeper_message_t *message, const uint8_t *payload, const uint8_t *end) {
    if (!message || !payload || !end) return ERROR_INVALID;

    /* Ensure we have enough data for the header */
    if (payload + sizeof(struct gatekeeper_serial_header) > end) {
        return ERROR_INVALID;
    }

    /* Read the header in one go to match C++ implementation */
    const struct gatekeeper_serial_header *header =
        (const struct gatekeeper_serial_header *)payload;

    message->error = (gatekeeper_error_t)header->error;
    message->user_id = header->user_id;
    payload += sizeof(struct gatekeeper_serial_header);

    /* For retry errors, read retry timeout */
    if (message->error == ERROR_RETRY) {
        if (payload + sizeof(uint32_t) > end) {
            return ERROR_INVALID;
        }
        uint32_t timeout;
        memcpy(&timeout, payload, sizeof(uint32_t));
        message->retry_timeout = timeout;
    } else {
        message->retry_timeout = 0;
    }

    return ERROR_NONE;
}

void gatekeeper_message_set_retry_timeout(gatekeeper_message_t *message, uint32_t retry_timeout) {
    if (!message) return;

    message->error = ERROR_RETRY;
    message->retry_timeout = retry_timeout;
}

/* Helper functions implementation */
uint32_t gatekeeper_compute_retry_timeout(const gatekeeper_failure_record_t *record) {
    static const int failure_timeout_ms = 30000;
    if (!record || record->failure_counter == 0) return 0;

    if (record->failure_counter > 0 && record->failure_counter <= 10) {
        if (record->failure_counter % 5 == 0) {
            return failure_timeout_ms;
        } else {
            return 0;
        }
    } else if (record->failure_counter < 30) {
        return failure_timeout_ms;
    } else if (record->failure_counter < 140) {
        return failure_timeout_ms << ((record->failure_counter - 30) / 10);
    }

    return GATEKEEPER_DAY_IN_MS;
}

bool gatekeeper_throttle_request(gatekeeper_device_t *dev,
                                uint32_t uid,
                                uint64_t timestamp,
                                gatekeeper_failure_record_t *record,
                                bool secure,
                                gatekeeper_message_t *response) {
    if (!dev || !record || !response) return false;

    uint64_t last_checked = record->last_checked_timestamp;
    uint32_t timeout = gatekeeper_compute_retry_timeout(record);

    if (timeout > 0) {
        /* we have a pending timeout */
        if (timestamp < last_checked + timeout && timestamp > last_checked) {
            /* attempt before timeout expired, return remaining time */
            gatekeeper_message_set_retry_timeout(response, timeout - (timestamp - last_checked));
            return true;
        } else if (timestamp <= last_checked) {
            /* device was rebooted or timer reset, don't count as new failure but reset timeout */
            record->last_checked_timestamp = timestamp;
            if (!dev->write_failure_record(dev, uid, record, secure)) {
                response->error = ERROR_UNKNOWN;
                return true;
            }
            gatekeeper_message_set_retry_timeout(response, timeout);
            return true;
        }
    }

    return false;
}

bool gatekeeper_increment_failure_record(gatekeeper_device_t *dev,
                                        uint32_t uid,
                                        gatekeeper_secure_id_t user_id,
                                        uint64_t timestamp,
                                        gatekeeper_failure_record_t *record,
                                        bool secure) {
    if (!dev || !record) return false;

    record->secure_user_id = user_id;
    record->failure_counter++;
    record->last_checked_timestamp = timestamp;

    return dev->write_failure_record(dev, uid, record, secure);
}

bool gatekeeper_create_password_handle(gatekeeper_device_t *dev,
                                      gatekeeper_buffer_t *password_handle_buffer,
                                      gatekeeper_salt_t salt,
                                      gatekeeper_secure_id_t user_id,
                                      uint64_t flags,
                                      uint8_t handle_version,
                                      const gatekeeper_buffer_t *password) {
    if (!dev || !password_handle_buffer || !password || !password->buffer) {
        return false;
    }

    gatekeeper_password_handle_t password_handle;

    password_handle.version = handle_version;
    password_handle.salt = salt;
    password_handle.user_id = user_id;
    password_handle.flags = flags;
    password_handle.hardware_backed = dev->is_hardware_backed(dev);

    const uint32_t metadata_length = sizeof(password_handle.version) +
                                    sizeof(password_handle.user_id) +
                                    sizeof(password_handle.flags);
    const size_t to_sign_size = password->length + metadata_length;

    uint8_t *to_sign = (uint8_t*)malloc(to_sign_size);
    if (!to_sign) {
        return false;
    }

    memcpy(to_sign, &password_handle, metadata_length);
    memcpy(to_sign + metadata_length, password->buffer, password->length);

    const uint8_t *password_key = NULL;
    uint32_t password_key_length = 0;
    dev->get_password_key(dev, &password_key, &password_key_length);

    if (!password_key || password_key_length == 0) {
        free(to_sign);
        return false;
    }

    dev->compute_password_signature(dev, password_handle.signature, sizeof(password_handle.signature),
            password_key, password_key_length, to_sign, to_sign_size, salt);

    free(to_sign);

    if (!gatekeeper_buffer_allocate(password_handle_buffer, sizeof(gatekeeper_password_handle_t))) {
        return false;
    }

    memcpy(password_handle_buffer->buffer, &password_handle, sizeof(gatekeeper_password_handle_t));
    return true;
}

bool gatekeeper_do_verify(gatekeeper_device_t *dev,
                         const gatekeeper_password_handle_t *expected_handle,
                         const gatekeeper_buffer_t *password) {
    if (!dev || !expected_handle || !password || !password->buffer) {
        return false;
    }

    gatekeeper_buffer_t provided_handle;
    memset(&provided_handle, 0, sizeof(provided_handle));
    gatekeeper_buffer_init(&provided_handle);

    bool result = false;

    if (gatekeeper_create_password_handle(dev, &provided_handle, expected_handle->salt,
                                          expected_handle->user_id, expected_handle->flags,
                                          expected_handle->version, password)) {
        const gatekeeper_password_handle_t *generated_handle =
            (const gatekeeper_password_handle_t *)provided_handle.buffer;

        /* Compare signatures */
        result = (memcmp(generated_handle->signature, expected_handle->signature,
                        sizeof(expected_handle->signature)) == 0);
    }

    gatekeeper_buffer_free(&provided_handle);
    return result;
}

gatekeeper_error_t gatekeeper_mint_auth_token(gatekeeper_device_t *dev,
                                             gatekeeper_buffer_t *auth_token,
                                             uint64_t timestamp,
                                             gatekeeper_secure_id_t user_id,
                                             gatekeeper_secure_id_t authenticator_id,
                                             uint64_t challenge) {
    /* Validate input parameters */
    if (!dev || !auth_token) {
        return ERROR_INVALID;
    }

    /* Free any existing auth token data */
    if (auth_token->buffer != NULL || auth_token->length != 0) {
        gatekeeper_buffer_free(auth_token);
    }

    /* Create and populate auth token structure */
    gatekeeper_hw_auth_token_t token;

    token.version = 0; /* HW_AUTH_TOKEN_VERSION */
    token.challenge = challenge;
    token.user_id = user_id;
    token.authenticator_id = authenticator_id;
    token.authenticator_type =
        TEE_U32_TO_BIG_ENDIAN(0x01); /* HW_AUTH_PASSWORD */
    token.timestamp = TEE_U64_TO_BIG_ENDIAN(timestamp);

    const uint32_t hashable_length = sizeof(token.version) +
                                    sizeof(token.challenge) +
                                    sizeof(token.user_id) +
                                    sizeof(token.authenticator_id) +
                                    sizeof(token.authenticator_type) +
                                    sizeof(token.timestamp);

    /* Get auth token key and compute signature */
    const uint8_t *auth_token_key = NULL;
    uint32_t key_len = 0;

    if (dev->get_auth_token_key(dev, &auth_token_key, &key_len)) {
        /* Validate key data */
        if (!auth_token_key || key_len == 0) {
            return ERROR_INVALID;
        }

        dev->compute_signature(dev, token.hmac, sizeof(token.hmac), auth_token_key, key_len,
                (uint8_t *)&token, hashable_length);
    } else {
        memset(token.hmac, 0, sizeof(token.hmac));
    }

    /* Allocate and copy token to output buffer */
    if (!gatekeeper_buffer_allocate(auth_token, sizeof(gatekeeper_hw_auth_token_t))) {
        return ERROR_MEMORY_ALLOCATION_FAILED;
    }

    if (!auth_token->buffer) {
        auth_token->length = 0;
        return ERROR_INVALID;
    }

    memcpy(auth_token->buffer, &token, sizeof(gatekeeper_hw_auth_token_t));

    return ERROR_NONE;
}

/* Main API implementations */
void gatekeeper_enroll(gatekeeper_device_t *dev,
                      const gatekeeper_enroll_request_t *request,
                      gatekeeper_enroll_response_t *response) {

    /* Validate input parameters */
    if (!dev || !request || !response) {
      return;
    }

    /* Initialize response as empty with no error */
    response->base.error = ERROR_NONE;
    response->base.user_id = request->base.user_id;
    response->base.retry_timeout = 0;

    gatekeeper_buffer_init(&response->enrolled_password_handle);

    /* Check for valid provided password */
    if (!request->provided_password.buffer || request->provided_password.length == 0) {
        response->base.error = ERROR_INVALID;
        return;
    }

    gatekeeper_secure_id_t user_id = 0;
    uint32_t uid = request->base.user_id;

    if (!gatekeeper_buffer_is_valid(&request->password_handle)) {
        /* Password handle does not exist, generate new secure ID */
        dev->get_random(dev, &user_id, sizeof(gatekeeper_secure_id_t));
    } else {
        /* Password handle exists, verify it */
        const gatekeeper_password_handle_t *pw_handle =
            (const gatekeeper_password_handle_t *)request->password_handle.buffer;

        if (!pw_handle) {
            response->base.error = ERROR_INVALID;
            return;
        }

        if (pw_handle->version > GATEKEEPER_HANDLE_VERSION) {
            response->base.error = ERROR_INVALID;
            return;
        }

        user_id = pw_handle->user_id;

        uint64_t timestamp = dev->get_milliseconds_since_boot(dev);

        uint32_t timeout = 0;
        bool throttle = (pw_handle->version >= GATEKEEPER_HANDLE_VERSION_THROTTLE);

        if (throttle) {
            bool throttle_secure = pw_handle->flags & GATEKEEPER_HANDLE_FLAG_THROTTLE_SECURE;

            gatekeeper_failure_record_t record;
            if (!dev->get_failure_record(dev, uid, user_id, &record, throttle_secure)) {
                response->base.error = ERROR_UNKNOWN;
                return;
            }

            if (gatekeeper_throttle_request(dev, uid, timestamp, &record, throttle_secure, &response->base)) {
                return;
            }

            if (!gatekeeper_increment_failure_record(dev, uid, user_id, timestamp, &record, throttle_secure)) {
                response->base.error = ERROR_UNKNOWN;
                return;
            }

            timeout = gatekeeper_compute_retry_timeout(&record);
        }

        if (!gatekeeper_do_verify(dev, pw_handle, &request->enrolled_password)) {
            /* incorrect old password */
            if (throttle && timeout > 0) {
                gatekeeper_message_set_retry_timeout(&response->base, timeout);
            } else {
                response->base.error = ERROR_INVALID;
            }
            return;
        }
    }

    uint64_t flags = 0;
    if (dev->clear_failure_record(dev, uid, user_id, true)) {
        flags |= GATEKEEPER_HANDLE_FLAG_THROTTLE_SECURE;
    } else {
        dev->clear_failure_record(dev, uid, user_id, false);
    }

    gatekeeper_salt_t salt;
    dev->get_random(dev, &salt, sizeof(salt));

    if (!gatekeeper_create_password_handle(dev, &response->enrolled_password_handle,
            salt, user_id, flags, GATEKEEPER_HANDLE_VERSION, &request->provided_password)) {
        response->base.error = ERROR_INVALID;
        return;
    }
}

void gatekeeper_verify(gatekeeper_device_t *dev,
                      const gatekeeper_verify_request_t *request,
                      gatekeeper_verify_response_t *response) {

    if (!dev || !request || !response) {
        return;
    }

    /* Initialize response */
    response->base.error = ERROR_NONE;
    response->base.user_id = request->base.user_id;
    response->base.retry_timeout = 0;
    response->request_reenroll = false;
    gatekeeper_buffer_init(&response->auth_token);

    if (!gatekeeper_buffer_is_valid(&request->provided_password) ||
        !gatekeeper_buffer_is_valid(&request->password_handle)) {
        response->base.error = ERROR_INVALID;
        return;
    }

    const gatekeeper_password_handle_t *password_handle =
        (const gatekeeper_password_handle_t *)request->password_handle.buffer;

    if (!password_handle || password_handle->version > GATEKEEPER_HANDLE_VERSION) {
        response->base.error = ERROR_INVALID;
        return;
    }

    gatekeeper_secure_id_t user_id = password_handle->user_id;
    gatekeeper_secure_id_t authenticator_id = 0;
    uint32_t uid = request->base.user_id;

    uint64_t timestamp = dev->get_milliseconds_since_boot(dev);

    uint32_t timeout = 0;
    bool throttle = (password_handle->version >= GATEKEEPER_HANDLE_VERSION_THROTTLE);
    bool throttle_secure = password_handle->flags & GATEKEEPER_HANDLE_FLAG_THROTTLE_SECURE;

    if (throttle) {
        gatekeeper_failure_record_t record;
        if (!dev->get_failure_record(dev, uid, user_id, &record, throttle_secure)) {
            response->base.error = ERROR_UNKNOWN;
            return;
        }

        if (gatekeeper_throttle_request(dev, uid, timestamp, &record, throttle_secure, &response->base)) {
            return;
        }

        if (!gatekeeper_increment_failure_record(dev, uid, user_id, timestamp, &record, throttle_secure)) {
            response->base.error = ERROR_UNKNOWN;
            return;
        }

        timeout = gatekeeper_compute_retry_timeout(&record);
    } else {
        response->request_reenroll = true;
    }

    if (gatekeeper_do_verify(dev, password_handle, &request->provided_password)) {
        /* Signature matches */

        /* Verify auth_token is properly initialized */
        if (response->auth_token.buffer != NULL || response->auth_token.length != 0) {
            gatekeeper_buffer_free(&response->auth_token);
        }

        response->base.error = gatekeeper_mint_auth_token(dev, &response->auth_token, timestamp,
                user_id, authenticator_id, request->challenge);

        /* Validate auth token */
        if (response->base.error == ERROR_NONE) {
            if (!response->auth_token.buffer && response->auth_token.length > 0) {
                response->auth_token.length = 0;
                response->base.error = ERROR_INVALID;
            } else if (response->auth_token.buffer && response->auth_token.length == 0) {
                gatekeeper_buffer_free(&response->auth_token);
                response->base.error = ERROR_INVALID;
            }
        }

        if (response->base.error != ERROR_NONE) {
            return;
        }

        if (throttle) {
            dev->clear_failure_record(dev, uid, user_id, throttle_secure);
        }
    } else {
        /* Password verification failed */

        /* compute the new timeout given the incremented record */
        if (throttle && timeout > 0) {
            gatekeeper_message_set_retry_timeout(&response->base, timeout);
        } else {
            response->base.error = ERROR_INVALID;
        }
    }
}

void gatekeeper_delete_user(gatekeeper_device_t *dev,
                           const gatekeeper_delete_user_request_t *request,
                           gatekeeper_delete_user_response_t *response) {
    if (!dev || !request || !response) return;

    uint32_t uid = request->base.user_id;
    response->base.error = dev->remove_user(dev, uid);
}

void gatekeeper_delete_all_users(gatekeeper_device_t *dev,
                                const gatekeeper_delete_all_users_request_t *request,
                                gatekeeper_delete_all_users_response_t *response) {
    if (!dev || !response) return;
    (void)request; /* Unused */

    response->base.error = dev->remove_all_users(dev);
}
