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
#include "gatekeeper_messages.h"
#include <stdio.h>
#include <tee_internal_api.h>

/* Helper serialization functions */
uint32_t gatekeeper_serialize_buffer(const gatekeeper_buffer_t *buffer,
                                    uint8_t **out, const uint8_t *end) {
    if (!buffer || !out || !*out || !end) return 0;

    /* Length of buffer plus 4 byte size field */
    uint32_t total_size = sizeof(uint32_t);

    /* Check if we have enough space for size field */
    if (*out + sizeof(uint32_t) > end) return 0;

    /* Write buffer length */
    uint32_t length = buffer->length;
    memcpy(*out, &length, sizeof(uint32_t));
    *out += sizeof(uint32_t);

    /* Add buffer data size to total */
    total_size += length;

    /* Check if we have enough space for data */
    if (*out + length > end) return 0;

    /* Write data if there is any */
    if (length > 0 && buffer->buffer) {
        memcpy(*out, buffer->buffer, length);
        *out += length;
    }

    return total_size;
}

gatekeeper_error_t gatekeeper_deserialize_buffer(gatekeeper_buffer_t *buffer,
                                               const uint8_t **in, const uint8_t *end) {
    /* Input validation */
    if (!buffer || !in || !*in || !end) {
        return ERROR_INVALID;
    }

    /* Check for negative available bytes which indicates pointer corruption */
    if (*in > end) {
        return ERROR_INVALID;
    }

    /* Free any existing buffer */
    gatekeeper_buffer_free(buffer);

    /* Check if we have enough space for size field */
    if (*in + sizeof(uint32_t) > end) {
        return ERROR_INVALID;
    }

    /* Read buffer length */
    uint32_t length;
    memcpy(&length, *in, sizeof(uint32_t));
    *in += sizeof(uint32_t);

    /* Sanity check on length value */
    if (length > 10 * 1024 * 1024) { /* 10MB as upper limit */
        return ERROR_INVALID;
    }

    /* Check if we have enough space for data */
    if (*in + length > end) {
        return ERROR_INVALID;
    }

    /* Allocate and copy data if there is any */
    if (length > 0) {
        /* Perform the allocation */
        if (!gatekeeper_buffer_allocate(buffer, length)) {
            buffer->buffer = NULL;
            buffer->length = 0;
            return ERROR_MEMORY_ALLOCATION_FAILED;
        }

        /* Verify allocation succeeded with expected values */
        if (!buffer->buffer || buffer->length != length) {
            gatekeeper_buffer_free(buffer);
            return ERROR_MEMORY_ALLOCATION_FAILED;
        }

        /* Copy data */
        memcpy(buffer->buffer, *in, length);
        *in += length;
    } else {
        /* Ensure buffer is in correct state for zero-length */
        buffer->buffer = NULL;
        buffer->length = 0;
    }

    /* Final buffer state verification */
    if ((length > 0 && !buffer->buffer) || buffer->length != length) {
        return ERROR_INVALID;
    }

    return ERROR_NONE;
}

/* Verify Request */
uint32_t gatekeeper_verify_request_get_size(const gatekeeper_verify_request_t *request) {
    if (!request) return 0;

    /* Base message plus challenge, password handle and provided password */
    uint32_t size = gatekeeper_message_get_serialized_size(&request->base) +
                   sizeof(uint64_t) +
                   sizeof(uint32_t) + request->password_handle.length +
                   sizeof(uint32_t) + request->provided_password.length;

    return size;
}

uint32_t gatekeeper_verify_request_serialize(const gatekeeper_verify_request_t *request,
                                            uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return 0;

    uint8_t *start = buffer;

    /* Serialize base message */
    uint32_t base_size = gatekeeper_message_serialize(&request->base, buffer, end);
    if (base_size == 0) return 0;
    buffer += base_size;

    /* Check if we have enough space for challenge */
    if (buffer + sizeof(uint64_t) > end) return 0;

    /* Write challenge */
    uint64_t challenge = request->challenge;
    memcpy(buffer, &challenge, sizeof(uint64_t));
    buffer += sizeof(uint64_t);

    /* Serialize password handle */
    uint32_t handle_size = gatekeeper_serialize_buffer(&request->password_handle, &buffer, end);
    if (handle_size == 0) return 0;

    /* Serialize provided password */
    uint32_t password_size = gatekeeper_serialize_buffer(&request->provided_password, &buffer, end);
    if (password_size == 0) return 0;

    return (uint32_t)(buffer - start);
}

gatekeeper_error_t gatekeeper_verify_request_deserialize(gatekeeper_verify_request_t *request,
                                                       const uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return ERROR_INVALID;

    /* Initialize request */
    gatekeeper_verify_request_clear(request);

    /* Deserialize base message */
    gatekeeper_error_t error = gatekeeper_message_deserialize(&request->base, buffer, end);
    if (error != ERROR_NONE) return error;

    /* Advance buffer past base message */
    buffer += gatekeeper_message_get_serialized_size(&request->base);

    /* Check if we have enough space for challenge */
    if (buffer + sizeof(uint64_t) > end) return ERROR_INVALID;

    /* Read challenge */
    uint64_t challenge;
    memcpy(&challenge, buffer, sizeof(uint64_t));
    request->challenge = challenge;
    buffer += sizeof(uint64_t);

    /* Deserialize password handle */
    error = gatekeeper_deserialize_buffer(&request->password_handle, &buffer, end);
    if (error != ERROR_NONE) return error;

    /* Deserialize provided password */
    error = gatekeeper_deserialize_buffer(&request->provided_password, &buffer, end);
    if (error != ERROR_NONE) return error;

    return ERROR_NONE;
}

void gatekeeper_verify_request_init(gatekeeper_verify_request_t *request,
                                   uint32_t user_id, uint64_t challenge,
                                   const gatekeeper_buffer_t *enrolled_password_handle,
                                   const gatekeeper_buffer_t *provided_password) {
    if (!request) return;

    /* Initialize base message */
    request->base.error = ERROR_NONE;
    request->base.user_id = user_id;
    request->base.retry_timeout = 0;

    /* Set challenge */
    request->challenge = challenge;

    /* Initialize buffers */
    gatekeeper_buffer_init(&request->password_handle);
    gatekeeper_buffer_init(&request->provided_password);

    /* Copy password handle if provided */
    if (enrolled_password_handle) {
        gatekeeper_buffer_copy(&request->password_handle, enrolled_password_handle);
    }

    /* Copy provided password if provided */
    if (provided_password) {
        gatekeeper_buffer_copy(&request->provided_password, provided_password);
    }
}

void gatekeeper_verify_request_clear(gatekeeper_verify_request_t *request) {
    if (!request) return;

    /* Free buffers */
    gatekeeper_buffer_free(&request->password_handle);
    gatekeeper_buffer_free(&request->provided_password);

    /* Reset fields */
    request->base.error = ERROR_NONE;
    request->base.user_id = 0;
    request->base.retry_timeout = 0;
    request->challenge = 0;
}

/* Verify Response */
uint32_t gatekeeper_verify_response_get_size(const gatekeeper_verify_response_t *response) {
    if (!response) {
        return 0;
    }

    /* Base message plus auth token and request reenroll flag */
    uint32_t size = gatekeeper_message_get_serialized_size(&response->base);

    /* Only include auth token and reenroll flag for success responses */
    if (response->base.error == ERROR_NONE) {
        uint32_t token_size = sizeof(uint32_t) + response->auth_token.length;
        size += token_size;
        size += sizeof(uint32_t); /* request_reenroll flag */
    }

    return size;
}

uint32_t gatekeeper_verify_response_serialize(const gatekeeper_verify_response_t *response,
                                             uint8_t *buffer, const uint8_t *end) {
    /* Input validation */
    if (!response || !buffer || !end) {
        return 0;
    }

    /* Check for buffer size */
    if (buffer > end) {
        return 0;
    }

    /* Extra validation of auth token */
    if (response->base.error == ERROR_NONE) {
        if (response->auth_token.length > 0 && !response->auth_token.buffer) {
            return 0;
        }
    }

    uint8_t *start = buffer;

    /* Serialize base message */
    uint32_t base_size = gatekeeper_message_serialize(&response->base, buffer, end);
    if (base_size == 0) {
        return 0;
    }

    buffer += base_size;

    /* Only include auth token and reenroll flag for success responses */
    if (response->base.error == ERROR_NONE) {
        /* Validate auth token state before serializing */
        if (response->auth_token.length > 0) {
            if (!response->auth_token.buffer) {
                return 0;
            }
        }

        /* Calculate required space */
        uint32_t required_space = sizeof(uint32_t) + response->auth_token.length;
        size_t remaining_space = (size_t)(end - buffer);

        if (required_space > remaining_space) {
            return 0;
        }
        uint32_t token_size = gatekeeper_serialize_buffer(&response->auth_token, &buffer, end);
        if (token_size == 0) {
            return 0;
        }

        /* Check if we have enough space for reenroll flag */
        if (buffer + sizeof(uint32_t) > end) {
            return 0;
        }

        /* Write reenroll flag */
        uint32_t reenroll_value = response->request_reenroll ? 1 : 0;
        memcpy(buffer, &reenroll_value, sizeof(uint32_t));
        buffer += sizeof(uint32_t);
    }

    uint32_t total_size = (uint32_t)(buffer - start);
    return total_size;
}

gatekeeper_error_t gatekeeper_verify_response_deserialize(gatekeeper_verify_response_t *response,
                                                        const uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return ERROR_INVALID;

    /* Initialize response */
    gatekeeper_verify_response_clear(response);

    /* Deserialize base message */
    gatekeeper_error_t error = gatekeeper_message_deserialize(&response->base, buffer, end);
    if (error != ERROR_NONE) return error;

    /* Advance buffer past base message */
    buffer += gatekeeper_message_get_serialized_size(&response->base);

    /* Only include auth token and reenroll flag for success responses */
    if (response->base.error == ERROR_NONE) {
        /* Deserialize auth token */
        error = gatekeeper_deserialize_buffer(&response->auth_token, &buffer, end);
        if (error != ERROR_NONE) return error;

        /* Check if we have enough space for reenroll flag */
        if (buffer + sizeof(uint32_t) > end) return ERROR_INVALID;

        /* Read reenroll flag */
        uint32_t reenroll_value;
        memcpy(&reenroll_value, buffer, sizeof(uint32_t));
        response->request_reenroll = (reenroll_value != 0);
        buffer += sizeof(uint32_t);
    }

    return ERROR_NONE;
}

void gatekeeper_verify_response_init(gatekeeper_verify_response_t *response, uint32_t user_id) {
    if (!response) return;

    /* Initialize base message */
    response->base.error = ERROR_NONE;
    response->base.user_id = user_id;
    response->base.retry_timeout = 0;

    /* Initialize auth token */
    gatekeeper_buffer_init(&response->auth_token);

    /* Set reenroll flag */
    response->request_reenroll = false;
}

void gatekeeper_verify_response_set_token(gatekeeper_verify_response_t *response,
                                         const gatekeeper_buffer_t *auth_token) {
    if (!response || !auth_token) return;

    /* Copy auth token */
    gatekeeper_buffer_copy(&response->auth_token, auth_token);
}

void gatekeeper_verify_response_clear(gatekeeper_verify_response_t *response) {
    if (!response) return;

    /* Free auth token */
    gatekeeper_buffer_free(&response->auth_token);

    /* Reset fields */
    response->base.error = ERROR_NONE;
    response->base.user_id = 0;
    response->base.retry_timeout = 0;
    response->request_reenroll = false;
}

/* Enroll Request */
uint32_t gatekeeper_enroll_request_get_size(const gatekeeper_enroll_request_t *request) {
    if (!request) return 0;

    /* CRITICAL FIX: Updated order to match C++ implementation */
    /* Base message plus provided password, enrolled password, and password handle */
    uint32_t size = gatekeeper_message_get_serialized_size(&request->base) +
                   sizeof(uint32_t) + request->provided_password.length +
                   sizeof(uint32_t) + request->enrolled_password.length +
                   sizeof(uint32_t) + request->password_handle.length;

    return size;
}

uint32_t gatekeeper_enroll_request_serialize(const gatekeeper_enroll_request_t *request,
                                           uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return 0;

    uint8_t *start = buffer;

    /* Serialize base message */
    uint32_t base_size = gatekeeper_message_serialize(&request->base, buffer, end);
    if (base_size == 0) return 0;
    buffer += base_size;

    /* CRITICAL FIX: Changed serialization order to match C++ implementation:
     * 1. provided_password
     * 2. enrolled_password
     * 3. password_handle
     */

    /* 1. First serialize provided password */
    uint32_t provided_size = gatekeeper_serialize_buffer(&request->provided_password, &buffer, end);
    if (provided_size == 0) return 0;

    /* 2. Next serialize enrolled password */
    uint32_t enrolled_size = gatekeeper_serialize_buffer(&request->enrolled_password, &buffer, end);
    if (enrolled_size == 0) return 0;

    /* 3. Finally serialize password handle */
    uint32_t handle_size = gatekeeper_serialize_buffer(&request->password_handle, &buffer, end);
    if (handle_size == 0) return 0;

    return (uint32_t)(buffer - start);
}

gatekeeper_error_t gatekeeper_enroll_request_deserialize(gatekeeper_enroll_request_t *request,
                                                       const uint8_t *buffer, const uint8_t *end) {
    /* Check input parameters */
    if (!request || !buffer || !end) {
        return ERROR_INVALID;
    }

    /* Free existing buffers and initialize request */
    gatekeeper_buffer_free(&request->password_handle);
    gatekeeper_buffer_free(&request->enrolled_password);
    gatekeeper_buffer_free(&request->provided_password);

    memset(request, 0, sizeof(gatekeeper_enroll_request_t));

    /* Initialize the buffers */
    gatekeeper_buffer_init(&request->password_handle);
    gatekeeper_buffer_init(&request->enrolled_password);
    gatekeeper_buffer_init(&request->provided_password);

    /* Deserialize base message */
    gatekeeper_error_t error = gatekeeper_message_deserialize(&request->base, buffer, end);
    if (error != ERROR_NONE) {
        return error;
    }

    /* Advance buffer past base message */
    buffer += gatekeeper_message_get_serialized_size(&request->base);

    /* The order of deserialization matches the C++ implementation:
     * 1. provided_password
     * 2. enrolled_password
     * 3. password_handle
     */

    /* 1. First deserialize the provided password */
    if (buffer + sizeof(uint32_t) > end) {
        return ERROR_INVALID;
    }

    /* Peek at size to validate */
    uint32_t pw_size_peek;
    memcpy(&pw_size_peek, buffer, sizeof(uint32_t));

    /* Validate size */
    if (pw_size_peek > 1024 * 1024 ||
        buffer + sizeof(uint32_t) + pw_size_peek > end) {
        return ERROR_INVALID;
    }

    /* Deserialize provided password */
    error = gatekeeper_deserialize_buffer(&request->provided_password, &buffer, end);
    if (error != ERROR_NONE) {
        return error;
    }

    /* 2. Next deserialize enrolled password */
    if (buffer + sizeof(uint32_t) > end) {
        gatekeeper_buffer_free(&request->provided_password);
        return ERROR_INVALID;
    }

    /* Peek at size to validate */
    uint32_t enrolled_size_peek;
    memcpy(&enrolled_size_peek, buffer, sizeof(uint32_t));

    /* Validate size */
    if (enrolled_size_peek > 1024 * 1024 ||
        buffer + sizeof(uint32_t) + enrolled_size_peek > end) {
        gatekeeper_buffer_free(&request->provided_password);
        return ERROR_INVALID;
    }

    /* Deserialize enrolled password */
    error = gatekeeper_deserialize_buffer(&request->enrolled_password, &buffer, end);
    if (error != ERROR_NONE) {
        gatekeeper_buffer_free(&request->provided_password);
        return error;
    }

    /* 3. Finally deserialize password handle */
    if (buffer + sizeof(uint32_t) > end) {
        gatekeeper_buffer_free(&request->provided_password);
        gatekeeper_buffer_free(&request->enrolled_password);
        return ERROR_INVALID;
    }

    /* Peek at size to validate */
    uint32_t handle_size_peek;
    memcpy(&handle_size_peek, buffer, sizeof(uint32_t));

    /* Validate size */
    if (handle_size_peek > 1024 * 1024 ||
        buffer + sizeof(uint32_t) + handle_size_peek > end) {
        gatekeeper_buffer_free(&request->provided_password);
        gatekeeper_buffer_free(&request->enrolled_password);
        return ERROR_INVALID;
    }

    /* Deserialize password handle */
    error = gatekeeper_deserialize_buffer(&request->password_handle, &buffer, end);
    if (error != ERROR_NONE) {
        gatekeeper_buffer_free(&request->provided_password);
        gatekeeper_buffer_free(&request->enrolled_password);
        return error;
    }

    return ERROR_NONE;
}

void gatekeeper_enroll_request_init(gatekeeper_enroll_request_t *request,
                                  uint32_t user_id,
                                  const gatekeeper_buffer_t *password_handle,
                                  const gatekeeper_buffer_t *enrolled_password,
                                  const gatekeeper_buffer_t *provided_password) {
    if (!request) {
        return;
    }

    /* Initialize base message */
    request->base.error = ERROR_NONE;
    request->base.user_id = user_id;
    request->base.retry_timeout = 0;

    /* Copy password handle if provided */
    if (password_handle) {
        gatekeeper_buffer_copy(&request->password_handle, password_handle);
    }

    /* Copy enrolled password if provided */
    if (enrolled_password) {
        gatekeeper_buffer_copy(&request->enrolled_password, enrolled_password);
    }

    /* Copy provided password if provided */
    if (provided_password) {
        gatekeeper_buffer_copy(&request->provided_password, provided_password);
    }
}

void gatekeeper_enroll_request_clear(gatekeeper_enroll_request_t *request) {
    /* Check for NULL request */
    if (!request) {
        return;
    }

    /* Double check for corrupted memory patterns in request */
    if ((uintptr_t)request < 1000 ||
        (uintptr_t)&request->password_handle < (uintptr_t)request ||
        (uintptr_t)&request->enrolled_password < (uintptr_t)request ||
        (uintptr_t)&request->provided_password < (uintptr_t)request) {
        return;
    }

    /* Validate buffer states and free appropriately */
    if (request->password_handle.length > 0 && !request->password_handle.buffer) {
        request->password_handle.length = 0;
    } else {
        gatekeeper_buffer_free(&request->password_handle);
    }

    if (request->enrolled_password.length > 0 && !request->enrolled_password.buffer) {
        request->enrolled_password.length = 0;
    } else {
        gatekeeper_buffer_free(&request->enrolled_password);
    }

    if (request->provided_password.length > 0 && !request->provided_password.buffer) {
        request->provided_password.length = 0;
    } else {
        gatekeeper_buffer_free(&request->provided_password);
    }

    /* Reset fields */
    request->base.error = ERROR_NONE;
    request->base.user_id = 0;
    request->base.retry_timeout = 0;

    /* Ensure all fields are NULL/0 for extra safety */
    if (request->password_handle.buffer != NULL ||
        request->password_handle.length != 0 ||
        request->enrolled_password.buffer != NULL ||
        request->enrolled_password.length != 0 ||
        request->provided_password.buffer != NULL ||
        request->provided_password.length != 0) {

        /* Explicitly set to NULL/0 */
        request->password_handle.buffer = NULL;
        request->password_handle.length = 0;
        request->enrolled_password.buffer = NULL;
        request->enrolled_password.length = 0;
        request->provided_password.buffer = NULL;
        request->provided_password.length = 0;
    }
}

/* Enroll Response */
uint32_t gatekeeper_enroll_response_get_size(const gatekeeper_enroll_response_t *response) {
    if (!response) return 0;

    /* Base message plus enrolled password handle */
    uint32_t size = gatekeeper_message_get_serialized_size(&response->base);

    /* Only include enrolled password handle for success responses */
    if (response->base.error == ERROR_NONE) {
        size += sizeof(uint32_t) + response->enrolled_password_handle.length;
    }

    return size;
}

uint32_t gatekeeper_enroll_response_serialize(const gatekeeper_enroll_response_t *response,
                                            uint8_t *buffer, const uint8_t *end) {
    /* Validate input parameters */
    if (!response || !buffer || !end) {
        return 0;
    }

    uint8_t *start = buffer;

    /* Serialize base message */
    uint32_t base_size = gatekeeper_message_serialize(&response->base, buffer, end);
    if (base_size == 0) {
        return 0;
    }

    buffer += base_size;

    /* Only include enrolled password handle for success responses */
    if (response->base.error == ERROR_NONE) {
        /* Check if handle is valid before trying to serialize it */
        if (!response->enrolled_password_handle.buffer && response->enrolled_password_handle.length > 0) {
            /* Initialize an empty buffer to avoid crashes */
            gatekeeper_buffer_t empty_buffer = {NULL, 0};
            uint32_t handle_size = gatekeeper_serialize_buffer(&empty_buffer, &buffer, end);
            if (handle_size == 0) {
                return 0;
            }
        } else {
            /* Serialize the handle (could be empty) */
            uint32_t handle_size = gatekeeper_serialize_buffer(&response->enrolled_password_handle, &buffer, end);
            if (handle_size == 0) {
                return 0;
            }
        }
    }

    uint32_t total_size = (uint32_t)(buffer - start);
    return total_size;
}

gatekeeper_error_t gatekeeper_enroll_response_deserialize(gatekeeper_enroll_response_t *response,
                                                        const uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return ERROR_INVALID;

    /* Initialize response */
    gatekeeper_enroll_response_clear(response);

    /* Deserialize base message */
    gatekeeper_error_t error = gatekeeper_message_deserialize(&response->base, buffer, end);
    if (error != ERROR_NONE) return error;

    /* Advance buffer past base message */
    buffer += gatekeeper_message_get_serialized_size(&response->base);

    /* Only include enrolled password handle for success responses */
    if (response->base.error == ERROR_NONE) {
        /* Deserialize enrolled password handle */
        error = gatekeeper_deserialize_buffer(&response->enrolled_password_handle, &buffer, end);
        if (error != ERROR_NONE) return error;
    }

    return ERROR_NONE;
}

void gatekeeper_enroll_response_init(gatekeeper_enroll_response_t *response, uint32_t user_id) {
    if (!response) return;

    /* Initialize base message */
    response->base.error = ERROR_NONE;
    response->base.user_id = user_id;
    response->base.retry_timeout = 0;

    /* Initialize enrolled password handle */
    gatekeeper_buffer_init(&response->enrolled_password_handle);
}

void gatekeeper_enroll_response_set_handle(gatekeeper_enroll_response_t *response,
                                          const gatekeeper_buffer_t *handle) {
    if (!response || !handle) return;

    /* Copy enrolled password handle */
    gatekeeper_buffer_copy(&response->enrolled_password_handle, handle);
}

void gatekeeper_enroll_response_clear(gatekeeper_enroll_response_t *response) {
    if (!response) return;

    /* Free enrolled password handle */
    gatekeeper_buffer_free(&response->enrolled_password_handle);

    /* Reset fields */
    response->base.error = ERROR_NONE;
    response->base.user_id = 0;
    response->base.retry_timeout = 0;
}

/* Delete User Request/Response */
uint32_t gatekeeper_delete_user_request_get_size(const gatekeeper_delete_user_request_t *request) {
    if (!request) return 0;

    /* Just base message */
    return gatekeeper_message_get_serialized_size(&request->base);
}

uint32_t gatekeeper_delete_user_request_serialize(const gatekeeper_delete_user_request_t *request,
                                                uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return 0;

    /* Serialize base message */
    return gatekeeper_message_serialize(&request->base, buffer, end);
}

gatekeeper_error_t gatekeeper_delete_user_request_deserialize(gatekeeper_delete_user_request_t *request,
                                                           const uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return ERROR_INVALID;

    /* Deserialize base message */
    return gatekeeper_message_deserialize(&request->base, buffer, end);
}

void gatekeeper_delete_user_request_init(gatekeeper_delete_user_request_t *request, uint32_t user_id) {
    if (!request) return;

    /* Initialize base message */
    request->base.error = ERROR_NONE;
    request->base.user_id = user_id;
    request->base.retry_timeout = 0;
}

uint32_t gatekeeper_delete_user_response_get_size(const gatekeeper_delete_user_response_t *response) {
    if (!response) return 0;

    /* Just base message */
    return gatekeeper_message_get_serialized_size(&response->base);
}

uint32_t gatekeeper_delete_user_response_serialize(const gatekeeper_delete_user_response_t *response,
                                                 uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return 0;

    /* Serialize base message */
    return gatekeeper_message_serialize(&response->base, buffer, end);
}

gatekeeper_error_t gatekeeper_delete_user_response_deserialize(gatekeeper_delete_user_response_t *response,
                                                            const uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return ERROR_INVALID;

    /* Deserialize base message */
    return gatekeeper_message_deserialize(&response->base, buffer, end);
}

void gatekeeper_delete_user_response_init(gatekeeper_delete_user_response_t *response) {
    if (!response) return;

    /* Initialize base message */
    response->base.error = ERROR_NONE;
    response->base.user_id = 0;
    response->base.retry_timeout = 0;
}

/* Delete All Users Request/Response */
uint32_t gatekeeper_delete_all_users_request_get_size(const gatekeeper_delete_all_users_request_t *request) {
    if (!request) return 0;

    /* Just base message */
    return gatekeeper_message_get_serialized_size(&request->base);
}

uint32_t gatekeeper_delete_all_users_request_serialize(const gatekeeper_delete_all_users_request_t *request,
                                                     uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return 0;

    /* Serialize base message */
    return gatekeeper_message_serialize(&request->base, buffer, end);
}

gatekeeper_error_t gatekeeper_delete_all_users_request_deserialize(gatekeeper_delete_all_users_request_t *request,
                                                                const uint8_t *buffer, const uint8_t *end) {
    if (!request || !buffer || !end) return ERROR_INVALID;

    /* Deserialize base message */
    return gatekeeper_message_deserialize(&request->base, buffer, end);
}

void gatekeeper_delete_all_users_request_init(gatekeeper_delete_all_users_request_t *request) {
    if (!request) return;

    /* Initialize base message */
    request->base.error = ERROR_NONE;
    request->base.user_id = 0;
    request->base.retry_timeout = 0;
}

uint32_t gatekeeper_delete_all_users_response_get_size(const gatekeeper_delete_all_users_response_t *response) {
    if (!response) return 0;

    /* Just base message */
    return gatekeeper_message_get_serialized_size(&response->base);
}

uint32_t gatekeeper_delete_all_users_response_serialize(const gatekeeper_delete_all_users_response_t *response,
                                                      uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return 0;

    /* Serialize base message */
    return gatekeeper_message_serialize(&response->base, buffer, end);
}

gatekeeper_error_t gatekeeper_delete_all_users_response_deserialize(gatekeeper_delete_all_users_response_t *response,
                                                                 const uint8_t *buffer, const uint8_t *end) {
    if (!response || !buffer || !end) return ERROR_INVALID;

    /* Deserialize base message */
    return gatekeeper_message_deserialize(&response->base, buffer, end);
}

void gatekeeper_delete_all_users_response_init(gatekeeper_delete_all_users_response_t *response) {
    if (!response) return;

    /* Initialize base message */
    response->base.error = ERROR_NONE;
    response->base.user_id = 0;
    response->base.retry_timeout = 0;
}
