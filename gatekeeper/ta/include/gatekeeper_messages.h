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

#ifndef GATEKEEPER_MESSAGES_C_H_
#define GATEKEEPER_MESSAGES_C_H_

#include "gatekeeper.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Message-specific serialization/deserialization functions */

/* Verify Request */
uint32_t gatekeeper_verify_request_get_size(const gatekeeper_verify_request_t *request);
uint32_t gatekeeper_verify_request_serialize(const gatekeeper_verify_request_t *request,
                                            uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_verify_request_deserialize(gatekeeper_verify_request_t *request,
                                                       const uint8_t *buffer, const uint8_t *end);
void gatekeeper_verify_request_init(gatekeeper_verify_request_t *request,
                                   uint32_t user_id, uint64_t challenge,
                                   const gatekeeper_buffer_t *enrolled_password_handle,
                                   const gatekeeper_buffer_t *provided_password);
void gatekeeper_verify_request_clear(gatekeeper_verify_request_t *request);

/* Verify Response */
uint32_t gatekeeper_verify_response_get_size(const gatekeeper_verify_response_t *response);
uint32_t gatekeeper_verify_response_serialize(const gatekeeper_verify_response_t *response,
                                             uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_verify_response_deserialize(gatekeeper_verify_response_t *response,
                                                        const uint8_t *buffer, const uint8_t *end);
void gatekeeper_verify_response_init(gatekeeper_verify_response_t *response,
                                    uint32_t user_id);
void gatekeeper_verify_response_set_token(gatekeeper_verify_response_t *response,
                                        const gatekeeper_buffer_t *auth_token);
void gatekeeper_verify_response_clear(gatekeeper_verify_response_t *response);

/* Enroll Request */
uint32_t gatekeeper_enroll_request_get_size(const gatekeeper_enroll_request_t *request);
uint32_t gatekeeper_enroll_request_serialize(const gatekeeper_enroll_request_t *request,
                                            uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_enroll_request_deserialize(gatekeeper_enroll_request_t *request,
                                                       const uint8_t *buffer, const uint8_t *end);
void gatekeeper_enroll_request_init(gatekeeper_enroll_request_t *request,
                                   uint32_t user_id,
                                   const gatekeeper_buffer_t *password_handle,
                                   const gatekeeper_buffer_t *enrolled_password,
                                   const gatekeeper_buffer_t *provided_password);
void gatekeeper_enroll_request_clear(gatekeeper_enroll_request_t *request);

/* Enroll Response */
uint32_t gatekeeper_enroll_response_get_size(const gatekeeper_enroll_response_t *response);
uint32_t gatekeeper_enroll_response_serialize(const gatekeeper_enroll_response_t *response,
                                             uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_enroll_response_deserialize(gatekeeper_enroll_response_t *response,
                                                        const uint8_t *buffer, const uint8_t *end);
void gatekeeper_enroll_response_init(gatekeeper_enroll_response_t *response,
                                    uint32_t user_id);
void gatekeeper_enroll_response_set_handle(gatekeeper_enroll_response_t *response,
                                          const gatekeeper_buffer_t *handle);
void gatekeeper_enroll_response_clear(gatekeeper_enroll_response_t *response);

/* Delete User Request/Response */
uint32_t gatekeeper_delete_user_request_get_size(const gatekeeper_delete_user_request_t *request);
uint32_t gatekeeper_delete_user_request_serialize(const gatekeeper_delete_user_request_t *request,
                                                 uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_delete_user_request_deserialize(gatekeeper_delete_user_request_t *request,
                                                            const uint8_t *buffer, const uint8_t *end);
void gatekeeper_delete_user_request_init(gatekeeper_delete_user_request_t *request, uint32_t user_id);

uint32_t gatekeeper_delete_user_response_get_size(const gatekeeper_delete_user_response_t *response);
uint32_t gatekeeper_delete_user_response_serialize(const gatekeeper_delete_user_response_t *response,
                                                  uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_delete_user_response_deserialize(gatekeeper_delete_user_response_t *response,
                                                             const uint8_t *buffer, const uint8_t *end);
void gatekeeper_delete_user_response_init(gatekeeper_delete_user_response_t *response);

/* Delete All Users Request/Response */
uint32_t gatekeeper_delete_all_users_request_get_size(const gatekeeper_delete_all_users_request_t *request);
uint32_t gatekeeper_delete_all_users_request_serialize(const gatekeeper_delete_all_users_request_t *request,
                                                      uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_delete_all_users_request_deserialize(gatekeeper_delete_all_users_request_t *request,
                                                                 const uint8_t *buffer, const uint8_t *end);
void gatekeeper_delete_all_users_request_init(gatekeeper_delete_all_users_request_t *request);

uint32_t gatekeeper_delete_all_users_response_get_size(const gatekeeper_delete_all_users_response_t *response);
uint32_t gatekeeper_delete_all_users_response_serialize(const gatekeeper_delete_all_users_response_t *response,
                                                       uint8_t *buffer, const uint8_t *end);
gatekeeper_error_t gatekeeper_delete_all_users_response_deserialize(gatekeeper_delete_all_users_response_t *response,
                                                                  const uint8_t *buffer, const uint8_t *end);
void gatekeeper_delete_all_users_response_init(gatekeeper_delete_all_users_response_t *response);

/* Helper serialization functions */
uint32_t gatekeeper_serialize_buffer(const gatekeeper_buffer_t *buffer,
                                    uint8_t **out, const uint8_t *end);
gatekeeper_error_t gatekeeper_deserialize_buffer(gatekeeper_buffer_t *buffer,
                                               const uint8_t **in, const uint8_t *end);

#ifdef __cplusplus
}
#endif

#endif /* GATEKEEPER_MESSAGES_C_H_ */
