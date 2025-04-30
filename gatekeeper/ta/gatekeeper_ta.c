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

#include <string.h>
#include "ta_gatekeeper.h"
#include "failure_record.h"
#include "gatekeeper_ipc.h"

/*
 * TA entry point - called once when the TA is loaded
 */
TEE_Result TA_CreateEntryPoint(void)
{
    return init_secure_keys(); // Initialize secure keys when TA starts
}

/*
 * TA destroy entry point - called when the TA is unloaded
 */
void TA_DestroyEntryPoint(void) {
}

/*
 * TA open session entry point
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[TEE_NUM_PARAMS], void **sess_ctx)
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    // No session context needed for this TA
    *sess_ctx = NULL;
	(void)&params;

	return TEE_SUCCESS;
}

/*
 * TA close session entry point
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	/* Unused parameters */
	(void)sess_ctx;
}

static void get_random(gatekeeper_device_t *dev, void *random,
                               uint32_t requested_size) {
  (void)dev; /* Unused */

  TEE_GenerateRandom(random, requested_size);
}

/*
 * Retrieve auth token key from Keymaster TA
 */
static bool get_auth_token_key(gatekeeper_device_t *dev,
                               const uint8_t **auth_token_key,
                               uint32_t *length) {
  (void)dev; /* Unused */
  TEE_Result res = TEE_ERROR_GENERIC;
  TEE_ObjectHandle key = TEE_HANDLE_NULL;
  uint8_t authTokenKeyData[HMAC_SHA256_KEY_SIZE_BYTE + AUTH_KEY_OFFSET];
  uint32_t paramTypes;
  TEE_Param params[TEE_NUM_PARAMS];
  TEE_TASessionHandle sess = TEE_HANDLE_NULL;
  uint32_t returnOrigin = 0;
  const TEE_UUID uuid = TA_KEYMASTER_UUID;
  TEE_Attribute attrs[1] = {0};
  uint8_t dummy[HMAC_SHA256_KEY_SIZE_BYTE];
  uint32_t readSize = 0;

  /* Validate input parameters */
  if (!auth_token_key || !length) {
    return false;
  }

  /* Initialize output parameters */
  *auth_token_key = NULL;
  *length = 0;

  /* Step 1: Allocate transient object for the key */
  res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256, &key);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to allocate transient object, res=%x", res);
    return false;
  }

  /* Step 2: Open session with Keymaster TA */
  res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                          &returnOrigin);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to open session with keymaster, res=%x, origin=%u", res, returnOrigin);
    TEE_FreeTransientObject(key);
    goto exit;
  }

  /* Step 3: Prepare parameters for command invocation */
  paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                 TEE_PARAM_TYPE_MEMREF_OUTPUT,
                 TEE_PARAM_TYPE_NONE,
                 TEE_PARAM_TYPE_NONE);
  memset(params, 0, sizeof(params));
  memset(dummy, 0xAA, sizeof(dummy)); /* Initialize dummy with pattern */
  memset(authTokenKeyData, 0, sizeof(authTokenKeyData));

  params[0].memref.buffer = dummy;
  params[0].memref.size = sizeof(dummy);

  params[1].memref.buffer = authTokenKeyData;
  params[1].memref.size = sizeof(authTokenKeyData);

  /* Step 4: Invoke command to get auth token key */
  res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, KM_GET_AUTHTOKEN_KEY,
          paramTypes, params, &returnOrigin);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to invoke command, res=%x, origin=%u", res, returnOrigin);
    goto close_sess;
  }

  /* Step 5: Validate returned data size */
  if (params[1].memref.size != sizeof(authTokenKeyData)) {
    EMSG("Invalid returned data size: %u, expected: %zu", params[1].memref.size, sizeof(authTokenKeyData));
    res = TEE_ERROR_BAD_STATE;
    goto close_sess;
  }

  /* Step 6: Initialize attribute with the key data */
  TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
                      (authTokenKeyData + AUTH_KEY_OFFSET),
                      (sizeof(authTokenKeyData) - AUTH_KEY_OFFSET));

  /* Step 7: Populate the transient object with the attribute */
  res = TEE_PopulateTransientObject(key, attrs, 1);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to populate transient object, res=%x", res);
    goto close_sess;
  }

  /* Step 8: Skip reading object data (which fails) and use data from authTokenKeyData directly */

  /* Create temporary buffer for key data */
  static uint8_t keyBuffer[256]; /* Static to ensure it's not freed */
  memset(keyBuffer, 0, sizeof(keyBuffer));

  /* Instead of trying to read from the object, use the data we already have */
  size_t keyDataSize = sizeof(authTokenKeyData) - AUTH_KEY_OFFSET;
  memcpy(keyBuffer, authTokenKeyData + AUTH_KEY_OFFSET, keyDataSize);
  readSize = keyDataSize;

  /* Set output parameters */
  *auth_token_key = keyBuffer;
  *length = readSize;

  /* Success! */
  TEE_CloseTASession(sess);
  TEE_CloseObject(key);
  return true;

close_sess:
  TEE_CloseTASession(sess);
  TEE_CloseObject(key);
exit:
  return false;
}

/*
 * Compute secure signature for a password handle
 * 
 * Modified to match keymaster's TA_ComputeSignature function logic exactly
 * to ensure both TAs generate the same HMAC for the same input.
 */
static void compute_signature(gatekeeper_device_t *dev,
                              uint8_t *signature, uint32_t signature_length,
                              const uint8_t *key, uint32_t key_length,
                              const uint8_t *message, const uint32_t length) {
  (void)dev; /* Unused */
  TEE_OperationHandle op = NULL;
  TEE_Result res = TEE_ERROR_GENERIC;
  TEE_ObjectHandle master_key = TEE_HANDLE_NULL;
  TEE_Attribute attrs[1];
  uint32_t buf_length = HMAC_SHA256_KEY_SIZE_BYTE;
  uint8_t buf[buf_length];
  uint32_t to_write;

  // Validate input parameters
  if (!signature || signature_length == 0 || !key || key_length == 0) {
    EMSG("Invalid parameters for compute_signature");
    return;
  }

  // Initialize HMAC operation - use same bit size as keymaster (256)
  res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, 256);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to allocate HMAC operation, res=%x", res);
    return;
  }

  // First allocate the transient object for the key
  res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_length * 8, &master_key);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to allocate transient object, res=%x", res);
    TEE_FreeOperation(op);
    return;
  }

  // Initialize the attribute with the correct key data and length
  TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE, key, key_length);

  // Populate the transient object with the attributes
  res = TEE_PopulateTransientObject(master_key, attrs, 1);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to populate transient object, res=%x", res);
    TEE_FreeTransientObject(master_key);
    TEE_FreeOperation(op);
    return;
  }

  // Set the key for the operation
  res = TEE_SetOperationKey(op, master_key);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to set operation key, res=%x", res);
    TEE_FreeTransientObject(master_key);
    TEE_FreeOperation(op);
    return;
  }

  // Initialize MAC operation
  TEE_MACInit(op, NULL, 0);

  // Using same method as keymaster's TA_ComputeSignature: compute HMAC in one step
  res = TEE_MACComputeFinal(op, (void *)message, length, buf, &buf_length);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to compute HMAC, res=%x", res);
    TEE_FreeTransientObject(master_key);
    TEE_FreeOperation(op);
    return;
  }
  
  // Copy result to output, same as keymaster
  to_write = buf_length;
  if (buf_length > signature_length)
    to_write = signature_length;

  memset(signature, 0, signature_length);
  memcpy(signature, buf, to_write);

  // Clean up resources
  TEE_FreeOperation(op);
  TEE_FreeTransientObject(master_key);

  return;
}

static void
compute_password_signature(gatekeeper_device_t *dev, uint8_t *signature,
                           uint32_t signature_length, const uint8_t *key,
                           uint32_t key_length, const uint8_t *password,
                           uint32_t password_length, gatekeeper_salt_t salt)
{
  uint8_t salted_password[password_length + sizeof(salt)];
  memcpy(salted_password, &salt, sizeof(salt));
  memcpy(salted_password + sizeof(salt), password, password_length);
  compute_signature(dev, signature, signature_length, key,
                           key_length, salted_password,
                           password_length + sizeof(salt));
}
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{

	// Decode param_types for debugging

	// Print buffer sizes if they are memory references
	if (TEE_PARAM_TYPE_GET(param_types, 0) == TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 0) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 0) == TEE_PARAM_TYPE_MEMREF_INOUT) {
	}

	if (TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_MEMREF_INOUT) {
	}

	TEE_Result res = TEE_ERROR_GENERIC;
	if (param_types != TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;

    /* Initialize device */
    gatekeeper_device_t dev;
    gatekeeper_error_t error;
    uint32_t resp_size;
        /* Initialize device functions */
    dev.impl = NULL; /* No implementation data needed for this example */
    dev.get_auth_token_key = get_auth_token_key;
    dev.get_password_key = GetMasterKey;
    dev.compute_password_signature = compute_password_signature;
    dev.get_random = get_random;
    dev.compute_signature = compute_signature;
    dev.get_milliseconds_since_boot = GetTimestamp;
    dev.remove_user = delete_user;
    dev.remove_all_users = delete_all_users;
    dev.get_failure_record = GetFailureRecord;
    dev.clear_failure_record = ClearFailureRecord;
    dev.write_failure_record = WriteFailureRecord;
    dev.is_hardware_backed = is_hardware_backed;

    switch (cmd_id) {
        case GK_ENROLL:
            /* Create a new request to deserialize into */
            gatekeeper_enroll_request_t deserialized_request;
            gatekeeper_enroll_response_t enroll_response;

            /* Explicitly zero out the structure to prevent uninitialized data issues */
            memset(&deserialized_request, 0, sizeof(deserialized_request));
            memset(&enroll_response, 0, sizeof(enroll_response));

            /* Extra safety check for buffer size */
            if (params[0].memref.size < 8) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            error = gatekeeper_enroll_request_deserialize(
                &deserialized_request,
                (uint8_t *)params[0].memref.buffer,
                (uint8_t *)params[0].memref.buffer + params[0].memref.size);
            if (error != ERROR_NONE) {
              return TEE_ERROR_BAD_PARAMETERS;
            }
            gatekeeper_enroll(&dev, &deserialized_request, &enroll_response);
            resp_size = gatekeeper_enroll_response_get_size(&enroll_response);
            res = gatekeeper_enroll_response_serialize(
                &enroll_response, (uint8_t *)params[1].memref.buffer,
                (uint8_t *)params[1].memref.buffer + resp_size);
            if (res == 0)
              return TEE_ERROR_GENERIC;
            else
              return TEE_SUCCESS;
        case GK_VERIFY:
            /* Create a new request to deserialize into */
            gatekeeper_verify_request_t verify_deserialized_request;
            gatekeeper_verify_response_t verify_response;

            /* Explicitly zero out the structure to prevent uninitialized data issues */
            memset(&verify_deserialized_request, 0, sizeof(verify_deserialized_request));
            memset(&verify_response, 0, sizeof(verify_response));

            /* Check if output buffer is large enough */
            if (params[1].memref.size < 16) {
                return TEE_ERROR_SHORT_BUFFER;
            }

            /* Extra safety check for input buffer size */
            if (params[0].memref.size < 8) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            /* STEP 1: Deserialize verify request */
            error = gatekeeper_verify_request_deserialize(
                &verify_deserialized_request,
                (uint8_t *)params[0].memref.buffer,
                (uint8_t *)params[0].memref.buffer + params[0].memref.size);

            if (error != ERROR_NONE) {
                return TEE_ERROR_BAD_PARAMETERS;
            }

            /* STEP 2: Process verify request */
            gatekeeper_verify(&dev, &verify_deserialized_request, &verify_response);

            /* STEP 3: Calculate response size */
            resp_size = gatekeeper_verify_response_get_size(&verify_response);

            /* Check if output buffer is large enough for response */
            if (params[1].memref.size < resp_size) {
                return TEE_ERROR_SHORT_BUFFER;
            }

            /* STEP 4: Serialize response */
            res = gatekeeper_verify_response_serialize(
                &verify_response,
                (uint8_t *)params[1].memref.buffer,
                (uint8_t *)params[1].memref.buffer + params[1].memref.size);


            /* Check for serialization errors */
            if (res == 0) {
                return TEE_ERROR_GENERIC;
            }

            /* Set correct output size */
            params[1].memref.size = res;

            return TEE_SUCCESS;
        case GK_DELETE_USER:
          gatekeeper_delete_user_request_t del_user_deserialized_request;
          gatekeeper_delete_user_response_t delete_user_response;

          /* Explicitly zero out the structure to prevent uninitialized data
           * issues */
          memset(&del_user_deserialized_request, 0,
                 sizeof(del_user_deserialized_request));
          memset(&delete_user_response, 0, sizeof(delete_user_response));
          /* Extra safety check for buffer size */
          if (params[0].memref.size < 8) {
            return TEE_ERROR_BAD_PARAMETERS;
          }

          /* CRITICAL FIX: Using actual buffer size instead of sizeof pointer */
          error = gatekeeper_delete_user_request_deserialize(
              &del_user_deserialized_request, (uint8_t *)params[0].memref.buffer,
              (uint8_t *)params[0].memref.buffer + params[0].memref.size);
          if (error != ERROR_NONE) {
            return TEE_ERROR_BAD_PARAMETERS;
          }
          gatekeeper_delete_user(&dev, &del_user_deserialized_request,
                                 &delete_user_response);
          resp_size = gatekeeper_delete_user_response_get_size(
              &delete_user_response);
          res = gatekeeper_delete_user_response_serialize(
              &delete_user_response, (uint8_t *)params[1].memref.buffer,
              (uint8_t *)params[1].memref.buffer + resp_size);
          if (res == 0)
            return TEE_ERROR_GENERIC;
          else
            return TEE_SUCCESS;
        case GK_DELETE_ALL_USERS:
          gatekeeper_delete_all_users_request_t del_all_deserialized_request;
          gatekeeper_delete_all_users_response_t delete_all_response;

          /* Explicitly zero out the structure to prevent uninitialized data
           * issues */
          memset(&del_all_deserialized_request, 0,
                 sizeof(del_all_deserialized_request));
          memset(&delete_all_response, 0, sizeof(delete_all_response));
          /* Extra safety check for buffer size */
          if (params[0].memref.size < 8) {
            return TEE_ERROR_BAD_PARAMETERS;
          }

          /* CRITICAL FIX: Using actual buffer size instead of sizeof pointer */
          error = gatekeeper_delete_all_users_request_deserialize(
              &del_all_deserialized_request, (uint8_t *)params[0].memref.buffer,
              (uint8_t *)params[0].memref.buffer + params[0].memref.size);
          if (error != ERROR_NONE) {
            return TEE_ERROR_BAD_PARAMETERS;
          }
          gatekeeper_delete_all_users(&dev, &del_all_deserialized_request,
                                      &delete_all_response);
          resp_size = gatekeeper_delete_all_users_response_get_size(
              &delete_all_response);
          res = gatekeeper_delete_all_users_response_serialize(
              &delete_all_response, (uint8_t *)params[1].memref.buffer,
              (uint8_t *)params[1].memref.buffer + resp_size);
          if (res == 0)
            return TEE_ERROR_GENERIC;
          else
            return TEE_SUCCESS;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }

	(void)&sess_ctx; /* Unused parameter */

	return TEE_ERROR_BAD_PARAMETERS;
}
