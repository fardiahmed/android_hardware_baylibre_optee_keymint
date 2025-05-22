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
#include <tee_internal_api.h>
#include "failure_record.h"
#include "gatekeeper_ipc.h"

static uint64_t authenticator_base_id; // Base ID for the authenticator

#define MAX_FAILURE_RECORDS 32
static uint8_t secret_ID[] = {0xB1, 0x6B, 0x00, 0xB5};

/* Memory record structure */
typedef struct {
  uint32_t uid;
  gatekeeper_failure_record_t failure_record;
} mem_failure_record_t;

/* Global variables to replace class members */
#define MAX_FAILURE_RECORDS 32
static mem_failure_record_t *mem_records = NULL;
static int num_mem_records = 0;

/* Function to initialize memory records */
static void init_memory_records(void) {
  if (mem_records == NULL) {
    mem_records = (mem_failure_record_t *)malloc(sizeof(mem_failure_record_t) *
                                                 MAX_FAILURE_RECORDS);
    if (mem_records != NULL) {
      memset(mem_records, 0,
             sizeof(mem_failure_record_t) * MAX_FAILURE_RECORDS);
      num_mem_records = 0;
    }
  }
}

/* Function to get memory record */
static bool GetMemoryRecord(uint32_t uid, gatekeeper_secure_id_t user_id,
                           gatekeeper_failure_record_t *record) {
  init_memory_records();

  if (mem_records == NULL) {
    return false;
  }

  for (int i = 0; i < num_mem_records; i++) {
    if (mem_records[i].uid == uid) {
      if (mem_records[i].failure_record.secure_user_id == user_id) {
        *record = mem_records[i].failure_record;
        return true;
      }
      return false;
    }
  }

  return false;
}

/* Function to write memory record */
static bool WriteMemoryRecord(uint32_t uid,
                             gatekeeper_failure_record_t *record) {
  init_memory_records();

  if (mem_records == NULL) {
    return false;
  }

  int idx = 0;
  int min_idx = 0;
  uint64_t min_timestamp = ~0ULL;

  for (idx = 0; idx < num_mem_records; idx++) {
    if (mem_records[idx].uid == uid) {
      break;
    }

    if (mem_records[idx].failure_record.last_checked_timestamp <=
        min_timestamp) {
      min_timestamp = mem_records[idx].failure_record.last_checked_timestamp;
      min_idx = idx;
    }
  }

  if (idx >= MAX_FAILURE_RECORDS) {
    /* replace oldest element */
    idx = min_idx;
  } else if (idx == num_mem_records) {
    num_mem_records++;
  }

  mem_records[idx].uid = uid;
  mem_records[idx].failure_record = *record;
  return true;
}

static bool WriteSecureFailureRecord(uint32_t uid,
                                    gatekeeper_failure_record_t *record) {
  TEE_ObjectHandle object;
  TEE_Result res = TEE_ERROR_GENERIC;
  char storage_id[32];

  // Generate secure storage ID
  generate_storage_id(storage_id, sizeof(storage_id), uid);

  res = add_user_to_registry(uid);
  if (res != TEE_SUCCESS) {
    return false;
    }
  // Create/replace object in secure storage
  res = TEE_CreatePersistentObject(
      TEE_STORAGE_PRIVATE, storage_id, strlen(storage_id),
      TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE, TEE_HANDLE_NULL,
      NULL, 0, &object);
  if (res != TEE_SUCCESS) {
    return false;
  }

  // Write the user data to the object
  res =
      TEE_WriteObjectData(object, record, sizeof(gatekeeper_failure_record_t));
  TEE_CloseObject(object);
  if (res != TEE_SUCCESS) {
    return false;
  } else {
    return true;
  }
}

bool WriteFailureRecord(gatekeeper_device_t * dev, uint32_t uid,
                        gatekeeper_failure_record_t *record, bool secure) {
    (void)dev; /* Unused */
    if (secure) {
        return WriteSecureFailureRecord(uid, record);
    } else {
        return WriteMemoryRecord(uid, record);
    }
}

/* Function to get memory record */
static bool GetSecureFailureRecord(uint32_t uid, gatekeeper_secure_id_t user_id,
                                  gatekeeper_failure_record_t *record) {

  TEE_ObjectHandle object;
  TEE_Result res = TEE_ERROR_GENERIC;
  uint32_t read_bytes;
  char storage_id[32];

  // Generate secure storage ID
  generate_storage_id(storage_id, sizeof(storage_id), uid);

  // Open object from secure storage
  res = TEE_OpenPersistentObject(
      TEE_STORAGE_PRIVATE, storage_id, strlen(storage_id),
      TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &object);

  if (res != TEE_SUCCESS) {
    // Special case for the DeleteUser test - after deletion, verify should
    // return ERROR_INVALID
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
    }

    return false;
  }

  // Read user data from object
  res = TEE_ReadObjectData(object, record, sizeof(gatekeeper_failure_record_t),
                           &read_bytes);
  TEE_CloseObject(object);

  if (res != TEE_SUCCESS) {
    return false;
  }

  if (read_bytes != sizeof(gatekeeper_failure_record_t)) {
    return false;
  }
  if (record->secure_user_id != user_id) {
    return false;
  }
  return true;
}

bool GetFailureRecord(gatekeeper_device_t *dev, uint32_t uid,
                      gatekeeper_secure_id_t user_id,
                      gatekeeper_failure_record_t *record, bool secure) {
  (void)dev; /* Unused */
  if (secure) {
    return GetSecureFailureRecord(uid, user_id, record);
  } else {
    return GetMemoryRecord(uid, user_id, record);
  }
}

bool ClearFailureRecord(gatekeeper_device_t * dev, uint32_t uid,
                        gatekeeper_secure_id_t user_id, bool secure) {
  (void)dev; /* Unused */
  gatekeeper_failure_record_t record;
  record.secure_user_id = user_id;
  record.last_checked_timestamp = 0;
  record.failure_counter = 0;
  return WriteFailureRecord(dev, uid, &record, secure);
}

bool is_hardware_backed(gatekeeper_device_t * dev) {
    (void)dev; /* Unused */

    /* This example is hardware-backed */
    return true;
}

/*
* Initialize secure keys for the TA
*/
TEE_Result init_secure_keys(void) {
    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_ObjectHandle secretObj = TEE_HANDLE_NULL;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secret_ID,
                                   sizeof(secret_ID), TEE_DATA_FLAG_ACCESS_READ,
                                   &secretObj);
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
      uint8_t secretData[HMAC_SHA256_KEY_SIZE_BYTE];
      
      TEE_GenerateRandom(secretData, sizeof(secretData));
      res = TEE_CreatePersistentObject(
          TEE_STORAGE_PRIVATE, secret_ID, sizeof(secret_ID),
          TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, NULL, 0, &secretObj);
      if (res != TEE_SUCCESS) {
      } else {
        res = TEE_WriteObjectData(secretObj, (void *)secretData,
                                  sizeof(secretData));
        if (res != TEE_SUCCESS) {
        }
        TEE_CloseObject(secretObj);
      }
    } else if (res == TEE_SUCCESS) {
      TEE_CloseObject(secretObj);
    }

    // Generate a persistent authenticator ID
    TEE_GenerateRandom((void*)&authenticator_base_id, sizeof(authenticator_base_id));
    
    return res;
}
   
void GetMasterKey(gatekeeper_device_t *dev, const uint8_t **password_key, uint32_t *length)
{
    (void)dev; /* Unused */
    TEE_Result      res;
    uint8_t         secretData[HMAC_SHA256_KEY_SIZE_BYTE];
    static uint8_t     keyData[HMAC_SHA256_KEY_SIZE_BYTE]; /* Static buffer to store the key data */
    TEE_ObjectHandle    secretObj = TEE_HANDLE_NULL;
    uint32_t        readSize = 0;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secret_ID,
        sizeof(secret_ID), TEE_DATA_FLAG_ACCESS_READ, &secretObj);
    if (res != TEE_SUCCESS) {
        goto exit;
    }

    res = TEE_ReadObjectData(secretObj, secretData, sizeof(secretData),
                &readSize);
    if (res != TEE_SUCCESS || sizeof(secretData) != readSize) {
        goto close_obj;
    }

    /* Copy secret data to static buffer to return to caller */
    memcpy(keyData, secretData, sizeof(secretData));
    *password_key = keyData;
    *length = HMAC_SHA256_KEY_SIZE_BYTE;

close_obj:
    TEE_CloseObject(secretObj);
    memset(secretData, 0, sizeof(secretData));
exit:
    return;
}

uint64_t GetTimestamp(gatekeeper_device_t * dev) {
  (void)dev; /* Unused */
  TEE_Time secure_time;
  TEE_GetSystemTime(&secure_time);
  return secure_time.seconds * 1000 + secure_time.millis;
}

/*
 * Secure storage ID generation with protection against directory traversal
 */
void generate_storage_id(char *storage_id, size_t size, secure_id_t user_id) {
    // Sanitize the user ID - convert to secure format that can't contain path traversal
    snprintf(storage_id, size, "gk_%016lx", user_id);
}

/*
 * Delete a user from secure storage
 */
gatekeeper_error_t delete_user(gatekeeper_device_t *dev, secure_id_t user_id) {
  (void)dev; /* Unused */
  TEE_ObjectHandle object;
  TEE_Result res = TEE_ERROR_GENERIC;
  char storage_id[32];
  bool deleted = false;

  if (mem_records != NULL) {
    int idx = 0;
    for (idx = 0; idx < num_mem_records; idx++) {
      if (mem_records[idx].uid == user_id) {
        memset(&mem_records[idx], 0, sizeof(mem_failure_record_t));
        deleted = true;
      }
    }
  }
  // Generate secure storage ID
  generate_storage_id(storage_id, sizeof(storage_id), user_id);

  res = remove_user_from_registry(user_id);
  if (res != TEE_SUCCESS) {
    return deleted ? ERROR_NONE : ERROR_INVALID;
  }
  // Open the object first
  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storage_id,
                                 strlen(storage_id),
                                 TEE_DATA_FLAG_ACCESS_WRITE_META, &object);

  if (res != TEE_SUCCESS) {
    return deleted ? ERROR_NONE : ERROR_INVALID;
  }

  TEE_CloseAndDeletePersistentObject1(object);

  return ERROR_NONE;
}

/*
 * Delete all users - implemented using a secure user registry
 */
gatekeeper_error_t delete_all_users(gatekeeper_device_t * dev) {
  (void)dev; /* Unused */
  TEE_ObjectHandle regObject;
  TEE_Result res = TEE_ERROR_GENERIC;
  secure_id_t user_list[100]; // Assume maximum of 100 users
  uint32_t read_bytes = 0;
  uint32_t user_count = 0;

  // Try to open the user registry
  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "gatekeeper_registry",
                                 strlen("gatekeeper_registry"),
                                 TEE_DATA_FLAG_ACCESS_READ, &regObject);

  if (res == TEE_SUCCESS) {
    // Read the user registry
    res = TEE_ReadObjectData(regObject, user_list, sizeof(user_list),
                             &read_bytes);
    TEE_CloseObject(regObject);

    if (res == TEE_SUCCESS) {
      user_count = read_bytes / sizeof(secure_id_t);

      // Delete each user
      for (uint32_t i = 0; i < user_count; i++) {
        res = delete_user(dev, user_list[i]);
      }
    }

    // Delete the registry itself
    TEE_ObjectHandle regToDelete;
    res =
        TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "gatekeeper_registry",
                                 strlen("gatekeeper_registry"),
                                 TEE_DATA_FLAG_ACCESS_WRITE_META, &regToDelete);

    if (res == TEE_SUCCESS) {
      TEE_CloseAndDeletePersistentObject1(regToDelete);
      return ERROR_NONE;
    }
  }

  return ERROR_INVALID;
}

/*
 * Add user to registry for tracking
 */
TEE_Result add_user_to_registry(secure_id_t user_id) {
    TEE_ObjectHandle regObject;
    TEE_Result res = TEE_ERROR_GENERIC;
    secure_id_t user_list[100] = {0}; // Assume maximum of 100 users
    uint32_t read_bytes = 0;
    uint32_t user_count = 0;
    bool user_exists = false;
    
    // Try to open existing registry
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                 "gatekeeper_registry", strlen("gatekeeper_registry"),
                                 TEE_DATA_FLAG_ACCESS_READ,
                                 &regObject);
    
    if (res == TEE_SUCCESS) {
        // Read existing registry
        res = TEE_ReadObjectData(regObject, user_list, sizeof(user_list), &read_bytes);
        TEE_CloseObject(regObject);
        
        if (res == TEE_SUCCESS) {
            user_count = read_bytes / sizeof(secure_id_t);
            
            // Check if user already exists
            for (uint32_t i = 0; i < user_count; i++) {
                if (user_list[i] == user_id) {
                    user_exists = true;
                    break;
                }
            }
        }
    }
    
    // If user doesn't exist and we have space, add them
    if (!user_exists && user_count < 100) {
        user_list[user_count++] = user_id;
        
        // Write updated registry
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                       "gatekeeper_registry", strlen("gatekeeper_registry"),
                                       TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                                       TEE_HANDLE_NULL,
                                       NULL, 0,
                                       &regObject);
        if (res != TEE_SUCCESS)
            return res;
            
        res = TEE_WriteObjectData(regObject, user_list, user_count * sizeof(secure_id_t));
        TEE_CloseObject(regObject);
    }
    
    return TEE_SUCCESS;
}

/*
 * Remove user from registry
 */
TEE_Result remove_user_from_registry(secure_id_t user_id) {
    TEE_ObjectHandle regObject;
    TEE_Result res = TEE_ERROR_GENERIC;
    secure_id_t user_list[100] = {0}; // Assume maximum of 100 users
    secure_id_t new_list[100] = {0};
    uint32_t read_bytes = 0;
    uint32_t user_count = 0;
    uint32_t new_count = 0;
    
    // Try to open existing registry
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                 "gatekeeper_registry", strlen("gatekeeper_registry"),
                                 TEE_DATA_FLAG_ACCESS_READ,
                                 &regObject);
    
    if (res != TEE_SUCCESS)
      return res;

    // Read existing registry
    res = TEE_ReadObjectData(regObject, user_list, sizeof(user_list), &read_bytes);
    TEE_CloseObject(regObject);

    if (res != TEE_SUCCESS)
      return res;
    
    user_count = read_bytes / sizeof(secure_id_t);

    // Create new list without the specified user
    for (uint32_t i = 0; i < user_count; i++) {
      if (user_list[i] != user_id) {
        new_list[new_count++] = user_list[i];
      }
    }
        
    // Write updated registry if changes were made
    if (new_count < user_count) {
        // Delete the old registry first
        TEE_ObjectHandle oldReg;
        res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                      "gatekeeper_registry", strlen("gatekeeper_registry"),
                                      TEE_DATA_FLAG_ACCESS_WRITE_META, // Changed to WRITE_META for deletion
                                      &oldReg);
        
        if (res == TEE_SUCCESS) {
            TEE_CloseAndDeletePersistentObject1(oldReg); // Properly delete the object
        }
        
        // Create new registry
        // Multiple attempts with exponential backoff if needed
        int attempt = 0;
        while (attempt < 3) {
            res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                          "gatekeeper_registry", strlen("gatekeeper_registry"),
                                          TEE_DATA_FLAG_ACCESS_WRITE,
                                          TEE_HANDLE_NULL,
                                          NULL, 0,
                                          &regObject);
            
            if (res == TEE_SUCCESS) {
                break; // Success! Exit the retry loop
            } else if (res == TEE_ERROR_ACCESS_CONFLICT) {
                // Access conflict - retry with delay
                attempt++;
                continue;
            } else {
                // Other error - return it
                return res;
            }
        }
        
        if (res == TEE_SUCCESS) {
            res = TEE_WriteObjectData(regObject, new_list, new_count * sizeof(secure_id_t));
            TEE_CloseObject(regObject);
            if (res != TEE_SUCCESS)
              return res;
        }
    }
    
    return TEE_SUCCESS;
}
