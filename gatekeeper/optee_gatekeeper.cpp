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
#include <android-base/logging.h>
#include <utils/Log.h>

#include <endian.h>
#include <limits>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <gatekeeper/password_handle.h>
#include <hardware/hw_auth_token.h>

#include "optee_gatekeeper.h"
#include "optee_gatekeeper_ipc.h"

namespace aidl::android::hardware::gatekeeper {

using ::gatekeeper::ERROR_INVALID;
using ::gatekeeper::ERROR_NONE;
using ::gatekeeper::ERROR_RETRY;
using ::gatekeeper::SizedBuffer;
using ::gatekeeper::VerifyRequest;
using ::gatekeeper::VerifyResponse;

OpteeGateKeeperDevice::OpteeGateKeeperDevice()
    : connected_(false)
{
    initialize();
    connect();
}

OpteeGateKeeperDevice::~OpteeGateKeeperDevice()
{
    disconnect();
    finalize();
}

bool OpteeGateKeeperDevice::getConnected() {
    return connected_;
}

SizedBuffer vec2sized_buffer(const std::vector<uint8_t>& vec) {
    if (vec.size() == 0 || vec.size() > std::numeric_limits<uint32_t>::max()) return {};
    auto buffer = new uint8_t[vec.size()];
    std::copy(vec.begin(), vec.end(), buffer);
    return {buffer, static_cast<uint32_t>(vec.size())};
}

void sizedBuffer2AidlHWToken(SizedBuffer& buffer,
                             android::hardware::security::keymint::HardwareAuthToken* aidlToken) {
    const hw_auth_token_t* authToken =
            reinterpret_cast<const hw_auth_token_t*>(buffer.Data<uint8_t>());
    
    // Copy values to AIDL token
    aidlToken->challenge = authToken->challenge;
    aidlToken->userId = authToken->user_id;
    aidlToken->authenticatorId = authToken->authenticator_id;
    
    // These are in network order: translate to host
    aidlToken->authenticatorType =
            static_cast<android::hardware::security::keymint::HardwareAuthenticatorType>(
                    be32toh(authToken->authenticator_type));
    aidlToken->timestamp.milliSeconds = be64toh(authToken->timestamp);
    aidlToken->mac.insert(aidlToken->mac.begin(), std::begin(authToken->hmac),
                          std::end(authToken->hmac));
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::enroll(
        int32_t uid, const std::vector<uint8_t>& currentPasswordHandle,
        const std::vector<uint8_t>& currentPassword, const std::vector<uint8_t>& desiredPassword,
        GatekeeperEnrollResponse* rsp) {
    if (!connected_) {
        LOG(ERROR) << "Device is not connected";
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (desiredPassword.size() == 0) {
        LOG(ERROR) << "Desired password size is 0";
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (currentPasswordHandle.size() > 0 && 
        currentPasswordHandle.size() != sizeof(::gatekeeper::password_handle_t)) {
        LOG(ERROR) << "Password handle has wrong length";
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }
    
    // Create and send the request
    EnrollRequest request(uid, vec2sized_buffer(currentPasswordHandle),
                          vec2sized_buffer(desiredPassword), vec2sized_buffer(currentPassword));
    EnrollResponse response;
    auto error = Send(request, &response);
    
    if (error != ERROR_NONE) {
        LOG(ERROR) << "Communication error during enroll";
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (response.error == ERROR_RETRY) {
        LOG(ERROR) << "Enroll response has a retry error: " << response.retry_timeout;
        *rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), 0, {}};
        return ndk::ScopedAStatus::ok();
    } else if (response.error != ERROR_NONE) {
        LOG(ERROR) << "Enroll response has an error: " << response.error;
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        const ::gatekeeper::password_handle_t* password_handle =
        response.enrolled_password_handle.Data<::gatekeeper::password_handle_t>();
        *rsp = {STATUS_OK,
                0,
                static_cast<int64_t>(password_handle->user_id),
                {response.enrolled_password_handle.Data<uint8_t>(),
                 (response.enrolled_password_handle.Data<uint8_t>() +
                  response.enrolled_password_handle.size())}};
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::verify(
        int32_t uid, int64_t challenge, const std::vector<uint8_t>& enrolledPasswordHandle,
        const std::vector<uint8_t>& providedPassword, GatekeeperVerifyResponse* rsp) {
  if (!connected_) {
    LOG(ERROR) << "Device is not connected";
    return ndk::ScopedAStatus(
        AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
  }

    if (enrolledPasswordHandle.size() == 0) {
        LOG(ERROR) << "Enrolled password size is 0";
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    if (enrolledPasswordHandle.size() > 0) {
        if (enrolledPasswordHandle.size() != sizeof(::gatekeeper::password_handle_t)) {
            LOG(ERROR) << "Password handle has wrong length";
            return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
        }
    }

    // Create and send the request
    VerifyRequest request(uid, challenge, vec2sized_buffer(enrolledPasswordHandle),
                          vec2sized_buffer(providedPassword));
    VerifyResponse response;

    auto error = Send(request, &response);
    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_RETRY) {
        *rsp = {ERROR_RETRY_TIMEOUT, static_cast<int32_t>(response.retry_timeout), {}};
        return ndk::ScopedAStatus::ok();
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        // On Success, return GatekeeperVerifyResponse with Success Status, timeout{0} and
        // valid HardwareAuthToken.
        *rsp = {response.request_reenroll ? STATUS_REENROLL : STATUS_OK, 0, {}};
        // Convert the hw_auth_token_t to HardwareAuthToken in the response.
        sizedBuffer2AidlHWToken(response.auth_token, &rsp->hardwareAuthToken);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::deleteUser(int32_t uid) {
    if (!connected_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    DeleteUserRequest request(uid);
    DeleteUserResponse response;
    auto error = Send(request, &response);

    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_NOT_IMPLEMENTED) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

::ndk::ScopedAStatus OpteeGateKeeperDevice::deleteAllUsers() {
    if (!connected_) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    }

    DeleteAllUsersRequest request;
    DeleteAllUsersResponse response;
    auto error = Send(request, &response);

    if (error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else if (response.error == ERROR_NOT_IMPLEMENTED) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_NOT_IMPLEMENTED));
    } else if (response.error != ERROR_NONE) {
        return ndk::ScopedAStatus(AStatus_fromServiceSpecificError(ERROR_GENERAL_FAILURE));
    } else {
        return ndk::ScopedAStatus::ok();
    }
}

bool OpteeGateKeeperDevice::initialize()
{
  if (!gatekeeperIPC_.initialize()) {
    LOG(ERROR) << "Failed to initialize TEE context";
    return false;
  }
  return true;
}

bool OpteeGateKeeperDevice::connect()
{
  if (connected_) {
    return false;
  }

  if (!gatekeeperIPC_.connect(TA_GATEKEEPER_UUID)) {
    LOG(ERROR) << "Failed to connect to Gatekeeper TA";
    return false;
  }
    
  connected_ = true;
  return true;
}

void OpteeGateKeeperDevice::disconnect()
{
    if (connected_) {
        gatekeeperIPC_.disconnect();
        connected_ = false;
    }
}

void OpteeGateKeeperDevice::finalize()
{
    gatekeeperIPC_.finalize();
}

gatekeeper_error_t OpteeGateKeeperDevice::Send(uint32_t command, const GateKeeperMessage& request,
        GateKeeperMessage *response) {
    uint32_t request_size = request.GetSerializedSize();
    if (request_size > SEND_BUF_SIZE) {
        LOG(ERROR) << "Request size exceeds SEND_BUF_SIZE (" << SEND_BUF_SIZE << " bytes)";
        return ERROR_INVALID;
    }
    uint8_t recv_buf[RECV_BUF_SIZE] = {0};  // Initialize to zeros
    uint8_t send_buf[SEND_BUF_SIZE] = {0};  // Initialize to zeros
    uint32_t response_size = RECV_BUF_SIZE;
    request.Serialize(send_buf, send_buf + request_size);
    int rc = gatekeeperIPC_.call(command, send_buf, request_size, recv_buf, response_size);
    if (!rc) {
        LOG(ERROR) << "IPC call failed";
        return ERROR_INVALID;
    }
    // Check if response is empty
    if (response_size == 0) {
        LOG(ERROR) << "Empty response received";
        response->error = ERROR_INVALID;
        return ERROR_INVALID;
    }
    
    // Deserialize response
    gatekeeper_error_t result = response->Deserialize(
         (const uint8_t *)(&recv_buf), (const uint8_t *)(&recv_buf + response_size));

    if (result != ERROR_NONE) {
        response->error = ERROR_INVALID;
        LOG(ERROR) << "Response deserialization error";
        return ERROR_INVALID;
    }

    return ERROR_NONE;
}

}  // namespace aidl::android::hardware::gatekeeper
