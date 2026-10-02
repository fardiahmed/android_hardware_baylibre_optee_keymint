# A16_RISCV/vendor/spacemit/hardware/optee_keymint: android16-riscv

Changes made for the Android 16 (AOSP, riscv64) bring-up of the BananaPi BPI-F3 (SpacemiT K1), on branch `android16-riscv`.

BayLibre's OP-TEE KeyMint 3 and Gatekeeper (HALs + TAs), used on the K1 with the RISE RISC-V OP-TEE port (OpenSBI domains + MPXY, `bootloader/spacemit/optee_os`). It replaces the software `rust_nonsecure` KeyMint and `nonsecure` Gatekeeper when `SPACEMIT_OPTEE` is on (device/spacemit/common/spacemit-features.mk).

## Changes

- **keymaster: ta: advance the output pointer in setAdditionalAttestationInfo**: TA_serialize_rsp_err() returns the number of bytes written, not the new position: assigning it to out turned the pointer into the value 4.
- **keymaster: ta: take the root of trust from OP-TEE's boot_rot PTA**: The bootloader sets it after AVB (CFG_BOOT_ROT_PTA in bootloader/spacemit/optee_os), with no secure storage needed, instead of an AVB TA persistent value. getRootOfTrust returns it, and attestation records use its boot key, lock and boot state instead of the stub key, the unlocked default and the HAL's boot state.

## Notes

- Root of trust: pi-u-boot sends it to OP-TEE after AVB. The device is always unlocked (no lock-state storage without RPMB), so the state is ORANGE; attestation keeps the version 2 RootOfTrust (no verifiedBootHash), getRootOfTrust has all four fields.
- The TAs are not built by Soong: `./build.sh k1` builds them after the bootloaders with OP-TEE's `export-ta_rv64` TA dev kit and the bootloader riscv64 toolchain, and stages them in `vendor/spacemit/k1/optee` (installed to `/vendor/lib/optee_armtz`). They need `CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y` (GP 1.1 TEE API, `uint32_t` sizes).
- The TAs are signed with OP-TEE's default development key (`optee_os/keys/default_ta.pem`).
- Secure storage is OP-TEE's REE FS through tee-supplicant in `/mnt/vendor/persist/tee`: KeyMint is an `early_hal` that vold needs before `/data` is mounted. The K1 port has no hardware unique key yet (OP-TEE's default zero HUK) and no RPMB, so the storage is encrypted with a key that is not device-unique and has no rollback protection: fine for development, not for products.
- No attestation keys are provisioned (`CFG_ATTESTATION_PROVISIONING` is off).
- `keymaster/3.0` (HIDL Keymaster 3) and `wait_for_keymaster_optee` are not installed.

## Build

```
./build.sh k1                                    # TAs, HALs and images
./build.sh k1 --bootloader-only                  # OP-TEE and the TAs only
```

## Test

```
adb shell ps -A | grep -E 'tee-supplicant|keymint|gatekeeper'
adb shell ls /mnt/vendor/persist/tee
adb shell dumpsys android.hardware.security.keymint.IKeyMintDevice/default
adb logcat -s android.hardware.security.keymint-service.optee
```
