use std::collections::HashMap;
use std::io::{self, Read};
use std::pin::Pin as StdPin;
use std::str::FromStr;
use std::task::{Context, Poll};

use aes_gcm_siv::aead::generic_array::typenum::Unsigned;
use aes_gcm_siv::{AeadCore, AeadInPlace, KeyInit};
use async_trait::async_trait;
use futures::executor::block_on;
use libsignal_account_keys::{
    AccountEntropyPool as LibSignalAccountEntropyPool, BACKUP_KEY_LEN,
    BackupKey as LibSignalBackupKey, MEDIA_ID_LEN, PinHash as LibSignalPinHash, local_pin_hash,
    verify_local_pin_hash,
};
use libsignal_protocol::{
    Aci as LibSignalAci, CiphertextMessage as LibSignalCiphertextMessage,
    ContentHint as LibSignalContentHint, DeviceId, Direction, Fingerprint as LibSignalFingerprint,
    GenericSignedPreKey, IdentityChange, IdentityKey as LibSignalIdentityKey,
    IdentityKeyPair as LibSignalIdentityKeyPair, IdentityKeyStore, KeyPair as LibSignalKeyPair,
    KyberPreKeyId, KyberPreKeyRecord as LibSignalKyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle as LibSignalPreKeyBundle, PreKeyId, PreKeyRecord as LibSignalPreKeyRecord,
    PreKeyStore, PrivateKey as LibSignalPrivateKey, ProtocolAddress as LibSignalProtocolAddress,
    PublicKey as LibSignalPublicKey, ScannableFingerprint as LibSignalScannableFingerprint,
    SealedSenderDecryptionResult as LibSignalSealedSenderDecryptionResult,
    SealedSenderV2SentMessage, SenderCertificate as LibSignalSenderCertificate,
    SenderKeyDistributionMessage as LibSignalSenderKeyDistributionMessage,
    SenderKeyMessage as LibSignalSenderKeyMessage, SenderKeyRecord as LibSignalSenderKeyRecord,
    SenderKeyStore, ServerCertificate as LibSignalServerCertificate,
    ServiceId as LibSignalServiceId, ServiceIdFixedWidthBinaryBytes,
    SessionRecord as LibSignalSessionRecord, SessionStore, SessionUsabilityRequirements,
    SignalMessage as LibSignalSignalMessage, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord as LibSignalSignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent as LibSignalUnidentifiedSenderMessageContent,
    create_sender_key_distribution_message, group_decrypt, group_encrypt, kem as libsignal_kem,
    message_decrypt, message_encrypt, process_prekey_bundle,
    process_sender_key_distribution_message, sealed_sender_decrypt, sealed_sender_decrypt_to_usmc,
    sealed_sender_encrypt, sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt,
    should_use_nonpq_session,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use signal_crypto::{SimpleHpkeReceiver, SimpleHpkeSender};
use signal_media::sanitize::{mp4, webp};
use usernames::{NicknameLimits, Username};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use zkgroup::auth::{
    AnyAuthCredentialPresentation as ZkAnyAuthCredentialPresentation,
    AuthCredentialWithPni as ZkAuthCredentialWithPni,
    AuthCredentialWithPniResponse as ZkAuthCredentialWithPniResponse,
    AuthCredentialWithPniZkcResponse as ZkAuthCredentialWithPniZkcResponse,
};
use zkgroup::backups::{
    BackupAuthCredential as ZkBackupAuthCredential,
    BackupAuthCredentialPresentation as ZkBackupAuthCredentialPresentation,
    BackupAuthCredentialRequest as ZkBackupAuthCredentialRequest,
    BackupAuthCredentialRequestContext as ZkBackupAuthCredentialRequestContext,
    BackupAuthCredentialResponse as ZkBackupAuthCredentialResponse,
    BackupCredentialType as ZkBackupCredentialType, BackupLevel as ZkBackupLevel,
};
use zkgroup::call_links::{
    CallLinkAuthCredential as ZkCallLinkAuthCredential,
    CallLinkAuthCredentialPresentation as ZkCallLinkAuthCredentialPresentation,
    CallLinkAuthCredentialResponse as ZkCallLinkAuthCredentialResponse,
    CallLinkPublicParams as ZkCallLinkPublicParams, CallLinkSecretParams as ZkCallLinkSecretParams,
    CreateCallLinkCredential as ZkCreateCallLinkCredential,
    CreateCallLinkCredentialPresentation as ZkCreateCallLinkCredentialPresentation,
    CreateCallLinkCredentialRequest as ZkCreateCallLinkCredentialRequest,
    CreateCallLinkCredentialRequestContext as ZkCreateCallLinkCredentialRequestContext,
    CreateCallLinkCredentialResponse as ZkCreateCallLinkCredentialResponse,
};
use zkgroup::generic_server_params::{
    GenericServerPublicParams as ZkGenericServerPublicParams,
    GenericServerSecretParams as ZkGenericServerSecretParams,
};
use zkgroup::groups::{
    GroupMasterKey as ZkGroupMasterKey, GroupPublicParams as ZkGroupPublicParams,
    GroupSecretParams as ZkGroupSecretParams, ProfileKeyCiphertext as ZkProfileKeyCiphertext,
    UuidCiphertext as ZkUuidCiphertext,
};
use zkgroup::groups::{
    GroupSendDerivedKeyPair as ZkGroupSendDerivedKeyPair,
    GroupSendEndorsement as ZkGroupSendEndorsement,
    GroupSendEndorsementsResponse as ZkGroupSendEndorsementsResponse,
    GroupSendFullToken as ZkGroupSendFullToken, GroupSendToken as ZkGroupSendToken,
};
use zkgroup::profiles::{
    AnyProfileKeyCredentialPresentation as ZkAnyProfileKeyCredentialPresentation,
    ExpiringProfileKeyCredential as ZkExpiringProfileKeyCredential,
    ExpiringProfileKeyCredentialPresentationV2 as ZkExpiringProfileKeyCredentialPresentationV2,
    ExpiringProfileKeyCredentialResponse as ZkExpiringProfileKeyCredentialResponse,
    ProfileKey as ZkProfileKey, ProfileKeyCommitment as ZkProfileKeyCommitment,
    ProfileKeyCredentialRequest as ZkProfileKeyCredentialRequest,
    ProfileKeyCredentialRequestContext as ZkProfileKeyCredentialRequestContext,
};
use zkgroup::receipts::{
    ReceiptCredential as ZkReceiptCredential,
    ReceiptCredentialPresentation as ZkReceiptCredentialPresentation,
    ReceiptCredentialRequest as ZkReceiptCredentialRequest,
    ReceiptCredentialRequestContext as ZkReceiptCredentialRequestContext,
    ReceiptCredentialResponse as ZkReceiptCredentialResponse,
};
use zkgroup::{
    GROUP_IDENTIFIER_LEN, GROUP_MASTER_KEY_LEN, NotarySignatureBytes, PROFILE_KEY_LEN,
    PROFILE_KEY_VERSION_ENCODED_LEN, RANDOMNESS_LEN, RECEIPT_SERIAL_LEN,
    ServerPublicParams as ZkServerPublicParams, ServerSecretParams as ZkServerSecretParams,
    Timestamp as ZkTimestamp,
};

fn js_error(error: impl std::fmt::Display) -> JsError {
    JsError::new(&error.to_string())
}

fn browser_csprng() -> Result<ChaCha20Rng, JsError> {
    let mut seed = <ChaCha20Rng as SeedableRng>::Seed::default();
    getrandom::fill(&mut seed).map_err(js_error)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn public_key_from_serialized(value: &[u8]) -> Result<LibSignalPublicKey, JsError> {
    LibSignalPublicKey::try_from(value).map_err(js_error)
}

fn private_key_from_serialized(value: &[u8]) -> Result<LibSignalPrivateKey, JsError> {
    LibSignalPrivateKey::try_from(value).map_err(js_error)
}

fn timestamp_from_js_millis(value: f64) -> Result<Timestamp, JsError> {
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return Err(JsError::new(
            "timestamp must be a non-negative finite number",
        ));
    }
    Ok(Timestamp::from_epoch_millis(value as u64))
}

fn zk_timestamp_from_seconds(value: f64) -> Result<ZkTimestamp, JsError> {
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return Err(JsError::new(
            "timestamp must be a non-negative finite number of seconds",
        ));
    }
    Ok(ZkTimestamp::from_epoch_seconds(value as u64))
}

fn current_zk_timestamp() -> ZkTimestamp {
    ZkTimestamp::from_epoch_seconds((js_sys::Date::now() / 1000.0) as u64)
}

fn service_id_from_fixed_width_binary(value: &[u8]) -> Result<LibSignalServiceId, JsError> {
    let bytes: ServiceIdFixedWidthBinaryBytes = value
        .try_into()
        .map_err(|_| JsError::new("invalid Service-Id-FixedWidthBinary length"))?;
    LibSignalServiceId::parse_from_service_id_fixed_width_binary(&bytes)
        .ok_or_else(|| JsError::new("invalid Service-Id-FixedWidthBinary"))
}

fn aci_from_uuid_bytes(uuid_bytes: &[u8]) -> Result<LibSignalAci, JsError> {
    let bytes: [u8; 16] = uuid_bytes
        .try_into()
        .map_err(|_| JsError::new("UUID bytes must be 16 bytes"))?;
    Ok(LibSignalAci::from_uuid_bytes(bytes))
}

fn uuid_from_string(value: &str) -> Result<Uuid, JsError> {
    Uuid::parse_str(value).map_err(js_error)
}

fn fixed_array<const N: usize>(value: &[u8], name: &str) -> Result<[u8; N], JsError> {
    value
        .try_into()
        .map_err(|_| JsError::new(&format!("{name} must be {N} bytes")))
}

fn aci_service_id(aci: &Aci) -> Result<LibSignalAci, JsError> {
    match aci.inner {
        LibSignalServiceId::Aci(aci) => Ok(aci),
        _ => Err(JsError::new("expected ACI")),
    }
}

fn aci_from_js(value: &JsValue) -> Result<LibSignalAci, JsError> {
    if let Some(uuid_string) = value.as_string() {
        return aci_from_uuid_bytes(uuid_from_string(&uuid_string)?.as_bytes());
    }
    match service_id_from_js(value)? {
        LibSignalServiceId::Aci(aci) => Ok(aci),
        _ => Err(JsError::new("expected ACI")),
    }
}

fn pni_service_id(pni: &Pni) -> Result<libsignal_protocol::Pni, JsError> {
    match pni.inner {
        LibSignalServiceId::Pni(pni) => Ok(pni),
        _ => Err(JsError::new("expected PNI")),
    }
}

fn zkgroup_deserialize<'a, T>(bytes: &'a [u8], name: &str) -> Result<T, JsError>
where
    T: serde::Deserialize<'a> + partial_default::PartialDefault,
{
    zkgroup::deserialize(bytes).map_err(|_| JsError::new(&format!("invalid {name}")))
}

fn svr2_group_id_for_mrenclave(mrenclave: &[u8]) -> Option<u64> {
    // Mirrors vendor/libsignal/rust/attest/src/constants.rs EXPECTED_RAFT_CONFIG_SVR2.
    const SVR2_MRENCLAVE_GROUP_IDS: &[([u8; 32], u64)] = &[
        (
            [
                0x29, 0xcd, 0x63, 0xc8, 0x7b, 0xea, 0x75, 0x1e, 0x3b, 0xfd, 0x0f, 0xbd, 0x40, 0x12,
                0x79, 0x19, 0x2e, 0x2e, 0x5c, 0x99, 0x94, 0x8b, 0x4e, 0xe9, 0x43, 0x7e, 0xaf, 0xc4,
                0x96, 0x83, 0x55, 0xfb,
            ],
            10263621230883829694,
        ),
        (
            [
                0x97, 0xf1, 0x51, 0xf6, 0xed, 0x07, 0x8e, 0xdb, 0xbf, 0xd7, 0x2f, 0xa9, 0xca, 0xe6,
                0x94, 0xdc, 0xc0, 0x83, 0x53, 0xf1, 0xf5, 0xe8, 0xd9, 0xcc, 0xd7, 0x9a, 0x97, 0x1b,
                0x10, 0xff, 0xc5, 0x35,
            ],
            2330628069874851020,
        ),
        (
            [
                0x12, 0x40, 0xac, 0xbd, 0x4a, 0xa2, 0x69, 0x74, 0x18, 0x48, 0x44, 0xc8, 0xa4, 0x6b,
                0x10, 0x22, 0xd3, 0x95, 0x7a, 0xc8, 0xa7, 0x6c, 0x1f, 0xd8, 0xf5, 0xb1, 0xa1, 0x51,
                0x41, 0xee, 0x07, 0x08,
            ],
            2076725645304009823,
        ),
        (
            [
                0x3c, 0x69, 0x9f, 0x49, 0x75, 0xaa, 0xa3, 0xd1, 0x72, 0xc0, 0xaa, 0xd0, 0x42, 0xf9,
                0x4f, 0x03, 0x1b, 0x2b, 0x03, 0xe1, 0x0b, 0x9c, 0x19, 0xa4, 0x51, 0x16, 0xa0, 0x16,
                0x93, 0xd8, 0x33, 0x02,
            ],
            5138641357881452604,
        ),
        (
            [
                0xce, 0xd8, 0x21, 0x7b, 0x26, 0x22, 0x8e, 0x4b, 0x21, 0x0c, 0x98, 0x57, 0x86, 0x99,
                0x9d, 0x09, 0x5c, 0x49, 0x58, 0xa9, 0x4f, 0xaf, 0x37, 0xb1, 0x4a, 0xca, 0xf2, 0x5c,
                0x4c, 0xbb, 0x02, 0xa4,
            ],
            11311619198250676136,
        ),
    ];

    SVR2_MRENCLAVE_GROUP_IDS
        .iter()
        .find_map(|(id, group_id)| (mrenclave == id.as_slice()).then_some(*group_id))
}

fn username_limits(min_len: u32, max_len: u32) -> Result<NicknameLimits, JsError> {
    if min_len > max_len {
        return Err(JsError::new(
            "minimum nickname length must be less than or equal to maximum nickname length",
        ));
    }
    if max_len > 48 {
        return Err(JsError::new(
            "maximum nickname length must be less than or equal to 48",
        ));
    }
    Ok(NicknameLimits::new(min_len as usize, max_len as usize))
}

fn call_js_method(value: &JsValue, method_name: &str) -> Result<JsValue, JsError> {
    let method = js_sys::Reflect::get(value, &JsValue::from_str(method_name))
        .map_err(|_| JsError::new(&format!("missing {method_name} method")))?;
    let method = method
        .dyn_into::<js_sys::Function>()
        .map_err(|_| JsError::new(&format!("{method_name} is not a function")))?;
    method
        .call0(value)
        .map_err(|_| JsError::new(&format!("{method_name} threw")))
}

fn js_u32(value: &JsValue, name: &str) -> Result<u32, JsError> {
    let value = value
        .as_f64()
        .ok_or_else(|| JsError::new(&format!("{name} must be a number")))?;
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u32::MAX as f64 {
        return Err(JsError::new(&format!("{name} must be a uint32")));
    }
    Ok(value as u32)
}

fn uint8_array_to_vec(value: JsValue, name: &str) -> Result<Vec<u8>, JsError> {
    if !value.is_instance_of::<js_sys::Uint8Array>() {
        return Err(JsError::new(&format!("{name} must return a Uint8Array")));
    }
    Ok(js_sys::Uint8Array::new(&value).to_vec())
}

fn js_property(value: &JsValue, name: &str) -> Result<JsValue, JsError> {
    js_sys::Reflect::get(value, &JsValue::from_str(name))
        .map_err(|_| JsError::new(&format!("failed to read {name}")))
}

fn required_js_string(value: &JsValue, name: &str) -> Result<String, JsError> {
    js_property(value, name)?
        .as_string()
        .ok_or_else(|| JsError::new(&format!("{name} must be a string")))
}

fn optional_js_string(value: &JsValue, name: &str) -> Result<Option<String>, JsError> {
    let property = js_property(value, name)?;
    if property.is_null() || property.is_undefined() {
        Ok(None)
    } else {
        property
            .as_string()
            .map(Some)
            .ok_or_else(|| JsError::new(&format!("{name} must be a string")))
    }
}

fn required_js_bool(value: &JsValue, name: &str) -> Result<bool, JsError> {
    js_property(value, name)?
        .as_bool()
        .ok_or_else(|| JsError::new(&format!("{name} must be a boolean")))
}

fn optional_js_u32(value: &JsValue, name: &str) -> Result<Option<u32>, JsError> {
    let property = js_property(value, name)?;
    if property.is_null() || property.is_undefined() {
        Ok(None)
    } else {
        js_u32(&property, name).map(Some)
    }
}

fn js_headers_to_vec(value: &JsValue, name: &str) -> Result<Vec<(String, String)>, JsError> {
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    if !js_sys::Array::is_array(value) {
        return Err(JsError::new(&format!("{name} must be an array")));
    }
    let headers = js_sys::Array::from(value);
    headers
        .iter()
        .map(|header| {
            if !js_sys::Array::is_array(&header) {
                return Err(JsError::new(&format!(
                    "{name} entries must be [name, value] arrays"
                )));
            }
            let header = js_sys::Array::from(&header);
            if header.length() != 2 {
                return Err(JsError::new(&format!(
                    "{name} entries must have exactly two items"
                )));
            }
            let header_name = header
                .get(0)
                .as_string()
                .ok_or_else(|| JsError::new("header name must be a string"))?;
            let header_value = header
                .get(1)
                .as_string()
                .ok_or_else(|| JsError::new("header value must be a string"))?;
            Ok((header_name, header_value))
        })
        .collect()
}

fn headers_to_js_array(headers: &[(String, String)]) -> js_sys::Array {
    let result = js_sys::Array::new();
    for (name, value) in headers {
        let pair = js_sys::Array::new();
        pair.push(&JsValue::from_str(name));
        pair.push(&JsValue::from_str(value));
        result.push(&pair);
    }
    result
}

fn timestamp_epoch_millis(value: f64) -> Result<u64, JsError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
        return Err(JsError::new("timestamp must be a non-negative integer"));
    }
    Ok(value as u64)
}

fn chat_auth_header(
    auth_kind: &str,
    auth_payload: Option<Vec<u8>>,
) -> Result<(String, String), JsError> {
    match auth_kind {
        "accessKey" => Ok((
            "unidentified-access-key".to_string(),
            base64_with_padding(&fixed_array::<{ zkgroup::ACCESS_KEY_LEN }>(
                auth_payload.as_deref().unwrap_or_default(),
                "access key",
            )?),
        )),
        "groupSend" => Ok((
            "group-send-token".to_string(),
            base64_with_padding(auth_payload.as_deref().unwrap_or_default()),
        )),
        "unrestricted" => Ok((
            "unidentified-access-key".to_string(),
            base64_with_padding(&[0; zkgroup::ACCESS_KEY_LEN]),
        )),
        "story" => Err(JsError::new("story auth does not use an auth header")),
        _ => Err(JsError::new(
            "auth kind must be accessKey, groupSend, unrestricted, or story",
        )),
    }
}

fn device_specifier(device_id: Option<u32>) -> String {
    device_id.map_or_else(|| "*".to_string(), |device_id| device_id.to_string())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserOutboundMessage {
    #[serde(rename = "type")]
    message_type: u8,
    destination_device_id: u32,
    destination_registration_id: u32,
    content: String,
}

#[derive(serde::Serialize)]
struct BrowserSendMessageRequest {
    messages: Vec<BrowserOutboundMessage>,
    online: bool,
    urgent: bool,
    timestamp: u64,
}

fn outbound_sealed_messages_from_js(
    contents: js_sys::Array,
) -> Result<Vec<BrowserOutboundMessage>, JsError> {
    if contents.length() == 0 {
        return Err(JsError::new("contents must include at least one message"));
    }
    contents
        .iter()
        .map(|value| {
            let bytes = uint8_array_to_vec(js_property(&value, "contents")?, "contents")?;
            Ok(BrowserOutboundMessage {
                message_type: 6,
                destination_device_id: js_u32(&js_property(&value, "deviceId")?, "deviceId")?,
                destination_registration_id: js_u32(
                    &js_property(&value, "registrationId")?,
                    "registrationId",
                )?,
                content: base64_with_padding(&bytes),
            })
        })
        .collect()
}

fn envelope_type_from_ciphertext_message_type(message_type: u8) -> Result<u8, JsError> {
    match message_type {
        2 => Ok(1),
        3 => Ok(3),
        8 => Ok(8),
        7 => Err(JsError::new("sender-key messages cannot be sent unsealed")),
        _ => Err(JsError::new("unsupported ciphertext message type")),
    }
}

fn outbound_unsealed_messages_from_js(
    contents: js_sys::Array,
) -> Result<Vec<BrowserOutboundMessage>, JsError> {
    if contents.length() == 0 {
        return Err(JsError::new("contents must include at least one message"));
    }
    contents
        .iter()
        .map(|value| {
            let message = js_property(&value, "contents")?;
            let bytes = uint8_array_to_vec(call_js_method(&message, "serialize")?, "serialize()")?;
            let message_type = js_u32(&call_js_method(&message, "type")?, "type()")?;
            Ok(BrowserOutboundMessage {
                message_type: envelope_type_from_ciphertext_message_type(message_type as u8)?,
                destination_device_id: js_u32(&js_property(&value, "deviceId")?, "deviceId")?,
                destination_registration_id: js_u32(
                    &js_property(&value, "registrationId")?,
                    "registrationId",
                )?,
                content: base64_with_padding(&bytes),
            })
        })
        .collect()
}

fn send_message_body(
    contents: js_sys::Array,
    timestamp_millis: f64,
    online_only: bool,
    urgent: bool,
) -> Result<Vec<u8>, JsError> {
    serde_json::to_vec(&BrowserSendMessageRequest {
        messages: outbound_sealed_messages_from_js(contents)?,
        online: online_only,
        urgent,
        timestamp: timestamp_epoch_millis(timestamp_millis)?,
    })
    .map_err(js_error)
}

fn send_unsealed_message_body(
    contents: js_sys::Array,
    timestamp_millis: f64,
    online_only: bool,
    urgent: bool,
) -> Result<Vec<u8>, JsError> {
    serde_json::to_vec(&BrowserSendMessageRequest {
        messages: outbound_unsealed_messages_from_js(contents)?,
        online: online_only,
        urgent,
        timestamp: timestamp_epoch_millis(timestamp_millis)?,
    })
    .map_err(js_error)
}

fn json_body(value: serde_json::Value) -> Result<Vec<u8>, JsError> {
    serde_json::to_vec(&value).map_err(js_error)
}

fn content_type_json(request: &mut HttpRequest) {
    request.add_header("content-type".to_string(), "application/json".to_string());
}

fn optional_json_string(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value {
        map.insert(key.to_string(), serde_json::Value::String(value));
    }
}

fn js_string_array(values: js_sys::Array, name: &str) -> Result<Vec<String>, JsError> {
    values
        .iter()
        .map(|value| {
            value
                .as_string()
                .ok_or_else(|| JsError::new(&format!("{name} entries must be strings")))
        })
        .collect()
}

fn optional_uint8_array_property(value: &JsValue, name: &str) -> Result<Option<Vec<u8>>, JsError> {
    let property = js_property(value, name)?;
    if property.is_null() || property.is_undefined() {
        Ok(None)
    } else {
        uint8_array_to_vec(property, name).map(Some)
    }
}

fn js_property_or_method(
    value: &JsValue,
    property_name: &str,
    method_name: &str,
) -> Result<JsValue, JsError> {
    let property = js_property(value, property_name)?;
    if property.is_null() || property.is_undefined() {
        call_js_method(value, method_name)
    } else {
        Ok(property)
    }
}

fn js_key_id(value: &JsValue) -> Result<u32, JsError> {
    let key_id = js_property(value, "keyId")?;
    if !key_id.is_null() && !key_id.is_undefined() {
        return js_u32(&key_id, "keyId");
    }
    let id = js_property(value, "id")?;
    if !id.is_null() && !id.is_undefined() {
        return js_u32(&id, "id");
    }
    js_u32(&call_js_method(value, "id")?, "id()")
}

fn serialized_key_base64(value: JsValue, name: &str) -> Result<String, JsError> {
    let serialized = uint8_array_to_vec(call_js_method(&value, "serialize")?, name)?;
    Ok(base64_with_padding(&serialized))
}

fn pre_key_registration_body(value: &JsValue) -> Result<serde_json::Value, JsError> {
    let public_key = js_property_or_method(value, "publicKey", "publicKey")?;
    let signature = js_property_or_method(value, "signature", "signature")?;
    Ok(serde_json::json!({
        "keyId": js_key_id(value)?,
        "publicKey": serialized_key_base64(public_key, "publicKey.serialize()")?,
        "signature": base64_with_padding(&uint8_array_to_vec(signature, "signature")?),
    }))
}

fn capabilities_from_js(value: &JsValue) -> Result<serde_json::Value, JsError> {
    let capabilities = js_property(value, "capabilities")?;
    if capabilities.is_null() || capabilities.is_undefined() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    if !js_sys::Array::is_array(&capabilities) {
        return Err(JsError::new("capabilities must be an array"));
    }
    let mut result = serde_json::Map::new();
    for capability in js_sys::Array::from(&capabilities).iter() {
        let capability = capability
            .as_string()
            .ok_or_else(|| JsError::new("capabilities entries must be strings"))?;
        result.insert(capability, serde_json::Value::Bool(true));
    }
    Ok(serde_json::Value::Object(result))
}

fn bytes_json_array(bytes: &[u8]) -> serde_json::Value {
    serde_json::Value::Array(
        bytes
            .iter()
            .map(|value| serde_json::Value::Number((*value).into()))
            .collect(),
    )
}

fn registration_account_attributes_body(
    account_attributes: &JsValue,
    fetches_messages: bool,
) -> Result<serde_json::Value, JsError> {
    let recovery_password = uint8_array_to_vec(
        js_property(account_attributes, "recoveryPassword")?,
        "recoveryPassword",
    )?;
    let unidentified_access_key = uint8_array_to_vec(
        js_property(account_attributes, "unidentifiedAccessKey")?,
        "unidentifiedAccessKey",
    )?;
    let mut attributes = serde_json::Map::new();
    attributes.insert(
        "capabilities".to_string(),
        capabilities_from_js(account_attributes)?,
    );
    attributes.insert(
        "discoverableByPhoneNumber".to_string(),
        serde_json::Value::Bool(required_js_bool(
            account_attributes,
            "discoverableByPhoneNumber",
        )?),
    );
    attributes.insert(
        "fetchesMessages".to_string(),
        serde_json::Value::Bool(fetches_messages),
    );
    attributes.insert(
        "pniRegistrationId".to_string(),
        serde_json::Value::Number(
            js_u32(
                &js_property(account_attributes, "pniRegistrationId")?,
                "pniRegistrationId",
            )?
            .into(),
        ),
    );
    attributes.insert(
        "recoveryPassword".to_string(),
        serde_json::Value::String(base64_with_padding(&recovery_password)),
    );
    attributes.insert(
        "registrationId".to_string(),
        serde_json::Value::Number(
            js_u32(
                &js_property(account_attributes, "registrationId")?,
                "registrationId",
            )?
            .into(),
        ),
    );
    optional_json_string(
        &mut attributes,
        "registrationLock",
        optional_js_string(account_attributes, "registrationLock")?,
    );
    attributes.insert(
        "unidentifiedAccessKey".to_string(),
        bytes_json_array(&unidentified_access_key),
    );
    attributes.insert(
        "unrestrictedUnidentifiedAccess".to_string(),
        serde_json::Value::Bool(required_js_bool(
            account_attributes,
            "unrestrictedUnidentifiedAccess",
        )?),
    );
    if let Some(name) = optional_uint8_array_property(account_attributes, "name")? {
        attributes.insert(
            "name".to_string(),
            serde_json::Value::String(base64_with_padding(&name)),
        );
    }
    Ok(serde_json::Value::Object(attributes))
}

fn backup_auth_headers(
    credential: &BackupAuthCredential,
    server_params: &GenericServerPublicParams,
    signing_key: &PrivateKey,
) -> Result<Vec<(String, String)>, JsError> {
    let mut randomness = [0; RANDOMNESS_LEN];
    getrandom::fill(&mut randomness).map_err(js_error)?;
    let presentation = credential.inner.present(&server_params.inner, randomness);
    let serialized_presentation = zkgroup::serialize(&presentation);
    let mut csprng = browser_csprng()?;
    let signature = signing_key
        .inner
        .calculate_signature(&serialized_presentation, &mut csprng)
        .map_err(js_error)?;
    Ok(vec![
        (
            "x-signal-zk-auth".to_string(),
            base64_with_padding(&serialized_presentation),
        ),
        (
            "x-signal-zk-auth-signature".to_string(),
            base64_with_padding(&signature.into_vec()),
        ),
    ])
}

struct MediaByteInput {
    bytes: Vec<u8>,
    pos: usize,
}

impl MediaByteInput {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    fn skip_bytes(&mut self, amount: u64) -> io::Result<()> {
        let amount = usize::try_from(amount)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "skip amount too large"))?;
        let new_pos = self
            .pos
            .checked_add(amount)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "skip amount too large"))?;
        if new_pos > self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "skip past end of input",
            ));
        }
        self.pos = new_pos;
        Ok(())
    }
}

impl Read for MediaByteInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.bytes.len().saturating_sub(self.pos);
        let amount = remaining.min(buf.len());
        buf[..amount].copy_from_slice(&self.bytes[self.pos..self.pos + amount]);
        self.pos += amount;
        Ok(amount)
    }
}

impl futures::io::AsyncRead for MediaByteInput {
    fn poll_read(
        mut self: StdPin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Read::read(&mut *self, buf))
    }
}

impl mediasan_common::Skip for MediaByteInput {
    fn skip(&mut self, amount: u64) -> io::Result<()> {
        self.skip_bytes(amount)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        u64::try_from(self.pos)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input position too large"))
    }

    fn stream_len(&mut self) -> io::Result<u64> {
        u64::try_from(self.bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input length too large"))
    }
}

impl mediasan_common::AsyncSkip for MediaByteInput {
    fn poll_skip(
        mut self: StdPin<&mut Self>,
        _cx: &mut Context<'_>,
        amount: u64,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(self.skip_bytes(amount))
    }

    fn poll_stream_position(
        mut self: StdPin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>> {
        Poll::Ready(mediasan_common::Skip::stream_position(&mut *self))
    }

    fn poll_stream_len(
        mut self: StdPin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<u64>> {
        Poll::Ready(mediasan_common::Skip::stream_len(&mut *self))
    }
}

fn base64_with_padding(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_value(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode_padded(value: &str) -> Result<Vec<u8>, JsError> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(JsError::new("invalid base64 length"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks(4).enumerate() {
        let last_chunk = chunk_index == bytes.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&next| next == b'=').count();
        if pad > 2 || (pad > 0 && !last_chunk) {
            return Err(JsError::new("invalid base64 padding"));
        }
        let a = base64_value(chunk[0]).ok_or_else(|| JsError::new("invalid base64 character"))?;
        let b = base64_value(chunk[1]).ok_or_else(|| JsError::new("invalid base64 character"))?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2]).ok_or_else(|| JsError::new("invalid base64 character"))?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3]).ok_or_else(|| JsError::new("invalid base64 character"))?
        };
        out.push((a << 2) | (b >> 4));
        if pad < 2 {
            out.push((b << 4) | (c >> 2));
        }
        if pad < 1 {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    base64_with_padding(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn base64_url_no_pad_decode(value: &str) -> Result<Vec<u8>, JsError> {
    let mut padded = value.replace('-', "+").replace('_', "/");
    match padded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        _ => return Err(JsError::new("invalid base64url length")),
    }
    base64_decode_padded(&padded)
}

fn deserialize_base64_public_key<'de, D>(deserializer: D) -> Result<LibSignalPublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let bytes =
        base64_decode_padded(&encoded).map_err(|_| serde::de::Error::custom("invalid base64"))?;
    LibSignalPublicKey::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
}

fn deserialize_base64_kem_public_key<'de, D>(
    deserializer: D,
) -> Result<libsignal_kem::PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let bytes =
        base64_decode_padded(&encoded).map_err(|_| serde::de::Error::custom("invalid base64"))?;
    libsignal_kem::PublicKey::deserialize(&bytes).map_err(serde::de::Error::custom)
}

fn deserialize_base64_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    base64_decode_padded(&encoded).map_err(|_| serde::de::Error::custom("invalid base64"))
}

fn deserialize_optional_base64_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = Option::<String>::deserialize(deserializer)?;
    encoded
        .map(|value| {
            base64_decode_padded(&value).map_err(|_| serde::de::Error::custom("invalid base64"))
        })
        .transpose()
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPreKeyResponse {
    #[serde(deserialize_with = "deserialize_base64_public_key")]
    identity_key: LibSignalPublicKey,
    devices: Vec<BrowserPreKeyDevice>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPreKeyDevice {
    device_id: u32,
    registration_id: u32,
    signed_pre_key: BrowserSignedPreKey,
    #[serde(default)]
    pre_key: Option<BrowserPreKey>,
    pq_pre_key: BrowserKyberPreKey,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserSignedPreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_base64_public_key")]
    public_key: LibSignalPublicKey,
    #[serde(deserialize_with = "deserialize_base64_bytes")]
    signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserPreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_base64_public_key")]
    public_key: LibSignalPublicKey,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserKyberPreKey {
    key_id: u32,
    #[serde(deserialize_with = "deserialize_base64_kem_public_key")]
    public_key: libsignal_kem::PublicKey,
    #[serde(deserialize_with = "deserialize_base64_bytes")]
    signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserUploadForm {
    cdn: u32,
    key: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(rename = "signedUploadLocation")]
    signed_upload_url: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BrowserRegistrationSession {
    allowed_to_request_code: bool,
    verified: bool,
    next_sms: Option<u64>,
    next_call: Option<u64>,
    next_verification_attempt: Option<u64>,
    requested_information: Vec<String>,
}

impl Default for BrowserRegistrationSession {
    fn default() -> Self {
        Self {
            allowed_to_request_code: false,
            verified: false,
            next_sms: None,
            next_call: None,
            next_verification_attempt: None,
            requested_information: Vec::new(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRegistrationResponse {
    #[serde(rename = "id")]
    session_id: String,
    #[serde(flatten)]
    session: BrowserRegistrationSession,
}

#[derive(serde::Deserialize)]
struct BrowserSvr2CredentialsResponse {
    matches: HashMap<String, String>,
}

#[derive(serde::Deserialize)]
struct BrowserUsernameHashResponse {
    uuid: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserUsernameLinkResponse {
    username_link_encrypted_value: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserEntitlementBadge {
    id: String,
    visible: bool,
    expiration_seconds: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserBackupEntitlement {
    backup_level: u64,
    expiration_seconds: u64,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BrowserRegisterAccountEntitlements {
    badges: Vec<BrowserEntitlementBadge>,
    backup: Option<BrowserBackupEntitlement>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserRegisterAccountResponse {
    uuid: String,
    number: String,
    pni: String,
    #[serde(deserialize_with = "deserialize_optional_base64_bytes")]
    username_hash: Option<Vec<u8>>,
    username_link_handle: Option<String>,
    storage_capable: bool,
    #[serde(default)]
    entitlements: BrowserRegisterAccountEntitlements,
    reregistration: bool,
}

fn protocol_address_from_js(value: &JsValue) -> Result<LibSignalProtocolAddress, JsError> {
    let name = call_js_method(value, "name")?
        .as_string()
        .ok_or_else(|| JsError::new("ProtocolAddress.name() must return a string"))?;
    let device_id = DeviceId::try_from(js_u32(
        &call_js_method(value, "deviceId")?,
        "ProtocolAddress.deviceId()",
    )?)
    .map_err(js_error)?;
    Ok(LibSignalProtocolAddress::new(name, device_id))
}

fn public_key_from_js(value: &JsValue) -> Result<LibSignalPublicKey, JsError> {
    let serialized =
        uint8_array_to_vec(call_js_method(value, "serialize")?, "PublicKey.serialize()")?;
    public_key_from_serialized(&serialized)
}

fn service_id_from_js(value: &JsValue) -> Result<LibSignalServiceId, JsError> {
    let fixed_width = uint8_array_to_vec(
        call_js_method(value, "getServiceIdFixedWidthBinary")?,
        "ServiceId.getServiceIdFixedWidthBinary()",
    )?;
    service_id_from_fixed_width_binary(&fixed_width)
}

fn service_ids_from_js_array(values: js_sys::Array) -> Result<Vec<LibSignalServiceId>, JsError> {
    values
        .iter()
        .map(|value| service_id_from_js(&value))
        .collect()
}

fn uuid_ciphertexts_from_js_array(values: js_sys::Array) -> Result<Vec<ZkUuidCiphertext>, JsError> {
    values
        .iter()
        .map(|value| {
            let contents =
                uint8_array_to_vec(call_js_method(&value, "getContents")?, "getContents()")?;
            zkgroup_deserialize(&contents, "UUID ciphertext")
        })
        .collect()
}

const STORE_SNAPSHOT_MAGIC: &[u8; 8] = b"LSWASM01";

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), JsError> {
    let len = u32::try_from(value.len()).map_err(|_| JsError::new("snapshot value too large"))?;
    write_u32(output, len);
    output.extend_from_slice(value);
    Ok(())
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<(), JsError> {
    write_bytes(output, value.as_bytes())
}

fn write_address(output: &mut Vec<u8>, address: &LibSignalProtocolAddress) -> Result<(), JsError> {
    write_string(output, address.name())?;
    write_u32(output, address.device_id().into());
    Ok(())
}

fn write_uuid(output: &mut Vec<u8>, value: &Uuid) {
    output.extend_from_slice(value.as_bytes());
}

struct SnapshotReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(input: &'a [u8]) -> Result<Self, JsError> {
        if input.len() < STORE_SNAPSHOT_MAGIC.len()
            || &input[..STORE_SNAPSHOT_MAGIC.len()] != STORE_SNAPSHOT_MAGIC
        {
            return Err(JsError::new("invalid SignalProtocolStore snapshot"));
        }
        Ok(Self {
            input,
            offset: STORE_SNAPSHOT_MAGIC.len(),
        })
    }

    fn read_u32(&mut self) -> Result<u32, JsError> {
        let value = self.read_exact(4)?;
        Ok(u32::from_le_bytes(
            value.try_into().expect("read_exact returned 4 bytes"),
        ))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], JsError> {
        let len = self.read_u32()? as usize;
        self.read_exact(len)
    }

    fn read_string(&mut self) -> Result<String, JsError> {
        String::from_utf8(self.read_bytes()?.to_vec())
            .map_err(|_| JsError::new("invalid UTF-8 in SignalProtocolStore snapshot"))
    }

    fn read_address(&mut self) -> Result<LibSignalProtocolAddress, JsError> {
        let name = self.read_string()?;
        let device_id = DeviceId::try_from(self.read_u32()?).map_err(js_error)?;
        Ok(LibSignalProtocolAddress::new(name, device_id))
    }

    fn read_uuid(&mut self) -> Result<Uuid, JsError> {
        Uuid::from_slice(self.read_exact(16)?).map_err(js_error)
    }

    fn finish(self) -> Result<(), JsError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(JsError::new(
                "trailing bytes in SignalProtocolStore snapshot",
            ))
        }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], JsError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| JsError::new("invalid SignalProtocolStore snapshot length"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| JsError::new("truncated SignalProtocolStore snapshot"))?;
        self.offset = end;
        Ok(value)
    }
}

struct BrowserIdentityStore {
    key_pair: LibSignalIdentityKeyPair,
    registration_id: u32,
    known_keys: HashMap<LibSignalProtocolAddress, LibSignalIdentityKey>,
}

#[async_trait(?Send)]
impl IdentityKeyStore for BrowserIdentityStore {
    async fn get_identity_key_pair(
        &self,
    ) -> std::result::Result<LibSignalIdentityKeyPair, SignalProtocolError> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> std::result::Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &LibSignalProtocolAddress,
        identity: &LibSignalIdentityKey,
    ) -> std::result::Result<IdentityChange, SignalProtocolError> {
        match self.known_keys.get(address) {
            None => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(IdentityChange::NewOrUnchanged)
            }
            Some(key) if key == identity => Ok(IdentityChange::NewOrUnchanged),
            Some(_) => {
                self.known_keys.insert(address.clone(), *identity);
                Ok(IdentityChange::ReplacedExisting)
            }
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &LibSignalProtocolAddress,
        identity: &LibSignalIdentityKey,
        _direction: Direction,
    ) -> std::result::Result<bool, SignalProtocolError> {
        Ok(self
            .known_keys
            .get(address)
            .is_none_or(|key| key == identity))
    }

    async fn get_identity(
        &self,
        address: &LibSignalProtocolAddress,
    ) -> std::result::Result<Option<LibSignalIdentityKey>, SignalProtocolError> {
        Ok(self.known_keys.get(address).copied())
    }
}

#[derive(Default)]
struct BrowserSessionStore {
    sessions: HashMap<LibSignalProtocolAddress, LibSignalSessionRecord>,
}

#[async_trait(?Send)]
impl SessionStore for BrowserSessionStore {
    async fn load_session(
        &self,
        address: &LibSignalProtocolAddress,
    ) -> std::result::Result<Option<LibSignalSessionRecord>, SignalProtocolError> {
        Ok(self.sessions.get(address).cloned())
    }

    async fn store_session(
        &mut self,
        address: &LibSignalProtocolAddress,
        record: &LibSignalSessionRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

#[derive(Default)]
struct BrowserPreKeyStore {
    pre_keys: HashMap<PreKeyId, LibSignalPreKeyRecord>,
}

#[async_trait(?Send)]
impl PreKeyStore for BrowserPreKeyStore {
    async fn get_pre_key(
        &self,
        id: PreKeyId,
    ) -> std::result::Result<LibSignalPreKeyRecord, SignalProtocolError> {
        self.pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &LibSignalPreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.pre_keys.insert(id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        id: PreKeyId,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.pre_keys.remove(&id);
        Ok(())
    }
}

#[derive(Default)]
struct BrowserSignedPreKeyStore {
    signed_pre_keys: HashMap<SignedPreKeyId, LibSignalSignedPreKeyRecord>,
}

#[async_trait(?Send)]
impl SignedPreKeyStore for BrowserSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> std::result::Result<LibSignalSignedPreKeyRecord, SignalProtocolError> {
        self.signed_pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &LibSignalSignedPreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.signed_pre_keys.insert(id, record.clone());
        Ok(())
    }
}

#[derive(Default)]
struct BrowserKyberPreKeyStore {
    kyber_pre_keys: HashMap<KyberPreKeyId, LibSignalKyberPreKeyRecord>,
    base_keys_seen: HashMap<(KyberPreKeyId, SignedPreKeyId), Vec<LibSignalPublicKey>>,
}

#[async_trait(?Send)]
impl KyberPreKeyStore for BrowserKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> std::result::Result<LibSignalKyberPreKeyRecord, SignalProtocolError> {
        self.kyber_pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &LibSignalKyberPreKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.kyber_pre_keys.insert(id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &LibSignalPublicKey,
    ) -> std::result::Result<(), SignalProtocolError> {
        let seen = self
            .base_keys_seen
            .entry((kyber_prekey_id, ec_prekey_id))
            .or_default();
        if seen.contains(base_key) {
            return Err(SignalProtocolError::InvalidMessage(
                libsignal_protocol::CiphertextMessageType::PreKey,
                "reused base key",
            ));
        }
        seen.push(*base_key);
        Ok(())
    }
}

#[derive(Default)]
struct BrowserSenderKeyStore {
    sender_keys: HashMap<(LibSignalProtocolAddress, Uuid), LibSignalSenderKeyRecord>,
}

#[async_trait(?Send)]
impl SenderKeyStore for BrowserSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &LibSignalProtocolAddress,
        distribution_id: Uuid,
        record: &LibSignalSenderKeyRecord,
    ) -> std::result::Result<(), SignalProtocolError> {
        self.sender_keys
            .insert((sender.clone(), distribution_id), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &LibSignalProtocolAddress,
        distribution_id: Uuid,
    ) -> std::result::Result<Option<LibSignalSenderKeyRecord>, SignalProtocolError> {
        Ok(self
            .sender_keys
            .get(&(sender.clone(), distribution_id))
            .cloned())
    }
}

struct BrowserSignalProtocolStore {
    session_store: BrowserSessionStore,
    pre_key_store: BrowserPreKeyStore,
    signed_pre_key_store: BrowserSignedPreKeyStore,
    kyber_pre_key_store: BrowserKyberPreKeyStore,
    identity_store: BrowserIdentityStore,
    sender_key_store: BrowserSenderKeyStore,
}

impl BrowserSignalProtocolStore {
    fn to_snapshot(&self) -> Result<Vec<u8>, JsError> {
        let mut output = Vec::new();
        output.extend_from_slice(STORE_SNAPSHOT_MAGIC);

        write_u32(&mut output, self.identity_store.registration_id);
        write_bytes(&mut output, &self.identity_store.key_pair.serialize())?;

        write_u32(
            &mut output,
            u32::try_from(self.identity_store.known_keys.len())
                .map_err(|_| JsError::new("too many known identities"))?,
        );
        for (address, identity) in &self.identity_store.known_keys {
            write_address(&mut output, address)?;
            write_bytes(&mut output, &identity.serialize())?;
        }

        write_u32(
            &mut output,
            u32::try_from(self.session_store.sessions.len())
                .map_err(|_| JsError::new("too many sessions"))?,
        );
        for (address, record) in &self.session_store.sessions {
            write_address(&mut output, address)?;
            write_bytes(&mut output, &record.serialize().map_err(js_error)?)?;
        }

        write_u32(
            &mut output,
            u32::try_from(self.pre_key_store.pre_keys.len())
                .map_err(|_| JsError::new("too many pre-keys"))?,
        );
        for (id, record) in &self.pre_key_store.pre_keys {
            write_u32(&mut output, (*id).into());
            write_bytes(&mut output, &record.serialize().map_err(js_error)?)?;
        }

        write_u32(
            &mut output,
            u32::try_from(self.signed_pre_key_store.signed_pre_keys.len())
                .map_err(|_| JsError::new("too many signed pre-keys"))?,
        );
        for (id, record) in &self.signed_pre_key_store.signed_pre_keys {
            write_u32(&mut output, (*id).into());
            write_bytes(&mut output, &record.serialize().map_err(js_error)?)?;
        }

        write_u32(
            &mut output,
            u32::try_from(self.kyber_pre_key_store.kyber_pre_keys.len())
                .map_err(|_| JsError::new("too many Kyber pre-keys"))?,
        );
        for (id, record) in &self.kyber_pre_key_store.kyber_pre_keys {
            write_u32(&mut output, (*id).into());
            write_bytes(&mut output, &record.serialize().map_err(js_error)?)?;
        }

        write_u32(
            &mut output,
            u32::try_from(self.kyber_pre_key_store.base_keys_seen.len())
                .map_err(|_| JsError::new("too many Kyber replay tracking entries"))?,
        );
        for ((kyber_id, ec_id), base_keys) in &self.kyber_pre_key_store.base_keys_seen {
            write_u32(&mut output, (*kyber_id).into());
            write_u32(&mut output, (*ec_id).into());
            write_u32(
                &mut output,
                u32::try_from(base_keys.len())
                    .map_err(|_| JsError::new("too many Kyber replay base keys"))?,
            );
            for base_key in base_keys {
                write_bytes(&mut output, &base_key.serialize())?;
            }
        }

        write_u32(
            &mut output,
            u32::try_from(self.sender_key_store.sender_keys.len())
                .map_err(|_| JsError::new("too many sender-key records"))?,
        );
        for ((address, distribution_id), record) in &self.sender_key_store.sender_keys {
            write_address(&mut output, address)?;
            write_uuid(&mut output, distribution_id);
            write_bytes(&mut output, &record.serialize().map_err(js_error)?)?;
        }

        Ok(output)
    }

    fn from_snapshot(snapshot: &[u8]) -> Result<Self, JsError> {
        let mut reader = SnapshotReader::new(snapshot)?;

        let registration_id = reader.read_u32()?;
        let key_pair =
            LibSignalIdentityKeyPair::try_from(reader.read_bytes()?).map_err(js_error)?;

        let known_identity_count = reader.read_u32()?;
        let mut known_keys = HashMap::new();
        for _ in 0..known_identity_count {
            let address = reader.read_address()?;
            let identity =
                LibSignalIdentityKey::try_from(reader.read_bytes()?).map_err(js_error)?;
            known_keys.insert(address, identity);
        }

        let session_count = reader.read_u32()?;
        let mut sessions = HashMap::new();
        for _ in 0..session_count {
            let address = reader.read_address()?;
            let record =
                LibSignalSessionRecord::deserialize(reader.read_bytes()?).map_err(js_error)?;
            sessions.insert(address, record);
        }

        let pre_key_count = reader.read_u32()?;
        let mut pre_keys = HashMap::new();
        for _ in 0..pre_key_count {
            let id: PreKeyId = reader.read_u32()?.into();
            let record =
                LibSignalPreKeyRecord::deserialize(reader.read_bytes()?).map_err(js_error)?;
            pre_keys.insert(id, record);
        }

        let signed_pre_key_count = reader.read_u32()?;
        let mut signed_pre_keys = HashMap::new();
        for _ in 0..signed_pre_key_count {
            let id: SignedPreKeyId = reader.read_u32()?.into();
            let record =
                LibSignalSignedPreKeyRecord::deserialize(reader.read_bytes()?).map_err(js_error)?;
            signed_pre_keys.insert(id, record);
        }

        let kyber_pre_key_count = reader.read_u32()?;
        let mut kyber_pre_keys = HashMap::new();
        for _ in 0..kyber_pre_key_count {
            let id: KyberPreKeyId = reader.read_u32()?.into();
            let record =
                LibSignalKyberPreKeyRecord::deserialize(reader.read_bytes()?).map_err(js_error)?;
            kyber_pre_keys.insert(id, record);
        }

        let replay_entry_count = reader.read_u32()?;
        let mut base_keys_seen = HashMap::new();
        for _ in 0..replay_entry_count {
            let kyber_id: KyberPreKeyId = reader.read_u32()?.into();
            let ec_id: SignedPreKeyId = reader.read_u32()?.into();
            let base_key_count = reader.read_u32()?;
            let mut base_keys = Vec::new();
            for _ in 0..base_key_count {
                base_keys.push(public_key_from_serialized(reader.read_bytes()?)?);
            }
            base_keys_seen.insert((kyber_id, ec_id), base_keys);
        }

        let mut sender_keys = HashMap::new();
        if !reader.is_finished() {
            let sender_key_count = reader.read_u32()?;
            for _ in 0..sender_key_count {
                let address = reader.read_address()?;
                let distribution_id = reader.read_uuid()?;
                let record = LibSignalSenderKeyRecord::deserialize(reader.read_bytes()?)
                    .map_err(js_error)?;
                sender_keys.insert((address, distribution_id), record);
            }
        }

        reader.finish()?;

        Ok(Self {
            session_store: BrowserSessionStore { sessions },
            pre_key_store: BrowserPreKeyStore { pre_keys },
            signed_pre_key_store: BrowserSignedPreKeyStore { signed_pre_keys },
            kyber_pre_key_store: BrowserKyberPreKeyStore {
                kyber_pre_keys,
                base_keys_seen,
            },
            identity_store: BrowserIdentityStore {
                key_pair,
                registration_id,
                known_keys,
            },
            sender_key_store: BrowserSenderKeyStore { sender_keys },
        })
    }
}

#[wasm_bindgen]
pub struct WasmKeyPair {
    inner: LibSignalKeyPair,
}

#[wasm_bindgen]
impl WasmKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn from_serialized(public_key: &[u8], private_key: &[u8]) -> Result<WasmKeyPair, JsError> {
        let public_key = public_key_from_serialized(public_key)?;
        let private_key = private_key_from_serialized(private_key)?;
        Ok(Self {
            inner: LibSignalKeyPair::new(public_key, private_key),
        })
    }

    pub fn generate() -> Result<WasmKeyPair, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(Self {
            inner: LibSignalKeyPair::generate(&mut csprng),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key.serialize().into_vec()
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.inner.private_key.serialize()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut csprng = browser_csprng()?;
        let signature = self
            .inner
            .private_key
            .calculate_signature(message, &mut csprng)
            .map_err(js_error)?;
        Ok(signature.into_vec())
    }

    pub fn calculate_agreement(&self, their_public_key: &[u8]) -> Result<Vec<u8>, JsError> {
        calculate_agreement(&self.private_key(), their_public_key)
    }
}

#[wasm_bindgen]
pub fn generate_key_pair() -> Result<WasmKeyPair, JsError> {
    WasmKeyPair::generate()
}

#[wasm_bindgen]
pub fn public_key_from_private_key(private_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let private_key = private_key_from_serialized(private_key)?;
    Ok(private_key
        .public_key()
        .map_err(js_error)?
        .serialize()
        .into_vec())
}

#[wasm_bindgen]
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    let public_key = public_key_from_serialized(public_key)?;
    Ok(public_key.verify_signature(message, signature))
}

#[wasm_bindgen]
pub fn calculate_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let private_key = private_key_from_serialized(private_key)?;
    let public_key = public_key_from_serialized(public_key)?;
    Ok(private_key
        .calculate_agreement(&public_key)
        .map_err(js_error)?
        .into_vec())
}

#[wasm_bindgen]
pub fn is_canonical_public_key(public_key: &[u8]) -> Result<bool, JsError> {
    let public_key = public_key_from_serialized(public_key)?;
    Ok(public_key.is_canonical())
}

#[wasm_bindgen]
pub fn hkdf(
    output_length: u32,
    key_material: &[u8],
    label: &[u8],
    salt: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let mut buffer = vec![0; output_length as usize];
    hkdf::Hkdf::<sha2::Sha256>::new(salt.as_deref(), key_material)
        .expand(label, &mut buffer)
        .map_err(|_| JsError::new(&format!("output too long ({output_length})")))?;
    Ok(buffer)
}

#[wasm_bindgen]
pub struct Aes256GcmSiv {
    inner: aes_gcm_siv::Aes256GcmSiv,
}

#[wasm_bindgen]
impl Aes256GcmSiv {
    pub fn new(key: &[u8]) -> Result<Aes256GcmSiv, JsError> {
        Ok(Self {
            inner: aes_gcm_siv::Aes256GcmSiv::new_from_slice(key)
                .map_err(|_| JsError::new("invalid AES-256-GCM-SIV key size"))?,
        })
    }

    pub fn encrypt(
        &self,
        message: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if nonce.len() != <aes_gcm_siv::Aes256GcmSiv as AeadCore>::NonceSize::USIZE {
            return Err(JsError::new("invalid AES-256-GCM-SIV nonce size"));
        }
        let nonce: &aes_gcm_siv::Nonce = nonce.into();
        let mut buffer = Vec::with_capacity(
            message.len() + <aes_gcm_siv::Aes256GcmSiv as AeadCore>::TagSize::USIZE,
        );
        buffer.extend_from_slice(message);
        self.inner
            .encrypt_in_place(nonce, associated_data, &mut buffer)
            .expect("Vec has enough capacity for AES-GCM-SIV tag");
        Ok(buffer)
    }

    pub fn decrypt(
        &self,
        message: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        if nonce.len() != <aes_gcm_siv::Aes256GcmSiv as AeadCore>::NonceSize::USIZE {
            return Err(JsError::new("invalid AES-256-GCM-SIV nonce size"));
        }
        let nonce: &aes_gcm_siv::Nonce = nonce.into();
        let mut buffer = message.to_vec();
        self.inner
            .decrypt_in_place(nonce, associated_data, &mut buffer)
            .map_err(|_| JsError::new("invalid AES-256-GCM-SIV tag"))?;
        Ok(buffer)
    }
}

#[wasm_bindgen]
pub struct ScannableFingerprint {
    scannable: Vec<u8>,
}

#[wasm_bindgen]
impl ScannableFingerprint {
    pub fn compare(&self, other: &ScannableFingerprint) -> Result<bool, JsError> {
        LibSignalScannableFingerprint::deserialize(&self.scannable)
            .map_err(js_error)?
            .compare(&other.scannable)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = toBuffer)]
    pub fn to_buffer(&self) -> Vec<u8> {
        self.scannable.clone()
    }
}

#[wasm_bindgen]
pub struct DisplayableFingerprint {
    display: String,
}

#[wasm_bindgen]
impl DisplayableFingerprint {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        self.display.clone()
    }
}

#[wasm_bindgen]
pub struct Fingerprint {
    inner: LibSignalFingerprint,
}

#[wasm_bindgen]
impl Fingerprint {
    pub fn new(
        iterations: u32,
        version: u32,
        local_identifier: &[u8],
        local_key: &PublicKey,
        remote_identifier: &[u8],
        remote_key: &PublicKey,
    ) -> Result<Fingerprint, JsError> {
        Ok(Self {
            inner: LibSignalFingerprint::new(
                version,
                iterations,
                local_identifier,
                &LibSignalIdentityKey::new(local_key.inner),
                remote_identifier,
                &LibSignalIdentityKey::new(remote_key.inner),
            )
            .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = displayableFingerprint)]
    pub fn displayable_fingerprint(&self) -> Result<DisplayableFingerprint, JsError> {
        Ok(DisplayableFingerprint {
            display: self.inner.display_string().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = scannableFingerprint)]
    pub fn scannable_fingerprint(&self) -> Result<ScannableFingerprint, JsError> {
        Ok(ScannableFingerprint {
            scannable: self.inner.scannable.serialize().map_err(js_error)?,
        })
    }
}

#[wasm_bindgen]
pub struct AccountEntropyPool;

#[wasm_bindgen]
impl AccountEntropyPool {
    pub fn generate() -> Result<String, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(LibSignalAccountEntropyPool::generate(&mut csprng).to_string())
    }

    #[wasm_bindgen(js_name = isValid)]
    pub fn is_valid(account_entropy_pool: &str) -> bool {
        LibSignalAccountEntropyPool::from_str(account_entropy_pool).is_ok()
    }

    #[wasm_bindgen(js_name = deriveSvrKey)]
    pub fn derive_svr_key(account_entropy_pool: &str) -> Result<Vec<u8>, JsError> {
        Ok(LibSignalAccountEntropyPool::from_str(account_entropy_pool)
            .map_err(js_error)?
            .derive_svr_key()
            .to_vec())
    }

    #[wasm_bindgen(js_name = deriveBackupKey)]
    pub fn derive_backup_key(account_entropy_pool: &str) -> Result<BackupKey, JsError> {
        let account_entropy_pool =
            LibSignalAccountEntropyPool::from_str(account_entropy_pool).map_err(js_error)?;
        Ok(BackupKey {
            bytes: LibSignalBackupKey::derive_from_account_entropy_pool(&account_entropy_pool).0,
        })
    }
}

#[wasm_bindgen]
pub struct BackupKey {
    bytes: [u8; BACKUP_KEY_LEN],
}

#[wasm_bindgen]
impl BackupKey {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupKey, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "backup key")?,
        })
    }

    #[wasm_bindgen(js_name = generateRandom)]
    pub fn generate_random() -> Result<BackupKey, JsError> {
        let mut bytes = [0; BACKUP_KEY_LEN];
        getrandom::fill(&mut bytes).map_err(js_error)?;
        Ok(Self { bytes })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = deriveBackupId)]
    pub fn derive_backup_id(&self, aci: &Aci) -> Result<Vec<u8>, JsError> {
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        Ok(backup_key
            .derive_backup_id(&aci_service_id(aci)?)
            .0
            .to_vec())
    }

    #[wasm_bindgen(js_name = deriveEcKey)]
    pub fn derive_ec_key(&self, aci: &Aci) -> Result<PrivateKey, JsError> {
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        Ok(PrivateKey {
            inner: backup_key.derive_ec_key(&aci_service_id(aci)?),
        })
    }

    #[wasm_bindgen(js_name = deriveLocalBackupMetadataKey)]
    pub fn derive_local_backup_metadata_key(&self) -> Vec<u8> {
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        backup_key.derive_local_backup_metadata_key().to_vec()
    }

    #[wasm_bindgen(js_name = deriveMediaId)]
    pub fn derive_media_id(&self, media_name: &str) -> Vec<u8> {
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        backup_key.derive_media_id(media_name).to_vec()
    }

    #[wasm_bindgen(js_name = deriveMediaEncryptionKey)]
    pub fn derive_media_encryption_key(&self, media_id: &[u8]) -> Result<Vec<u8>, JsError> {
        let media_id = fixed_array::<MEDIA_ID_LEN>(media_id, "media ID")?;
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        Ok(backup_key
            .derive_media_encryption_key_data(&media_id)
            .to_vec())
    }

    #[wasm_bindgen(js_name = deriveThumbnailTransitEncryptionKey)]
    pub fn derive_thumbnail_transit_encryption_key(
        &self,
        media_id: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let media_id = fixed_array::<MEDIA_ID_LEN>(media_id, "media ID")?;
        let backup_key: LibSignalBackupKey = LibSignalBackupKey(self.bytes);
        Ok(backup_key
            .derive_thumbnail_transit_encryption_key_data(&media_id)
            .to_vec())
    }
}

#[wasm_bindgen]
pub struct BackupForwardSecrecyToken {
    bytes: [u8; 32],
}

#[wasm_bindgen]
impl BackupForwardSecrecyToken {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupForwardSecrecyToken, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "backup forward secrecy token")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct PinHash {
    inner: LibSignalPinHash,
}

#[wasm_bindgen]
impl PinHash {
    #[wasm_bindgen(js_name = fromSalt)]
    pub fn from_salt(normalized_pin: &[u8], salt: &[u8]) -> Result<PinHash, JsError> {
        Ok(Self {
            inner: LibSignalPinHash::create(
                normalized_pin,
                &fixed_array::<32>(salt, "PIN hash salt")?,
            )
            .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromUsernameMrenclave)]
    pub fn from_username_mrenclave(
        normalized_pin: &[u8],
        username: &str,
        mrenclave: &[u8],
    ) -> Result<PinHash, JsError> {
        if mrenclave.len() != 32 {
            return Err(JsError::new("SVR2 mrenclave must be 32 bytes"));
        }
        let group_id = svr2_group_id_for_mrenclave(mrenclave)
            .ok_or_else(|| JsError::new("unknown SVR2 mrenclave"))?;
        Ok(Self {
            inner: LibSignalPinHash::create(
                normalized_pin,
                &LibSignalPinHash::make_salt(username, group_id),
            )
            .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(getter, js_name = encryptionKey)]
    pub fn encryption_key(&self) -> Vec<u8> {
        self.inner.encryption_key.to_vec()
    }

    #[wasm_bindgen(getter, js_name = accessKey)]
    pub fn access_key(&self) -> Vec<u8> {
        self.inner.access_key.to_vec()
    }
}

#[wasm_bindgen]
pub struct Pin;

#[wasm_bindgen]
impl Pin {
    #[wasm_bindgen(js_name = localHash)]
    pub fn local_hash(normalized_pin: &[u8]) -> Result<String, JsError> {
        local_pin_hash(normalized_pin).map_err(js_error)
    }

    #[wasm_bindgen(js_name = verifyLocalHash)]
    pub fn verify_local_hash(encoded_hash: &str, normalized_pin: &[u8]) -> Result<bool, JsError> {
        verify_local_pin_hash(encoded_hash, normalized_pin).map_err(js_error)
    }
}

#[wasm_bindgen(js_name = pinLocalHash)]
pub fn pin_local_hash(normalized_pin: &[u8]) -> Result<String, JsError> {
    Pin::local_hash(normalized_pin)
}

#[wasm_bindgen(js_name = pinVerifyLocalHash)]
pub fn pin_verify_local_hash(encoded_hash: &str, normalized_pin: &[u8]) -> Result<bool, JsError> {
    Pin::verify_local_hash(encoded_hash, normalized_pin)
}

#[wasm_bindgen]
pub struct GroupMasterKey {
    bytes: [u8; GROUP_MASTER_KEY_LEN],
}

#[wasm_bindgen]
impl GroupMasterKey {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupMasterKey, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "group master key")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct GroupSecretParams {
    inner: ZkGroupSecretParams,
}

#[wasm_bindgen]
impl GroupSecretParams {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_random() -> Result<GroupSecretParams, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(Self {
            inner: ZkGroupSecretParams::generate(randomness),
        })
    }

    #[wasm_bindgen(js_name = generateWithRandom)]
    pub fn generate_with_random(randomness: &[u8]) -> Result<GroupSecretParams, JsError> {
        Ok(Self {
            inner: ZkGroupSecretParams::generate(fixed_array(randomness, "zkgroup randomness")?),
        })
    }

    #[wasm_bindgen(js_name = deriveFromMasterKey)]
    pub fn derive_from_master_key(
        group_master_key: &GroupMasterKey,
    ) -> Result<GroupSecretParams, JsError> {
        Ok(Self {
            inner: ZkGroupSecretParams::derive_from_master_key(ZkGroupMasterKey::new(
                group_master_key.bytes,
            )),
        })
    }

    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSecretParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group secret params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getMasterKey)]
    pub fn get_master_key(&self) -> Result<GroupMasterKey, JsError> {
        Ok(GroupMasterKey {
            bytes: zkgroup::serialize(&self.inner.get_master_key())
                .try_into()
                .map_err(|_| JsError::new("invalid group master key length"))?,
        })
    }

    #[wasm_bindgen(js_name = getPublicParams)]
    pub fn get_public_params(&self) -> GroupPublicParams {
        GroupPublicParams {
            inner: self.inner.get_public_params(),
        }
    }
}

#[wasm_bindgen]
pub struct GroupPublicParams {
    inner: ZkGroupPublicParams,
}

#[wasm_bindgen]
impl GroupPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupPublicParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group public params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getGroupIdentifier)]
    pub fn get_group_identifier(&self) -> GroupIdentifier {
        GroupIdentifier {
            bytes: self.inner.get_group_identifier(),
        }
    }
}

#[wasm_bindgen]
pub struct GroupIdentifier {
    bytes: [u8; GROUP_IDENTIFIER_LEN],
}

#[wasm_bindgen]
impl GroupIdentifier {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupIdentifier, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "group identifier")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        base64_with_padding(&self.bytes)
    }
}

#[wasm_bindgen]
pub struct ProfileKey {
    bytes: [u8; PROFILE_KEY_LEN],
}

#[wasm_bindgen]
impl ProfileKey {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_random() -> Result<ProfileKey, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(Self {
            bytes: ZkProfileKey::generate(randomness).get_bytes(),
        })
    }

    #[wasm_bindgen(js_name = generateWithRandom)]
    pub fn generate_with_random(randomness: &[u8]) -> Result<ProfileKey, JsError> {
        Ok(Self {
            bytes: ZkProfileKey::generate(fixed_array(randomness, "zkgroup randomness")?)
                .get_bytes(),
        })
    }

    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKey, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "profile key")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getCommitment)]
    pub fn get_commitment(&self, user_id: &Aci) -> Result<ProfileKeyCommitment, JsError> {
        Ok(ProfileKeyCommitment {
            inner: ZkProfileKey::create(self.bytes).get_commitment(aci_service_id(user_id)?),
        })
    }

    #[wasm_bindgen(js_name = getProfileKeyVersion)]
    pub fn get_profile_key_version(&self, user_id: &Aci) -> Result<ProfileKeyVersion, JsError> {
        let version =
            ZkProfileKey::create(self.bytes).get_profile_key_version(aci_service_id(user_id)?);
        Ok(ProfileKeyVersion {
            bytes: zkgroup::serialize(&version)
                .try_into()
                .map_err(|_| JsError::new("invalid profile key version length"))?,
        })
    }

    #[wasm_bindgen(js_name = deriveAccessKey)]
    pub fn derive_access_key(&self) -> Vec<u8> {
        ZkProfileKey::create(self.bytes)
            .derive_access_key()
            .to_vec()
    }
}

#[wasm_bindgen]
pub struct ProfileKeyVersion {
    bytes: [u8; PROFILE_KEY_VERSION_ENCODED_LEN],
}

#[wasm_bindgen]
impl ProfileKeyVersion {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyVersion, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "profile key version")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> Result<String, JsError> {
        String::from_utf8(self.bytes.to_vec()).map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct ProfileKeyCommitment {
    inner: ZkProfileKeyCommitment,
}

#[wasm_bindgen]
impl ProfileKeyCommitment {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyCommitment, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "profile key commitment")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct UuidCiphertext {
    inner: ZkUuidCiphertext,
}

#[wasm_bindgen]
impl UuidCiphertext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<UuidCiphertext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "UUID ciphertext")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = serializeAndConcatenate)]
    pub fn serialize_and_concatenate(ciphertexts: js_sys::Array) -> Result<Vec<u8>, JsError> {
        let mut concatenated = Vec::with_capacity(ciphertexts.length() as usize * 65);
        let mut expected_len = None;
        for value in ciphertexts.iter() {
            let serialized =
                uint8_array_to_vec(call_js_method(&value, "getContents")?, "getContents()")?;
            if let Some(expected_len) = expected_len {
                if serialized.len() != expected_len {
                    return Err(JsError::new("UuidCiphertext with unexpected length"));
                }
            } else {
                expected_len = Some(serialized.len());
            }
            concatenated.extend(serialized);
        }
        Ok(concatenated)
    }
}

#[wasm_bindgen]
pub struct ProfileKeyCiphertext {
    inner: ZkProfileKeyCiphertext,
}

#[wasm_bindgen]
impl ProfileKeyCiphertext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyCiphertext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "profile key ciphertext")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct NotarySignature {
    bytes: NotarySignatureBytes,
}

#[wasm_bindgen]
impl NotarySignature {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<NotarySignature, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "notary signature")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ServerSecretParams {
    inner: ZkServerSecretParams,
}

#[wasm_bindgen]
impl ServerSecretParams {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_random() -> Result<ServerSecretParams, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(Self {
            inner: ZkServerSecretParams::generate(randomness),
        })
    }

    #[wasm_bindgen(js_name = generateWithRandom)]
    pub fn generate_with_random(randomness: &[u8]) -> Result<ServerSecretParams, JsError> {
        Ok(Self {
            inner: ZkServerSecretParams::generate(fixed_array(randomness, "zkgroup randomness")?),
        })
    }

    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ServerSecretParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "server secret params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getPublicParams)]
    pub fn get_public_params(&self) -> ServerPublicParams {
        ServerPublicParams {
            inner: self.inner.get_public_params(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<NotarySignature, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(NotarySignature {
            bytes: self.inner.sign(randomness, message),
        })
    }

    #[wasm_bindgen(js_name = signWithRandom)]
    pub fn sign_with_random(
        &self,
        randomness: &[u8],
        message: &[u8],
    ) -> Result<NotarySignature, JsError> {
        Ok(NotarySignature {
            bytes: self
                .inner
                .sign(fixed_array(randomness, "zkgroup randomness")?, message),
        })
    }
}

#[wasm_bindgen]
pub struct ServerPublicParams {
    inner: ZkServerPublicParams,
}

#[wasm_bindgen]
impl ServerPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ServerPublicParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "server public params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(
        &self,
        message: &[u8],
        notary_signature: &NotarySignature,
    ) -> Result<(), JsError> {
        self.inner
            .verify_signature(message, notary_signature.bytes)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct ProfileKeyCredentialRequestContext {
    inner: ZkProfileKeyCredentialRequestContext,
}

#[wasm_bindgen]
impl ProfileKeyCredentialRequestContext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyCredentialRequestContext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "profile key credential request context")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getRequest)]
    pub fn get_request(&self) -> ProfileKeyCredentialRequest {
        ProfileKeyCredentialRequest {
            inner: self.inner.get_request(),
        }
    }
}

#[wasm_bindgen]
pub struct ProfileKeyCredentialRequest {
    inner: ZkProfileKeyCredentialRequest,
}

#[wasm_bindgen]
impl ProfileKeyCredentialRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyCredentialRequest, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "profile key credential request")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ExpiringProfileKeyCredentialResponse {
    inner: ZkExpiringProfileKeyCredentialResponse,
}

#[wasm_bindgen]
impl ExpiringProfileKeyCredentialResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ExpiringProfileKeyCredentialResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "expiring profile key credential response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ExpiringProfileKeyCredential {
    inner: ZkExpiringProfileKeyCredential,
}

#[wasm_bindgen]
impl ExpiringProfileKeyCredential {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ExpiringProfileKeyCredential, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "expiring profile key credential")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getExpirationTime)]
    pub fn get_expiration_time(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from_f64(
            self.inner.get_expiration_time().epoch_seconds() as f64 * 1000.0,
        ))
    }
}

#[wasm_bindgen]
pub struct ProfileKeyCredentialPresentation {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl ProfileKeyCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ProfileKeyCredentialPresentation, JsError> {
        ZkAnyProfileKeyCredentialPresentation::new(contents)
            .map_err(|_| JsError::new("invalid profile key credential presentation"))?;
        Ok(Self {
            bytes: contents.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getUuidCiphertext)]
    pub fn get_uuid_ciphertext(&self) -> Result<UuidCiphertext, JsError> {
        Ok(UuidCiphertext {
            inner: ZkAnyProfileKeyCredentialPresentation::new(&self.bytes)
                .map_err(|_| JsError::new("invalid profile key credential presentation"))?
                .get_uuid_ciphertext(),
        })
    }

    #[wasm_bindgen(js_name = getProfileKeyCiphertext)]
    pub fn get_profile_key_ciphertext(&self) -> Result<ProfileKeyCiphertext, JsError> {
        Ok(ProfileKeyCiphertext {
            inner: ZkAnyProfileKeyCredentialPresentation::new(&self.bytes)
                .map_err(|_| JsError::new("invalid profile key credential presentation"))?
                .get_profile_key_ciphertext(),
        })
    }
}

#[wasm_bindgen]
pub struct AuthCredentialWithPniResponse {
    inner: ZkAuthCredentialWithPniResponse,
}

#[wasm_bindgen]
impl AuthCredentialWithPniResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<AuthCredentialWithPniResponse, JsError> {
        Ok(Self {
            inner: ZkAuthCredentialWithPniResponse::new(contents)
                .map_err(|_| JsError::new("invalid auth credential with PNI response"))?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct AuthCredentialWithPni {
    inner: ZkAuthCredentialWithPni,
}

#[wasm_bindgen]
impl AuthCredentialWithPni {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<AuthCredentialWithPni, JsError> {
        Ok(Self {
            inner: ZkAuthCredentialWithPni::new(contents)
                .map_err(|_| JsError::new("invalid auth credential with PNI"))?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct AuthCredentialPresentation {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl AuthCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<AuthCredentialPresentation, JsError> {
        ZkAnyAuthCredentialPresentation::new(contents)
            .map_err(|_| JsError::new("invalid auth credential presentation"))?;
        Ok(Self {
            bytes: contents.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getUuidCiphertext)]
    pub fn get_uuid_ciphertext(&self) -> Result<UuidCiphertext, JsError> {
        Ok(UuidCiphertext {
            inner: ZkAnyAuthCredentialPresentation::new(&self.bytes)
                .map_err(|_| JsError::new("invalid auth credential presentation"))?
                .get_aci_ciphertext(),
        })
    }

    #[wasm_bindgen(js_name = getPniCiphertext)]
    pub fn get_pni_ciphertext(&self) -> Result<UuidCiphertext, JsError> {
        Ok(UuidCiphertext {
            inner: ZkAnyAuthCredentialPresentation::new(&self.bytes)
                .map_err(|_| JsError::new("invalid auth credential presentation"))?
                .get_pni_ciphertext(),
        })
    }

    #[wasm_bindgen(js_name = getRedemptionTime)]
    pub fn get_redemption_time(&self) -> Result<js_sys::Date, JsError> {
        let presentation = ZkAnyAuthCredentialPresentation::new(&self.bytes)
            .map_err(|_| JsError::new("invalid auth credential presentation"))?;
        Ok(js_sys::Date::new(&JsValue::from_f64(
            presentation.get_redemption_time().epoch_seconds() as f64 * 1000.0,
        )))
    }
}

#[wasm_bindgen]
pub struct ClientZkAuthOperations {
    server_public_params: ZkServerPublicParams,
}

#[wasm_bindgen]
impl ClientZkAuthOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_public_params: &ServerPublicParams) -> ClientZkAuthOperations {
        Self {
            server_public_params: server_public_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = receiveAuthCredentialWithPniAsServiceId)]
    pub fn receive_auth_credential_with_pni_as_service_id(
        &self,
        aci: &Aci,
        pni: &Pni,
        redemption_time: f64,
        auth_credential_response: &AuthCredentialWithPniResponse,
    ) -> Result<AuthCredentialWithPni, JsError> {
        Ok(AuthCredentialWithPni {
            inner: auth_credential_response
                .inner
                .clone()
                .receive(
                    &self.server_public_params,
                    aci_service_id(aci)?,
                    pni_service_id(pni)?,
                    zk_timestamp_from_seconds(redemption_time)?,
                )
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = createAuthCredentialWithPniPresentation)]
    pub fn create_auth_credential_with_pni_presentation(
        &self,
        group_secret_params: &GroupSecretParams,
        auth_credential: &AuthCredentialWithPni,
    ) -> Result<AuthCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.create_auth_credential_with_pni_presentation_with_random(
            &randomness,
            group_secret_params,
            auth_credential,
        )
    }

    #[wasm_bindgen(js_name = createAuthCredentialWithPniPresentationWithRandom)]
    pub fn create_auth_credential_with_pni_presentation_with_random(
        &self,
        randomness: &[u8],
        group_secret_params: &GroupSecretParams,
        auth_credential: &AuthCredentialWithPni,
    ) -> Result<AuthCredentialPresentation, JsError> {
        let presentation = auth_credential.inner.present(
            &self.server_public_params,
            &group_secret_params.inner,
            fixed_array(randomness, "zkgroup randomness")?,
        );
        Ok(AuthCredentialPresentation {
            bytes: zkgroup::serialize(&presentation),
        })
    }
}

#[wasm_bindgen]
pub struct ServerZkAuthOperations {
    server_secret_params: ZkServerSecretParams,
}

#[wasm_bindgen]
impl ServerZkAuthOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_secret_params: &ServerSecretParams) -> ServerZkAuthOperations {
        Self {
            server_secret_params: server_secret_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = issueAuthCredentialWithPniZkc)]
    pub fn issue_auth_credential_with_pni_zkc(
        &self,
        aci: &Aci,
        pni: &Pni,
        redemption_time: f64,
    ) -> Result<AuthCredentialWithPniResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.issue_auth_credential_with_pni_zkc_with_random(&randomness, aci, pni, redemption_time)
    }

    #[wasm_bindgen(js_name = issueAuthCredentialWithPniZkcWithRandom)]
    pub fn issue_auth_credential_with_pni_zkc_with_random(
        &self,
        randomness: &[u8],
        aci: &Aci,
        pni: &Pni,
        redemption_time: f64,
    ) -> Result<AuthCredentialWithPniResponse, JsError> {
        Ok(AuthCredentialWithPniResponse {
            inner: ZkAuthCredentialWithPniResponse::Zkc(
                ZkAuthCredentialWithPniZkcResponse::issue_credential(
                    aci_service_id(aci)?,
                    pni_service_id(pni)?,
                    zk_timestamp_from_seconds(redemption_time)?,
                    &self.server_secret_params,
                    fixed_array(randomness, "zkgroup randomness")?,
                ),
            ),
        })
    }

    #[wasm_bindgen(js_name = verifyAuthCredentialPresentation)]
    pub fn verify_auth_credential_presentation(
        &self,
        group_public_params: &GroupPublicParams,
        auth_credential_presentation: &AuthCredentialPresentation,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        let presentation =
            ZkAnyAuthCredentialPresentation::new(&auth_credential_presentation.bytes)
                .map_err(|_| JsError::new("invalid auth credential presentation"))?;
        self.server_secret_params
            .verify_auth_credential_presentation(
                group_public_params.inner,
                &presentation,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
            )
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct ReceiptSerial {
    bytes: [u8; RECEIPT_SERIAL_LEN],
}

#[wasm_bindgen]
impl ReceiptSerial {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptSerial, JsError> {
        Ok(Self {
            bytes: fixed_array(contents, "receipt serial")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ReceiptCredentialRequestContext {
    inner: ZkReceiptCredentialRequestContext,
}

#[wasm_bindgen]
impl ReceiptCredentialRequestContext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptCredentialRequestContext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "receipt credential request context")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getRequest)]
    pub fn get_request(&self) -> ReceiptCredentialRequest {
        ReceiptCredentialRequest {
            inner: self.inner.get_request(),
        }
    }
}

#[wasm_bindgen]
pub struct ReceiptCredentialRequest {
    inner: ZkReceiptCredentialRequest,
}

#[wasm_bindgen]
impl ReceiptCredentialRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptCredentialRequest, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "receipt credential request")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ReceiptCredentialResponse {
    inner: ZkReceiptCredentialResponse,
}

#[wasm_bindgen]
impl ReceiptCredentialResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptCredentialResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "receipt credential response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct ReceiptCredential {
    inner: ZkReceiptCredential,
}

#[wasm_bindgen]
impl ReceiptCredential {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptCredential, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "receipt credential")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getReceiptExpirationTime)]
    pub fn get_receipt_expiration_time(&self) -> f64 {
        self.inner.get_receipt_expiration_time().epoch_seconds() as f64
    }

    #[wasm_bindgen(js_name = getReceiptLevel)]
    pub fn get_receipt_level(&self) -> js_sys::BigInt {
        js_sys::BigInt::from(self.inner.get_receipt_level())
    }
}

#[wasm_bindgen]
pub struct ReceiptCredentialPresentation {
    inner: ZkReceiptCredentialPresentation,
}

#[wasm_bindgen]
impl ReceiptCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<ReceiptCredentialPresentation, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "receipt credential presentation")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getReceiptExpirationTime)]
    pub fn get_receipt_expiration_time(&self) -> f64 {
        self.inner.get_receipt_expiration_time().epoch_seconds() as f64
    }

    #[wasm_bindgen(js_name = getReceiptLevel)]
    pub fn get_receipt_level(&self) -> js_sys::BigInt {
        js_sys::BigInt::from(self.inner.get_receipt_level())
    }

    #[wasm_bindgen(js_name = getReceiptSerialBytes)]
    pub fn get_receipt_serial_bytes(&self) -> ReceiptSerial {
        ReceiptSerial {
            bytes: self.inner.get_receipt_serial_bytes(),
        }
    }
}

#[wasm_bindgen]
pub struct ClientZkReceiptOperations {
    server_public_params: ZkServerPublicParams,
}

#[wasm_bindgen]
impl ClientZkReceiptOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_public_params: &ServerPublicParams) -> ClientZkReceiptOperations {
        Self {
            server_public_params: server_public_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = createReceiptCredentialRequestContext)]
    pub fn create_receipt_credential_request_context(
        &self,
        receipt_serial: &ReceiptSerial,
    ) -> Result<ReceiptCredentialRequestContext, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.create_receipt_credential_request_context_with_random(&randomness, receipt_serial)
    }

    #[wasm_bindgen(js_name = createReceiptCredentialRequestContextWithRandom)]
    pub fn create_receipt_credential_request_context_with_random(
        &self,
        randomness: &[u8],
        receipt_serial: &ReceiptSerial,
    ) -> Result<ReceiptCredentialRequestContext, JsError> {
        Ok(ReceiptCredentialRequestContext {
            inner: self
                .server_public_params
                .create_receipt_credential_request_context(
                    fixed_array(randomness, "zkgroup randomness")?,
                    receipt_serial.bytes,
                ),
        })
    }

    #[wasm_bindgen(js_name = receiveReceiptCredential)]
    pub fn receive_receipt_credential(
        &self,
        receipt_credential_request_context: &ReceiptCredentialRequestContext,
        receipt_credential_response: &ReceiptCredentialResponse,
    ) -> Result<ReceiptCredential, JsError> {
        Ok(ReceiptCredential {
            inner: self
                .server_public_params
                .receive_receipt_credential(
                    &receipt_credential_request_context.inner,
                    &receipt_credential_response.inner,
                )
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = createReceiptCredentialPresentation)]
    pub fn create_receipt_credential_presentation(
        &self,
        receipt_credential: &ReceiptCredential,
    ) -> Result<ReceiptCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.create_receipt_credential_presentation_with_random(&randomness, receipt_credential)
    }

    #[wasm_bindgen(js_name = createReceiptCredentialPresentationWithRandom)]
    pub fn create_receipt_credential_presentation_with_random(
        &self,
        randomness: &[u8],
        receipt_credential: &ReceiptCredential,
    ) -> Result<ReceiptCredentialPresentation, JsError> {
        Ok(ReceiptCredentialPresentation {
            inner: self
                .server_public_params
                .create_receipt_credential_presentation(
                    fixed_array(randomness, "zkgroup randomness")?,
                    &receipt_credential.inner,
                ),
        })
    }
}

#[wasm_bindgen]
pub struct ServerZkReceiptOperations {
    server_secret_params: ZkServerSecretParams,
}

#[wasm_bindgen]
impl ServerZkReceiptOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_secret_params: &ServerSecretParams) -> ServerZkReceiptOperations {
        Self {
            server_secret_params: server_secret_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = issueReceiptCredential)]
    pub fn issue_receipt_credential(
        &self,
        receipt_credential_request: &ReceiptCredentialRequest,
        receipt_expiration_time: f64,
        receipt_level: u64,
    ) -> Result<ReceiptCredentialResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.issue_receipt_credential_with_random(
            &randomness,
            receipt_credential_request,
            receipt_expiration_time,
            receipt_level,
        )
    }

    #[wasm_bindgen(js_name = issueReceiptCredentialWithRandom)]
    pub fn issue_receipt_credential_with_random(
        &self,
        randomness: &[u8],
        receipt_credential_request: &ReceiptCredentialRequest,
        receipt_expiration_time: f64,
        receipt_level: u64,
    ) -> Result<ReceiptCredentialResponse, JsError> {
        Ok(ReceiptCredentialResponse {
            inner: self.server_secret_params.issue_receipt_credential(
                fixed_array(randomness, "zkgroup randomness")?,
                &receipt_credential_request.inner,
                zk_timestamp_from_seconds(receipt_expiration_time)?,
                receipt_level,
            ),
        })
    }

    #[wasm_bindgen(js_name = verifyReceiptCredentialPresentation)]
    pub fn verify_receipt_credential_presentation(
        &self,
        receipt_credential_presentation: &ReceiptCredentialPresentation,
    ) -> Result<(), JsError> {
        self.server_secret_params
            .verify_receipt_credential_presentation(&receipt_credential_presentation.inner)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct GenericServerSecretParams {
    inner: ZkGenericServerSecretParams,
}

#[wasm_bindgen]
impl GenericServerSecretParams {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_random() -> Result<GenericServerSecretParams, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(Self {
            inner: ZkGenericServerSecretParams::generate(randomness),
        })
    }

    #[wasm_bindgen(js_name = generateWithRandom)]
    pub fn generate_with_random(randomness: &[u8]) -> Result<GenericServerSecretParams, JsError> {
        Ok(Self {
            inner: ZkGenericServerSecretParams::generate(fixed_array(
                randomness,
                "zkgroup randomness",
            )?),
        })
    }

    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GenericServerSecretParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "generic server secret params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getPublicParams)]
    pub fn get_public_params(&self) -> GenericServerPublicParams {
        GenericServerPublicParams {
            inner: self.inner.get_public_params(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum BackupLevel {
    Free = 200,
    Paid = 201,
}

impl TryFrom<BackupLevel> for ZkBackupLevel {
    type Error = JsError;

    fn try_from(value: BackupLevel) -> Result<Self, Self::Error> {
        match value {
            BackupLevel::Free => Ok(ZkBackupLevel::Free),
            BackupLevel::Paid => Ok(ZkBackupLevel::Paid),
        }
    }
}

fn backup_level_from_zk(value: ZkBackupLevel) -> BackupLevel {
    match value {
        ZkBackupLevel::Free => BackupLevel::Free,
        ZkBackupLevel::Paid => BackupLevel::Paid,
    }
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum BackupCredentialType {
    Messages = 1,
    Media = 2,
}

impl TryFrom<BackupCredentialType> for ZkBackupCredentialType {
    type Error = JsError;

    fn try_from(value: BackupCredentialType) -> Result<Self, Self::Error> {
        match value {
            BackupCredentialType::Messages => Ok(ZkBackupCredentialType::Messages),
            BackupCredentialType::Media => Ok(ZkBackupCredentialType::Media),
        }
    }
}

fn backup_credential_type_from_zk(value: ZkBackupCredentialType) -> BackupCredentialType {
    match value {
        ZkBackupCredentialType::Messages => BackupCredentialType::Messages,
        ZkBackupCredentialType::Media => BackupCredentialType::Media,
    }
}

#[wasm_bindgen]
pub struct BackupAuthCredentialRequestContext {
    inner: ZkBackupAuthCredentialRequestContext,
}

#[wasm_bindgen]
impl BackupAuthCredentialRequestContext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupAuthCredentialRequestContext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "backup auth credential request context")?,
        })
    }

    pub fn create(
        backup_key: &[u8],
        aci: JsValue,
    ) -> Result<BackupAuthCredentialRequestContext, JsError> {
        let backup_key: LibSignalBackupKey =
            LibSignalBackupKey(fixed_array(backup_key, "backup key")?);
        Ok(Self {
            inner: ZkBackupAuthCredentialRequestContext::new(&backup_key, aci_from_js(&aci)?),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getRequest)]
    pub fn get_request(&self) -> BackupAuthCredentialRequest {
        BackupAuthCredentialRequest {
            inner: self.inner.get_request(),
        }
    }

    pub fn receive(
        &self,
        response: &BackupAuthCredentialResponse,
        redemption_time: f64,
        params: &GenericServerPublicParams,
    ) -> Result<BackupAuthCredential, JsError> {
        Ok(BackupAuthCredential {
            inner: self
                .inner
                .clone()
                .receive(
                    response.inner.clone(),
                    &params.inner,
                    zk_timestamp_from_seconds(redemption_time)?,
                )
                .map_err(js_error)?,
        })
    }
}

#[wasm_bindgen]
pub struct BackupAuthCredentialRequest {
    inner: ZkBackupAuthCredentialRequest,
}

#[wasm_bindgen]
impl BackupAuthCredentialRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupAuthCredentialRequest, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "backup auth credential request")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = issueCredential)]
    pub fn issue_credential(
        &self,
        timestamp: f64,
        backup_level: BackupLevel,
        credential_type: BackupCredentialType,
        params: &GenericServerSecretParams,
    ) -> Result<BackupAuthCredentialResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.issue_credential_with_random(
            timestamp,
            backup_level,
            credential_type,
            params,
            &randomness,
        )
    }

    #[wasm_bindgen(js_name = issueCredentialWithRandom)]
    pub fn issue_credential_with_random(
        &self,
        timestamp: f64,
        backup_level: BackupLevel,
        credential_type: BackupCredentialType,
        params: &GenericServerSecretParams,
        randomness: &[u8],
    ) -> Result<BackupAuthCredentialResponse, JsError> {
        Ok(BackupAuthCredentialResponse {
            inner: self.inner.issue(
                zk_timestamp_from_seconds(timestamp)?,
                backup_level.try_into()?,
                credential_type.try_into()?,
                &params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }
}

#[wasm_bindgen]
pub struct BackupAuthCredentialResponse {
    inner: ZkBackupAuthCredentialResponse,
}

#[wasm_bindgen]
impl BackupAuthCredentialResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupAuthCredentialResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "backup auth credential response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct BackupAuthCredential {
    inner: ZkBackupAuthCredential,
}

#[wasm_bindgen]
impl BackupAuthCredential {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupAuthCredential, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "backup auth credential")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn present(
        &self,
        server_params: &GenericServerPublicParams,
    ) -> Result<BackupAuthCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.present_with_random(server_params, &randomness)
    }

    #[wasm_bindgen(js_name = presentWithRandom)]
    pub fn present_with_random(
        &self,
        server_params: &GenericServerPublicParams,
        randomness: &[u8],
    ) -> Result<BackupAuthCredentialPresentation, JsError> {
        Ok(BackupAuthCredentialPresentation {
            inner: self.inner.present(
                &server_params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }

    #[wasm_bindgen(js_name = getBackupId)]
    pub fn get_backup_id(&self) -> Vec<u8> {
        self.inner.backup_id().0.to_vec()
    }

    #[wasm_bindgen(js_name = getBackupLevel)]
    pub fn get_backup_level(&self) -> BackupLevel {
        backup_level_from_zk(self.inner.backup_level())
    }

    #[wasm_bindgen(js_name = getType)]
    pub fn get_type(&self) -> BackupCredentialType {
        backup_credential_type_from_zk(self.inner.credential_type())
    }
}

#[wasm_bindgen]
pub struct BackupAuthCredentialPresentation {
    inner: ZkBackupAuthCredentialPresentation,
}

#[wasm_bindgen]
impl BackupAuthCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<BackupAuthCredentialPresentation, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "backup auth credential presentation")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn verify(
        &self,
        server_params: &GenericServerSecretParams,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        self.inner
            .verify(
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &server_params.inner,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = getBackupId)]
    pub fn get_backup_id(&self) -> Vec<u8> {
        self.inner.backup_id().0.to_vec()
    }

    #[wasm_bindgen(js_name = getBackupLevel)]
    pub fn get_backup_level(&self) -> BackupLevel {
        backup_level_from_zk(self.inner.backup_level())
    }

    #[wasm_bindgen(js_name = getType)]
    pub fn get_type(&self) -> BackupCredentialType {
        backup_credential_type_from_zk(self.inner.credential_type())
    }
}

#[wasm_bindgen]
pub struct GroupSendDerivedKeyPair {
    inner: ZkGroupSendDerivedKeyPair,
}

#[wasm_bindgen]
impl GroupSendDerivedKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSendDerivedKeyPair, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group send derived key pair")?,
        })
    }

    #[wasm_bindgen(js_name = forExpiration)]
    pub fn for_expiration(
        expiration_seconds: f64,
        server_params: &ServerSecretParams,
    ) -> Result<GroupSendDerivedKeyPair, JsError> {
        Ok(Self {
            inner: ZkGroupSendDerivedKeyPair::for_expiration(
                zk_timestamp_from_seconds(expiration_seconds)?,
                &server_params.inner,
            ),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct GroupSendEndorsementsResponse {
    inner: ZkGroupSendEndorsementsResponse,
}

#[wasm_bindgen]
impl GroupSendEndorsementsResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSendEndorsementsResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group send endorsements response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn issue(
        group_members: js_sys::Array,
        key_pair: &GroupSendDerivedKeyPair,
    ) -> Result<GroupSendEndorsementsResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Self::issue_with_random(group_members, key_pair, &randomness)
    }

    #[wasm_bindgen(js_name = issueWithRandom)]
    pub fn issue_with_random(
        group_members: js_sys::Array,
        key_pair: &GroupSendDerivedKeyPair,
        randomness: &[u8],
    ) -> Result<GroupSendEndorsementsResponse, JsError> {
        Ok(Self {
            inner: ZkGroupSendEndorsementsResponse::issue(
                uuid_ciphertexts_from_js_array(group_members)?,
                &key_pair.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }

    #[wasm_bindgen(js_name = getExpiration)]
    pub fn get_expiration(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from_f64(
            self.inner.expiration().epoch_seconds() as f64 * 1000.0,
        ))
    }

    #[wasm_bindgen(js_name = receiveWithServiceIds)]
    pub fn receive_with_service_ids(
        &self,
        group_members: js_sys::Array,
        local_user: &Aci,
        group_params: &GroupSecretParams,
        server_params: &ServerPublicParams,
        now_seconds: Option<f64>,
    ) -> Result<JsValue, JsError> {
        let group_members = service_ids_from_js_array(group_members)?;
        let local_user = LibSignalServiceId::from(aci_service_id(local_user)?);
        let local_user_index = group_members
            .iter()
            .position(|next| *next == local_user)
            .ok_or_else(|| JsError::new("local user not included in member list"))?;
        let received = self
            .inner
            .clone()
            .receive_with_service_ids(
                group_members,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &group_params.inner,
                &server_params.inner,
            )
            .map_err(js_error)?;
        let endorsements = js_sys::Array::new();
        let combined = ZkGroupSendEndorsement::combine(
            received[..local_user_index]
                .iter()
                .chain(&received[local_user_index + 1..])
                .map(|received| received.decompressed),
        );
        for endorsement in received {
            endorsements.push(
                &GroupSendEndorsement {
                    inner: endorsement.decompressed,
                }
                .into(),
            );
        }
        group_send_received_object(endorsements, combined)
    }

    #[wasm_bindgen(js_name = receiveWithCiphertexts)]
    pub fn receive_with_ciphertexts(
        &self,
        group_members: js_sys::Array,
        local_user: &UuidCiphertext,
        server_params: &ServerPublicParams,
        now_seconds: Option<f64>,
    ) -> Result<JsValue, JsError> {
        let group_members = uuid_ciphertexts_from_js_array(group_members)?;
        let local_user_index = group_members
            .iter()
            .position(|next| *next == local_user.inner)
            .ok_or_else(|| JsError::new("local user not included in member list"))?;
        let received = self
            .inner
            .clone()
            .receive_with_ciphertexts(
                group_members,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &server_params.inner,
            )
            .map_err(js_error)?;
        let endorsements = js_sys::Array::new();
        let combined = ZkGroupSendEndorsement::combine(
            received[..local_user_index]
                .iter()
                .chain(&received[local_user_index + 1..])
                .map(|received| received.decompressed),
        );
        for endorsement in received {
            endorsements.push(
                &GroupSendEndorsement {
                    inner: endorsement.decompressed,
                }
                .into(),
            );
        }
        group_send_received_object(endorsements, combined)
    }
}

fn group_send_received_object(
    endorsements: js_sys::Array,
    combined: ZkGroupSendEndorsement,
) -> Result<JsValue, JsError> {
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("endorsements"),
        endorsements.as_ref(),
    )
    .map_err(|_| JsError::new("failed to set endorsements"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("combinedEndorsement"),
        &GroupSendEndorsement { inner: combined }.into(),
    )
    .map_err(|_| JsError::new("failed to set combinedEndorsement"))?;
    Ok(result.into())
}

#[wasm_bindgen]
pub struct GroupSendEndorsement {
    inner: ZkGroupSendEndorsement,
}

#[wasm_bindgen]
impl GroupSendEndorsement {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSendEndorsement, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group send endorsement")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn combine(endorsements: js_sys::Array) -> Result<GroupSendEndorsement, JsError> {
        let endorsements = endorsements
            .iter()
            .map(|value| {
                let contents =
                    uint8_array_to_vec(call_js_method(&value, "getContents")?, "getContents()")?;
                zkgroup_deserialize(&contents, "group send endorsement")
            })
            .collect::<Result<Vec<_>, JsError>>()?;
        Ok(Self {
            inner: ZkGroupSendEndorsement::combine(endorsements),
        })
    }

    #[wasm_bindgen(js_name = byRemoving)]
    pub fn by_removing(&self, to_remove: &GroupSendEndorsement) -> GroupSendEndorsement {
        GroupSendEndorsement {
            inner: self.inner.remove(&to_remove.inner),
        }
    }

    #[wasm_bindgen(js_name = toToken)]
    pub fn to_token(&self, params: &GroupSecretParams) -> GroupSendToken {
        GroupSendToken {
            inner: self.inner.to_token(params.inner),
        }
    }

    #[wasm_bindgen(js_name = toTokenWithCallLinkParams)]
    pub fn to_token_with_call_link_params(&self, params: &CallLinkSecretParams) -> GroupSendToken {
        GroupSendToken {
            inner: self.inner.to_token(params.inner),
        }
    }

    #[wasm_bindgen(js_name = toFullToken)]
    pub fn to_full_token(
        &self,
        params: &GroupSecretParams,
        expiration_seconds: f64,
    ) -> Result<GroupSendFullToken, JsError> {
        self.to_token(params).to_full_token(expiration_seconds)
    }

    #[wasm_bindgen(js_name = toFullTokenWithCallLinkParams)]
    pub fn to_full_token_with_call_link_params(
        &self,
        params: &CallLinkSecretParams,
        expiration_seconds: f64,
    ) -> Result<GroupSendFullToken, JsError> {
        self.to_token_with_call_link_params(params)
            .to_full_token(expiration_seconds)
    }
}

#[wasm_bindgen]
pub struct GroupSendToken {
    inner: ZkGroupSendToken,
}

#[wasm_bindgen]
impl GroupSendToken {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSendToken, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group send token")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = toFullToken)]
    pub fn to_full_token(&self, expiration_seconds: f64) -> Result<GroupSendFullToken, JsError> {
        Ok(GroupSendFullToken {
            inner: self
                .inner
                .clone()
                .into_full_token(zk_timestamp_from_seconds(expiration_seconds)?),
        })
    }
}

#[wasm_bindgen]
pub struct GroupSendFullToken {
    inner: ZkGroupSendFullToken,
}

#[wasm_bindgen]
impl GroupSendFullToken {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GroupSendFullToken, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "group send full token")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getExpiration)]
    pub fn get_expiration(&self) -> js_sys::Date {
        js_sys::Date::new(&JsValue::from_f64(
            self.inner.expiration().epoch_seconds() as f64 * 1000.0,
        ))
    }

    pub fn verify(
        &self,
        user_ids: js_sys::Array,
        key_pair: &GroupSendDerivedKeyPair,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        self.inner
            .verify(
                service_ids_from_js_array(user_ids)?,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &key_pair.inner,
            )
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SanitizedMetadata {
    metadata: Option<Vec<u8>>,
    data_offset: u64,
    data_len: u64,
}

impl From<mp4::SanitizedMetadata> for SanitizedMetadata {
    fn from(value: mp4::SanitizedMetadata) -> Self {
        Self {
            metadata: value.metadata,
            data_offset: value.data.offset,
            data_len: value.data.len,
        }
    }
}

#[wasm_bindgen]
impl SanitizedMetadata {
    #[wasm_bindgen(js_name = getMetadata)]
    pub fn get_metadata(&self) -> JsValue {
        self.metadata.as_ref().map_or(JsValue::NULL, |metadata| {
            js_sys::Uint8Array::from(metadata.as_slice()).into()
        })
    }

    #[wasm_bindgen(js_name = getDataOffset)]
    pub fn get_data_offset(&self) -> u64 {
        self.data_offset
    }

    #[wasm_bindgen(js_name = getDataLen)]
    pub fn get_data_len(&self) -> u64 {
        self.data_len
    }
}

#[wasm_bindgen(js_name = signalMediaCheckAvailable)]
pub fn signal_media_check_available() {}

#[wasm_bindgen(js_name = mp4SanitizerSanitize)]
pub fn mp4_sanitizer_sanitize(input: &[u8]) -> Result<SanitizedMetadata, JsError> {
    let input = MediaByteInput::new(input);
    Ok(block_on(mp4::sanitize(input, None))
        .map_err(js_error)?
        .into())
}

#[wasm_bindgen(js_name = mp4SanitizerSanitizeWithCompoundedMdatBoxes)]
pub fn mp4_sanitizer_sanitize_with_compounded_mdat_boxes(
    input: &[u8],
    cumulative_mdat_box_size: u32,
) -> Result<SanitizedMetadata, JsError> {
    let input = MediaByteInput::new(input);
    Ok(
        block_on(mp4::sanitize(input, Some(cumulative_mdat_box_size)))
            .map_err(js_error)?
            .into(),
    )
}

#[wasm_bindgen(js_name = webpSanitizerSanitize)]
pub fn webp_sanitizer_sanitize(input: &[u8]) -> Result<(), JsError> {
    let mut input = MediaByteInput::new(input);
    webp::sanitize(&mut input).map_err(js_error)
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum Environment {
    Staging = 0,
    Production = 1,
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub enum BuildVariant {
    Production = 0,
    Beta = 1,
}

#[wasm_bindgen]
pub struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout_millis: Option<u32>,
}

impl HttpRequest {
    fn from_js(value: &JsValue) -> Result<Self, JsError> {
        let body = js_property(value, "body")?;
        let body = if body.is_null() || body.is_undefined() {
            None
        } else if body.is_instance_of::<js_sys::Uint8Array>() {
            Some(js_sys::Uint8Array::new(&body).to_vec())
        } else {
            return Err(JsError::new("body must be a Uint8Array when present"));
        };
        Ok(Self {
            method: required_js_string(value, "verb")
                .or_else(|_| required_js_string(value, "method"))?,
            path: required_js_string(value, "path")?,
            headers: js_headers_to_vec(&js_property(value, "headers")?, "headers")?,
            body,
            timeout_millis: optional_js_u32(value, "timeoutMillis")?,
        })
    }

    fn to_js(&self) -> Result<JsValue, JsError> {
        let request = js_sys::Object::new();
        js_sys::Reflect::set(
            &request,
            &JsValue::from_str("verb"),
            &JsValue::from_str(&self.method),
        )
        .map_err(|_| JsError::new("failed to set verb"))?;
        js_sys::Reflect::set(
            &request,
            &JsValue::from_str("method"),
            &JsValue::from_str(&self.method),
        )
        .map_err(|_| JsError::new("failed to set method"))?;
        js_sys::Reflect::set(
            &request,
            &JsValue::from_str("path"),
            &JsValue::from_str(&self.path),
        )
        .map_err(|_| JsError::new("failed to set path"))?;
        js_sys::Reflect::set(
            &request,
            &JsValue::from_str("headers"),
            &headers_to_js_array(&self.headers),
        )
        .map_err(|_| JsError::new("failed to set headers"))?;
        let body = self.body.as_ref().map_or(JsValue::NULL, |body| {
            js_sys::Uint8Array::from(body.as_slice()).into()
        });
        js_sys::Reflect::set(&request, &JsValue::from_str("body"), &body)
            .map_err(|_| JsError::new("failed to set body"))?;
        if let Some(timeout_millis) = self.timeout_millis {
            js_sys::Reflect::set(
                &request,
                &JsValue::from_str("timeoutMillis"),
                &JsValue::from_f64(timeout_millis as f64),
            )
            .map_err(|_| JsError::new("failed to set timeoutMillis"))?;
        }
        Ok(request.into())
    }
}

#[wasm_bindgen]
impl HttpRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(method: String, path: String, body: Option<Vec<u8>>) -> HttpRequest {
        Self {
            method,
            path,
            headers: Vec::new(),
            body,
            timeout_millis: None,
        }
    }

    #[wasm_bindgen(js_name = addHeader)]
    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    #[wasm_bindgen(js_name = setTimeoutMillis)]
    pub fn set_timeout_millis(&mut self, timeout_millis: Option<u32>) {
        self.timeout_millis = timeout_millis;
    }

    pub fn method(&self) -> String {
        self.method.clone()
    }

    pub fn verb(&self) -> String {
        self.method()
    }

    pub fn path(&self) -> String {
        self.path.clone()
    }

    pub fn headers(&self) -> js_sys::Array {
        headers_to_js_array(&self.headers)
    }

    pub fn body(&self) -> JsValue {
        self.body.as_ref().map_or(JsValue::NULL, |body| {
            js_sys::Uint8Array::from(body.as_slice()).into()
        })
    }

    #[wasm_bindgen(js_name = timeoutMillis)]
    pub fn timeout_millis(&self) -> Option<u32> {
        self.timeout_millis
    }

    #[wasm_bindgen(js_name = toObject)]
    pub fn to_object(&self) -> Result<JsValue, JsError> {
        self.to_js()
    }
}

#[wasm_bindgen(js_name = buildHttpRequest)]
pub fn build_http_request(chat_request: JsValue) -> Result<HttpRequest, JsError> {
    HttpRequest::from_js(&chat_request)
}

#[wasm_bindgen]
pub struct ChatResponse {
    status: u16,
    message: Option<String>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl ChatResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        status: u16,
        message: Option<String>,
        body: Option<Vec<u8>>,
    ) -> Result<ChatResponse, JsError> {
        Ok(Self {
            status,
            message,
            headers: Vec::new(),
            body,
        })
    }

    #[wasm_bindgen(js_name = fromObject)]
    pub fn from_object(value: JsValue) -> Result<ChatResponse, JsError> {
        let status = js_u32(&js_property(&value, "status")?, "status")?;
        let status =
            u16::try_from(status).map_err(|_| JsError::new("status must fit in uint16"))?;
        let body = js_property(&value, "body")?;
        let body = if body.is_null() || body.is_undefined() {
            None
        } else if body.is_instance_of::<js_sys::Uint8Array>() {
            Some(js_sys::Uint8Array::new(&body).to_vec())
        } else {
            return Err(JsError::new("body must be a Uint8Array when present"));
        };
        Ok(Self {
            status,
            message: optional_js_string(&value, "message")?,
            headers: js_headers_to_vec(&js_property(&value, "headers")?, "headers")?,
            body,
        })
    }

    #[wasm_bindgen(js_name = addHeader)]
    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn message(&self) -> Option<String> {
        self.message.clone()
    }

    pub fn headers(&self) -> js_sys::Array {
        headers_to_js_array(&self.headers)
    }

    pub fn body(&self) -> JsValue {
        self.body.as_ref().map_or(JsValue::NULL, |body| {
            js_sys::Uint8Array::from(body.as_slice()).into()
        })
    }

    #[wasm_bindgen(js_name = toObject)]
    pub fn to_object(&self) -> Result<JsValue, JsError> {
        let response = js_sys::Object::new();
        js_sys::Reflect::set(
            &response,
            &JsValue::from_str("status"),
            &JsValue::from_f64(self.status as f64),
        )
        .map_err(|_| JsError::new("failed to set status"))?;
        js_sys::Reflect::set(
            &response,
            &JsValue::from_str("message"),
            &self
                .message
                .as_ref()
                .map_or(JsValue::UNDEFINED, |message| JsValue::from_str(message)),
        )
        .map_err(|_| JsError::new("failed to set message"))?;
        js_sys::Reflect::set(
            &response,
            &JsValue::from_str("headers"),
            &headers_to_js_array(&self.headers),
        )
        .map_err(|_| JsError::new("failed to set headers"))?;
        js_sys::Reflect::set(&response, &JsValue::from_str("body"), &self.body())
            .map_err(|_| JsError::new("failed to set body"))?;
        Ok(response.into())
    }
}

fn require_success_response_body<'a>(
    response: &'a ChatResponse,
    operation: &str,
) -> Result<&'a [u8], JsError> {
    if !(200..300).contains(&response.status) {
        return Err(JsError::new(&format!(
            "{operation} response status was {}",
            response.status
        )));
    }
    response
        .body
        .as_deref()
        .ok_or_else(|| JsError::new(&format!("{operation} response body is missing")))
}

#[wasm_bindgen(js_name = parseGetPreKeysResponse)]
pub fn parse_get_pre_keys_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    let raw: BrowserPreKeyResponse =
        serde_json::from_slice(require_success_response_body(response, "getPreKeys")?)
            .map_err(js_error)?;

    let bundles = js_sys::Array::new();
    for device in raw.devices {
        let pre_key = device
            .pre_key
            .map(|pre_key| (pre_key.key_id, pre_key.public_key));
        let bundle = PreKeyBundle {
            inner: LibSignalPreKeyBundle::new(
                device.registration_id,
                DeviceId::try_from(device.device_id).map_err(js_error)?,
                pre_key.map(|(id, key)| (PreKeyId::from(id), key)),
                SignedPreKeyId::from(device.signed_pre_key.key_id),
                device.signed_pre_key.public_key,
                device.signed_pre_key.signature,
                device.pq_pre_key.key_id.into(),
                device.pq_pre_key.public_key,
                device.pq_pre_key.signature,
                LibSignalIdentityKey::new(raw.identity_key),
            )
            .map_err(js_error)?,
        };
        bundles.push(&bundle.into());
    }

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("identityKey"),
        &PublicKey {
            inner: raw.identity_key,
        }
        .into(),
    )
    .map_err(|_| JsError::new("failed to set identityKey"))?;
    js_sys::Reflect::set(&result, &JsValue::from_str("preKeyBundles"), &bundles)
        .map_err(|_| JsError::new("failed to set preKeyBundles"))?;
    Ok(result.into())
}

#[wasm_bindgen(js_name = parseUploadFormResponse)]
pub fn parse_upload_form_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    let raw: BrowserUploadForm =
        serde_json::from_slice(require_success_response_body(response, "getUploadForm")?)
            .map_err(js_error)?;
    let headers = raw.headers.into_iter().collect::<Vec<_>>();
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("cdn"),
        &JsValue::from_f64(raw.cdn as f64),
    )
    .map_err(|_| JsError::new("failed to set cdn"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("key"),
        &JsValue::from_str(&raw.key),
    )
    .map_err(|_| JsError::new("failed to set key"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("headers"),
        &headers_to_js_array(&headers),
    )
    .map_err(|_| JsError::new("failed to set headers"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("signedUploadUrl"),
        &JsValue::from_str(&raw.signed_upload_url),
    )
    .map_err(|_| JsError::new("failed to set signedUploadUrl"))?;
    Ok(result.into())
}

fn registration_session_to_js(session: BrowserRegistrationSession) -> Result<JsValue, JsError> {
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("allowedToRequestCode"),
        &JsValue::from_bool(session.allowed_to_request_code),
    )
    .map_err(|_| JsError::new("failed to set allowedToRequestCode"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("verified"),
        &JsValue::from_bool(session.verified),
    )
    .map_err(|_| JsError::new("failed to set verified"))?;
    if let Some(next_sms) = session.next_sms {
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("nextSmsSecs"),
            &JsValue::from_f64(next_sms as f64),
        )
        .map_err(|_| JsError::new("failed to set nextSmsSecs"))?;
    }
    if let Some(next_call) = session.next_call {
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("nextCallSecs"),
            &JsValue::from_f64(next_call as f64),
        )
        .map_err(|_| JsError::new("failed to set nextCallSecs"))?;
    }
    if let Some(next_verification_attempt) = session.next_verification_attempt {
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("nextVerificationAttemptSecs"),
            &JsValue::from_f64(next_verification_attempt as f64),
        )
        .map_err(|_| JsError::new("failed to set nextVerificationAttemptSecs"))?;
    }
    let requested_information = js_sys::Array::new();
    for value in session.requested_information {
        requested_information.push(&JsValue::from_str(&value));
    }
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("requestedInformation"),
        &requested_information,
    )
    .map_err(|_| JsError::new("failed to set requestedInformation"))?;
    Ok(result.into())
}

#[wasm_bindgen(js_name = parseRegistrationSessionResponse)]
pub fn parse_registration_session_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    let raw: BrowserRegistrationResponse =
        serde_json::from_slice(require_success_response_body(response, "registration")?)
            .map_err(js_error)?;
    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("sessionId"),
        &JsValue::from_str(&raw.session_id),
    )
    .map_err(|_| JsError::new("failed to set sessionId"))?;
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("sessionState"),
        &registration_session_to_js(raw.session)?,
    )
    .map_err(|_| JsError::new("failed to set sessionState"))?;
    Ok(result.into())
}

#[wasm_bindgen(js_name = parseCheckSvr2CredentialsResponse)]
pub fn parse_check_svr2_credentials_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    let raw: BrowserSvr2CredentialsResponse = serde_json::from_slice(
        require_success_response_body(response, "checkSvr2Credentials")?,
    )
    .map_err(js_error)?;
    let matches = js_sys::Object::new();
    for (token, result) in raw.matches {
        js_sys::Reflect::set(
            &matches,
            &JsValue::from_str(&token),
            &JsValue::from_str(&result),
        )
        .map_err(|_| JsError::new("failed to set SVR2 credential result"))?;
    }
    Ok(matches.into())
}

#[wasm_bindgen(js_name = parseLookUpUsernameHashResponse)]
pub fn parse_look_up_username_hash_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    if response.status == 404 {
        return Ok(JsValue::NULL);
    }
    let raw: BrowserUsernameHashResponse = serde_json::from_slice(require_success_response_body(
        response,
        "lookUpUsernameHash",
    )?)
    .map_err(js_error)?;
    Ok(Aci::from_uuid(&raw.uuid)?.into())
}

#[wasm_bindgen(js_name = parseLookUpUsernameLinkResponse)]
pub fn parse_look_up_username_link_response(
    response: &ChatResponse,
    entropy: &[u8],
) -> Result<JsValue, JsError> {
    if response.status == 404 {
        return Ok(JsValue::NULL);
    }
    let entropy: [u8; 32] = entropy
        .try_into()
        .map_err(|_| JsError::new("username link entropy must be 32 bytes"))?;
    let raw: BrowserUsernameLinkResponse = serde_json::from_slice(require_success_response_body(
        response,
        "lookUpUsernameLink",
    )?)
    .map_err(js_error)?;
    let encrypted_username = base64_url_no_pad_decode(&raw.username_link_encrypted_value)?;
    let username = usernames::decrypt_username(&entropy, &encrypted_username).map_err(js_error)?;
    let username = Username::new(&username).map_err(js_error)?;

    let result = js_sys::Object::new();
    set_object_property(
        &result,
        "username",
        &JsValue::from_str(&username.to_string()),
    )?;
    set_object_property(
        &result,
        "hash",
        &js_sys::Uint8Array::from(username.hash().as_slice()).into(),
    )?;
    Ok(result.into())
}

#[wasm_bindgen(js_name = parseAccountExistsResponse)]
pub fn parse_account_exists_response(response: &ChatResponse) -> Result<bool, JsError> {
    match response.status {
        200 => Ok(true),
        404 => Ok(false),
        status => Err(JsError::new(&format!(
            "accountExists response status was {status}"
        ))),
    }
}

fn set_object_property(
    object: &js_sys::Object,
    name: &str,
    value: &JsValue,
) -> Result<(), JsError> {
    js_sys::Reflect::set(object, &JsValue::from_str(name), value)
        .map(|_| ())
        .map_err(|_| JsError::new(&format!("failed to set {name}")))
}

fn js_u64_bigint(value: u64) -> JsValue {
    js_sys::BigInt::from(value).into()
}

fn entitlement_badge_to_js(badge: BrowserEntitlementBadge) -> Result<JsValue, JsError> {
    let result = js_sys::Object::new();
    set_object_property(&result, "id", &JsValue::from_str(&badge.id))?;
    set_object_property(&result, "visible", &JsValue::from_bool(badge.visible))?;
    set_object_property(
        &result,
        "expirationSeconds",
        &js_u64_bigint(badge.expiration_seconds),
    )?;
    Ok(result.into())
}

fn backup_entitlement_to_js(backup: BrowserBackupEntitlement) -> Result<JsValue, JsError> {
    let result = js_sys::Object::new();
    set_object_property(&result, "backupLevel", &js_u64_bigint(backup.backup_level))?;
    set_object_property(
        &result,
        "expirationSeconds",
        &js_u64_bigint(backup.expiration_seconds),
    )?;
    Ok(result.into())
}

#[wasm_bindgen(js_name = parseRegisterAccountResponse)]
pub fn parse_register_account_response(response: &ChatResponse) -> Result<JsValue, JsError> {
    let raw: BrowserRegisterAccountResponse =
        serde_json::from_slice(require_success_response_body(response, "registerAccount")?)
            .map_err(js_error)?;
    let entitlements = js_sys::Object::new();
    let badges = js_sys::Array::new();
    for badge in raw.entitlements.badges {
        badges.push(&entitlement_badge_to_js(badge)?);
    }
    set_object_property(&entitlements, "badges", &badges)?;
    set_object_property(
        &entitlements,
        "backup",
        &raw.entitlements
            .backup
            .map(backup_entitlement_to_js)
            .transpose()?
            .unwrap_or(JsValue::NULL),
    )?;

    let result = js_sys::Object::new();
    set_object_property(&result, "aci", &Aci::from_uuid(&raw.uuid)?.into())?;
    set_object_property(&result, "uuid", &JsValue::from_str(&raw.uuid))?;
    set_object_property(&result, "pni", &Pni::from_uuid(&raw.pni)?.into())?;
    set_object_property(&result, "number", &JsValue::from_str(&raw.number))?;
    set_object_property(
        &result,
        "usernameHash",
        &raw.username_hash.map_or(JsValue::NULL, |hash| {
            js_sys::Uint8Array::from(hash.as_slice()).into()
        }),
    )?;
    set_object_property(
        &result,
        "usernameLinkHandle",
        &raw.username_link_handle
            .map_or(JsValue::NULL, |handle| JsValue::from_str(&handle)),
    )?;
    set_object_property(
        &result,
        "storageCapable",
        &JsValue::from_bool(raw.storage_capable),
    )?;
    set_object_property(&result, "entitlements", &entitlements)?;
    set_object_property(
        &result,
        "reregistration",
        &JsValue::from_bool(raw.reregistration),
    )?;
    Ok(result.into())
}

#[wasm_bindgen]
pub struct BrowserChatConnection {
    transport: js_sys::Function,
    connected: bool,
}

#[wasm_bindgen]
impl BrowserChatConnection {
    #[wasm_bindgen(constructor)]
    pub fn new(transport: js_sys::Function) -> BrowserChatConnection {
        Self {
            transport,
            connected: true,
        }
    }

    pub fn fetch(&self, chat_request: JsValue) -> Result<js_sys::Promise, JsError> {
        if !self.connected {
            return Err(JsError::new("chat connection is disconnected"));
        }
        let request = HttpRequest::from_js(&chat_request)?.to_js()?;
        let response = self
            .transport
            .call1(&JsValue::UNDEFINED, &request)
            .map_err(|_| JsError::new("browser chat transport threw"))?;
        Ok(js_sys::Promise::resolve(&response))
    }

    pub fn disconnect(&mut self) -> js_sys::Promise {
        self.connected = false;
        js_sys::Promise::resolve(&JsValue::UNDEFINED)
    }

    #[wasm_bindgen(js_name = getPreKeys)]
    pub fn get_pre_keys(
        &self,
        target: JsValue,
        device_id: Option<u32>,
        auth_kind: String,
        auth_payload: Option<Vec<u8>>,
    ) -> Result<js_sys::Promise, JsError> {
        let target = service_id_from_js(&target)?;
        let mut request = HttpRequest::new(
            "GET".to_string(),
            format!(
                "/v2/keys/{}/{}",
                target.service_id_string(),
                device_specifier(device_id)
            ),
            None,
        );
        let (name, value) = chat_auth_header(&auth_kind, auth_payload)?;
        request.add_header(name, value);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = sendMultiRecipientMessage)]
    pub fn send_multi_recipient_message(
        &self,
        payload: &[u8],
        timestamp_millis: f64,
        auth_kind: String,
        auth_payload: Option<Vec<u8>>,
        online_only: bool,
        urgent: bool,
    ) -> Result<js_sys::Promise, JsError> {
        let story = auth_kind == "story";
        let mut request = HttpRequest::new(
            "PUT".to_string(),
            format!(
                "/v1/messages/multi_recipient?ts={}&online={}&urgent={}{}",
                timestamp_epoch_millis(timestamp_millis)?,
                online_only,
                urgent,
                if story { "&story=true" } else { "" }
            ),
            Some(payload.to_vec()),
        );
        request.add_header(
            "content-type".to_string(),
            "application/vnd.signal-messenger.mrm".to_string(),
        );
        if !story {
            let (name, value) = chat_auth_header(&auth_kind, auth_payload)?;
            request.add_header(name, value);
        }
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = sendSealedSenderMessage)]
    pub fn send_sealed_sender_message(
        &self,
        destination: JsValue,
        timestamp_millis: f64,
        contents: js_sys::Array,
        auth_kind: String,
        auth_payload: Option<Vec<u8>>,
        online_only: bool,
        urgent: bool,
    ) -> Result<js_sys::Promise, JsError> {
        let destination = service_id_from_js(&destination)?;
        let story = auth_kind == "story";
        let mut request = HttpRequest::new(
            "PUT".to_string(),
            format!(
                "/v1/messages/{}{}",
                destination.service_id_string(),
                if story { "?story=true" } else { "" }
            ),
            Some(send_message_body(
                contents,
                timestamp_millis,
                online_only,
                urgent,
            )?),
        );
        request.add_header("content-type".to_string(), "application/json".to_string());
        if !story {
            let (name, value) = chat_auth_header(&auth_kind, auth_payload)?;
            request.add_header(name, value);
        }
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = sendAuthenticatedMessage)]
    pub fn send_authenticated_message(
        &self,
        destination: JsValue,
        timestamp_millis: f64,
        contents: js_sys::Array,
        online_only: bool,
        urgent: bool,
    ) -> Result<js_sys::Promise, JsError> {
        let destination = service_id_from_js(&destination)?;
        let mut request = HttpRequest::new(
            "PUT".to_string(),
            format!("/v1/messages/{}", destination.service_id_string()),
            Some(send_unsealed_message_body(
                contents,
                timestamp_millis,
                online_only,
                urgent,
            )?),
        );
        request.add_header("content-type".to_string(), "application/json".to_string());
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = sendSyncMessage)]
    pub fn send_sync_message(
        &self,
        local_user: JsValue,
        timestamp_millis: f64,
        contents: js_sys::Array,
        urgent: bool,
    ) -> Result<js_sys::Promise, JsError> {
        self.send_authenticated_message(local_user, timestamp_millis, contents, false, urgent)
    }

    #[wasm_bindgen(js_name = getUploadForm)]
    pub fn get_upload_form(&self, upload_size: u64) -> Result<js_sys::Promise, JsError> {
        let request = HttpRequest::new(
            "GET".to_string(),
            format!("/v4/attachments/form/upload?uploadLength={upload_size}"),
            None,
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = lookUpUsernameHash)]
    pub fn look_up_username_hash(&self, hash: &[u8]) -> Result<js_sys::Promise, JsError> {
        let request = HttpRequest::new(
            "GET".to_string(),
            format!("/v1/accounts/username_hash/{}", base64_url_no_pad(hash)),
            None,
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = lookUpUsernameLink)]
    pub fn look_up_username_link(&self, uuid: String) -> Result<js_sys::Promise, JsError> {
        let uuid = Uuid::parse_str(&uuid).map_err(js_error)?;
        let request = HttpRequest::new(
            "GET".to_string(),
            format!("/v1/accounts/username_link/{uuid}"),
            None,
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = accountExists)]
    pub fn account_exists(&self, account: JsValue) -> Result<js_sys::Promise, JsError> {
        let account = service_id_from_js(&account)?;
        let request = HttpRequest::new(
            "HEAD".to_string(),
            format!("/v1/accounts/account/{}", account.service_id_string()),
            None,
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = getBackupUploadForm)]
    pub fn get_backup_upload_form(
        &self,
        upload_size: u64,
        credential: &BackupAuthCredential,
        server_params: &GenericServerPublicParams,
        signing_key: &PrivateKey,
    ) -> Result<js_sys::Promise, JsError> {
        let mut request = HttpRequest::new(
            "GET".to_string(),
            format!("/v1/archives/upload/form?uploadLength={upload_size}"),
            None,
        );
        for (name, value) in backup_auth_headers(credential, server_params, signing_key)? {
            request.add_header(name, value);
        }
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = getBackupMediaUploadForm)]
    pub fn get_backup_media_upload_form(
        &self,
        upload_size: u64,
        credential: &BackupAuthCredential,
        server_params: &GenericServerPublicParams,
        signing_key: &PrivateKey,
    ) -> Result<js_sys::Promise, JsError> {
        let mut request = HttpRequest::new(
            "GET".to_string(),
            format!("/v1/archives/media/upload/form?uploadLength={upload_size}"),
            None,
        );
        for (name, value) in backup_auth_headers(credential, server_params, signing_key)? {
            request.add_header(name, value);
        }
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = createRegistrationSession)]
    pub fn create_registration_session(
        &self,
        e164: String,
        push_token_type: Option<String>,
        push_token: Option<String>,
        mcc: Option<String>,
        mnc: Option<String>,
    ) -> Result<js_sys::Promise, JsError> {
        let mut body = serde_json::Map::new();
        body.insert("number".to_string(), serde_json::Value::String(e164));
        match (push_token_type, push_token) {
            (Some(push_token_type), Some(push_token)) => {
                if push_token_type != "apn" && push_token_type != "fcm" {
                    return Err(JsError::new("push token type must be apn or fcm"));
                }
                body.insert(
                    "pushTokenType".to_string(),
                    serde_json::Value::String(push_token_type),
                );
                body.insert(
                    "pushToken".to_string(),
                    serde_json::Value::String(push_token),
                );
            }
            (None, None) => {}
            _ => {
                return Err(JsError::new(
                    "push token type and push token must both be set or both be null",
                ));
            }
        }
        optional_json_string(&mut body, "mcc", mcc);
        optional_json_string(&mut body, "mnc", mnc);
        let mut request = HttpRequest::new(
            "POST".to_string(),
            "/v1/verification/session".to_string(),
            Some(json_body(serde_json::Value::Object(body))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = getRegistrationSession)]
    pub fn get_registration_session(&self, session_id: String) -> Result<js_sys::Promise, JsError> {
        let request = HttpRequest::new(
            "GET".to_string(),
            format!("/v1/verification/session/{session_id}"),
            None,
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = submitRegistrationCaptcha)]
    pub fn submit_registration_captcha(
        &self,
        session_id: String,
        captcha: String,
    ) -> Result<js_sys::Promise, JsError> {
        let mut request = HttpRequest::new(
            "PATCH".to_string(),
            format!("/v1/verification/session/{session_id}"),
            Some(json_body(serde_json::json!({ "captcha": captcha }))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = requestRegistrationPushChallenge)]
    pub fn request_registration_push_challenge(
        &self,
        session_id: String,
        push_token_type: String,
        push_token: String,
    ) -> Result<js_sys::Promise, JsError> {
        if push_token_type != "apn" && push_token_type != "fcm" {
            return Err(JsError::new("push token type must be apn or fcm"));
        }
        let mut request = HttpRequest::new(
            "PATCH".to_string(),
            format!("/v1/verification/session/{session_id}"),
            Some(json_body(serde_json::json!({
                "pushTokenType": push_token_type,
                "pushToken": push_token,
            }))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = submitRegistrationPushChallenge)]
    pub fn submit_registration_push_challenge(
        &self,
        session_id: String,
        push_challenge: String,
    ) -> Result<js_sys::Promise, JsError> {
        let mut request = HttpRequest::new(
            "PATCH".to_string(),
            format!("/v1/verification/session/{session_id}"),
            Some(json_body(serde_json::json!({
                "pushChallenge": push_challenge,
            }))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = requestVerificationCode)]
    pub fn request_verification_code(
        &self,
        session_id: String,
        transport: String,
        client: String,
        languages: js_sys::Array,
    ) -> Result<js_sys::Promise, JsError> {
        if transport != "sms" && transport != "voice" {
            return Err(JsError::new("verification transport must be sms or voice"));
        }
        let mut request = HttpRequest::new(
            "POST".to_string(),
            format!("/v1/verification/session/{session_id}/code"),
            Some(json_body(serde_json::json!({
                "transport": transport,
                "client": client,
            }))?),
        );
        content_type_json(&mut request);
        let languages = js_string_array(languages, "languages")?;
        if !languages.is_empty() {
            request.add_header("accept-language".to_string(), languages.join(","));
        }
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = submitVerificationCode)]
    pub fn submit_verification_code(
        &self,
        session_id: String,
        code: String,
    ) -> Result<js_sys::Promise, JsError> {
        let mut request = HttpRequest::new(
            "PUT".to_string(),
            format!("/v1/verification/session/{session_id}/code"),
            Some(json_body(serde_json::json!({ "code": code }))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = registerAccount)]
    #[allow(clippy::too_many_arguments)]
    pub fn register_account(
        &self,
        e164: String,
        account_password: String,
        session_id: Option<String>,
        recovery_password: Option<Vec<u8>>,
        skip_device_transfer: bool,
        fetches_messages: bool,
        push_token_type: Option<String>,
        push_token: Option<String>,
        account_attributes: JsValue,
        aci_identity_key: JsValue,
        pni_identity_key: JsValue,
        aci_signed_pre_key: JsValue,
        pni_signed_pre_key: JsValue,
        aci_pq_last_resort_pre_key: JsValue,
        pni_pq_last_resort_pre_key: JsValue,
    ) -> Result<js_sys::Promise, JsError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "accountAttributes".to_string(),
            registration_account_attributes_body(&account_attributes, fetches_messages)?,
        );
        body.insert(
            "aciIdentityKey".to_string(),
            serde_json::Value::String(serialized_key_base64(
                aci_identity_key,
                "aciIdentityKey.serialize()",
            )?),
        );
        body.insert(
            "pniIdentityKey".to_string(),
            serde_json::Value::String(serialized_key_base64(
                pni_identity_key,
                "pniIdentityKey.serialize()",
            )?),
        );
        body.insert(
            "aciSignedPreKey".to_string(),
            pre_key_registration_body(&aci_signed_pre_key)?,
        );
        body.insert(
            "pniSignedPreKey".to_string(),
            pre_key_registration_body(&pni_signed_pre_key)?,
        );
        body.insert(
            "aciPqLastResortPreKey".to_string(),
            pre_key_registration_body(&aci_pq_last_resort_pre_key)?,
        );
        body.insert(
            "pniPqLastResortPreKey".to_string(),
            pre_key_registration_body(&pni_pq_last_resort_pre_key)?,
        );
        body.insert(
            "skipDeviceTransfer".to_string(),
            serde_json::Value::Bool(skip_device_transfer),
        );

        match session_id {
            Some(session_id) => {
                if recovery_password.is_some() {
                    return Err(JsError::new(
                        "top-level recovery password must be null when session ID is set",
                    ));
                }
                body.insert(
                    "sessionId".to_string(),
                    serde_json::Value::String(session_id),
                );
            }
            None => {
                let recovery_password = recovery_password
                    .or_else(|| {
                        optional_uint8_array_property(&account_attributes, "recoveryPassword")
                            .ok()
                            .flatten()
                    })
                    .ok_or_else(|| {
                        JsError::new(
                            "top-level recovery password is required when session ID is null",
                        )
                    })?;
                body.insert(
                    "recoveryPassword".to_string(),
                    serde_json::Value::String(base64_with_padding(&recovery_password)),
                );
            }
        }

        if !fetches_messages {
            let (push_token_type, push_token) =
                push_token_type.zip(push_token).ok_or_else(|| {
                    JsError::new("push token is required unless fetchesMessages is true")
                })?;
            let token_key = match push_token_type.as_str() {
                "apn" => "apnRegistrationId",
                "fcm" => "gcmRegistrationId",
                _ => return Err(JsError::new("push token type must be apn or fcm")),
            };
            body.insert(
                "pushToken".to_string(),
                serde_json::json!({ token_key: push_token }),
            );
        }

        let mut request = HttpRequest::new(
            "POST".to_string(),
            "/v1/registration".to_string(),
            Some(json_body(serde_json::Value::Object(body))?),
        );
        content_type_json(&mut request);
        request.add_header(
            "authorization".to_string(),
            format!(
                "Basic {}",
                base64_with_padding(format!("{e164}:{account_password}").as_bytes())
            ),
        );
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = checkSvr2Credentials)]
    pub fn check_svr2_credentials(
        &self,
        e164: String,
        tokens: js_sys::Array,
    ) -> Result<js_sys::Promise, JsError> {
        let tokens = js_string_array(tokens, "tokens")?;
        let mut request = HttpRequest::new(
            "POST".to_string(),
            "/v2/backup/auth/check".to_string(),
            Some(json_body(serde_json::json!({
                "number": e164,
                "tokens": tokens,
            }))?),
        );
        content_type_json(&mut request);
        self.fetch(request.to_js()?)
    }

    #[wasm_bindgen(js_name = connectionInfo)]
    pub fn connection_info(&self) -> JsValue {
        let info = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &info,
            &JsValue::from_str("localPort"),
            &JsValue::from_f64(0.0),
        );
        let _ = js_sys::Reflect::set(
            &info,
            &JsValue::from_str("ipVersion"),
            &JsValue::from_str("browser"),
        );
        info.into()
    }
}

#[wasm_bindgen]
pub struct GenericServerPublicParams {
    inner: ZkGenericServerPublicParams,
}

#[wasm_bindgen]
impl GenericServerPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<GenericServerPublicParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "generic server public params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct CallLinkSecretParams {
    inner: ZkCallLinkSecretParams,
}

#[wasm_bindgen]
impl CallLinkSecretParams {
    #[wasm_bindgen(js_name = deriveFromRootKey)]
    pub fn derive_from_root_key(call_link_root_key: &[u8]) -> CallLinkSecretParams {
        Self {
            inner: ZkCallLinkSecretParams::derive_from_root_key(call_link_root_key),
        }
    }

    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CallLinkSecretParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "call link secret params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getPublicParams)]
    pub fn get_public_params(&self) -> CallLinkPublicParams {
        CallLinkPublicParams {
            inner: self.inner.get_public_params(),
        }
    }

    #[wasm_bindgen(js_name = decryptUserId)]
    pub fn decrypt_user_id(&self, user_id: &UuidCiphertext) -> Result<Aci, JsError> {
        Ok(Aci {
            inner: LibSignalServiceId::from(
                self.inner.decrypt_uid(user_id.inner).map_err(js_error)?,
            ),
        })
    }

    #[wasm_bindgen(js_name = encryptUserId)]
    pub fn encrypt_user_id(&self, user_id: &Aci) -> Result<UuidCiphertext, JsError> {
        Ok(UuidCiphertext {
            inner: self.inner.encrypt_uid(aci_service_id(user_id)?),
        })
    }
}

#[wasm_bindgen]
pub struct CallLinkPublicParams {
    inner: ZkCallLinkPublicParams,
}

#[wasm_bindgen]
impl CallLinkPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CallLinkPublicParams, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "call link public params")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct CreateCallLinkCredentialRequestContext {
    inner: ZkCreateCallLinkCredentialRequestContext,
}

#[wasm_bindgen]
impl CreateCallLinkCredentialRequestContext {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CreateCallLinkCredentialRequestContext, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "create call link credential request context")?,
        })
    }

    #[wasm_bindgen(js_name = forRoomId)]
    pub fn for_room_id(room_id: &[u8]) -> Result<CreateCallLinkCredentialRequestContext, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(Self {
            inner: ZkCreateCallLinkCredentialRequestContext::new(room_id, randomness),
        })
    }

    #[wasm_bindgen(js_name = forRoomIdWithRandom)]
    pub fn for_room_id_with_random(
        room_id: &[u8],
        randomness: &[u8],
    ) -> Result<CreateCallLinkCredentialRequestContext, JsError> {
        Ok(Self {
            inner: ZkCreateCallLinkCredentialRequestContext::new(
                room_id,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = getRequest)]
    pub fn get_request(&self) -> CreateCallLinkCredentialRequest {
        CreateCallLinkCredentialRequest {
            inner: self.inner.get_request(),
        }
    }

    pub fn receive(
        &self,
        response: &CreateCallLinkCredentialResponse,
        user_id: &Aci,
        params: &GenericServerPublicParams,
    ) -> Result<CreateCallLinkCredential, JsError> {
        Ok(CreateCallLinkCredential {
            inner: self
                .inner
                .clone()
                .receive(
                    response.inner.clone(),
                    aci_service_id(user_id)?,
                    &params.inner,
                )
                .map_err(js_error)?,
        })
    }
}

#[wasm_bindgen]
pub struct CreateCallLinkCredentialRequest {
    inner: ZkCreateCallLinkCredentialRequest,
}

#[wasm_bindgen]
impl CreateCallLinkCredentialRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CreateCallLinkCredentialRequest, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "create call link credential request")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = issueCredential)]
    pub fn issue_credential(
        &self,
        user_id: &Aci,
        timestamp: f64,
        params: &GenericServerSecretParams,
    ) -> Result<CreateCallLinkCredentialResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.issue_credential_with_random(user_id, timestamp, params, &randomness)
    }

    #[wasm_bindgen(js_name = issueCredentialWithRandom)]
    pub fn issue_credential_with_random(
        &self,
        user_id: &Aci,
        timestamp: f64,
        params: &GenericServerSecretParams,
        randomness: &[u8],
    ) -> Result<CreateCallLinkCredentialResponse, JsError> {
        Ok(CreateCallLinkCredentialResponse {
            inner: self.inner.issue(
                aci_service_id(user_id)?,
                zk_timestamp_from_seconds(timestamp)?,
                &params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }
}

#[wasm_bindgen]
pub struct CreateCallLinkCredentialResponse {
    inner: ZkCreateCallLinkCredentialResponse,
}

#[wasm_bindgen]
impl CreateCallLinkCredentialResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CreateCallLinkCredentialResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "create call link credential response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }
}

#[wasm_bindgen]
pub struct CreateCallLinkCredential {
    inner: ZkCreateCallLinkCredential,
}

#[wasm_bindgen]
impl CreateCallLinkCredential {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CreateCallLinkCredential, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "create call link credential")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn present(
        &self,
        room_id: &[u8],
        user_id: &Aci,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
    ) -> Result<CreateCallLinkCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.present_with_random(
            room_id,
            user_id,
            server_params,
            call_link_params,
            &randomness,
        )
    }

    #[wasm_bindgen(js_name = presentWithRandom)]
    pub fn present_with_random(
        &self,
        room_id: &[u8],
        user_id: &Aci,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: &[u8],
    ) -> Result<CreateCallLinkCredentialPresentation, JsError> {
        Ok(CreateCallLinkCredentialPresentation {
            inner: self.inner.present(
                room_id,
                aci_service_id(user_id)?,
                &server_params.inner,
                &call_link_params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }
}

#[wasm_bindgen]
pub struct CreateCallLinkCredentialPresentation {
    inner: ZkCreateCallLinkCredentialPresentation,
}

#[wasm_bindgen]
impl CreateCallLinkCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CreateCallLinkCredentialPresentation, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "create call link credential presentation")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn verify(
        &self,
        room_id: &[u8],
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        self.inner
            .verify(
                room_id,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &server_params.inner,
                &call_link_params.inner,
            )
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct CallLinkAuthCredentialResponse {
    inner: ZkCallLinkAuthCredentialResponse,
}

#[wasm_bindgen]
impl CallLinkAuthCredentialResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CallLinkAuthCredentialResponse, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "call link auth credential response")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    #[wasm_bindgen(js_name = issueCredential)]
    pub fn issue_credential(
        user_id: &Aci,
        redemption_time: f64,
        params: &GenericServerSecretParams,
    ) -> Result<CallLinkAuthCredentialResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Self::issue_credential_with_random(user_id, redemption_time, params, &randomness)
    }

    #[wasm_bindgen(js_name = issueCredentialWithRandom)]
    pub fn issue_credential_with_random(
        user_id: &Aci,
        redemption_time: f64,
        params: &GenericServerSecretParams,
        randomness: &[u8],
    ) -> Result<CallLinkAuthCredentialResponse, JsError> {
        Ok(Self {
            inner: ZkCallLinkAuthCredentialResponse::issue_credential(
                aci_service_id(user_id)?,
                zk_timestamp_from_seconds(redemption_time)?,
                &params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }

    pub fn receive(
        &self,
        user_id: &Aci,
        redemption_time: f64,
        params: &GenericServerPublicParams,
    ) -> Result<CallLinkAuthCredential, JsError> {
        Ok(CallLinkAuthCredential {
            inner: self
                .inner
                .clone()
                .receive(
                    aci_service_id(user_id)?,
                    zk_timestamp_from_seconds(redemption_time)?,
                    &params.inner,
                )
                .map_err(js_error)?,
        })
    }
}

#[wasm_bindgen]
pub struct CallLinkAuthCredential {
    inner: ZkCallLinkAuthCredential,
}

#[wasm_bindgen]
impl CallLinkAuthCredential {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CallLinkAuthCredential, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "call link auth credential")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn present(
        &self,
        user_id: &Aci,
        redemption_time: f64,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
    ) -> Result<CallLinkAuthCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.present_with_random(
            user_id,
            redemption_time,
            server_params,
            call_link_params,
            &randomness,
        )
    }

    #[wasm_bindgen(js_name = presentWithRandom)]
    pub fn present_with_random(
        &self,
        user_id: &Aci,
        redemption_time: f64,
        server_params: &GenericServerPublicParams,
        call_link_params: &CallLinkSecretParams,
        randomness: &[u8],
    ) -> Result<CallLinkAuthCredentialPresentation, JsError> {
        Ok(CallLinkAuthCredentialPresentation {
            inner: self.inner.present(
                aci_service_id(user_id)?,
                zk_timestamp_from_seconds(redemption_time)?,
                &server_params.inner,
                &call_link_params.inner,
                fixed_array(randomness, "zkgroup randomness")?,
            ),
        })
    }
}

#[wasm_bindgen]
pub struct CallLinkAuthCredentialPresentation {
    inner: ZkCallLinkAuthCredentialPresentation,
}

#[wasm_bindgen]
impl CallLinkAuthCredentialPresentation {
    #[wasm_bindgen(constructor)]
    pub fn new(contents: &[u8]) -> Result<CallLinkAuthCredentialPresentation, JsError> {
        Ok(Self {
            inner: zkgroup_deserialize(contents, "call link auth credential presentation")?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        zkgroup::serialize(&self.inner)
    }

    #[wasm_bindgen(js_name = getContents)]
    pub fn get_contents(&self) -> Vec<u8> {
        self.serialize()
    }

    pub fn verify(
        &self,
        server_params: &GenericServerSecretParams,
        call_link_params: &CallLinkPublicParams,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        self.inner
            .verify(
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
                &server_params.inner,
                &call_link_params.inner,
            )
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = getUserId)]
    pub fn get_user_id(&self) -> UuidCiphertext {
        UuidCiphertext {
            inner: self.inner.get_user_id(),
        }
    }
}

#[wasm_bindgen]
pub struct ClientZkProfileOperations {
    server_public_params: ZkServerPublicParams,
}

#[wasm_bindgen]
impl ClientZkProfileOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_public_params: &ServerPublicParams) -> ClientZkProfileOperations {
        Self {
            server_public_params: server_public_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = createProfileKeyCredentialRequestContext)]
    pub fn create_profile_key_credential_request_context(
        &self,
        user_id: &Aci,
        profile_key: &ProfileKey,
    ) -> Result<ProfileKeyCredentialRequestContext, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.create_profile_key_credential_request_context_with_random(
            &randomness,
            user_id,
            profile_key,
        )
    }

    #[wasm_bindgen(js_name = createProfileKeyCredentialRequestContextWithRandom)]
    pub fn create_profile_key_credential_request_context_with_random(
        &self,
        randomness: &[u8],
        user_id: &Aci,
        profile_key: &ProfileKey,
    ) -> Result<ProfileKeyCredentialRequestContext, JsError> {
        Ok(ProfileKeyCredentialRequestContext {
            inner: self
                .server_public_params
                .create_profile_key_credential_request_context(
                    fixed_array(randomness, "zkgroup randomness")?,
                    aci_service_id(user_id)?,
                    ZkProfileKey::create(profile_key.bytes),
                ),
        })
    }

    #[wasm_bindgen(js_name = receiveExpiringProfileKeyCredential)]
    pub fn receive_expiring_profile_key_credential(
        &self,
        profile_key_credential_request_context: &ProfileKeyCredentialRequestContext,
        profile_key_credential_response: &ExpiringProfileKeyCredentialResponse,
        now_seconds: Option<f64>,
    ) -> Result<ExpiringProfileKeyCredential, JsError> {
        Ok(ExpiringProfileKeyCredential {
            inner: self
                .server_public_params
                .receive_expiring_profile_key_credential(
                    &profile_key_credential_request_context.inner,
                    &profile_key_credential_response.inner,
                    now_seconds
                        .map(zk_timestamp_from_seconds)
                        .transpose()?
                        .unwrap_or_else(current_zk_timestamp),
                )
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = createExpiringProfileKeyCredentialPresentation)]
    pub fn create_expiring_profile_key_credential_presentation(
        &self,
        group_secret_params: &GroupSecretParams,
        profile_key_credential: &ExpiringProfileKeyCredential,
    ) -> Result<ProfileKeyCredentialPresentation, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.create_expiring_profile_key_credential_presentation_with_random(
            &randomness,
            group_secret_params,
            profile_key_credential,
        )
    }

    #[wasm_bindgen(js_name = createExpiringProfileKeyCredentialPresentationWithRandom)]
    pub fn create_expiring_profile_key_credential_presentation_with_random(
        &self,
        randomness: &[u8],
        group_secret_params: &GroupSecretParams,
        profile_key_credential: &ExpiringProfileKeyCredential,
    ) -> Result<ProfileKeyCredentialPresentation, JsError> {
        let presentation: ZkExpiringProfileKeyCredentialPresentationV2 = self
            .server_public_params
            .create_expiring_profile_key_credential_presentation(
                fixed_array(randomness, "zkgroup randomness")?,
                group_secret_params.inner,
                profile_key_credential.inner,
            );
        Ok(ProfileKeyCredentialPresentation {
            bytes: zkgroup::serialize(&presentation),
        })
    }
}

#[wasm_bindgen]
pub struct ServerZkProfileOperations {
    server_secret_params: ZkServerSecretParams,
}

#[wasm_bindgen]
impl ServerZkProfileOperations {
    #[wasm_bindgen(constructor)]
    pub fn new(server_secret_params: &ServerSecretParams) -> ServerZkProfileOperations {
        Self {
            server_secret_params: server_secret_params.inner.clone(),
        }
    }

    #[wasm_bindgen(js_name = issueExpiringProfileKeyCredential)]
    pub fn issue_expiring_profile_key_credential(
        &self,
        profile_key_credential_request: &ProfileKeyCredentialRequest,
        user_id: &Aci,
        profile_key_commitment: &ProfileKeyCommitment,
        expiration_in_seconds: f64,
    ) -> Result<ExpiringProfileKeyCredentialResponse, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        self.issue_expiring_profile_key_credential_with_random(
            &randomness,
            profile_key_credential_request,
            user_id,
            profile_key_commitment,
            expiration_in_seconds,
        )
    }

    #[wasm_bindgen(js_name = issueExpiringProfileKeyCredentialWithRandom)]
    pub fn issue_expiring_profile_key_credential_with_random(
        &self,
        randomness: &[u8],
        profile_key_credential_request: &ProfileKeyCredentialRequest,
        user_id: &Aci,
        profile_key_commitment: &ProfileKeyCommitment,
        expiration_in_seconds: f64,
    ) -> Result<ExpiringProfileKeyCredentialResponse, JsError> {
        Ok(ExpiringProfileKeyCredentialResponse {
            inner: self
                .server_secret_params
                .issue_expiring_profile_key_credential(
                    fixed_array(randomness, "zkgroup randomness")?,
                    &profile_key_credential_request.inner,
                    aci_service_id(user_id)?,
                    profile_key_commitment.inner.clone(),
                    zk_timestamp_from_seconds(expiration_in_seconds)?,
                )
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = verifyProfileKeyCredentialPresentation)]
    pub fn verify_profile_key_credential_presentation(
        &self,
        group_public_params: &GroupPublicParams,
        profile_key_credential_presentation: &ProfileKeyCredentialPresentation,
        now_seconds: Option<f64>,
    ) -> Result<(), JsError> {
        let presentation =
            ZkAnyProfileKeyCredentialPresentation::new(&profile_key_credential_presentation.bytes)
                .map_err(|_| JsError::new("invalid profile key credential presentation"))?;
        self.server_secret_params
            .verify_profile_key_credential_presentation(
                group_public_params.inner,
                &presentation,
                now_seconds
                    .map(zk_timestamp_from_seconds)
                    .transpose()?
                    .unwrap_or_else(current_zk_timestamp),
            )
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct ClientZkGroupCipher {
    group_secret_params: ZkGroupSecretParams,
}

#[wasm_bindgen]
impl ClientZkGroupCipher {
    #[wasm_bindgen(constructor)]
    pub fn new(group_secret_params: &GroupSecretParams) -> ClientZkGroupCipher {
        Self {
            group_secret_params: group_secret_params.inner,
        }
    }

    #[wasm_bindgen(js_name = encryptServiceId)]
    pub fn encrypt_service_id(&self, service_id: JsValue) -> Result<UuidCiphertext, JsError> {
        Ok(UuidCiphertext {
            inner: self
                .group_secret_params
                .encrypt_service_id(service_id_from_js(&service_id)?),
        })
    }

    #[wasm_bindgen(js_name = decryptServiceId)]
    pub fn decrypt_service_id(&self, ciphertext: &UuidCiphertext) -> Result<ServiceId, JsError> {
        Ok(ServiceId {
            inner: self
                .group_secret_params
                .decrypt_service_id(ciphertext.inner)
                .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = encryptProfileKey)]
    pub fn encrypt_profile_key(
        &self,
        profile_key: &ProfileKey,
        user_id: &Aci,
    ) -> Result<ProfileKeyCiphertext, JsError> {
        Ok(ProfileKeyCiphertext {
            inner: self.group_secret_params.encrypt_profile_key(
                ZkProfileKey::create(profile_key.bytes),
                aci_service_id(user_id)?,
            ),
        })
    }

    #[wasm_bindgen(js_name = decryptProfileKey)]
    pub fn decrypt_profile_key(
        &self,
        profile_key_ciphertext: &ProfileKeyCiphertext,
        user_id: &Aci,
    ) -> Result<ProfileKey, JsError> {
        Ok(ProfileKey {
            bytes: self
                .group_secret_params
                .decrypt_profile_key(profile_key_ciphertext.inner, aci_service_id(user_id)?)
                .map_err(js_error)?
                .get_bytes(),
        })
    }

    #[wasm_bindgen(js_name = encryptBlob)]
    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut randomness = [0; RANDOMNESS_LEN];
        getrandom::fill(&mut randomness).map_err(js_error)?;
        Ok(self
            .group_secret_params
            .encrypt_blob_with_padding(randomness, plaintext, 0))
    }

    #[wasm_bindgen(js_name = encryptBlobWithRandom)]
    pub fn encrypt_blob_with_random(
        &self,
        randomness: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.group_secret_params.encrypt_blob_with_padding(
            fixed_array(randomness, "zkgroup randomness")?,
            plaintext,
            0,
        ))
    }

    #[wasm_bindgen(js_name = encryptBlobWithPadding)]
    pub fn encrypt_blob_with_padding(
        &self,
        randomness: &[u8],
        plaintext: &[u8],
        padding_len: u32,
    ) -> Result<Vec<u8>, JsError> {
        Ok(self.group_secret_params.encrypt_blob_with_padding(
            fixed_array(randomness, "zkgroup randomness")?,
            plaintext,
            padding_len,
        ))
    }

    #[wasm_bindgen(js_name = decryptBlob)]
    pub fn decrypt_blob(&self, blob_ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.group_secret_params
            .decrypt_blob_with_padding(blob_ciphertext)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct UsernamePartsResult {
    username: String,
    hash: Vec<u8>,
}

#[wasm_bindgen]
impl UsernamePartsResult {
    #[wasm_bindgen(getter)]
    pub fn username(&self) -> String {
        self.username.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

#[wasm_bindgen]
pub struct UsernameLink {
    entropy: Vec<u8>,
    encrypted_username: Vec<u8>,
}

#[wasm_bindgen]
impl UsernameLink {
    #[wasm_bindgen(getter)]
    pub fn entropy(&self) -> Vec<u8> {
        self.entropy.clone()
    }

    #[wasm_bindgen(getter, js_name = encryptedUsername)]
    pub fn encrypted_username(&self) -> Vec<u8> {
        self.encrypted_username.clone()
    }
}

#[wasm_bindgen(js_name = usernameGenerateCandidates)]
pub fn username_generate_candidates(
    nickname: &str,
    min_nickname_length: u32,
    max_nickname_length: u32,
) -> Result<js_sys::Array, JsError> {
    let mut csprng = browser_csprng()?;
    let candidates = Username::candidates_from(
        &mut csprng,
        nickname,
        username_limits(min_nickname_length, max_nickname_length)?,
    )
    .map_err(js_error)?;
    let output = js_sys::Array::new();
    for candidate in candidates {
        output.push(&JsValue::from_str(&candidate));
    }
    Ok(output)
}

#[wasm_bindgen(js_name = usernameFromParts)]
pub fn username_from_parts(
    nickname: &str,
    discriminator: &str,
    min_nickname_length: u32,
    max_nickname_length: u32,
) -> Result<UsernamePartsResult, JsError> {
    let username = Username::from_parts(
        nickname,
        discriminator,
        username_limits(min_nickname_length, max_nickname_length)?,
    )
    .map_err(js_error)?;
    Ok(UsernamePartsResult {
        username: format!("{nickname}.{discriminator}"),
        hash: username.hash().to_vec(),
    })
}

#[wasm_bindgen(js_name = usernameHash)]
pub fn username_hash(username: &str) -> Result<Vec<u8>, JsError> {
    Ok(Username::new(username).map_err(js_error)?.hash().to_vec())
}

#[wasm_bindgen(js_name = usernameGenerateProof)]
pub fn username_generate_proof(username: &str) -> Result<Vec<u8>, JsError> {
    let mut randomness = [0; 32];
    getrandom::fill(&mut randomness).map_err(js_error)?;
    username_generate_proof_with_random(username, &randomness)
}

#[wasm_bindgen(js_name = usernameGenerateProofWithRandom)]
pub fn username_generate_proof_with_random(
    username: &str,
    randomness: &[u8],
) -> Result<Vec<u8>, JsError> {
    let randomness: [u8; 32] = randomness
        .try_into()
        .map_err(|_| JsError::new("username proof randomness must be 32 bytes"))?;
    Username::new(username)
        .map_err(js_error)?
        .proof(&randomness)
        .map_err(js_error)
}

#[wasm_bindgen(js_name = usernameVerifyProof)]
pub fn username_verify_proof(proof: &[u8], hash: &[u8]) -> Result<(), JsError> {
    let hash: [u8; 32] = hash
        .try_into()
        .map_err(|_| JsError::new("username hash must be 32 bytes"))?;
    Username::verify_proof(proof, hash).map_err(js_error)
}

#[wasm_bindgen(js_name = usernameCreateLink)]
pub fn username_create_link(
    username: &str,
    previous_entropy: Option<Vec<u8>>,
) -> Result<UsernameLink, JsError> {
    let mut csprng = browser_csprng()?;
    let entropy = previous_entropy
        .as_deref()
        .map(|entropy| {
            entropy
                .try_into()
                .map_err(|_| JsError::new("username link entropy must be 32 bytes"))
        })
        .transpose()?;
    let (entropy, encrypted_username) =
        usernames::create_for_username(&mut csprng, username.to_string(), entropy)
            .map_err(js_error)?;
    Ok(UsernameLink {
        entropy: entropy.to_vec(),
        encrypted_username,
    })
}

#[wasm_bindgen(js_name = usernameDecryptLink)]
pub fn username_decrypt_link(entropy: &[u8], encrypted_username: &[u8]) -> Result<String, JsError> {
    let entropy: [u8; 32] = entropy
        .try_into()
        .map_err(|_| JsError::new("username link entropy must be 32 bytes"))?;
    usernames::decrypt_username(&entropy, encrypted_username).map_err(js_error)
}

#[wasm_bindgen]
pub struct ServiceId {
    inner: LibSignalServiceId,
}

#[wasm_bindgen]
impl ServiceId {
    #[wasm_bindgen(constructor)]
    pub fn new(service_id_fixed_width_binary: &[u8]) -> Result<ServiceId, JsError> {
        Ok(Self {
            inner: service_id_from_fixed_width_binary(service_id_fixed_width_binary)?,
        })
    }

    #[wasm_bindgen(js_name = parseFromServiceIdFixedWidthBinary)]
    pub fn parse_from_service_id_fixed_width_binary(
        service_id_fixed_width_binary: &[u8],
    ) -> Result<ServiceId, JsError> {
        Self::new(service_id_fixed_width_binary)
    }

    #[wasm_bindgen(js_name = parseFromServiceIdBinary)]
    pub fn parse_from_service_id_binary(service_id_binary: &[u8]) -> Result<ServiceId, JsError> {
        Ok(Self {
            inner: LibSignalServiceId::parse_from_service_id_binary(service_id_binary)
                .ok_or_else(|| JsError::new("invalid Service-Id-Binary"))?,
        })
    }

    #[wasm_bindgen(js_name = parseFromServiceIdString)]
    pub fn parse_from_service_id_string(service_id_string: &str) -> Result<ServiceId, JsError> {
        Ok(Self {
            inner: LibSignalServiceId::parse_from_service_id_string(service_id_string)
                .ok_or_else(|| JsError::new("invalid Service-Id string"))?,
        })
    }

    #[wasm_bindgen(js_name = getServiceIdBinary)]
    pub fn get_service_id_binary(&self) -> Vec<u8> {
        self.inner.service_id_binary()
    }

    #[wasm_bindgen(js_name = getServiceIdFixedWidthBinary)]
    pub fn get_service_id_fixed_width_binary(&self) -> Vec<u8> {
        self.inner.service_id_fixed_width_binary().to_vec()
    }

    #[wasm_bindgen(js_name = getServiceIdString)]
    pub fn get_service_id_string(&self) -> String {
        self.inner.service_id_string()
    }

    #[wasm_bindgen(js_name = getRawUuid)]
    pub fn get_raw_uuid(&self) -> String {
        self.inner.raw_uuid().to_string()
    }

    #[wasm_bindgen(js_name = getRawUuidBytes)]
    pub fn get_raw_uuid_bytes(&self) -> Vec<u8> {
        self.inner.raw_uuid().as_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = isEqual)]
    pub fn is_equal(&self, other: &ServiceId) -> bool {
        self.inner == other.inner
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        format!("{:?}", self.inner)
    }
}

#[wasm_bindgen]
pub struct Aci {
    inner: LibSignalServiceId,
}

#[wasm_bindgen]
impl Aci {
    #[wasm_bindgen(js_name = fromUuid)]
    pub fn from_uuid(uuid_string: &str) -> Result<Aci, JsError> {
        let service_id = LibSignalServiceId::parse_from_service_id_string(uuid_string)
            .ok_or_else(|| JsError::new("invalid ACI UUID"))?;
        if !matches!(service_id, LibSignalServiceId::Aci(_)) {
            return Err(JsError::new("expected ACI"));
        }
        Ok(Self { inner: service_id })
    }

    #[wasm_bindgen(js_name = fromUuidBytes)]
    pub fn from_uuid_bytes(uuid_bytes: &[u8]) -> Result<Aci, JsError> {
        Ok(Self {
            inner: LibSignalServiceId::from(aci_from_uuid_bytes(uuid_bytes)?),
        })
    }

    #[wasm_bindgen(js_name = parseFromServiceIdFixedWidthBinary)]
    pub fn parse_from_service_id_fixed_width_binary(
        service_id_fixed_width_binary: &[u8],
    ) -> Result<Aci, JsError> {
        let service_id = service_id_from_fixed_width_binary(service_id_fixed_width_binary)?;
        if !matches!(service_id, LibSignalServiceId::Aci(_)) {
            return Err(JsError::new("expected ACI"));
        }
        Ok(Self { inner: service_id })
    }

    #[wasm_bindgen(js_name = getServiceIdBinary)]
    pub fn get_service_id_binary(&self) -> Vec<u8> {
        self.inner.service_id_binary()
    }

    #[wasm_bindgen(js_name = getServiceIdFixedWidthBinary)]
    pub fn get_service_id_fixed_width_binary(&self) -> Vec<u8> {
        self.inner.service_id_fixed_width_binary().to_vec()
    }

    #[wasm_bindgen(js_name = getServiceIdString)]
    pub fn get_service_id_string(&self) -> String {
        self.inner.service_id_string()
    }

    #[wasm_bindgen(js_name = getRawUuid)]
    pub fn get_raw_uuid(&self) -> String {
        self.inner.raw_uuid().to_string()
    }
}

#[wasm_bindgen]
pub struct Pni {
    inner: LibSignalServiceId,
}

#[wasm_bindgen]
impl Pni {
    #[wasm_bindgen(js_name = fromUuid)]
    pub fn from_uuid(uuid_string: &str) -> Result<Pni, JsError> {
        let service_id =
            LibSignalServiceId::parse_from_service_id_string(&format!("PNI:{uuid_string}"))
                .ok_or_else(|| JsError::new("invalid PNI UUID"))?;
        Ok(Self { inner: service_id })
    }

    #[wasm_bindgen(js_name = fromUuidBytes)]
    pub fn from_uuid_bytes(uuid_bytes: &[u8]) -> Result<Pni, JsError> {
        let mut fixed_width = vec![1];
        fixed_width.extend_from_slice(uuid_bytes);
        let service_id = service_id_from_fixed_width_binary(&fixed_width)?;
        Ok(Self { inner: service_id })
    }

    #[wasm_bindgen(js_name = parseFromServiceIdFixedWidthBinary)]
    pub fn parse_from_service_id_fixed_width_binary(
        service_id_fixed_width_binary: &[u8],
    ) -> Result<Pni, JsError> {
        let service_id = service_id_from_fixed_width_binary(service_id_fixed_width_binary)?;
        if !matches!(service_id, LibSignalServiceId::Pni(_)) {
            return Err(JsError::new("expected PNI"));
        }
        Ok(Self { inner: service_id })
    }

    #[wasm_bindgen(js_name = getServiceIdBinary)]
    pub fn get_service_id_binary(&self) -> Vec<u8> {
        self.inner.service_id_binary()
    }

    #[wasm_bindgen(js_name = getServiceIdFixedWidthBinary)]
    pub fn get_service_id_fixed_width_binary(&self) -> Vec<u8> {
        self.inner.service_id_fixed_width_binary().to_vec()
    }

    #[wasm_bindgen(js_name = getServiceIdString)]
    pub fn get_service_id_string(&self) -> String {
        self.inner.service_id_string()
    }

    #[wasm_bindgen(js_name = getRawUuid)]
    pub fn get_raw_uuid(&self) -> String {
        self.inner.raw_uuid().to_string()
    }
}

#[wasm_bindgen]
pub struct ProtocolAddress {
    inner: LibSignalProtocolAddress,
}

#[wasm_bindgen]
impl ProtocolAddress {
    pub fn new(name: &str, device_id: u32) -> Result<ProtocolAddress, JsError> {
        let device_id = DeviceId::try_from(device_id).map_err(js_error)?;
        Ok(Self {
            inner: LibSignalProtocolAddress::new(name.to_owned(), device_id),
        })
    }

    #[wasm_bindgen(js_name = newFromServiceId)]
    pub fn new_from_service_id(
        service_id: &ServiceId,
        device_id: u32,
    ) -> Result<ProtocolAddress, JsError> {
        Self::new(&service_id.inner.service_id_string(), device_id)
    }

    #[wasm_bindgen(js_name = newFromAci)]
    pub fn new_from_aci(aci: &Aci, device_id: u32) -> Result<ProtocolAddress, JsError> {
        Self::new(&aci.inner.service_id_string(), device_id)
    }

    #[wasm_bindgen(js_name = newFromPni)]
    pub fn new_from_pni(pni: &Pni, device_id: u32) -> Result<ProtocolAddress, JsError> {
        Self::new(&pni.inner.service_id_string(), device_id)
    }

    pub fn name(&self) -> String {
        self.inner.name().to_owned()
    }

    #[wasm_bindgen(js_name = serviceId)]
    pub fn service_id(&self) -> Option<ServiceId> {
        LibSignalServiceId::parse_from_service_id_string(self.inner.name())
            .map(|inner| ServiceId { inner })
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> u32 {
        self.inner.device_id().into()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        self.inner.to_string()
    }
}

#[wasm_bindgen]
pub struct PublicKey {
    inner: LibSignalPublicKey,
}

#[wasm_bindgen]
impl PublicKey {
    pub fn deserialize(buf: &[u8]) -> Result<PublicKey, JsError> {
        Ok(Self {
            inner: public_key_from_serialized(buf)?,
        })
    }

    pub fn equals(&self, other: &PublicKey) -> bool {
        self.inner == other.inner
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().into_vec()
    }

    #[wasm_bindgen(js_name = getPublicKeyBytes)]
    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.inner.verify_signature(msg, sig)
    }

    #[wasm_bindgen(js_name = verifyAlternateIdentity)]
    pub fn verify_alternate_identity(
        &self,
        other: &PublicKey,
        signature: &[u8],
    ) -> Result<bool, JsError> {
        let trusted = LibSignalIdentityKey::new(self.inner);
        let alternate = LibSignalIdentityKey::new(other.inner);
        trusted
            .verify_alternate_identity(&alternate, signature)
            .map_err(js_error)
    }

    pub fn seal(
        &self,
        msg: &[u8],
        info: &[u8],
        associated_data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsError> {
        let associated_data = associated_data.unwrap_or_default();
        self.inner
            .seal(info, &associated_data, msg)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct PrivateKey {
    inner: LibSignalPrivateKey,
}

#[wasm_bindgen]
impl PrivateKey {
    pub fn generate() -> Result<PrivateKey, JsError> {
        let mut csprng = browser_csprng()?;
        let key_pair = LibSignalKeyPair::generate(&mut csprng);
        Ok(Self {
            inner: key_pair.private_key,
        })
    }

    pub fn deserialize(buf: &[u8]) -> Result<PrivateKey, JsError> {
        Ok(Self {
            inner: private_key_from_serialized(buf)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut csprng = browser_csprng()?;
        self.inner
            .calculate_signature(msg, &mut csprng)
            .map(|signature| signature.into_vec())
            .map_err(js_error)
    }

    pub fn agree(&self, other_key: &PublicKey) -> Result<Vec<u8>, JsError> {
        self.inner
            .calculate_agreement(&other_key.inner)
            .map(|shared_secret| shared_secret.into_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    pub fn open(
        &self,
        ciphertext: &[u8],
        info: &[u8],
        associated_data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, JsError> {
        let associated_data = associated_data.unwrap_or_default();
        self.inner
            .open(info, &associated_data, ciphertext)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct IdentityKeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

#[wasm_bindgen]
pub struct PreKeyRecord {
    inner: LibSignalPreKeyRecord,
}

#[wasm_bindgen]
impl PreKeyRecord {
    pub fn new(id: u32, pub_key: &PublicKey, priv_key: &PrivateKey) -> PreKeyRecord {
        let key_pair = LibSignalKeyPair::new(pub_key.inner, priv_key.inner);
        Self {
            inner: LibSignalPreKeyRecord::new(id.into(), &key_pair),
        }
    }

    pub fn deserialize(buffer: &[u8]) -> Result<PreKeyRecord, JsError> {
        Ok(Self {
            inner: LibSignalPreKeyRecord::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn id(&self) -> Result<u32, JsError> {
        self.inner.id().map(Into::into).map_err(js_error)
    }

    #[wasm_bindgen(js_name = privateKey)]
    pub fn private_key(&self) -> Result<PrivateKey, JsError> {
        Ok(PrivateKey {
            inner: self.inner.private_key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.serialize().map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SignedPreKeyRecord {
    inner: LibSignalSignedPreKeyRecord,
}

#[wasm_bindgen]
impl SignedPreKeyRecord {
    pub fn new(
        id: u32,
        timestamp: f64,
        pub_key: &PublicKey,
        priv_key: &PrivateKey,
        signature: &[u8],
    ) -> Result<SignedPreKeyRecord, JsError> {
        let timestamp = timestamp_from_js_millis(timestamp)?;
        let key_pair = LibSignalKeyPair::new(pub_key.inner, priv_key.inner);
        Ok(Self {
            inner: LibSignalSignedPreKeyRecord::new(id.into(), timestamp, &key_pair, signature),
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<SignedPreKeyRecord, JsError> {
        Ok(Self {
            inner: LibSignalSignedPreKeyRecord::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn id(&self) -> Result<u32, JsError> {
        self.inner.id().map(Into::into).map_err(js_error)
    }

    #[wasm_bindgen(js_name = privateKey)]
    pub fn private_key(&self) -> Result<PrivateKey, JsError> {
        Ok(PrivateKey {
            inner: self.inner.private_key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.serialize().map_err(js_error)
    }

    pub fn signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner.signature().map_err(js_error)
    }

    pub fn timestamp(&self) -> Result<f64, JsError> {
        self.inner
            .timestamp()
            .map(|timestamp| timestamp.epoch_millis() as f64)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SessionRecord {
    inner: LibSignalSessionRecord,
}

#[wasm_bindgen]
pub struct KEMPublicKey {
    inner: libsignal_kem::PublicKey,
}

#[wasm_bindgen]
impl KEMPublicKey {
    pub fn deserialize(buf: &[u8]) -> Result<KEMPublicKey, JsError> {
        Ok(Self {
            inner: libsignal_kem::PublicKey::deserialize(buf).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().into_vec()
    }
}

#[wasm_bindgen]
pub struct KEMSecretKey {
    inner: libsignal_kem::SecretKey,
}

#[wasm_bindgen]
impl KEMSecretKey {
    pub fn deserialize(buf: &[u8]) -> Result<KEMSecretKey, JsError> {
        Ok(Self {
            inner: libsignal_kem::SecretKey::deserialize(buf).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().into_vec()
    }
}

#[wasm_bindgen]
pub struct KEMKeyPair {
    inner: libsignal_kem::KeyPair,
}

#[wasm_bindgen]
impl KEMKeyPair {
    pub fn generate() -> Result<KEMKeyPair, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(Self {
            inner: libsignal_kem::KeyPair::generate(libsignal_kem::KeyType::Kyber1024, &mut csprng),
        })
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> KEMPublicKey {
        KEMPublicKey {
            inner: self.inner.public_key.clone(),
        }
    }

    #[wasm_bindgen(js_name = getSecretKey)]
    pub fn get_secret_key(&self) -> KEMSecretKey {
        KEMSecretKey {
            inner: self.inner.secret_key.clone(),
        }
    }
}

#[wasm_bindgen]
pub struct KyberPreKeyRecord {
    inner: LibSignalKyberPreKeyRecord,
}

#[wasm_bindgen]
impl KyberPreKeyRecord {
    pub fn new(
        id: u32,
        timestamp: f64,
        key_pair: &KEMKeyPair,
        signature: &[u8],
    ) -> Result<KyberPreKeyRecord, JsError> {
        Ok(Self {
            inner: LibSignalKyberPreKeyRecord::new(
                id.into(),
                timestamp_from_js_millis(timestamp)?,
                &key_pair.inner,
                signature,
            ),
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<KyberPreKeyRecord, JsError> {
        Ok(Self {
            inner: LibSignalKyberPreKeyRecord::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.serialize().map_err(js_error)
    }

    pub fn id(&self) -> Result<u32, JsError> {
        self.inner.id().map(Into::into).map_err(js_error)
    }

    #[wasm_bindgen(js_name = keyPair)]
    pub fn key_pair(&self) -> Result<KEMKeyPair, JsError> {
        Ok(KEMKeyPair {
            inner: self.inner.key_pair().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<KEMPublicKey, JsError> {
        Ok(KEMPublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = secretKey)]
    pub fn secret_key(&self) -> Result<KEMSecretKey, JsError> {
        Ok(KEMSecretKey {
            inner: self.inner.secret_key().map_err(js_error)?,
        })
    }

    pub fn signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner.signature().map_err(js_error)
    }

    pub fn timestamp(&self) -> Result<f64, JsError> {
        self.inner
            .timestamp()
            .map(|timestamp| timestamp.epoch_millis() as f64)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct PreKeyBundle {
    inner: LibSignalPreKeyBundle,
}

#[wasm_bindgen]
pub struct CiphertextMessage {
    inner: LibSignalCiphertextMessage,
}

#[wasm_bindgen]
impl CiphertextMessage {
    pub fn deserialize(message_type: u8, buffer: &[u8]) -> Result<CiphertextMessage, JsError> {
        let inner = match message_type {
            2 => LibSignalCiphertextMessage::SignalMessage(
                LibSignalSignalMessage::try_from(buffer).map_err(js_error)?,
            ),
            3 => LibSignalCiphertextMessage::PreKeySignalMessage(
                libsignal_protocol::PreKeySignalMessage::try_from(buffer).map_err(js_error)?,
            ),
            7 => LibSignalCiphertextMessage::SenderKeyMessage(
                LibSignalSenderKeyMessage::try_from(buffer).map_err(js_error)?,
            ),
            _ => {
                return Err(JsError::new(
                    "unsupported ciphertext message type for browser decrypt",
                ));
            }
        };
        Ok(Self { inner })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = type)]
    pub fn message_type(&self) -> u8 {
        self.inner.message_type() as u8
    }
}

#[wasm_bindgen]
pub struct SenderKeyRecord {
    inner: LibSignalSenderKeyRecord,
}

#[wasm_bindgen]
impl SenderKeyRecord {
    pub fn deserialize(buffer: &[u8]) -> Result<SenderKeyRecord, JsError> {
        Ok(Self {
            inner: LibSignalSenderKeyRecord::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.serialize().map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SenderKeyDistributionMessage {
    inner: LibSignalSenderKeyDistributionMessage,
}

#[wasm_bindgen]
impl SenderKeyDistributionMessage {
    pub fn create(
        sender: &ProtocolAddress,
        distribution_id: &str,
        store: &mut SignalProtocolStore,
    ) -> Result<SenderKeyDistributionMessage, JsError> {
        let mut csprng = browser_csprng()?;
        let inner = block_on(create_sender_key_distribution_message(
            &sender.inner,
            uuid_from_string(distribution_id)?,
            &mut store.inner.sender_key_store,
            &mut csprng,
        ))
        .map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = _new)]
    pub fn new_for_testing(
        message_version: u8,
        distribution_id: &str,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        public_key: &PublicKey,
    ) -> Result<SenderKeyDistributionMessage, JsError> {
        Ok(Self {
            inner: LibSignalSenderKeyDistributionMessage::new(
                message_version,
                uuid_from_string(distribution_id)?,
                chain_id,
                iteration,
                chain_key.to_vec(),
                public_key.inner,
            )
            .map_err(js_error)?,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<SenderKeyDistributionMessage, JsError> {
        Ok(Self {
            inner: LibSignalSenderKeyDistributionMessage::try_from(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialized().to_vec()
    }

    #[wasm_bindgen(js_name = chainKey)]
    pub fn chain_key(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .chain_key()
            .map(|chain_key| chain_key.to_vec())
            .map_err(js_error)
    }

    pub fn iteration(&self) -> Result<u32, JsError> {
        self.inner.iteration().map_err(js_error)
    }

    #[wasm_bindgen(js_name = chainId)]
    pub fn chain_id(&self) -> Result<u32, JsError> {
        self.inner.chain_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = distributionId)]
    pub fn distribution_id(&self) -> Result<String, JsError> {
        self.inner
            .distribution_id()
            .map(|id| id.to_string())
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SenderKeyMessage {
    inner: LibSignalSenderKeyMessage,
}

#[wasm_bindgen]
impl SenderKeyMessage {
    #[wasm_bindgen(js_name = _new)]
    pub fn new_for_testing(
        message_version: u8,
        distribution_id: &str,
        chain_id: u32,
        iteration: u32,
        ciphertext: &[u8],
        private_key: &PrivateKey,
    ) -> Result<SenderKeyMessage, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(Self {
            inner: LibSignalSenderKeyMessage::new(
                message_version,
                uuid_from_string(distribution_id)?,
                chain_id,
                iteration,
                Box::from(ciphertext),
                &mut csprng,
                &private_key.inner,
            )
            .map_err(js_error)?,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<SenderKeyMessage, JsError> {
        Ok(Self {
            inner: LibSignalSenderKeyMessage::try_from(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialized().to_vec()
    }

    pub fn ciphertext(&self) -> Vec<u8> {
        self.inner.ciphertext().to_vec()
    }

    pub fn iteration(&self) -> u32 {
        self.inner.iteration()
    }

    #[wasm_bindgen(js_name = chainId)]
    pub fn chain_id(&self) -> u32 {
        self.inner.chain_id()
    }

    #[wasm_bindgen(js_name = distributionId)]
    pub fn distribution_id(&self) -> String {
        self.inner.distribution_id().to_string()
    }

    #[wasm_bindgen(js_name = verifySignature)]
    pub fn verify_signature(&self, key: &PublicKey) -> Result<bool, JsError> {
        self.inner.verify_signature(&key.inner).map_err(js_error)
    }
}

#[wasm_bindgen]
pub enum ContentHint {
    Default = 0,
    Resendable = 1,
    Implicit = 2,
}

#[wasm_bindgen]
pub struct ServerCertificate {
    inner: LibSignalServerCertificate,
}

#[wasm_bindgen]
impl ServerCertificate {
    pub fn new(
        key_id: u32,
        server_key: &PublicKey,
        trust_root: &PrivateKey,
    ) -> Result<ServerCertificate, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(Self {
            inner: LibSignalServerCertificate::new(
                key_id,
                server_key.inner,
                &trust_root.inner,
                &mut csprng,
            )
            .map_err(js_error)?,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<ServerCertificate, JsError> {
        Ok(Self {
            inner: LibSignalServerCertificate::deserialize(buffer).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = certificateData)]
    pub fn certificate_data(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .certificate()
            .map(|certificate| certificate.to_vec())
            .map_err(js_error)
    }

    pub fn key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.public_key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> Result<u32, JsError> {
        self.inner.key_id().map_err(js_error)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .serialized()
            .map(|serialized| serialized.to_vec())
            .map_err(js_error)
    }

    pub fn signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .signature()
            .map(|signature| signature.to_vec())
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SenderCertificate {
    inner: LibSignalSenderCertificate,
}

#[wasm_bindgen]
impl SenderCertificate {
    pub fn new(
        sender_uuid: &str,
        sender_e164: Option<String>,
        sender_device_id: u32,
        sender_key: &PublicKey,
        expiration: f64,
        signer_cert: &ServerCertificate,
        signer_key: &PrivateKey,
    ) -> Result<SenderCertificate, JsError> {
        let mut csprng = browser_csprng()?;
        Ok(Self {
            inner: LibSignalSenderCertificate::new(
                sender_uuid.to_string(),
                sender_e164,
                sender_key.inner,
                DeviceId::try_from(sender_device_id).map_err(js_error)?,
                timestamp_from_js_millis(expiration)?,
                signer_cert.inner.clone(),
                &signer_key.inner,
                &mut csprng,
            )
            .map_err(js_error)?,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<SenderCertificate, JsError> {
        Ok(Self {
            inner: LibSignalSenderCertificate::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .serialized()
            .map(|serialized| serialized.to_vec())
            .map_err(js_error)
    }

    pub fn certificate(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .certificate()
            .map(|certificate| certificate.to_vec())
            .map_err(js_error)
    }

    pub fn expiration(&self) -> Result<f64, JsError> {
        self.inner
            .expiration()
            .map(|expiration| expiration.epoch_millis() as f64)
            .map_err(js_error)
    }

    pub fn key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.key().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = senderE164)]
    pub fn sender_e164(&self) -> Result<Option<String>, JsError> {
        self.inner
            .sender_e164()
            .map(|sender| sender.map(ToOwned::to_owned))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderUuid)]
    pub fn sender_uuid(&self) -> Result<String, JsError> {
        self.inner
            .sender_uuid()
            .map(ToOwned::to_owned)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderAci)]
    pub fn sender_aci(&self) -> Result<Option<Aci>, JsError> {
        let Some(service_id) = LibSignalServiceId::parse_from_service_id_string(
            self.inner.sender_uuid().map_err(js_error)?,
        ) else {
            return Ok(None);
        };
        Ok(matches!(service_id, LibSignalServiceId::Aci(_)).then_some(Aci { inner: service_id }))
    }

    #[wasm_bindgen(js_name = senderDeviceId)]
    pub fn sender_device_id(&self) -> Result<u32, JsError> {
        self.inner
            .sender_device_id()
            .map(Into::into)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = serverCertificate)]
    pub fn server_certificate(&self) -> Result<ServerCertificate, JsError> {
        Ok(ServerCertificate {
            inner: self.inner.signer().map_err(js_error)?.clone(),
        })
    }

    pub fn signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .signature()
            .map(|signature| signature.to_vec())
            .map_err(js_error)
    }

    pub fn validate(&self, trust_root: &PublicKey, time: f64) -> Result<bool, JsError> {
        self.inner
            .validate(&trust_root.inner, timestamp_from_js_millis(time)?)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = validateWithTrustRoots)]
    pub fn validate_with_trust_roots(
        &self,
        trust_roots: js_sys::Array,
        time: f64,
    ) -> Result<bool, JsError> {
        let trust_roots = trust_roots
            .iter()
            .map(|value| public_key_from_js(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let trust_root_refs = trust_roots.iter().collect::<Vec<_>>();
        self.inner
            .validate_with_trust_roots(&trust_root_refs, timestamp_from_js_millis(time)?)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct UnidentifiedSenderMessageContent {
    inner: LibSignalUnidentifiedSenderMessageContent,
}

#[wasm_bindgen]
impl UnidentifiedSenderMessageContent {
    pub fn new(
        message: &CiphertextMessage,
        sender: &SenderCertificate,
        content_hint: u32,
        group_id: Option<Vec<u8>>,
    ) -> Result<UnidentifiedSenderMessageContent, JsError> {
        Ok(Self {
            inner: LibSignalUnidentifiedSenderMessageContent::new(
                message.inner.message_type(),
                sender.inner.clone(),
                message.inner.serialize().to_vec(),
                LibSignalContentHint::from(content_hint),
                group_id,
            )
            .map_err(js_error)?,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<UnidentifiedSenderMessageContent, JsError> {
        Ok(Self {
            inner: LibSignalUnidentifiedSenderMessageContent::deserialize(buffer)
                .map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .serialized()
            .map(|serialized| serialized.to_vec())
            .map_err(js_error)
    }

    pub fn contents(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .contents()
            .map(|contents| contents.to_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = msgType)]
    pub fn msg_type(&self) -> Result<u8, JsError> {
        self.inner
            .msg_type()
            .map(|message_type| message_type as u8)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderCertificate)]
    pub fn sender_certificate(&self) -> Result<SenderCertificate, JsError> {
        Ok(SenderCertificate {
            inner: self.inner.sender().map_err(js_error)?.clone(),
        })
    }

    #[wasm_bindgen(js_name = contentHint)]
    pub fn content_hint(&self) -> Result<u32, JsError> {
        self.inner
            .content_hint()
            .map(|content_hint| content_hint.to_u32())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = groupId)]
    pub fn group_id(&self) -> Result<Option<Vec<u8>>, JsError> {
        self.inner
            .group_id()
            .map(|group_id| group_id.map(|bytes| bytes.to_vec()))
            .map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SealedSenderDecryptionResult {
    inner: LibSignalSealedSenderDecryptionResult,
}

#[wasm_bindgen]
impl SealedSenderDecryptionResult {
    pub fn message(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .message()
            .map(|message| message.to_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderE164)]
    pub fn sender_e164(&self) -> Result<Option<String>, JsError> {
        self.inner
            .sender_e164()
            .map(|sender| sender.map(ToOwned::to_owned))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderUuid)]
    pub fn sender_uuid(&self) -> Result<String, JsError> {
        self.inner
            .sender_uuid()
            .map(ToOwned::to_owned)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = senderAci)]
    pub fn sender_aci(&self) -> Result<Option<Aci>, JsError> {
        let Some(service_id) = LibSignalServiceId::parse_from_service_id_string(
            self.inner.sender_uuid().map_err(js_error)?,
        ) else {
            return Ok(None);
        };
        Ok(matches!(service_id, LibSignalServiceId::Aci(_)).then_some(Aci { inner: service_id }))
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> Result<u32, JsError> {
        self.inner.device_id().map(Into::into).map_err(js_error)
    }
}

#[wasm_bindgen]
pub struct SignalProtocolStore {
    inner: BrowserSignalProtocolStore,
}

#[wasm_bindgen]
impl SignalProtocolStore {
    #[wasm_bindgen(constructor)]
    pub fn new(identity_key_pair: &IdentityKeyPair, registration_id: u32) -> Result<Self, JsError> {
        let key_pair = LibSignalIdentityKeyPair::new(
            LibSignalIdentityKey::new(identity_key_pair.public_key.inner),
            identity_key_pair.private_key.inner,
        );
        Ok(Self {
            inner: BrowserSignalProtocolStore {
                session_store: BrowserSessionStore::default(),
                pre_key_store: BrowserPreKeyStore::default(),
                signed_pre_key_store: BrowserSignedPreKeyStore::default(),
                kyber_pre_key_store: BrowserKyberPreKeyStore::default(),
                identity_store: BrowserIdentityStore {
                    key_pair,
                    registration_id,
                    known_keys: HashMap::new(),
                },
                sender_key_store: BrowserSenderKeyStore::default(),
            },
        })
    }

    #[wasm_bindgen(js_name = fromSnapshot)]
    pub fn from_snapshot(snapshot: &[u8]) -> Result<SignalProtocolStore, JsError> {
        Ok(Self {
            inner: BrowserSignalProtocolStore::from_snapshot(snapshot)?,
        })
    }

    #[wasm_bindgen(js_name = exportSnapshot)]
    pub fn export_snapshot(&self) -> Result<Vec<u8>, JsError> {
        self.inner.to_snapshot()
    }

    #[wasm_bindgen(js_name = savePreKey)]
    pub fn save_pre_key(&mut self, id: u32, record: &PreKeyRecord) -> Result<(), JsError> {
        self.inner
            .pre_key_store
            .pre_keys
            .insert(id.into(), record.inner.clone());
        Ok(())
    }

    #[wasm_bindgen(js_name = saveSignedPreKey)]
    pub fn save_signed_pre_key(
        &mut self,
        id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), JsError> {
        self.inner
            .signed_pre_key_store
            .signed_pre_keys
            .insert(id.into(), record.inner.clone());
        Ok(())
    }

    #[wasm_bindgen(js_name = saveKyberPreKey)]
    pub fn save_kyber_pre_key(
        &mut self,
        id: u32,
        record: &KyberPreKeyRecord,
    ) -> Result<(), JsError> {
        self.inner
            .kyber_pre_key_store
            .kyber_pre_keys
            .insert(id.into(), record.inner.clone());
        Ok(())
    }

    #[wasm_bindgen(js_name = loadSession)]
    pub fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, JsError> {
        Ok(self
            .inner
            .session_store
            .sessions
            .get(&address.inner)
            .cloned()
            .map(|inner| SessionRecord { inner }))
    }

    #[wasm_bindgen(js_name = storeSession)]
    pub fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), JsError> {
        self.inner
            .session_store
            .sessions
            .insert(address.inner.clone(), record.inner.clone());
        Ok(())
    }

    #[wasm_bindgen(js_name = saveSenderKey)]
    pub fn save_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: &str,
        record: &SenderKeyRecord,
    ) -> Result<(), JsError> {
        self.inner.sender_key_store.sender_keys.insert(
            (sender.inner.clone(), uuid_from_string(distribution_id)?),
            record.inner.clone(),
        );
        Ok(())
    }

    #[wasm_bindgen(js_name = getSenderKey)]
    pub fn get_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: &str,
    ) -> Result<Option<SenderKeyRecord>, JsError> {
        Ok(self
            .inner
            .sender_key_store
            .sender_keys
            .get(&(sender.inner.clone(), uuid_from_string(distribution_id)?))
            .cloned()
            .map(|inner| SenderKeyRecord { inner }))
    }
}

#[wasm_bindgen(js_name = processPreKeyBundle)]
pub fn process_pre_key_bundle(
    bundle: &PreKeyBundle,
    address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    store: &mut SignalProtocolStore,
    now: f64,
) -> Result<(), JsError> {
    let mut csprng = browser_csprng()?;
    block_on(process_prekey_bundle(
        &address.inner,
        &local_address.inner,
        &mut store.inner.session_store,
        &mut store.inner.identity_store,
        &bundle.inner,
        timestamp_from_js_millis(now)?.into(),
        &mut csprng,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = signalEncrypt)]
pub fn signal_encrypt(
    message: &[u8],
    address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    store: &mut SignalProtocolStore,
    now: f64,
) -> Result<CiphertextMessage, JsError> {
    let mut csprng = browser_csprng()?;
    let inner = block_on(message_encrypt(
        message,
        &address.inner,
        &local_address.inner,
        &mut store.inner.session_store,
        &mut store.inner.identity_store,
        timestamp_from_js_millis(now)?.into(),
        &mut csprng,
    ))
    .map_err(js_error)?;
    Ok(CiphertextMessage { inner })
}

#[wasm_bindgen(js_name = signalDecrypt)]
pub fn signal_decrypt(
    message: &CiphertextMessage,
    address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    store: &mut SignalProtocolStore,
) -> Result<Vec<u8>, JsError> {
    let mut csprng = browser_csprng()?;
    let store = &mut store.inner;
    block_on(message_decrypt(
        &message.inner,
        &address.inner,
        &local_address.inner,
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut csprng,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = processSenderKeyDistributionMessage)]
pub fn process_sender_key_distribution_message_js(
    sender: &ProtocolAddress,
    message: &SenderKeyDistributionMessage,
    store: &mut SignalProtocolStore,
) -> Result<(), JsError> {
    block_on(process_sender_key_distribution_message(
        &sender.inner,
        &message.inner,
        &mut store.inner.sender_key_store,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = groupEncrypt)]
pub fn group_encrypt_js(
    sender: &ProtocolAddress,
    distribution_id: &str,
    store: &mut SignalProtocolStore,
    message: &[u8],
) -> Result<CiphertextMessage, JsError> {
    let mut csprng = browser_csprng()?;
    let inner = block_on(group_encrypt(
        &mut store.inner.sender_key_store,
        &sender.inner,
        uuid_from_string(distribution_id)?,
        message,
        &mut csprng,
    ))
    .map(LibSignalCiphertextMessage::SenderKeyMessage)
    .map_err(js_error)?;
    Ok(CiphertextMessage { inner })
}

#[wasm_bindgen(js_name = groupDecrypt)]
pub fn group_decrypt_js(
    sender: &ProtocolAddress,
    store: &mut SignalProtocolStore,
    message: &[u8],
) -> Result<Vec<u8>, JsError> {
    block_on(group_decrypt(
        message,
        &mut store.inner.sender_key_store,
        &sender.inner,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = sealedSenderEncryptMessage)]
pub fn sealed_sender_encrypt_message(
    message: &[u8],
    address: &ProtocolAddress,
    sender_cert: &SenderCertificate,
    store: &mut SignalProtocolStore,
    now: Option<f64>,
) -> Result<Vec<u8>, JsError> {
    let mut csprng = browser_csprng()?;
    let now = timestamp_from_js_millis(now.unwrap_or_else(js_sys::Date::now))?;
    block_on(sealed_sender_encrypt(
        &address.inner,
        &sender_cert.inner,
        message,
        &mut store.inner.session_store,
        &mut store.inner.identity_store,
        now.into(),
        &mut csprng,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = sealedSenderEncrypt)]
pub fn sealed_sender_encrypt_content(
    content: &UnidentifiedSenderMessageContent,
    address: &ProtocolAddress,
    store: &mut SignalProtocolStore,
) -> Result<Vec<u8>, JsError> {
    let mut csprng = browser_csprng()?;
    block_on(sealed_sender_encrypt_from_usmc(
        &address.inner,
        &content.inner,
        &store.inner.identity_store,
        &mut csprng,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = sealedSenderMultiRecipientEncrypt)]
pub fn sealed_sender_multi_recipient_encrypt_content(
    content: &UnidentifiedSenderMessageContent,
    recipients: js_sys::Array,
    store: &mut SignalProtocolStore,
    excluded_recipients: Option<js_sys::Array>,
) -> Result<Vec<u8>, JsError> {
    let recipients = recipients
        .iter()
        .map(|value| protocol_address_from_js(&value))
        .collect::<Result<Vec<_>, _>>()?;

    let recipient_sessions = recipients
        .iter()
        .map(|recipient| {
            store
                .inner
                .session_store
                .sessions
                .get(recipient)
                .cloned()
                .ok_or_else(|| {
                    JsError::new(&format!(
                        "missing session for multi-recipient sealed sender recipient {}.{}",
                        recipient.name(),
                        u32::from(recipient.device_id())
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let excluded_recipients = excluded_recipients
        .map(|recipients| {
            recipients
                .iter()
                .map(|value| service_id_from_js(&value))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let recipient_refs = recipients.iter().collect::<Vec<_>>();
    let session_refs = recipient_sessions.iter().collect::<Vec<_>>();
    let mut csprng = browser_csprng()?;
    block_on(sealed_sender_multi_recipient_encrypt(
        &recipient_refs,
        &session_refs,
        excluded_recipients,
        &content.inner,
        &store.inner.identity_store,
        &mut csprng,
    ))
    .map_err(js_error)
}

#[wasm_bindgen(js_name = sealedSenderMultiRecipientMessageForSingleRecipient)]
pub fn sealed_sender_multi_recipient_message_for_single_recipient(
    encoded_multi_recipient_message: &[u8],
) -> Result<Vec<u8>, JsError> {
    let messages =
        SealedSenderV2SentMessage::parse(encoded_multi_recipient_message).map_err(js_error)?;
    if messages.recipients.len() != 1 {
        return Err(JsError::new(
            "only supports messages with exactly one recipient",
        ));
    }
    Ok(messages
        .received_message_parts_for_recipient(&messages.recipients[0])
        .as_ref()
        .concat())
}

#[wasm_bindgen(js_name = sealedSenderDecryptMessage)]
pub fn sealed_sender_decrypt_message(
    message: &[u8],
    trust_root: &PublicKey,
    timestamp: f64,
    local_e164: Option<String>,
    local_uuid: &str,
    local_device_id: u32,
    store: &mut SignalProtocolStore,
) -> Result<SealedSenderDecryptionResult, JsError> {
    let local_device_id = DeviceId::try_from(local_device_id).map_err(js_error)?;
    let store = &mut store.inner;
    let inner = block_on(sealed_sender_decrypt(
        message,
        &trust_root.inner,
        timestamp_from_js_millis(timestamp)?,
        local_e164,
        local_uuid.to_string(),
        local_device_id,
        &mut store.identity_store,
        &mut store.session_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
    ))
    .map_err(js_error)?;
    Ok(SealedSenderDecryptionResult { inner })
}

#[wasm_bindgen(js_name = sealedSenderDecryptToUsmc)]
pub fn sealed_sender_decrypt_to_usmc_content(
    message: &[u8],
    store: &mut SignalProtocolStore,
) -> Result<UnidentifiedSenderMessageContent, JsError> {
    let inner = block_on(sealed_sender_decrypt_to_usmc(
        message,
        &store.inner.identity_store,
    ))
    .map_err(js_error)?;
    Ok(UnidentifiedSenderMessageContent { inner })
}

#[wasm_bindgen]
impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        prekey_id: Option<u32>,
        prekey: Option<PublicKey>,
        signed_prekey_id: u32,
        signed_prekey: &PublicKey,
        signed_prekey_signature: &[u8],
        identity_key: &PublicKey,
        kyber_prekey_id: u32,
        kyber_prekey: &KEMPublicKey,
        kyber_prekey_signature: &[u8],
    ) -> Result<PreKeyBundle, JsError> {
        let pre_key = match (prekey_id, prekey) {
            (Some(id), Some(key)) => Some((id.into(), key.inner)),
            (None, None) => None,
            _ => {
                return Err(JsError::new(
                    "prekey_id and prekey must both be set or both be null",
                ));
            }
        };
        Ok(Self {
            inner: LibSignalPreKeyBundle::new(
                registration_id,
                DeviceId::try_from(device_id).map_err(js_error)?,
                pre_key,
                signed_prekey_id.into(),
                signed_prekey.inner,
                signed_prekey_signature.to_vec(),
                kyber_prekey_id.into(),
                kyber_prekey.inner.clone(),
                kyber_prekey_signature.to_vec(),
                LibSignalIdentityKey::new(identity_key.inner),
            )
            .map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = registrationId)]
    pub fn registration_id(&self) -> Result<u32, JsError> {
        self.inner.registration_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> Result<u32, JsError> {
        self.inner.device_id().map(Into::into).map_err(js_error)
    }

    #[wasm_bindgen(js_name = preKeyId)]
    pub fn pre_key_id(&self) -> Result<Option<u32>, JsError> {
        self.inner
            .pre_key_id()
            .map(|id| id.map(Into::into))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = preKeyPublic)]
    pub fn pre_key_public(&self) -> Result<Option<PublicKey>, JsError> {
        self.inner
            .pre_key_public()
            .map(|key| key.map(|inner| PublicKey { inner }))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = signedPreKeyId)]
    pub fn signed_pre_key_id(&self) -> Result<u32, JsError> {
        self.inner
            .signed_pre_key_id()
            .map(Into::into)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = signedPreKeyPublic)]
    pub fn signed_pre_key_public(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: self.inner.signed_pre_key_public().map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = signedPreKeySignature)]
    pub fn signed_pre_key_signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .signed_pre_key_signature()
            .map(|signature| signature.to_vec())
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = identityKey)]
    pub fn identity_key(&self) -> Result<PublicKey, JsError> {
        Ok(PublicKey {
            inner: *self.inner.identity_key().map_err(js_error)?.public_key(),
        })
    }

    #[wasm_bindgen(js_name = kyberPreKeyId)]
    pub fn kyber_pre_key_id(&self) -> Result<u32, JsError> {
        self.inner
            .kyber_pre_key_id()
            .map(Into::into)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = kyberPreKeyPublic)]
    pub fn kyber_pre_key_public(&self) -> Result<KEMPublicKey, JsError> {
        Ok(KEMPublicKey {
            inner: self.inner.kyber_pre_key_public().map_err(js_error)?.clone(),
        })
    }

    #[wasm_bindgen(js_name = kyberPreKeySignature)]
    pub fn kyber_pre_key_signature(&self) -> Result<Vec<u8>, JsError> {
        self.inner
            .kyber_pre_key_signature()
            .map(|signature| signature.to_vec())
            .map_err(js_error)
    }
}

#[wasm_bindgen]
impl SessionRecord {
    #[wasm_bindgen(js_name = newFresh)]
    pub fn new_fresh() -> SessionRecord {
        Self {
            inner: LibSignalSessionRecord::new_fresh(),
        }
    }

    pub fn deserialize(buffer: &[u8]) -> Result<SessionRecord, JsError> {
        Ok(Self {
            inner: LibSignalSessionRecord::deserialize(buffer).map_err(js_error)?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, JsError> {
        self.inner.serialize().map_err(js_error)
    }

    #[wasm_bindgen(js_name = archiveCurrentState)]
    pub fn archive_current_state(&mut self) -> Result<(), JsError> {
        self.inner.archive_current_state().map_err(js_error)
    }

    #[wasm_bindgen(js_name = localRegistrationId)]
    pub fn local_registration_id(&self) -> Result<u32, JsError> {
        self.inner.local_registration_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = remoteRegistrationId)]
    pub fn remote_registration_id(&self) -> Result<u32, JsError> {
        self.inner.remote_registration_id().map_err(js_error)
    }

    #[wasm_bindgen(js_name = hasCurrentState)]
    pub fn has_current_state(&self, require_pq_ratio: f64, now: f64) -> Result<bool, JsError> {
        let now = timestamp_from_js_millis(now)?;
        let has_chain = self
            .inner
            .has_usable_sender_chain(now.into(), SessionUsabilityRequirements::NotStale)
            .map_err(js_error)?;
        if !has_chain {
            return Ok(false);
        }

        let has_pq_chain = self
            .inner
            .has_usable_sender_chain(
                now.into(),
                SessionUsabilityRequirements::NotStale
                    | SessionUsabilityRequirements::EstablishedWithPqxdh
                    | SessionUsabilityRequirements::Spqr,
            )
            .map_err(js_error)?;
        if has_pq_chain || require_pq_ratio == 0.0 {
            return Ok(true);
        }

        let require_pq_ratio = require_pq_ratio.clamp(0.0, 1.0);
        Ok(should_use_nonpq_session(
            require_pq_ratio,
            self.inner.alice_base_key().map_err(js_error)?,
        ))
    }

    #[wasm_bindgen(js_name = currentRatchetKeyMatches)]
    pub fn current_ratchet_key_matches(&self, key: &PublicKey) -> Result<bool, JsError> {
        self.inner
            .current_ratchet_key_matches(&key.inner)
            .map_err(js_error)
    }
}

#[wasm_bindgen]
impl IdentityKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> IdentityKeyPair {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn generate() -> Result<IdentityKeyPair, JsError> {
        let private_key = PrivateKey::generate()?;
        let public_key = private_key.get_public_key()?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn deserialize(buffer: &[u8]) -> Result<IdentityKeyPair, JsError> {
        let inner = LibSignalIdentityKeyPair::try_from(buffer).map_err(js_error)?;
        Ok(Self {
            public_key: PublicKey {
                inner: *inner.public_key(),
            },
            private_key: PrivateKey {
                inner: *inner.private_key(),
            },
        })
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.public_key.inner,
        }
    }

    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey {
            inner: self.private_key.inner,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let pair = LibSignalIdentityKeyPair::new(
            LibSignalIdentityKey::new(self.public_key.inner),
            self.private_key.inner,
        );
        pair.serialize().into_vec()
    }

    #[wasm_bindgen(js_name = signAlternateIdentity)]
    pub fn sign_alternate_identity(&self, other: &PublicKey) -> Result<Vec<u8>, JsError> {
        let mut csprng = browser_csprng()?;
        let pair = LibSignalIdentityKeyPair::new(
            LibSignalIdentityKey::new(self.public_key.inner),
            self.private_key.inner,
        );
        pair.sign_alternate_identity(&LibSignalIdentityKey::new(other.inner), &mut csprng)
            .map(|signature| signature.into_vec())
            .map_err(js_error)
    }
}
