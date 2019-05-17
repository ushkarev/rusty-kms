#![allow(non_snake_case)]

use std::collections::HashMap;

use hyper::Body;
use serde::{Deserialize, Serialize};

macro_rules! response_traits {
    ( $( $t:ty ),* ) => {
        $(
            impl<'a> ToString for $t {
                fn to_string(&self) -> String {
                    serde_json::to_string(self).expect("cannot convert to JSON")
                }
            }

            impl<'a> Into<Body> for $t {
                fn into(self) -> Body {
                    self.to_string().into()
                }
            }
        )*
    };
}

#[derive(Deserialize, Debug)]
pub struct GenerateRandomRequest<'a> {
    pub CustomKeyStoreId: Option<&'a str>,
    pub NumberOfBytes: Option<usize>,
}

#[derive(Serialize, Debug)]
pub struct GenerateRandomResponse<'a> {
    pub Plaintext: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct CreateKeyRequest<'a> {
    pub BypassPolicyLockoutSafetyCheck: Option<bool>,
    pub CustomKeyStoreId: Option<&'a str>,
    pub Description: Option<&'a str>,
    pub KeyUsage: Option<&'a str>,
    pub Origin: Option<&'a str>,
    pub Policy: Option<&'a str>,
    pub Tags: Option<Vec<Tag<'a>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tag<'a> {
    pub TagKey: &'a str,
    pub TagValue: &'a str,
}

#[derive(Serialize, Debug)]
pub struct CreateKeyResponse<'a> {
    pub KeyMetadata: KeyMetadata<'a>,
}

#[derive(Deserialize, Debug)]
pub struct GetParametersForImportRequest<'a> {
    pub KeyId: &'a str,
    pub WrappingAlgorithm: &'a str,
    pub WrappingKeySpec: &'a str,
}

#[derive(Serialize, Debug)]
pub struct GetParametersForImportResponse<'a> {
    pub KeyId: &'a str,
    pub ImportToken: &'a str,
    pub PublicKey: &'a str,
    pub ParametersValidTo: f64,
}

#[derive(Deserialize, Debug)]
pub struct ImportKeyMaterialRequest<'a> {
    pub KeyId: &'a str,
    pub ImportToken: &'a str,
    pub EncryptedKeyMaterial: &'a str,
    pub ExpirationModel: Option<&'a str>,
    pub ValidTo: Option<f64>,
}

#[derive(Deserialize, Debug)]
pub struct DeleteImportedKeyMaterialRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct UpdateKeyDescriptionRequest<'a> {
    pub KeyId: &'a str,
    pub Description: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct DescribeKeyRequest<'a> {
    pub KeyId: &'a str,
    pub GrantTokens: Option<Vec<&'a str>>,
}

#[derive(Serialize, Debug)]
pub struct DescribeKeyResponse<'a> {
    pub KeyMetadata: KeyMetadata<'a>,
}

#[derive(Serialize, Debug)]
pub struct KeyMetadata<'a> {
    pub AWSAccountId: &'a str,
    pub Arn: &'a str,
    pub CreationDate: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub DeletionDate: Option<f64>,
    pub Description: &'a str,
    pub Enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ExpirationModel: Option<&'a str>,
    pub KeyId: &'a str,
    pub KeyManager: &'a str,
    pub KeyState: &'a str,
    pub KeyUsage: &'a str,
    pub Origin: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ValidTo: Option<f64>,
}

#[derive(Deserialize, Debug)]
pub struct ListKeysRequest<'a> {
    pub Limit: Option<usize>,
    pub Marker: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct ListKeysResponse<'a> {
    pub Keys: Vec<KeyID<'a>>,
    pub Truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub NextMarker: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct KeyID<'a> {
    pub KeyId: &'a str,
    pub KeyArn: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct ListTagsRequest<'a> {
    pub KeyId: &'a str,
    pub Limit: Option<usize>,
    pub Marker: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct ListTagsResponse<'a> {
    pub Tags: Vec<Tag<'a>>,
    pub Truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub NextMarker: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
pub struct TagResourceRequest<'a> {
    pub KeyId: &'a str,
    pub Tags: Vec<Tag<'a>>,
}

#[derive(Deserialize, Debug)]
pub struct UntagResourceRequest<'a> {
    pub KeyId: &'a str,
    pub TagKeys: Vec<&'a str>,
}

#[derive(Deserialize, Debug)]
pub struct EncryptRequest<'a> {
    pub EncryptionContext: Option<HashMap<&'a str, &'a str>>,
    pub GrantTokens: Option<Vec<&'a str>>,
    pub KeyId: &'a str,
    pub Plaintext: &'a str,
}

#[derive(Serialize, Debug)]
pub struct EncryptResponse<'a> {
    pub KeyId: &'a str,
    pub CiphertextBlob: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct DecryptRequest<'a> {
    pub EncryptionContext: Option<HashMap<&'a str, &'a str>>,
    pub GrantTokens: Option<Vec<&'a str>>,
    pub CiphertextBlob: &'a str,
}

#[derive(Serialize, Debug)]
pub struct DecryptResponse<'a> {
    pub KeyId: &'a str,
    pub Plaintext: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct ReEncryptRequest<'a> {
    pub CiphertextBlob: &'a str,
    pub SourceEncryptionContext: Option<HashMap<&'a str, &'a str>>,
    pub DestinationEncryptionContext: Option<HashMap<&'a str, &'a str>>,
    pub DestinationKeyId: &'a str,
    pub GrantTokens: Option<Vec<&'a str>>,
}

#[derive(Serialize, Debug)]
pub struct ReEncryptResponse<'a> {
    pub KeyId: &'a str,
    pub SourceKeyId: &'a str,
    pub CiphertextBlob: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct GenerateDataKeyRequest<'a> {
    pub KeyId: &'a str,
    pub KeySpec: Option<&'a str>,
    pub NumberOfBytes: Option<u32>,
    pub EncryptionContext: Option<HashMap<&'a str, &'a str>>,
    pub GrantTokens: Option<Vec<&'a str>>,
}

#[derive(Serialize, Debug)]
pub struct GenerateDataKeyResponse<'a> {
    pub KeyId: &'a str,
    pub CiphertextBlob: &'a str,
    pub Plaintext: &'a str,
}

#[derive(Serialize, Debug)]
pub struct GenerateDataKeyWithoutPlaintextResponse<'a> {
    pub KeyId: &'a str,
    pub CiphertextBlob: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct CreateAliasRequest<'a> {
    pub AliasName: &'a str,
    pub TargetKeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct ListAliasesRequest<'a> {
    pub KeyId: Option<&'a str>,
    pub Limit: Option<usize>,
    pub Marker: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct ListAliasesResponse<'a> {
    pub Aliases: Vec<Alias<'a>>,
    pub Truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub NextMarker: Option<&'a str>,
}

#[derive(Serialize, Debug)]
pub struct Alias<'a> {
    pub AliasArn: &'a str,
    pub AliasName: &'a str,
    pub TargetKeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct DeleteAliasRequest<'a> {
    pub AliasName: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct UpdateAliasRequest<'a> {
    pub AliasName: &'a str,
    pub TargetKeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct DisableRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct EnableRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct ScheduleKeyDeletionRequest<'a> {
    pub KeyId: &'a str,
    pub PendingWindowInDays: Option<u8>,
}

#[derive(Serialize, Debug)]
pub struct ScheduleKeyDeletionResponse<'a> {
    pub KeyId: &'a str,
    pub DeletionDate: f64,
}

#[derive(Deserialize, Debug)]
pub struct CancelKeyDeletionRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Serialize, Debug)]
pub struct CancelKeyDeletionResponse<'a> {
    pub KeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct GetKeyRotationStatusRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Serialize, Debug)]
pub struct GetKeyRotationStatusResponse {
    pub KeyRotationEnabled: bool,
}

#[derive(Deserialize, Debug)]
pub struct EnableKeyRotationRequest<'a> {
    pub KeyId: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct DisableKeyRotationRequest<'a> {
    pub KeyId: &'a str,
}

response_traits!(
    GenerateRandomResponse<'a>, CreateKeyResponse<'a>, GetParametersForImportResponse<'a>,
    DescribeKeyResponse<'a>, ListKeysResponse<'a>, ListTagsResponse<'a>,
    EncryptResponse<'a>, DecryptResponse<'a>, ReEncryptResponse<'a>,
    GenerateDataKeyResponse<'a>, GenerateDataKeyWithoutPlaintextResponse<'a>,
    ListAliasesResponse<'a>,
    ScheduleKeyDeletionResponse<'a>, CancelKeyDeletionResponse<'a>,
    GetKeyRotationStatusResponse
);

#[cfg(test)]
mod tests {
    use futures::{Future, Stream};

    use super::*;

    #[test]
    fn simple_response() {
        let response = GenerateRandomResponse {Plaintext: "Hello! 💖"};
        let body: Body = response.into();
        let body = body.concat2().wait().unwrap();
        let body = String::from_utf8_lossy(body.as_ref());
        assert_eq!(body, "{\"Plaintext\":\"Hello! 💖\"}");
    }
}
