define_error!(RawDecryptError; Length="invalid length", InvalidNonce="invalid nonce", InvalidKey="invalid key", Error="cannot decrypt");
define_error!(RawEncryptError; InvalidKey="invalid key", Error="cannot encrypt");

define_error!(UnwrapCipherTextError; InvalidWrapper="invalid wrapped cipher text", UnsupportedVersion="cipher text version unsupported");
define_error!(WrapCipherTextError; ArnLength="invalid arn length", DataLength="encrypted data too short");

define_error!(DecryptError; InvalidState="invalid state", KeyMaterialGeneration="invalid key material generation", RawError="cannot decrypt");
define_error!(EncryptError; InvalidState="invalid state", RawError="cannot encrypt");
define_error!(MakeImportTokenError; InvalidState="invalid state");
define_error!(ImportKeyMaterialError; InvalidState="invalid state");
define_error!(RemoveKeyMaterialError; InternalKey="internal key", PendingDeletion="pending deletion");

define_error!(IntoImportTokenError; Invalid="invalid import token", Mode="unknown import mode", Expired="token expired", Arn="invalid arn");
define_error!(FromImportTokenError; Encryption="encryption error");

define_error!(SetDescriptionError; InvalidState="pending deletion");
define_error!(SetEnabledError; InvalidState="invalid state");

define_error!(CancelDeletionError; InvalidState="not pending deletion");
define_error!(ScheduleDeletionError; DeletionWindow="deletion window must be between 7 and 30 days", InvalidState="pending deletion");
define_error!(SetRotationError; Disabled="key is disabled", InvalidState="invalid state");

define_error!(AddTagError; InvalidState="pending deletion");
define_error!(RemoveTagError; NotFound="tag not found", InvalidState="pending deletion");

define_error!(AddKeyError; DuplicateKeyId="key already exists");
define_error!(RemoveKeyError; NotFound="key not found");

define_error!(AddAliasError; AlreadyExists="alias already exists", KeyNotFound="key not found", InvalidState="pending deletion");
define_error!(UpdateAliasError; AliasNotFound="alias not found", KeyNotFound="key not found", InvalidState="pending deletion");
define_error!(RemoveAliasError; NotFound="alias not found");

define_error!(AddFromPortableStoreError; InvalidKeys="some invalid or duplicate keys", InvalidAliases="some invalid aliases", DuplicateKeyIds="some keys already exist", DuplicateAliases="some aliases already exist");
