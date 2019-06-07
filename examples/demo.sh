#!/usr/bin/env bash

# Usage:
# pip install -r examples/demo-requirements.txt
# AWS_ACCESS_KEY_ID=AAAAAAAAAAAAAAAAAAAAA AWS_SECRET_ACCESS_KEY=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ AWS_DEFAULT_REGION=eu-west-2 examples/demo.sh

set -e

function kms_preflight {
    [[ -z ${AWS_ACCESS_KEY_ID} || -z ${AWS_SECRET_ACCESS_KEY} ]] && {
        echo '$AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY are required'
        exit 1
    }
    [[ -x `which aws` ]] || {
        echo 'AWS cli tools not found'
        exit 1
    }
}

function kms_random_str {
    LEN=$1
    LEN=${LEN:-6}
    aws kms --endpoint-url http://127.0.0.1:6767/ generate-random --number-of-bytes ${LEN} --query Plaintext --output text
}

function kms_list_keys {
    echo "All keys:"
    aws kms --endpoint-url http://127.0.0.1:6767/ list-keys --query 'Keys' --output table
}

function kms_describe_key {
    echo "Description:"
    aws kms --endpoint-url http://127.0.0.1:6767/ describe-key --key-id $1 --query 'KeyMetadata' --output table
}

function kms_key_tags {
    echo "Tags: ${1}"
    aws kms --endpoint-url http://127.0.0.1:6767/ list-resource-tags --key-id $1 --query 'Tags[*].[TagKey, TagValue]' --output table
}

function kms_key_aliases {
    echo "Aliases: ${1}"
    aws kms --endpoint-url http://127.0.0.1:6767/ list-aliases --key-id $1 --query 'Aliases' --output table
}

function demo_enc_dec {
    INPUT="Lørem impsum 😀 $(kms_random_str)"
    INPUT_B64=`echo ${INPUT} | base64`

    # new key
    KEY_ID=`aws kms --endpoint-url http://127.0.0.1:6767/ create-key --tags TagKey=Purpose,TagValue=Testing --query KeyMetadata.KeyId --output text`
    echo "Key ID: ${KEY_ID}"
    kms_describe_key ${KEY_ID}

    # alias new key
    aws kms --endpoint-url http://127.0.0.1:6767/ create-alias --target-key-id ${KEY_ID} --alias-name "alias/test-key"

    # add description
    aws kms --endpoint-url http://127.0.0.1:6767/ update-key-description --key-id ${KEY_ID} --description "Test key"

    # encrypt data
    ENCRYPTED_B64=`aws kms --endpoint-url http://127.0.0.1:6767/ encrypt --key-id "alias/test-key" --plaintext ${INPUT_B64} --query CiphertextBlob --output text`
    [[ ${INPUT_B64} = ${ENCRYPTED_B64} ]] && echo "Encryption did nothing 😡"

    # delete alias
    aws kms --endpoint-url http://127.0.0.1:6767/ delete-alias --alias-name "alias/test-key"

    # decrypt data
    echo ${ENCRYPTED_B64} | base64 -D > target/encrypted.dat
    DECRYPTED_B64=`aws kms --endpoint-url http://127.0.0.1:6767/ decrypt --ciphertext-blob fileb://target/encrypted.dat --query Plaintext --output text`
    rm target/encrypted.dat
    # TODO: why doubly base64-encoded?
    DECRYPTED_B64=`echo ${DECRYPTED_B64} | base64 -D`
    OUTPUT=`echo ${DECRYPTED_B64} | base64 -D`
    [[ ${INPUT} = ${OUTPUT} ]] && echo "Encryption-decryption works 😀" || echo "Encryption-decryption cycle didn't work 😡"

    # disable key
    aws kms --endpoint-url http://127.0.0.1:6767/ disable-key --key-id ${KEY_ID}
    kms_describe_key ${KEY_ID}
}

function demo_import {
    IMPORT_KEY_ID=`aws kms --endpoint-url http://127.0.0.1:6767/ create-key --origin EXTERNAL --query KeyMetadata.KeyId --output text`
    echo "Import key ID: ${IMPORT_KEY_ID}"
    kms_describe_key ${IMPORT_KEY_ID}
    aws kms --endpoint-url http://127.0.0.1:6767/ get-parameters-for-import --key-id ${IMPORT_KEY_ID} --wrapping-algorithm RSAES_PKCS1_V1_5 --wrapping-key-spec RSA_2048 --query 'PublicKey' --output text | base64 -D > target/public_key
    aws kms --endpoint-url http://127.0.0.1:6767/ get-parameters-for-import --key-id ${IMPORT_KEY_ID} --wrapping-algorithm RSAES_PKCS1_V1_5 --wrapping-key-spec RSA_2048 --query 'ImportToken' --output text | base64 -D > target/import_token
    echo $(kms_random_str 32) | base64 -D > target/key_material.txt
    openssl pkeyutl -in target/key_material.txt -out target/key_material -inkey target/public_key -pubin -keyform DER -encrypt
    # openssl pkeyutl -in target/key_material.txt -out target/key_material -inkey target/public_key -pubin -keyform DER -encrypt -rsa_padding_mode [pkcs1|sslv23|none|oaep|x931|pss]
    # openssl rsautl -in target/key_material.txt -out target/key_material -inkey target/public_key -pubin -keyform DER -encrypt [-raw | -pkcs | -oaep]
    aws kms --endpoint-url http://127.0.0.1:6767/ import-key-material --key-id ${IMPORT_KEY_ID} --import-token fileb://target/import_token --encrypted-key-material fileb://target/key_material
    rm -f target/key_material.txt target/key_material target/import_token target/public_key
    kms_describe_key ${IMPORT_KEY_ID}
    INPUT_B64=`kms_random_str 32`
    ENCRYPTED_B64=`aws kms --endpoint-url http://127.0.0.1:6767/ encrypt --key-id ${IMPORT_KEY_ID} --plaintext ${INPUT_B64} --query CiphertextBlob --output text`
    [[ ${INPUT_B64} = ${ENCRYPTED_B64} ]] && echo "Encryption did nothing 😡"
    echo ${ENCRYPTED_B64} | base64 -D > target/encrypted.dat
    DECRYPTED_B64=`aws kms --endpoint-url http://127.0.0.1:6767/ decrypt --ciphertext-blob fileb://target/encrypted.dat --query Plaintext --output text`
    rm target/encrypted.dat
    # TODO: why doubly base64-encoded?
    DECRYPTED_B64=`echo ${DECRYPTED_B64} | base64 -D`
    [[ ${INPUT_B64} = ${DECRYPTED_B64} ]] && echo "Imported key materials work 😀" || echo "Encryption-decryption cycle didn't work 😡"
}

kms_preflight
demo_enc_dec
demo_import
kms_list_keys
