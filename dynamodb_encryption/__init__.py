import boto3
from typing import List, Optional
from dynamodb_encryption.utils import Parser
from dynamodb_encryption_sdk.encrypted import CryptoConfig
from dynamodb_encryption_sdk.identifiers import CryptoAction
from dynamodb_encryption_sdk.delegated_keys.jce import JceNameLocalDelegatedKey
from dynamodb_encryption_sdk.material_providers.wrapped import WrappedCryptographicMaterialsProvider
from dynamodb_encryption_sdk.identifiers import EncryptionKeyType, KeyEncodingType
from dynamodb_encryption_sdk.structures import AttributeActions, EncryptionContext, TableInfo
from dynamodb_encryption_sdk.transform import dict_to_ddb
from dynamodb_encryption_sdk.encrypted.item import decrypt_python_item, encrypt_python_item

kms_client = boto3.client('kms')
dynamo_db = boto3.resource('dynamodb')


def get_table_info(table_name: str):
    table = dynamo_db.Table(table_name)
    table_info = TableInfo(name=table_name)
    table_info.refresh_indexed_attributes(table.meta.client)
    return table, table_info


def encrypt(table_info: TableInfo,
            key_id: str,
            item: dict,
            context_attributes: Optional[dict] = None,
            dont_encrypt: Optional[List[str]] = None):
    data_key = kms_client.generate_data_key(KeyId=key_id, KeySpec='AES_256')
    key_bytes = data_key['Plaintext']
    pointer = data_key['CiphertextBlob']

    item = Parser.to_decimal(item)
    item['pointer'] = pointer

    config = _get_config(table_info=table_info,
                         key_bytes=key_bytes,
                         context_attributes=context_attributes,
                         dont_encrypt=dont_encrypt)

    response = encrypt_python_item(item, config)

    del data_key, key_bytes, pointer, config

    return Parser.to_number(response)


def decrypt(table_info: TableInfo,
            key_id: str,
            item: dict,
            context_attributes: Optional[dict] = None,
            dont_encrypt: Optional[List[str]] = None):
    pointer = item.pop('pointer', None)
    if not pointer:
        raise Exception('Pointer not found')

    pointer_bytes = kms_client.decrypt(
        CiphertextBlob=pointer.value,
        KeyId=key_id,
        EncryptionAlgorithm='SYMMETRIC_DEFAULT')['Plaintext']

    config = _get_config(table_info=table_info,
                         key_bytes=pointer_bytes,
                         context_attributes=context_attributes,
                         dont_encrypt=dont_encrypt)

    item = decrypt_python_item(item, config)
    item = Parser.to_number(item)

    del pointer, pointer_bytes, config

    return item


def _get_config(table_info: TableInfo,
                key_bytes: bytes,
                context_attributes: Optional[dict] = None,
                dont_encrypt: Optional[List[str]] = None,
                type: EncryptionKeyType = EncryptionKeyType.SYMMETRIC,
                encoding: KeyEncodingType = KeyEncodingType.RAW):
    wrap = JceNameLocalDelegatedKey(
        key=key_bytes,
        algorithm="AES" if type == EncryptionKeyType.SYMMETRIC else 'RSA',
        key_type=type,
        key_encoding=encoding,
    )
    sign = JceNameLocalDelegatedKey(
        key=key_bytes,
        algorithm="HmacSHA512"
        if type == EncryptionKeyType.SYMMETRIC else 'SHA512withRSA',
        key_type=type,
        key_encoding=encoding,
    )

    wrapped_cmp = WrappedCryptographicMaterialsProvider(wrapping_key=wrap,
                                                        unwrapping_key=wrap,
                                                        signing_key=sign)

    context = EncryptionContext(
        table_name=table_info.name,
        partition_key_name=table_info.primary_index.partition,
        sort_key_name=table_info.primary_index.sort,
        attributes=dict_to_ddb(context_attributes)
        if context_attributes else None,
    )

    _dont_encrypt = ['pointer', *(dont_encrypt if dont_encrypt else [])]
    actions = AttributeActions(
        default_action=CryptoAction.ENCRYPT_AND_SIGN,
        attribute_actions={k: CryptoAction.DO_NOTHING
                           for k in _dont_encrypt},
    )
    actions.set_index_keys(*table_info.protected_index_keys())

    config = CryptoConfig(materials_provider=wrapped_cmp,
                          encryption_context=context,
                          attribute_actions=actions)

    del wrap, sign, wrapped_cmp, context, actions

    return config
