import { randomBytes } from 'crypto';
import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';
import VerificationFailedException from '../errors/VerificationFailedException';
import { RANDOM_LENGTH } from '../internal/Constants';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import UuidCiphertext from './UuidCiphertext';

import ProfileKeyCiphertext from './ProfileKeyCiphertext';
import ProfileKey from '../profiles/ProfileKey';
import GroupSecretParams from './GroupSecretParams';
import { UUID_LENGTH, UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ClientZkGroupCipher {

  groupSecretParams: GroupSecretParams;

  constructor(groupSecretParams: GroupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  encryptUuid(uuid: UUIDType): UuidCiphertext {
    const newContents = new FFICompatArray(UuidCiphertext.SIZE);

    const groupSecretParamsContents = this.groupSecretParams.getContents()
    const uuidContents = fromUUID(uuid);

    const ffi_return = Native.FFI_GroupSecretParams_encryptUuid(groupSecretParamsContents, groupSecretParamsContents.length, uuidContents, uuidContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new UuidCiphertext(newContents);
  }

  decryptUuid(uuidCiphertext: UuidCiphertext): UUIDType {
    const newContents = new FFICompatArray(UUID_LENGTH);

    const groupSecretParamsContents = this.groupSecretParams.getContents();
    const uuidCiphertextContents = uuidCiphertext.getContents();

    const ffi_return = Native.FFI_GroupSecretParams_decryptUuid(groupSecretParamsContents, groupSecretParamsContents.length, uuidCiphertextContents, uuidCiphertextContents.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return toUUID(newContents);
  }

  encryptProfileKey(profileKey: ProfileKey): ProfileKeyCiphertext {
    const random = new FFICompatArray(randomBytes(RANDOM_LENGTH));

    return this.encryptProfileKeyWithRandom(random, profileKey);
  }

  encryptProfileKeyWithRandom(random: FFICompatArrayType, profileKey: ProfileKey): ProfileKeyCiphertext {
    const newContents = new FFICompatArray(ProfileKeyCiphertext.SIZE);

    const groupSecretParamsContents = this.groupSecretParams.getContents();
    const profileKeyContents = profileKey.getContents();

    const ffi_return = Native.FFI_GroupSecretParams_encryptProfileKeyDeterministic(groupSecretParamsContents, groupSecretParamsContents.length, random, random.length, profileKeyContents, profileKeyContents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKeyCiphertext(newContents);
  }

  decryptProfileKey(profileKeyCiphertext: ProfileKeyCiphertext): ProfileKey {
    const newContents = new FFICompatArray(ProfileKey.SIZE);

    const groupSecretParamsContents = this.groupSecretParams.getContents()
    const profileKeyCiphertextContents = profileKeyCiphertext.getContents();

    const ffi_return = Native.FFI_GroupSecretParams_decryptProfileKey(groupSecretParamsContents, groupSecretParamsContents.length, profileKeyCiphertextContents, profileKeyCiphertextContents.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKey(newContents);
  }

  encryptBlob(plaintext: FFICompatArrayType): FFICompatArrayType {
    const newContents = FFICompatArray(plaintext.length);

    const groupSecretParamsContents = this.groupSecretParams.getContents();

    const ffi_return = Native.FFI_GroupSecretParams_encryptBlob(groupSecretParamsContents, groupSecretParamsContents.length, plaintext, plaintext.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return newContents;
  }

  decryptBlob(blobCiphertext: FFICompatArrayType): FFICompatArrayType {
    const newContents = new FFICompatArray(blobCiphertext.length);

    const groupSecretParamsContents = this.groupSecretParams.getContents()

    const ffi_return = Native.FFI_GroupSecretParams_decryptBlob(groupSecretParamsContents, groupSecretParamsContents.length, blobCiphertext, blobCiphertext.length, newContents, newContents.length);
    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new VerificationFailedException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return newContents;
  }

}
