import ByteArray from '../internal/ByteArray';
import FFICompatArray, { FFICompatArrayType } from '../internal/FFICompatArray';

import InvalidInputException from '../errors/InvalidInputException';
import ZkGroupError from '../errors/ZkGroupError';

import Native, { FFI_RETURN_OK, FFI_RETURN_INPUT_ERROR } from '../internal/Native';

import ProfileKeyCredentialRequest from './ProfileKeyCredentialRequest';


export default class PniCredentialRequestContext extends ByteArray {

  static SIZE = 489;

  constructor(contents: FFICompatArrayType) {
    super(contents, PniCredentialRequestContext.SIZE, true);

    const ffi_return = Native.FFI_PniCredentialRequestContext_checkValidContents(this.contents, this.contents.length);

    if (ffi_return == FFI_RETURN_INPUT_ERROR) {
      throw new InvalidInputException('FFI_RETURN_INPUT_ERROR');
    }

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }
  }

  getRequest(): ProfileKeyCredentialRequest {
    const newContents = new FFICompatArray(ProfileKeyCredentialRequest.SIZE);

    const ffi_return = Native.FFI_PniCredentialRequestContext_getRequest(this.contents, this.contents.length, newContents, newContents.length);

    if (ffi_return != FFI_RETURN_OK) {
      throw new ZkGroupError('FFI_RETURN!=OK');
    }

    return new ProfileKeyCredentialRequest(newContents);
  }
}
