import { assert } from 'chai';
import { toUUID, fromUUID } from '../../zkgroup/internal/UUIDUtil';
import FFICompatArray from '../../zkgroup/internal/FFICompatArray';

describe('UUIDUtil', () => {
  it('roundtrips', () => {
    const expected = 'b83dfb0b-67f1-41aa-992e-030c167cd011';
    const array = fromUUID(expected);
    const actual = toUUID(array);

    assert.strictEqual(expected, actual);
  });

  it('fromUUID produces correct array', () => {
    const expected = Buffer.from('67dfd496ea024720b13d83a462168b1d', 'hex');
    const actual = fromUUID('67dfd496-ea02-4720-b13d-83a462168b1d');

    assert.strictEqual(expected.toString('hex'), actual.buffer.toString('hex'));
  });

  it('fromUUID produces correct array, alternative values', () => {
    const expected = Buffer.from('b70df6ac3b214b39a514613561f51e2a', 'hex');
    const actual = fromUUID('b70df6ac-3b21-4b39-a514-613561f51e2a');

    assert.strictEqual(expected.toString('hex'), actual.buffer.toString('hex'));
  });

  it('toUUID produces correct string', () => {
    const expected = '3dc48790-568b-49c1-9bd6-ab6604a5bc32';
    const array = new FFICompatArray(Buffer.from('3dc48790568b49c19bd6ab6604a5bc32', 'hex'));
    const actual = toUUID(array);

    assert.strictEqual(expected, actual);
  });

  it('toUUID produces correct string, alternative values', () => {
    const expected = 'b83dfb0b-67f1-41aa-992e-030c167cd011';
    const array = new FFICompatArray(Buffer.from('b83dfb0b67f141aa992e030c167cd011', 'hex'));
    const actual = toUUID(array);

    assert.strictEqual(expected, actual);
  });
});
