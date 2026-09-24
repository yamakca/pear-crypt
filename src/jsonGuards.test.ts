import { describe, expect, it } from 'vitest';
import { parseFileMetadataPlaintext } from './metadata/metadata.ts';
import { parseRecoveryWrapEnvelope } from './recovery/envelope.ts';
import { parseWrappedMasterKeyPayload } from './keys/payload.ts';

describe('json guards', () => {
  it('accepts a wrapped master key and defaults a missing version', () => {
    expect(parseWrappedMasterKeyPayload({ iv: 'a', data: 'b' })).toEqual({
      v: 1,
      iv: 'a',
      data: 'b',
    });
    expect(
      parseWrappedMasterKeyPayload({
        v: 2,
        iv: 'a',
        data: 'b',
        kdf: { alg: 'argon2id', m: 1, t: 1, p: 1 },
      }).kdf?.alg,
    ).toBe('argon2id');
  });

  it('rejects corrupt wrap, recovery, and share headers', () => {
    expect(() => parseWrappedMasterKeyPayload(null)).toThrow('corruptServerE2eeData');
    expect(() => parseWrappedMasterKeyPayload({ iv: ' ', data: 'b' })).toThrow(
      'corruptServerE2eeData',
    );
    expect(() =>
      parseWrappedMasterKeyPayload({ iv: 'a', data: 'b', kdf: { alg: 'pbkdf2' } }),
    ).toThrow('corruptServerE2eeData');
    expect(() => parseWrappedMasterKeyPayload({ iv: 'a', data: 'b', kdf: 'nope' })).toThrow(
      'corruptServerE2eeData',
    );

    expect(() => parseRecoveryWrapEnvelope([])).toThrow('corruptRecoveryData');
    expect(() => parseRecoveryWrapEnvelope({ salt: 's', wrapped: '' })).toThrow(
      'corruptRecoveryData',
    );
  });

  it('keeps optional metadata text and numeric timestamps', () => {
    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        tags: 'a',
        comments: 'b',
        extension: 'pdf',
        marker: 'red',
        type: 'application/pdf',
        contentDigest: 'abc',
        contentUpdatedAt: '1700000000000',
      }),
    ).toEqual({
      label: 'scan',
      tags: 'a',
      comments: 'b',
      extension: 'pdf',
      marker: 'red',
      type: 'application/pdf',
      contentDigest: 'abc',
      contentUpdatedAt: 1700000000000,
    });
  });

  it('drops sloppy optional metadata values', () => {
    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        tags: 1,
        contentUpdatedAt: 'not-a-number',
        contentDigest: null,
      }),
    ).toEqual({ label: 'scan' });

    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        contentUpdatedAt: Number.POSITIVE_INFINITY,
      }),
    ).toEqual({ label: 'scan' });

    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        contentUpdatedAt: '  ',
      }),
    ).toEqual({ label: 'scan' });

    expect(() => parseFileMetadataPlaintext({ label: 1 })).toThrow(
      'invalidEncryptedMetadataFormat',
    );
    expect(() => parseFileMetadataPlaintext('nope')).toThrow('invalidEncryptedMetadataFormat');
  });

  it('keeps a zero timestamp and empty strings', () => {
    expect(
      parseFileMetadataPlaintext({
        label: '',
        tags: '',
        contentUpdatedAt: 0,
      }),
    ).toEqual({
      label: '',
      tags: '',
      contentUpdatedAt: 0,
    });

    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        contentUpdatedAt: Number.NaN,
      }),
    ).toEqual({ label: 'scan' });

    expect(
      parseFileMetadataPlaintext({
        label: 'scan',
        contentUpdatedAt: ' 1700 ',
      }),
    ).toEqual({
      label: 'scan',
      contentUpdatedAt: 1700,
    });
  });
});
