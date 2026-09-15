export interface WrapKdfParams {
  alg: 'argon2id';
  m: number;
  t: number;
  p: number;
}

export interface WrappedMasterKeyPayload {
  v: number;
  iv: string;
  data: string;
  kdf?: WrapKdfParams;
}

export interface E2eeKeyMaterial {
  keySalt: string;
  wrappedMasterKey: string;
  keyVersion: number;
  recoveryWrappedMasterKey?: string;
}
