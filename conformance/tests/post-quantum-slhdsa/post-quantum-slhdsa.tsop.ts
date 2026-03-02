import { SmartContract, assert, verifySLHDSA_SHA2_128s } from 'tsop-lang';
import type { ByteString } from 'tsop-lang';

class PostQuantumSLHDSA extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
  }
}
