import { SmartContract, assert, verifyWOTS } from 'tsop-lang';
import type { ByteString } from 'tsop-lang';

class PostQuantumWOTS extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
