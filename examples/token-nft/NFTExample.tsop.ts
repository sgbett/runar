import { StatefulSmartContract, assert, checkSig } from 'tsop-lang';
import type { PubKey, Sig, ByteString } from 'tsop-lang';

class SimpleNFT extends StatefulSmartContract {
  owner: PubKey;             // stateful
  readonly tokenId: ByteString;   // immutable: unique token identifier
  readonly metadata: ByteString;  // immutable: token metadata URI/hash

  constructor(owner: PubKey, tokenId: ByteString, metadata: ByteString) {
    super(owner, tokenId, metadata);
    this.owner = owner;
    this.tokenId = tokenId;
    this.metadata = metadata;
  }

  public transfer(sig: Sig, newOwner: PubKey) {
    assert(checkSig(sig, this.owner));
    this.owner = newOwner;
  }

  public burn(sig: Sig) {
    // Only owner can burn
    assert(checkSig(sig, this.owner));
    // No state mutation = token destroyed
  }
}
