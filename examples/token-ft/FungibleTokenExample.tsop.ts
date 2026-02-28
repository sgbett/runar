import { StatefulSmartContract, assert, checkSig } from 'tsop-lang';
import type { PubKey, Sig } from 'tsop-lang';

class SimpleFungibleToken extends StatefulSmartContract {
  owner: PubKey;          // stateful: current token owner
  readonly supply: bigint; // immutable: total supply

  constructor(owner: PubKey, supply: bigint) {
    super(owner, supply);
    this.owner = owner;
    this.supply = supply;
  }

  public transfer(sig: Sig, newOwner: PubKey) {
    // Only current owner can transfer
    assert(checkSig(sig, this.owner));

    // Update owner
    this.owner = newOwner;
  }
}
