import { StatefulSmartContract, assert } from 'tsop-lang';

class Counter extends StatefulSmartContract {
  count: bigint; // non-readonly = stateful

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public decrement() {
    assert(this.count > 0n);
    this.count--;
  }
}
