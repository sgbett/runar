"""RunarContract — main contract runtime wrapper."""

from __future__ import annotations
from runar.sdk.types import (
    RunarArtifact, Utxo, Transaction, TxOutput,
    DeployOptions, CallOptions,
)
from runar.sdk.provider import Provider
from runar.sdk.signer import Signer
from runar.sdk.deployment import build_deploy_transaction, select_utxos, build_p2pkh_script
from runar.sdk.calling import build_call_transaction, insert_unlocking_script
from runar.sdk.state import (
    serialize_state, extract_state_from_script, find_last_op_return,
    encode_push_data,
)


class RunarContract:
    """Runtime wrapper for a compiled Runar contract.

    Handles deployment, method invocation, state tracking, and script construction.
    """

    def __init__(self, artifact: RunarArtifact, constructor_args: list):
        expected = len(artifact.abi.constructor_params)
        if len(constructor_args) != expected:
            raise ValueError(
                f"RunarContract: expected {expected} constructor args for "
                f"{artifact.contract_name}, got {len(constructor_args)}"
            )

        self.artifact = artifact
        self._constructor_args = list(constructor_args)
        self._state: dict = {}
        self._code_script = ''
        self._current_utxo: Utxo | None = None
        self._provider: Provider | None = None
        self._signer: Signer | None = None

        # Initialize state from constructor args for stateful contracts
        if artifact.state_fields:
            for field in artifact.state_fields:
                if field.index < len(constructor_args):
                    self._state[field.name] = constructor_args[field.index]

    def connect(self, provider: Provider, signer: Signer) -> None:
        """Store provider and signer for later use."""
        self._provider = provider
        self._signer = signer

    def deploy(
        self,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: DeployOptions | None = None,
    ) -> tuple[str, Transaction]:
        """Deploy the contract. Returns (txid, transaction)."""
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.deploy: no provider/signer. Call connect() or pass them."
            )

        opts = options or DeployOptions()
        address = signer.get_address()
        change_address = opts.change_address or address
        locking_script = self.get_locking_script()

        fee_rate = provider.get_fee_rate()
        all_utxos = provider.get_utxos(address)
        if not all_utxos:
            raise RuntimeError(f"RunarContract.deploy: no UTXOs found for {address}")

        utxos = select_utxos(all_utxos, opts.satoshis, len(locking_script) // 2, fee_rate)
        change_script = build_p2pkh_script(change_address)

        tx_hex, input_count = build_deploy_transaction(
            locking_script, utxos, opts.satoshis, change_address, change_script, fee_rate,
        )

        # Sign all inputs
        signed_tx = tx_hex
        pub_key = signer.get_public_key()
        for i in range(input_count):
            utxo = utxos[i]
            sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
            unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
            signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        txid = provider.broadcast(signed_tx)

        self._current_utxo = Utxo(
            txid=txid, output_index=0, satoshis=opts.satoshis, script=locking_script,
        )

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = Transaction(
                txid=txid, version=1,
                outputs=[TxOutput(satoshis=opts.satoshis, script=locking_script)],
                raw=signed_tx,
            )

        return txid, tx

    def call(
        self,
        method_name: str,
        args: list | None = None,
        provider: Provider | None = None,
        signer: Signer | None = None,
        options: CallOptions | None = None,
    ) -> tuple[str, Transaction]:
        """Invoke a public method (spend the UTXO). Returns (txid, transaction)."""
        provider = provider or self._provider
        signer = signer or self._signer
        if provider is None or signer is None:
            raise RuntimeError(
                "RunarContract.call: no provider/signer. Call connect() or pass them."
            )

        args = args or []
        method = self._find_method(method_name)
        if method is None:
            raise ValueError(
                f"RunarContract.call: method '{method_name}' not found in {self.artifact.contract_name}"
            )
        if len(method.params) != len(args):
            raise ValueError(
                f"RunarContract.call: method '{method_name}' expects {len(method.params)} args, got {len(args)}"
            )
        if self._current_utxo is None:
            raise RuntimeError(
                "RunarContract.call: contract is not deployed. Call deploy() or from_txid() first."
            )

        address = signer.get_address()
        opts = options or CallOptions()
        change_address = opts.change_address or address
        unlocking_script = self.build_unlocking_script(method_name, args)

        is_stateful = bool(self.artifact.state_fields)
        new_locking_script = ''
        new_satoshis = 0

        if is_stateful:
            new_satoshis = opts.satoshis if opts.satoshis > 0 else self._current_utxo.satoshis
            if opts.new_state:
                for k, v in opts.new_state.items():
                    self._state[k] = v
            new_locking_script = self.get_locking_script()

        change_script = build_p2pkh_script(change_address)
        fee_rate = provider.get_fee_rate()
        additional_utxos = provider.get_utxos(address)

        tx_hex, input_count = build_call_transaction(
            self._current_utxo, unlocking_script, new_locking_script,
            new_satoshis, change_address, change_script, additional_utxos, fee_rate,
        )

        # Sign additional inputs
        signed_tx = tx_hex
        pub_key = signer.get_public_key()
        for i in range(1, input_count):
            if i - 1 < len(additional_utxos):
                utxo = additional_utxos[i - 1]
                sig = signer.sign(signed_tx, i, utxo.script, utxo.satoshis)
                unlock_script = encode_push_data(sig) + encode_push_data(pub_key)
                signed_tx = insert_unlocking_script(signed_tx, i, unlock_script)

        txid = provider.broadcast(signed_tx)

        if is_stateful and new_locking_script:
            self._current_utxo = Utxo(
                txid=txid, output_index=0, satoshis=new_satoshis, script=new_locking_script,
            )
        else:
            self._current_utxo = None

        try:
            tx = provider.get_transaction(txid)
        except Exception:
            tx = Transaction(txid=txid, version=1, raw=signed_tx)

        return txid, tx

    @staticmethod
    def from_txid(
        artifact: RunarArtifact,
        txid: str,
        output_index: int,
        provider: Provider,
    ) -> RunarContract:
        """Reconnect to an existing deployed contract."""
        tx = provider.get_transaction(txid)
        if output_index >= len(tx.outputs):
            raise ValueError(
                f"RunarContract.from_txid: output index {output_index} out of range "
                f"(tx has {len(tx.outputs)} outputs)"
            )

        output = tx.outputs[output_index]
        dummy_args = [0] * len(artifact.abi.constructor_params)
        contract = RunarContract(artifact, dummy_args)

        if artifact.state_fields:
            last_op_return = find_last_op_return(output.script)
            if last_op_return != -1:
                contract._code_script = output.script[:last_op_return]
            else:
                contract._code_script = output.script
        else:
            contract._code_script = output.script

        contract._current_utxo = Utxo(
            txid=txid, output_index=output_index,
            satoshis=output.satoshis, script=output.script,
        )

        if artifact.state_fields:
            state = extract_state_from_script(artifact, output.script)
            if state is not None:
                contract._state = state

        return contract

    def get_locking_script(self) -> str:
        """Return the full locking script hex."""
        script = self._code_script or self._build_code_script()

        if self.artifact.state_fields:
            state_hex = serialize_state(self.artifact.state_fields, self._state)
            if state_hex:
                script += '6a'  # OP_RETURN
                script += state_hex

        return script

    def build_unlocking_script(self, method_name: str, args: list) -> str:
        """Build the unlocking script for a method call."""
        script = ''
        for arg in args:
            script += _encode_arg(arg)

        public_methods = self._get_public_methods()
        if len(public_methods) > 1:
            method_index = -1
            for i, m in enumerate(public_methods):
                if m.name == method_name:
                    method_index = i
                    break
            if method_index < 0:
                raise ValueError(
                    f"build_unlocking_script: public method '{method_name}' not found"
                )
            script += _encode_script_number(method_index)

        return script

    def get_state(self) -> dict:
        """Return a copy of the current state."""
        return dict(self._state)

    def set_state(self, new_state: dict) -> None:
        """Update state values directly."""
        self._state.update(new_state)

    # -- Private helpers --

    def _build_code_script(self) -> str:
        script = self.artifact.script

        if self.artifact.constructor_slots:
            slots = sorted(self.artifact.constructor_slots, key=lambda s: s.byte_offset, reverse=True)
            for slot in slots:
                encoded = _encode_arg(self._constructor_args[slot.param_index])
                hex_offset = slot.byte_offset * 2
                script = script[:hex_offset] + encoded + script[hex_offset + 2:]
        else:
            for arg in self._constructor_args:
                script += _encode_arg(arg)

        return script

    def _find_method(self, name: str):
        for m in self.artifact.abi.methods:
            if m.name == name and m.is_public:
                return m
        return None

    def _get_public_methods(self):
        return [m for m in self.artifact.abi.methods if m.is_public]


# ---------------------------------------------------------------------------
# Argument encoding
# ---------------------------------------------------------------------------

def _encode_arg(value) -> str:
    if isinstance(value, bool):
        return '51' if value else '00'
    if isinstance(value, int):
        return _encode_script_number(value)
    if isinstance(value, str):
        return encode_push_data(value)
    if isinstance(value, bytes):
        return encode_push_data(value.hex())
    return encode_push_data(str(value))


def _encode_script_number(n: int) -> str:
    """Encode an integer as a Bitcoin Script opcode or push data."""
    if n == 0:
        return '00'  # OP_0
    if 1 <= n <= 16:
        return f'{0x50 + n:02x}'
    if n == -1:
        return '4f'  # OP_1NEGATE

    negative = n < 0
    abs_val = abs(n)

    result_bytes = []
    while abs_val > 0:
        result_bytes.append(abs_val & 0xFF)
        abs_val >>= 8

    if result_bytes[-1] & 0x80:
        result_bytes.append(0x80 if negative else 0x00)
    elif negative:
        result_bytes[-1] |= 0x80

    data_hex = bytes(result_bytes).hex()
    return encode_push_data(data_hex)
