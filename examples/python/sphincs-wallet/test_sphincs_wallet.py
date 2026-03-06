from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "SPHINCSWallet.runar.py"))
SPHINCSWallet = contract_mod.SPHINCSWallet


def test_spend():
    c = SPHINCSWallet(pubkey=b'\x00' * 32)
    # verify_slh_dsa_sha2_128s is mocked to return True
    c.spend(b'hello', b'\x00' * 7856)
