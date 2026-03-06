from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "PostQuantumWallet.runar.py"))
PostQuantumWallet = contract_mod.PostQuantumWallet


def test_spend():
    c = PostQuantumWallet(pubkey=b'\x00' * 32)
    # verify_wots is mocked to return True
    c.spend(b'hello', b'\x00' * 2144)
