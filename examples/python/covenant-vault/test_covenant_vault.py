from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "CovenantVault.runar.py"))
CovenantVault = contract_mod.CovenantVault

from runar import mock_sig, mock_pub_key, mock_preimage, hash160


def test_spend_valid():
    c = CovenantVault(
        owner=mock_pub_key(),
        recipient=hash160(mock_pub_key()),
        min_amount=1000,
    )
    c.spend(mock_sig(), 5000, mock_preimage())
