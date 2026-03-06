import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "FungibleTokenExample.runar.py"))
FungibleToken = contract_mod.FungibleToken

from runar import mock_sig, mock_pub_key


def test_transfer():
    c = FungibleToken(owner=mock_pub_key(), balance=1000, token_id=b'\xab' * 16)
    recipient = b'\x03' + b'\x01' * 32
    c.transfer(mock_sig(), recipient, 300, 546)
    assert len(c._outputs) == 2


def test_transfer_exceeds_balance_fails():
    c = FungibleToken(owner=mock_pub_key(), balance=100, token_id=b'\xab' * 16)
    with pytest.raises(AssertionError):
        c.transfer(mock_sig(), mock_pub_key(), 200, 546)


def test_send():
    c = FungibleToken(owner=mock_pub_key(), balance=1000, token_id=b'\xab' * 16)
    recipient = b'\x03' + b'\x01' * 32
    c.send(mock_sig(), recipient, 546)
    assert len(c._outputs) == 1
