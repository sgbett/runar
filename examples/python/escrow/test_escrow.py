import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "Escrow.runar.py"))
Escrow = contract_mod.Escrow

from runar import mock_sig, mock_pub_key


def test_release_by_seller():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.release_by_seller(mock_sig())


def test_release_by_arbiter():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.release_by_arbiter(mock_sig())


def test_refund_to_buyer():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.refund_to_buyer(mock_sig())


def test_refund_by_arbiter():
    c = Escrow(buyer=mock_pub_key(), seller=mock_pub_key(), arbiter=mock_pub_key())
    c.refund_by_arbiter(mock_sig())
