from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "SchnorrZKP.runar.py"))
SchnorrZKP = contract_mod.SchnorrZKP

from runar import ec_mul_gen, EC_N


def test_schnorr_verify():
    # Private key k, public key P = k*G
    k = 12345
    pub_key = ec_mul_gen(k)

    # Prover: pick random r, compute R = r*G
    r = 67890
    r_point = ec_mul_gen(r)

    # Challenge e (in real protocol, hash of R and message)
    e = 42

    # Response s = r + e*k (mod n)
    s = (r + e * k) % EC_N

    c = SchnorrZKP(pub_key=pub_key)
    c.verify(r_point, s, e)
