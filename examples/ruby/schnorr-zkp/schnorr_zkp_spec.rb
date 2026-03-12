# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'SchnorrZKP.runar'

RSpec.describe SchnorrZKP do
  it 'verifies a Schnorr zero-knowledge proof' do
    # Private key k, public key P = k*G
    k = 12_345
    pub_key = ec_mul_gen(k)

    # Prover: pick random r, compute R = r*G
    r = 67_890
    r_point = ec_mul_gen(r)

    # Challenge e (in real protocol, hash of R and message)
    e = 42

    # Response s = r + e*k (mod n)
    s = (r + e * k) % EC_N

    c = SchnorrZKP.new(pub_key)
    expect { c.verify(r_point, s, e) }.not_to raise_error
  end
end
