# frozen_string_literal: true

# PriceBet unit tests.
#
# Tests the PriceBet contract business logic directly (no on-chain deployment).
# Rabin signing and verification use the same deterministic test keypair as
# the TypeScript and Go test suites. ECDSA check_sig uses real signatures from
# Runar::TestKeys.

require 'spec_helper'
require 'digest'
require_relative 'PriceBet.runar.rb'

# ---------------------------------------------------------------------------
# Rabin helpers (mirrors integration/ruby/spec/spec_helper.rb)
# ---------------------------------------------------------------------------

def buffer_to_unsigned_le(buf)
  result = 0
  buf.each_byte.with_index { |byte, i| result += byte << (i * 8) }
  result
end

def quadratic_residue?(a, p_val)
  return true if a % p_val == 0

  a.pow((p_val - 1) / 2, p_val) == 1
end

def chinese_remainder(a1, m1, a2, m2)
  m  = m1 * m2
  p1 = m2.pow(m1 - 2, m1)
  p2 = m1.pow(m2 - 2, m2)
  (a1 * m2 * p1 + a2 * m1 * p2) % m
end

# Generate the deterministic Rabin test keypair.
# Uses 130-bit primes matching the TypeScript and Go helpers.
def generate_rabin_key_pair
  p_val = 1361129467683753853853498429727072846227
  q_val = 1361129467683753853853498429727082846007
  { p: p_val, q: q_val, n: p_val * q_val }
end

# Sign a binary message with a Rabin keypair.
# Returns { sig: Integer, padding: Integer }.
def rabin_sign(msg_bytes, kp)
  p_val = kp[:p]
  q_val = kp[:q]
  n     = kp[:n]
  h        = Digest::SHA256.digest(msg_bytes)
  hash_bn  = buffer_to_unsigned_le(h)

  1000.times do |padding|
    target = (hash_bn - padding) % n
    target += n if target < 0
    next unless quadratic_residue?(target, p_val) && quadratic_residue?(target, q_val)

    sp  = target.pow((p_val + 1) / 4, p_val)
    sq  = target.pow((q_val + 1) / 4, q_val)
    sig = chinese_remainder(sp, p_val, sq, q_val)

    return { sig: sig, padding: padding } if (sig * sig + padding) % n == hash_bn % n

    sig_alt = n - sig
    return { sig: sig_alt, padding: padding } if (sig_alt * sig_alt + padding) % n == hash_bn % n
  end

  raise 'Rabin sign: no valid padding found within 1000 attempts'
end

# Convert a non-negative integer to an unsigned little-endian hex string.
# This matches Bitcoin Script's LE byte representation used throughout Runar.
def int_to_unsigned_le_hex(n)
  return '00' if n.zero?

  bytes = []
  v = n
  while v > 0
    bytes << (v & 0xFF)
    v >>= 8
  end
  bytes.map { |b| format('%02x', b) }.join
end

# Encode a price as 8-byte little-endian binary — matches num2bin(price, 8).
# Used to produce the message bytes that the Rabin oracle signs.
def price_to_msg_bytes(price)
  result = Array.new(8, 0)
  v = price
  8.times do |i|
    result[i] = v & 0xFF
    v >>= 8
  end
  result.pack('C*')
end

# Sign a price with the Rabin keypair and return { rabin_sig_hex:, padding_hex: }.
def sign_price(price, kp)
  msg_bytes = price_to_msg_bytes(price)
  result    = rabin_sign(msg_bytes, kp)
  {
    rabin_sig_hex: int_to_unsigned_le_hex(result[:sig]),
    padding_hex:   int_to_unsigned_le_hex(result[:padding])
  }
end

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

RABIN_KP      = generate_rabin_key_pair.freeze
ORACLE_PUB_HEX = int_to_unsigned_le_hex(RABIN_KP[:n]).freeze
STRIKE_PRICE  = 50_000

ALICE_PUB = Runar::TestKeys::ALICE.pub_key.freeze
BOB_PUB   = Runar::TestKeys::BOB.pub_key.freeze
ALICE_SIG = Runar::TestKeys::ALICE.test_sig.freeze
BOB_SIG   = Runar::TestKeys::BOB.test_sig.freeze

def make_bet
  PriceBet.new(ALICE_PUB, BOB_PUB, ORACLE_PUB_HEX, STRIKE_PRICE)
end

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

RSpec.describe PriceBet do
  describe '#settle' do
    it 'succeeds when price exceeds strike (Alice wins)' do
      signed = sign_price(60_000, RABIN_KP)

      expect do
        make_bet.settle(60_000, signed[:rabin_sig_hex], signed[:padding_hex], ALICE_SIG, BOB_SIG)
      end.not_to raise_error
    end

    it 'succeeds when price is below strike (Bob wins)' do
      signed = sign_price(30_000, RABIN_KP)

      expect do
        make_bet.settle(30_000, signed[:rabin_sig_hex], signed[:padding_hex], ALICE_SIG, BOB_SIG)
      end.not_to raise_error
    end

    it 'fails when the oracle public key is wrong' do
      # Sign with the correct key but construct the contract with a different modulus.
      # Adding 1 to n produces a value that is not the actual Rabin modulus, so the
      # verify_rabin_sig check fails even though the signature itself is valid.
      wrong_n_hex = int_to_unsigned_le_hex(RABIN_KP[:n] + 1)

      bet    = PriceBet.new(ALICE_PUB, BOB_PUB, wrong_n_hex, STRIKE_PRICE)
      signed = sign_price(60_000, RABIN_KP)

      expect do
        bet.settle(60_000, signed[:rabin_sig_hex], signed[:padding_hex], ALICE_SIG, BOB_SIG)
      end.to raise_error(RuntimeError, 'runar: assertion failed')
    end
  end

  describe '#cancel' do
    it 'succeeds when both signatures are valid' do
      expect do
        make_bet.cancel(ALICE_SIG, BOB_SIG)
      end.not_to raise_error
    end

    it 'fails when the alice signature is wrong' do
      wrong_sig = Runar::TestKeys::CHARLIE.test_sig

      expect do
        make_bet.cancel(wrong_sig, BOB_SIG)
      end.to raise_error(RuntimeError, 'runar: assertion failed')
    end
  end
end
