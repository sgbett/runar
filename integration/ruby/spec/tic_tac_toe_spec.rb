# frozen_string_literal: true

# TicTacToe integration test -- two-player stateful game contract.
#
# TicTacToe is a StatefulSmartContract with:
#   - playerX: PubKey (readonly), betAmount: bigint (readonly)
#   - playerO: PubKey (mutable), c0-c8: bigint (board), turn/status: bigint
#
# Methods: join, move, moveAndWin, moveAndTie, cancelBeforeJoin, cancel

require 'spec_helper'

RSpec.describe 'TicTacToe' do # rubocop:disable RSpec/DescribeClass
  it 'deploys with playerX and betAmount' do
    artifact = compile_contract('examples/ts/tic-tac-toe/TicTacToe.runar.ts')

    provider = create_provider
    player_x = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [player_x[:pub_key_hex], 5000])

    txid, _count = contract.deploy(provider, player_x[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))
    expect(txid).to be_truthy
    expect(txid.length).to eq(64)
  end

  it 'joins the game as player O' do
    artifact = compile_contract('examples/ts/tic-tac-toe/TicTacToe.runar.ts')

    provider = create_provider
    player_x = create_funded_wallet(provider)
    player_o = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [player_x[:pub_key_hex], 5000])
    contract.deploy(provider, player_x[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    call_txid, _count = contract.call(
      'join', [player_o[:pub_key_hex], nil], provider, player_o[:signer]
    )
    expect(call_txid).to be_truthy
    expect(call_txid.length).to eq(64)
  end

  it 'makes a move after join' do
    artifact = compile_contract('examples/ts/tic-tac-toe/TicTacToe.runar.ts')

    provider = create_provider
    player_x = create_funded_wallet(provider)
    player_o = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [player_x[:pub_key_hex], 5000])
    contract.deploy(provider, player_x[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call('join', [player_o[:pub_key_hex], nil], provider, player_o[:signer])

    # Player X moves to center (position 4)
    move_txid, _count = contract.call(
      'move', [4, player_x[:pub_key_hex], nil], provider, player_x[:signer],
      Runar::SDK::CallOptions.new(new_state: { 'c4' => 1, 'turn' => 2 })
    )
    expect(move_txid).to be_truthy
    expect(move_txid.length).to eq(64)
  end

  it 'rejects move by wrong player' do
    artifact = compile_contract('examples/ts/tic-tac-toe/TicTacToe.runar.ts')

    provider = create_provider
    player_x = create_funded_wallet(provider)
    player_o = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [player_x[:pub_key_hex], 5000])
    contract.deploy(provider, player_x[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call('join', [player_o[:pub_key_hex], nil], provider, player_o[:signer])

    # Player O tries to move when it's X's turn
    expect do
      contract.call('move', [4, player_o[:pub_key_hex], nil], provider, player_o[:signer])
    end.to raise_error(StandardError)
  end

  it 'rejects join when game is already playing' do
    artifact = compile_contract('examples/ts/tic-tac-toe/TicTacToe.runar.ts')

    provider = create_provider
    player_x = create_funded_wallet(provider)
    player_o = create_funded_wallet(provider)

    contract = Runar::SDK::RunarContract.new(artifact, [player_x[:pub_key_hex], 5000])
    contract.deploy(provider, player_x[:signer], Runar::SDK::DeployOptions.new(satoshis: 5000))

    contract.call('join', [player_o[:pub_key_hex], nil], provider, player_o[:signer])

    another = create_funded_wallet(provider)
    expect do
      contract.call('join', [another[:pub_key_hex], nil], provider, another[:signer])
    end.to raise_error(StandardError)
  end
end
