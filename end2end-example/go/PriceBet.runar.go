package contract

import "runar"

type PriceBet struct {
	runar.SmartContract
	AlicePubKey  runar.PubKey      `runar:"readonly"`
	BobPubKey    runar.PubKey      `runar:"readonly"`
	OraclePubKey runar.RabinPubKey `runar:"readonly"`
	StrikePrice  runar.Bigint      `runar:"readonly"`
}

func (c *PriceBet) Settle(price runar.Bigint, rabinSig runar.RabinSig, padding runar.ByteString, aliceSig runar.Sig, bobSig runar.Sig) {
	msg := runar.Num2Bin(price, 8)
	runar.Assert(runar.VerifyRabinSig(msg, rabinSig, padding, c.OraclePubKey))

	runar.Assert(price > 0)

	if price > c.StrikePrice {
		runar.Assert(runar.CheckSig(aliceSig, c.AlicePubKey))
	} else {
		runar.Assert(runar.CheckSig(bobSig, c.BobPubKey))
	}
}

func (c *PriceBet) Cancel(aliceSig runar.Sig, bobSig runar.Sig) {
	runar.Assert(runar.CheckSig(aliceSig, c.AlicePubKey))
	runar.Assert(runar.CheckSig(bobSig, c.BobPubKey))
}
