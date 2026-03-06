package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ConvergenceProof verifies OPRF-based fraud signal convergence.
//
// Two parties submit randomized tokens R_A = (T + o_A)*G and R_B = (T + o_B)*G.
// An authority proves the submissions share the same underlying token T by
// providing delta_o = o_A - o_B and verifying: R_A - R_B = delta_o * G.
type ConvergenceProof struct {
	runar.SmartContract
	RA runar.Point `runar:"readonly"`
	RB runar.Point `runar:"readonly"`
}

// ProveConvergence verifies convergence via offset difference.
func (c *ConvergenceProof) ProveConvergence(deltaO runar.Bigint) {
	runar.Assert(runar.EcOnCurve(c.RA))
	runar.Assert(runar.EcOnCurve(c.RB))

	// R_A - R_B (point subtraction = add + negate)
	diff := runar.EcAdd(c.RA, runar.EcNegate(c.RB))

	// delta_o * G
	expected := runar.EcMulGen(deltaO)

	// Assert point equality via coordinates
	runar.Assert(runar.EcPointX(diff) == runar.EcPointX(expected))
	runar.Assert(runar.EcPointY(diff) == runar.EcPointY(expected))
}
