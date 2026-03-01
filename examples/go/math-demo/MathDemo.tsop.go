package contract

import "tsop"

type MathDemo struct {
	tsop.StatefulSmartContract
	Value tsop.Bigint
}

func (c *MathDemo) DivideBy(divisor tsop.Bigint) {
	c.Value = tsop.Safediv(c.Value, divisor)
}

func (c *MathDemo) WithdrawWithFee(amount, feeBps tsop.Bigint) {
	fee := tsop.PercentOf(amount, feeBps)
	total := amount + fee
	tsop.Assert(total <= c.Value)
	c.Value = c.Value - total
}

func (c *MathDemo) ClampValue(lo, hi tsop.Bigint) {
	c.Value = tsop.Clamp(c.Value, lo, hi)
}

func (c *MathDemo) Normalize() {
	c.Value = tsop.Sign(c.Value)
}

func (c *MathDemo) Exponentiate(exp tsop.Bigint) {
	c.Value = tsop.Pow(c.Value, exp)
}

func (c *MathDemo) SquareRoot() {
	c.Value = tsop.Sqrt(c.Value)
}

func (c *MathDemo) ReduceGcd(other tsop.Bigint) {
	c.Value = tsop.Gcd(c.Value, other)
}

func (c *MathDemo) ScaleByRatio(numerator, denominator tsop.Bigint) {
	c.Value = tsop.MulDiv(c.Value, numerator, denominator)
}

func (c *MathDemo) ComputeLog2() {
	c.Value = tsop.Log2(c.Value)
}
