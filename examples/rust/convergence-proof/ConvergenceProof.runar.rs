use runar::prelude::*;

/// OPRF-based fraud signal convergence proof.
///
/// Two parties submit randomized tokens R_A = (T + o_A)*G and R_B = (T + o_B)*G.
/// An authority proves the submissions share the same underlying token T by
/// providing delta_o = o_A - o_B and verifying: R_A - R_B = delta_o * G.
#[runar::contract]
pub struct ConvergenceProof {
    #[readonly]
    pub r_a: Point,
    #[readonly]
    pub r_b: Point,
}

#[runar::methods(ConvergenceProof)]
impl ConvergenceProof {
    /// Prove convergence via offset difference.
    #[public]
    pub fn prove_convergence(&self, delta_o: Bigint) {
        assert!(ec_on_curve(&self.r_a));
        assert!(ec_on_curve(&self.r_b));

        // R_A - R_B (point subtraction = add + negate)
        let diff = ec_add(&self.r_a, &ec_negate(&self.r_b));

        // delta_o * G
        let expected = ec_mul_gen(delta_o);

        // Assert point equality via coordinates
        assert!(ec_point_x(&diff) == ec_point_x(&expected));
        assert!(ec_point_y(&diff) == ec_point_y(&expected));
    }
}
