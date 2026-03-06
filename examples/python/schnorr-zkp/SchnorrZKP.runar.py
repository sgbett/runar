from runar import (
    SmartContract, Point, Bigint, public, assert_,
    ec_add, ec_mul, ec_mul_gen, ec_point_x, ec_point_y, ec_on_curve,
)

class SchnorrZKP(SmartContract):
    pub_key: Point

    def __init__(self, pub_key: Point):
        super().__init__(pub_key)
        self.pub_key = pub_key

    @public
    def verify(self, r_point: Point, s: Bigint, e: Bigint):
        assert_(ec_on_curve(r_point))
        s_g = ec_mul_gen(s)
        e_p = ec_mul(self.pub_key, e)
        rhs = ec_add(r_point, e_p)
        assert_(ec_point_x(s_g) == ec_point_x(rhs))
        assert_(ec_point_y(s_g) == ec_point_y(rhs))
