require 'runar'

class SchnorrZKP < Runar::SmartContract
  prop :pub_key, Point

  def initialize(pub_key)
    super(pub_key)
    @pub_key = pub_key
  end

  runar_public r_point: Point, s: Bigint, e: Bigint
  def verify(r_point, s, e)
    assert ec_on_curve(r_point)
    s_g = ec_mul_gen(s)
    e_p = ec_mul(@pub_key, e)
    rhs = ec_add(r_point, e_p)
    assert ec_point_x(s_g) == ec_point_x(rhs)
    assert ec_point_y(s_g) == ec_point_y(rhs)
  end
end
