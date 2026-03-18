const runar = @import("runar");

pub const FunctionPatterns = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey,
    balance: i64 = 0,

    pub fn init(owner: runar.PubKey, balance: i64) FunctionPatterns {
        return .{ .owner = owner, .balance = balance };
    }

    fn requireOwner(self: *const FunctionPatterns, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }

    fn computeFee(amount: i64, feeBps: i64) i64 {
        return runar.percentOf(amount, feeBps);
    }

    fn scaleValue(value: i64, numerator: i64, denominator: i64) i64 {
        return runar.mulDiv(value, numerator, denominator);
    }

    fn clampValue(value: i64, lo: i64, hi: i64) i64 {
        return runar.clamp(value, lo, hi);
    }

    fn roundDown(value: i64, step: i64) i64 {
        const remainder = runar.safemod(value, step);
        return value - remainder;
    }

    pub fn deposit(self: *FunctionPatterns, sig: runar.Sig, amount: i64) void {
        self.requireOwner(sig);
        runar.assert(amount > 0);
        self.balance = self.balance + amount;
    }

    pub fn withdraw(self: *FunctionPatterns, sig: runar.Sig, amount: i64, feeBps: i64) void {
        self.requireOwner(sig);
        runar.assert(amount > 0);
        const fee = computeFee(amount, feeBps);
        const total = amount + fee;
        runar.assert(total <= self.balance);
        self.balance = self.balance - total;
    }

    pub fn scale(self: *FunctionPatterns, sig: runar.Sig, numerator: i64, denominator: i64) void {
        self.requireOwner(sig);
        self.balance = scaleValue(self.balance, numerator, denominator);
    }

    pub fn normalizeBalance(self: *FunctionPatterns, sig: runar.Sig, lo: i64, hi: i64, step: i64) void {
        self.requireOwner(sig);
        const clamped = clampValue(self.balance, lo, hi);
        self.balance = roundDown(clamped, step);
    }
};
