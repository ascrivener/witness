/-! Bounty statements, as the poster writes them: each is a `Prop`-valued definition.
The poster exports one (`lean4export Proofs.Statements -- GoalGcd`) as the statement environment. -/

def GoalTwo : Prop := 2 + 2 = 4

def GoalAddComm : Prop := ∀ a b : Nat, a + b = b + a

def GoalGcd : Prop := ∀ a b : Nat, Nat.gcd a b = Nat.gcd b a

-- A statement over the poster's own vocabulary, to test redefinition attacks.
def myF (n : Nat) : Nat := n + 1

def GoalF : Prop := ∀ n, myF n ≠ 0
