import Proofs.Statements

/-! Honest solutions: each proves its statement as a theorem whose type is the statement constant. -/

theorem goal_two : GoalTwo := by unfold GoalTwo; rfl

theorem goal_add_comm : GoalAddComm := by
  unfold GoalAddComm; intro a b; exact Nat.add_comm a b

theorem goal_gcd : GoalGcd := by
  unfold GoalGcd; intro a b; exact Nat.gcd_comm a b

theorem goal_f : GoalF := by
  unfold GoalF myF; intro n; exact Nat.succ_ne_zero n

/-! Dishonest submissions that still type-check on their own. -/

-- Proves something, just not the statement.
theorem goal_wrong : True := trivial

-- Not a theorem.
def goal_def : GoalTwo := by unfold GoalTwo; rfl

-- An extra axiom.
axiom extra_axiom : False
theorem goal_axiom : GoalGcd := extra_axiom.elim

-- `sorry`.
theorem goal_sorry : GoalGcd := sorry
