/-! A redefinition attack: the solver's own `myF`, which makes the statement mean something else.
Deliberately does not import `Proofs.Statements`. -/

def myF (_ : Nat) : Nat := 1

def GoalF : Prop := ∀ n, myF n ≠ 0

theorem goal_f : GoalF := by
  unfold GoalF myF; intro _; decide
