-- Literal arithmetic, checked by the kernel's Nat extension.
theorem two_add_two : 2 + 2 = 4 := rfl

-- Cites a core library lemma, so its proof comes along as a dependency.
theorem add_comm_ex (a b : Nat) : a + b = b + a := Nat.add_comm a b

-- Self-contained: own naturals, proof by induction.
inductive MyNat where
  | zero : MyNat
  | succ : MyNat → MyNat

def MyNat.add : MyNat → MyNat → MyNat
  | n, .zero => n
  | n, .succ m => .succ (MyNat.add n m)

theorem MyNat.zero_add (n : MyNat) : MyNat.add .zero n = n := by
  induction n with
  | zero => rfl
  | succ m ih => simp [MyNat.add, ih]

-- Heavier: list reversal and a gcd fact from the core library.
theorem rev_rev_ex (l : List Nat) : l.reverse.reverse = l := List.reverse_reverse l

theorem gcd_comm_ex (a b : Nat) : Nat.gcd a b = Nat.gcd b a := Nat.gcd_comm a b
