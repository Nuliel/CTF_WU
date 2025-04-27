import sys
from hashlib import sha256
from math import isqrt
from sympy.solvers.diophantine.diophantine import diop_DN
sys.set_int_max_str_digits(31337)

# sqrt_delta**2 - D * (sqrt_k')**2 = 1

D = 12 * 2*7*23*159*487**2

# solve Pell equation
l = diop_DN(D, 1)
# get the result
sqrt_delta, sqrt_k_prime = l[0][0], l[0][1]

# evaluate all unknowns
k_prime = sqrt_k_prime**2
k = 7*23*487*k_prime
a = 487*485*k
b = 159*487*k
c = 485 * k
x = isqrt(a+b)
y = (1 + sqrt_delta) // 6

# time to verify each equation
assert a > 0
assert a == 487 * c
assert 159 * a == 485 * b
assert x ** 2 == a + b
assert y * (3 * y - 1) == 2 * b

# and get the flag
h = sha256(str(a).encode()).hexdigest()
print(f"FCSC{{{h}}}")