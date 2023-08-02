from gmpy2 import invert
p = 473398607161
q = 4511491
s = (p - 1) * (q - 1)
n = p * q
e = 17
v = invert(e, s)
print(v)


