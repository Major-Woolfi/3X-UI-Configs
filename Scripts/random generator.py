import secrets

x = secrets.token_hex(32)
y = secrets.token_hex(32)
z = secrets.token_hex(16)

print("32 HEX:", x)
print("32 HEX:", y)
print("16 HEX:", z)

input()
