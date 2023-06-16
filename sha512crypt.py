import hashlib
import binascii

# Testing with a password >64 characters
key = b"pass"
salt = b"saltsalt"
rounds = 5000

ctx = key + salt
alt_ctx = key + salt + key

# Testing with both "hash.update" and just appending the string
# Not sure which I will ultimately decide to use
result = hashlib.sha512(ctx)
alt_result = hashlib.sha512(alt_ctx).digest()
print("alt result: ", hashlib.sha512(alt_ctx).hexdigest())

# All below code is mimic-ing the C source.
# I will update this with more "pythonic" code when I finish translating all the C
cnt = len(key)
while cnt > 64:
    print("alternate sum!")
    ctx += alt_result[:64]
    result.update(alt_result[:64])
    cnt -= 64

ctx += alt_result[:cnt]
result.update(alt_result[:cnt])

cnt = len(key)
while cnt > 0:
    if (cnt & 1) != 0:
        print("IF")
        ctx += alt_result[:64]
        result.update(alt_result[:64])
    else:
        print("ELSE")
        ctx += key
        result.update(key)
    cnt = cnt >> 1

# INTERMEDIATE RESULTS
print("Intermediate Results")
alt_result = hashlib.sha512(ctx).digest()
print(hashlib.sha512(ctx).hexdigest())

alt_ctx = b""
cnt = 0
while (cnt < len(key)):
    alt_ctx += key
    cnt += 1

temp_result = hashlib.sha512(alt_ctx)
print(temp_result.hexdigest())
temp_result = temp_result.digest()

p_bytes = b""
for n in range(len(key)):
    p_bytes += temp_result[n%len(temp_result):n+1]
#p_bytes = b"".join([temp_result[n%len(temp_result)] for n in range(len(key))])


alt_ctx = b""
cnt = 0
while (cnt < 16 + alt_result[0]):
    alt_ctx += salt
    cnt += 1

temp_result = hashlib.sha512(alt_ctx).digest()
print(binascii.hexlify(temp_result))
#s_bytes = b"".join([temp_result[n%len(temp_result)] for n in range(len(salt))])
s_bytes = b""
for n in range(len(salt)):
    s_bytes += temp_result[n%len(temp_result):n+1]

cnt = 0
while cnt < rounds:
    ctx = b""
    if ((cnt & 1) != 0):
        ctx += p_bytes[:len(key)]
    else:
        ctx += alt_result[:64]
    if (cnt % 3 != 0):
        ctx += s_bytes[:len(salt)]
    if (cnt % 7 != 0):
        ctx += p_bytes[:len(key)]
    if ((cnt & 1) != 0):
        ctx += alt_result[:64]
    else:
        ctx += p_bytes[:len(key)]
    alt_result = hashlib.sha512(ctx).digest()
    cnt += 1

print("Final result:", binascii.hexlify(alt_result))
