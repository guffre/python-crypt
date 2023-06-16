import hashlib

# Testing with a password >64 characters
key = b"passpasspasspasspasspasspasspasspasspasspasspasspasspasspasspasspass"
salt = b"saltsalt"

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
print(hashlib.sha512(ctx).hexdigest())

alt_ctx = b""
cnt = 0
while (cnt < len(key)):
    alt_ctx += key
    cnt += 1

temp_result = hashlib.sha512(alt_ctx)
print(temp_result.hexdigest())
temp_result = temp_result.digest()