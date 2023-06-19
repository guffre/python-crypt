import hashlib
import base64
import string

def make_bytes(data, rounds, hash):
    """ Used to make p_bytes and s_bytes for the sha hashing rounds"""
    alt_ctx = hash()
    for n in range(rounds):
        alt_ctx.update(data)
    temp_result = alt_ctx.digest()
        
    tmp_bytes = b"".join(temp_result[n%len(temp_result):n+1] for n in range(len(data)))
    return tmp_bytes

def crypt_base64(buffer):
    """The custom base64 that is specific to these crypt algorithms
       I know it looks weird, but this is apparently what the spec is"""
    unix_crypt_base = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    normal_base     = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    ret = b""
    if len(buffer) == 32:
        c1 = [(n*21+00)%30 for n in range(10)]
        c2 = [(n*21+10)%30 for n in range(10)]
        c3 = [(n*21+20)%30 for n in range(10)]
    elif len(buffer) == 64:
        c1 = [(n*22+00)%63 for n in range(21)]
        c2 = [(n*22+21)%63 for n in range(21)]
        c3 = [(n*22+42)%63 for n in range(21)]
    else:
        return None
    for block in zip(c1, c2, c3):
        collect = b''.join(buffer[n:n+1] for n in block)
        ret += base64.b64encode(collect)[::-1]
    if len(buffer) == 32:
        ret += base64.b64encode(b"0"+buffer[31:32]+buffer[30:31])[::-1][:2]
    elif len(buffer) == 64:
        ret += base64.b64encode(b"00"+buffer[63:64])[::-1][:2]
    # Python 2/3 compatability
    trans = string if bytes == str else bytes
    ret = ret.translate(trans.maketrans(normal_base,unix_crypt_base))
    return ret

def crypt_sha512(key, salt, rounds=5000, hash=hashlib.sha512):
    """ sha512-crypt and sha256-crypt both have the exact same pattern
        This function allows you to do both, but defaults to sha512-crypt"""
    # Initialize the two contexts
    ctx        = hash(key + salt)
    alt_ctx    = hash(key + salt + key)
    alt_result = alt_ctx.digest()

    # Add hash-bytes of second context to first
    cnt = len(key)
    while cnt > ctx.digest_size:
        ctx.update(alt_result)
        cnt -= ctx.digest_size
    ctx.update(alt_result[:cnt])

    # Iterates through the binary representation of the key
    # If binary 1, add the "alternate sum"; if binary 0, add the key
    cnt = len(key)
    while cnt > 0:
        if (cnt & 1) != 0:
            ctx.update(alt_result)
        else:
            ctx.update(key)
        cnt = cnt >> 1

    # Create byte arrays. These will be used in the rounds of hashing
    alt_result = ctx.digest()
    offset = ord(alt_result[0]) if isinstance(alt_result, str) else alt_result[0]
    p_bytes = make_bytes(key, len(key), hash)
    s_bytes = make_bytes(salt, 16 + offset, hash)

    # Perform rounds of hashing
    for cnt in range(rounds):
        ctx = hash()
        if ((cnt & 1) != 0):
            ctx.update(p_bytes)
        else:
            ctx.update(alt_result)
        if (cnt % 3 != 0):
            ctx.update(s_bytes)
        if (cnt % 7 != 0):
            ctx.update(p_bytes)
        if ((cnt & 1) != 0):
            ctx.update(alt_result)
        else:
            ctx.update(p_bytes)
        alt_result = ctx.digest()

    # Crypt-base64 the hash digest
    encoded = crypt_base64(alt_result).decode()

    # Make some nice output
    hashnumber = 5 if hash == hashlib.sha256 else 6
    if rounds == 5000:
        formatted = "${}${}${}".format(hashnumber,salt.decode(),encoded)
    else:
        rounds = "rounds={}".format(rounds)
        formatted = "${}${}${}${}".format(hashnumber,rounds,salt.decode(),encoded)
    return (alt_result,formatted)

if __name__ == '__main__':
    import binascii
    import sys
    try:
        key  = sys.argv[1].encode()
        salt = sys.argv[2].encode()
        if len(sys.argv) == 4:
            rounds = int(sys.argv[3])
        else:
            rounds = 5000
        digest,hash = crypt_sha512(key, salt, rounds)
        print("sha512-crypt digest: {}".format(binascii.hexlify(digest)))
        print("sha512-crypt hash: {}".format(hash))
        digest,hash = crypt_sha512(key, salt, rounds, hashlib.sha256)
        print("sha256-crypt digest: {}".format(binascii.hexlify(digest)))
        print("sha256-crypt hash: {}".format(hash))
    except:
        print("Usage: ./{} <password> <hash> <rounds>".format(sys.argv[0]))