import hashlib
import base64
import string

def make_bytes(data, length):
    """ Used to make context data for the "rounds" of sha hashing"""
    alt_ctx = hashlib.sha512()
    for n in range(length):
        alt_ctx.update(data)
    temp_result = alt_ctx.digest()
        
    tmp_bytes = b"".join(temp_result[n%len(temp_result):n+1] for n in range(length))
    return tmp_bytes

def crypt_base64(buffer):
    """The custom base64 that is specific to these crypt algorithms
       I know it looks weird, but this is apparently what the spec is"""
    unix_crypt_base = b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    normal_base     = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    ret = b""
    for n in range(0,22*21,22):
        n = n%63
        collect = b""
        for m in range(n,n+21*3,21):
            m = m%63
            collect += buffer[m:m+1]
        ret += base64.b64encode(collect)[::-1]
    ret += base64.b64encode(b"00"+buffer[63:64])[::-1][:2]
    # Python 2/3 compatability hack
    trans = string if bytes == str else bytes
    ret = ret.translate(trans.maketrans(normal_base,unix_crypt_base))
    return ret

def crypt_sha512(key, salt, rounds=5000):
    # Initialize the two contexts
    ctx        = hashlib.sha512(key + salt)
    alt_ctx    = hashlib.sha512(key + salt + key)
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
    if isinstance(alt_result, str):
        alt_result = bytearray(alt_result)
    p_bytes = make_bytes(key, len(key))
    s_bytes = make_bytes(salt, 16 + alt_result[0])[:len(salt)]

    # Perform rounds of hashing
    for cnt in range(rounds):
        ctx = hashlib.sha512()
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

    encoded = crypt_base64(alt_result)
    return (alt_result,encoded)

if __name__ == '__main__':
    import binascii
    import sys
    try:
        digest,hash = crypt_sha512(sys.argv[1].encode(), sys.argv[2].encode(), int(sys.argv[3]))
        print("Digest: {}".format(binascii.hexlify(digest)))
        print("Hash: {}".format(hash))
    except:
        print("Usage: ./{} <password> <hash> <rounds>".format(sys.argv[0]))