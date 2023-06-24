import blowfish
import base64
import string
import os

class bcrypt(object):
    def __init__(self, key, salt):
        self.BCRYPT_MAXSALT = 16
        self.BCRYPT_WORDS = 6

    def gensalt(self, rounds):
        csalt = os.urandom(self.BCRYPT_MAXSALT)
        rounds = min(max(4,rounds),31) # rounds must be between 4-31
        encoded = self.encode_base64(csalt).decode()
        salt = "$2b${:02d}${}".format(rounds, encoded)
        return salt

    def hashpass(self, key, salt):
        ciphertext = bytearray(b"OrpheanBeholderScryDoubt")
        key = bytearray(key)
        if (salt[0] != '$'):
            return None
        if (salt[1] != "2"):
            return None
        # Check for minor versions 
        if salt[2] == 'a':
            key_len = (u_int8_t)(strlen(key) + 1);
        elif salt[2] ==  'b':
            key_len = len(key)
            if (key_len > 72):
                key_len = 72
            key_len += 1 # include the NULL
            key += b"\0"
        else:
             return 3
        minor = salt[2]
        if (salt[3] != '$'):
            return None
        salt = salt[4:]
        # Check and parse num rounds
        if not (str.isdigit(salt[0]) and str.isdigit(salt[1]) and salt[2] == '$'):
            return None
        logr = int(salt[:2])
        if (logr < 4 or logr > 31):
            return None
        
        rounds = 1 << logr

        # Discard num rounds + "$" identifier
        salt = salt[3:]

        # Ignore for testing
        if (len(salt) * 3 / 4 < self.BCRYPT_MAXSALT):
            return None

        # We dont want the base64 salt but the raw data
        csalt = bytearray(self.decode_base64(salt))
        if (csalt == None):
            return None
        salt_len = self.BCRYPT_MAXSALT
        csalt = csalt[:self.BCRYPT_MAXSALT]
        print(csalt, len(csalt))
        

        # Setting up S-Boxes and Subkeys
        Blowfish = blowfish.blowfish()
        Blowfish.expandstate(csalt, salt_len, key, key_len)
        for k in range(rounds):
            Blowfish.expand0state(key, key_len)
            Blowfish.expand0state(csalt, salt_len)

        # This can be precomputed later
        Blowfish.current = 0
        cdata = list()
        for i in range(self.BCRYPT_WORDS):
            cdata.append(Blowfish.stream2word(ciphertext, 4 * self.BCRYPT_WORDS, Blowfish.current))

        # Now do the encryption 
        for k in range(64):
            Blowfish.blf_enc(cdata, int(self.BCRYPT_WORDS / 2))      

        for i in range(self.BCRYPT_WORDS):
            ciphertext[4 * i + 3] = cdata[i] & 0xff
            cdata[i] = cdata[i] >> 8
            ciphertext[4 * i + 2] = cdata[i] & 0xff
            cdata[i] = cdata[i] >> 8
            ciphertext[4 * i + 1] = cdata[i] & 0xff
            cdata[i] = cdata[i] >> 8
            ciphertext[4 * i + 0] = cdata[i] & 0xff

        encrypted = "$2{}${:02d}$".format(minor, logr)
        encrypted += (self.encode_base64(csalt[:self.BCRYPT_MAXSALT])).decode()
        encrypted += (self.encode_base64(ciphertext[:4 * self.BCRYPT_WORDS - 1])).decode()
        print(encrypted)
        return 0

    @staticmethod
    def decode_base64(data):
        trans = string if bytes == str else bytes
        bcrypt_base = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        normal_base = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        data = data.translate(trans.maketrans(bcrypt_base,normal_base))
        ret = base64.b64decode(data+"==")
        return ret
    
    @staticmethod
    def encode_base64(data):
        trans = string if bytes == str else bytes
        bcrypt_base = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        normal_base = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        ret = base64.b64encode(data)
        ret = ret.translate(trans.maketrans(normal_base, bcrypt_base)).replace(b"=",b"")
        return ret

if __name__ == "__main__":
    b = blowfish.blowfish()

    key = bytearray(b"AAAAA")
    key2 = bytearray(b"abcdefghijklmnopqrstuvwxyz")

    data = [i for i in range(10)]
    data2 = [0x424c4f57, 0x46495348]

    # First test
    #blf_key(&c, (u_int8_t *) key, 5);
    #blf_enc(&c, data, 5);
    #blf_dec(&c, data, 1);
    #blf_dec(&c, data + 2, 4);
    #printf("Should read as 0 - 9.\n");
    #report(data, 10);

    # Second test
    b.blf_key(key2, len(key2))
    b.blf_enc(data2, 1)
    print("\nShould read as: 0x324ed0fe 0xf413a203.\n");
    print([hex(n) for n in data2])
    
    b = bcrypt(1,2)
    b.hashpass(b"password","$2b$04$22pb8uzFKQF5LlzGqDcHhu")