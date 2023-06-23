import blowfish

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