# crypt.py
The `crypt.py` script will generate md5-crypt, sha256-crypt, and sha512-crypt hashes. This is using vanilla python, so it will work on Windows as well. Also, I like Python 2 so it works in both Python2 and Python3.
Todo: The only thing I am missing is Blowfish to completely reimplement the whole `crypt` function, I'll work on that. This is complicated since theres no `hashlib.blowfish`. I will probably just implement Blowfish in python and then use that.

# bcrypt.py and blowfish.py
These are a native Python implementation of blowfish and bcrypt. Obviously blowfish will run slower in pure Python than in C, but I wanted to do it. Currently only supports the "$2b$" hash-type, but I might work on implementing "$2a$" as well.

# Why?
To learn! Sometimes in discussion, the concept of "salting" a password comes up. In a similar vein, sometimes the question of "why dont linux password hashes look like a md5/sha hash digest?" also rises.
I knew conceptually how to answer these questions: salting "adds" to a password to help prevent precomputed attacks like rainbow tables, and the linux crypt hashes are actually base64'd.

My simple explanation was:

    hash = sha512(salt+password)
    for _ in range(5000):
        hash = sha512(hash)
    base64(hash)

But! I had never looked at the codebase to understand EXACTLY how sha512-crypt worked.
Thus this little project was born.

# How?
I found the source code of sha512-crypt here: https://elixir.bootlin.com/glibc/latest/source/crypt

From that start, I analyzed it and converted it over to Python.
After finishing the sha512-crypt portion, I took a peek at sha256-crypt. I found that the code was mostly identical, so I included it!
In the C portion of the code, I removed most of the codebase since the only thing I am interested in is producing sha512-crypt hashes, like on a linux machine.

Most of the edits to the source are just `printf` to output "Hey this is what the hash output looks like".

# How To Use
You can use the python code like a library, but since I included a `if __name__ == "__main__"` you can also use it on the commandline:

    Usage: ./crypt.py <password> <hash> <rounds>
    # Note: rounds is optional, it defaults to 5000 (or hardcoded to 1000 for md5)
    
![image](https://github.com/guffre/sha512crypt/assets/21281361/ee18c956-0a3a-429c-8b36-d14b26a32a08)

# How To Build (the C program in the sha512crypt folder)
The C code only supports sha512-crypt. I just needed something to test with since I didn't want to do complete static analysis.
I included the source here in case anyone else wants to go down that path.

    ./run <password> <salt> <rounds>
    ./run password saltsalt 0

This lets you do 0 rounds, I wanted this for testing purposes. You can also have any length salt.
