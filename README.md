# sha512crypt
The `sha512crypt.py` script will generate sha256-crypt and sha512-crypt hashes. This is using vanilla python, so it will work on Windows as well. Also, I like Python 2 so it works in both Python2 and Python3.

# Why?
Sometimes in discussion, the concept of "salting" a password comes up. In a similar vein, sometimes the question of "why doesnt the sha512-crypt password look like a sha512 hash digest?" rises as well.
I knew conceptually how to answer these questions: salting "adds" to a password to help prevent precomputed attacks like rainbow tables, and the sha512-crypt hash is actually base64'd.

My simple explanation was:

    hash = sha512(salt+password)
    for _ in range(5000):
        hash = sha512(hash)
    base64(hash)

But! I had never looked at the codebase to understand EXACTLY how sha512-crypt worked.
I found the source code of sha512-crypt here: https://elixir.bootlin.com/glibc/latest/source/crypt

From that start, I analyzed it and converted it over to Python.
After finishing the sha512-crypt portion, I took a peek at sha256-crypt. I found that the code was mostly identical, so I included it!
In the C portion of the code, I removed most of the codebase since the only thing I am interested in is producing sha512-crypt hashes, like on a linux machine.

Most of the edits to the source are just `printf` to output "Hey this is what the hash output looks like".

# How To Use
You can use the code like a library, or since I included a `if __name__ == "__main__"` you can just use it on the commandline:

    Usage: ./sha512crypt.py <password> <hash> <rounds>
    # Note: rounds is optional, it defaults to 5000
    
![image](https://github.com/guffre/sha512crypt/assets/21281361/ee18c956-0a3a-429c-8b36-d14b26a32a08)


# How To Build (the C program)

    ./run <password> <salt> <rounds>
    ./run password saltsalt 0

This lets you do 0 rounds, I wanted this for testing purposes. You can also have any length salt.
