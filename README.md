# sha512crypt
Deep dive into understanding exactly how sha512-crypt works
The final result of this will be python code that lets you generate sha512-crypt hashes on windows. Ideally in vanilla python (no libraries/dependencies).

# Work In Progress
This repo is currently a work in progress.

I took the source code of sha512-crypt from https://elixir.bootlin.com/glibc/latest/source/crypt
I removed most of the codebase since the only thing I am interested in is producing sha512-crypt hashes, like on a linux machine.

Most of the edits to the source are just `printf` to output "Hey this is what the hash output looks like".

# How To Use

    ./run <password> <salt> <rounds>
    ./run password saltsalt 0

This lets you do 0 rounds, I wanted this for testing purposes. You can also have any length salt.
