#include <stdio.h>
#include <stdlib.h>

char *__sha512_crypt (const char *key, const char *salt);

int main(int argc, char **argv) {

    if (argc != 4) {
        printf("Usage: %s <key> <salt> <rounds>\n", argv[0]);
        exit(1);
    }

    char* salt = calloc(1024,1);
    snprintf(salt, 1024, "rounds=%d$%s", atoi(argv[3]), argv[2]);

    char* buffer = __sha512_crypt(argv[1],salt);
    printf("%s\n", buffer);

}