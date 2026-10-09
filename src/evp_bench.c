#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void check(int ok) {
    if (!ok) { ERR_print_errors_fp(stderr); exit(1); }
}
static double now(void) {
    struct timespec t;
    check(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
int main(int argc, char **argv) {
    int reps = argc > 1 ? atoi(argv[1]) : 8;
    int n = argc > 2 ? atoi(argv[2]) : 2000;
    if (reps < 1 || n < 1) return 2;
    const char *algs[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    fprintf(stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));
    puts("algorithm,repetition,operation,operations,us,ct_bytes,ss_bytes");
    for (int a = 0; a < 3; ++a) {
        EVP_PKEY_CTX *kg = EVP_PKEY_CTX_new_from_name(NULL, algs[a], NULL);
        check(kg != NULL); check(EVP_PKEY_keygen_init(kg) > 0);
        EVP_PKEY *key = NULL;
        check(EVP_PKEY_generate(kg, &key) > 0);
        EVP_PKEY_CTX *en = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        EVP_PKEY_CTX *de = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
        check(en != NULL && de != NULL);
        check(EVP_PKEY_encapsulate_init(en, NULL) > 0);
        check(EVP_PKEY_decapsulate_init(de, NULL) > 0);
        unsigned char ct[2048], ss[64], recovered[64];
        size_t cl = sizeof(ct), sl = sizeof(ss), rl = sizeof(recovered);
        check(EVP_PKEY_encapsulate(en, ct, &cl, ss, &sl) > 0);
        check(EVP_PKEY_decapsulate(de, recovered, &rl, ct, cl) > 0);
        check(sl == 32 && rl == sl && memcmp(ss, recovered, sl) == 0);
        for (int rep = 0; rep < reps; ++rep) {
            double start = now();
            for (int i = 0; i < n; ++i) {
                EVP_PKEY *tmp = NULL;
                check(EVP_PKEY_generate(kg, &tmp) > 0);
                EVP_PKEY_free(tmp);
            }
            printf("%s,%d,keygen,%d,%.9f,%zu,%zu\n", algs[a], rep, n, (now()-start)*1e6/n, cl, sl);
            start = now();
            for (int i = 0; i < n; ++i) {
                cl = sizeof(ct); sl = sizeof(ss);
                check(EVP_PKEY_encapsulate(en, ct, &cl, ss, &sl) > 0);
            }
            printf("%s,%d,encaps,%d,%.9f,%zu,%zu\n", algs[a], rep, n, (now()-start)*1e6/n, cl, sl);
            start = now();
            for (int i = 0; i < n; ++i) {
                rl = sizeof(recovered);
                check(EVP_PKEY_decapsulate(de, recovered, &rl, ct, cl) > 0);
            }
            printf("%s,%d,decaps,%d,%.9f,%zu,%zu\n", algs[a], rep, n, (now()-start)*1e6/n, cl, sl);
            check(sl == rl && memcmp(ss, recovered, sl) == 0);
        }
        EVP_PKEY_CTX_free(en); EVP_PKEY_CTX_free(de);
        EVP_PKEY_free(key); EVP_PKEY_CTX_free(kg);
    }
    return 0;
}
