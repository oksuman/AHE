#ifndef __GM_H__
#define __GM_H__

#define STR_LENGTH 1024

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C"
{
#endif

    inline void handleErrors()
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    typedef struct
    {
        BIGNUM *n, *g;
    } PK;

    typedef struct
    {
        BIGNUM *p, *q;
    } SK;

    class GM
    {
    private:
        BN_CTX *bn_ctx;

    public:
        // functions
        GM();
        GM(int labmda);
        ~GM();

        BIGNUM *generate_random_prime1(int len);
        unsigned char *generate_random_prime2(int len);

        BIGNUM *generate_random_element1(const BIGNUM *n);
        unsigned char *generate_random_element2(const BIGNUM *n);

        void KeyGen(int lambda, PK &pk, SK &sk);

        BIGNUM *Enc(const PK pk, const BIGNUM *m);
        unsigned char *Enc(const PK pk, const char M);

        bool Dec(const PK pk, const SK sk, const BIGNUM *c);
        bool Dec(const PK pk, const SK sk, const unsigned char *C);

        BIGNUM *XOR(const PK pk, const BIGNUM *c1, const BIGNUM *c2);
        unsigned char *XOR(const PK pk, unsigned char *C1, unsigned char *C2);
    };

#ifdef __cplusplus
}
#endif

#endif