#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

void generate_ecdsa_signature(const unsigned char* msg, size_t msg_len, const BIGNUM* priv_key, ECDSA_SIG** sig)
{
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return;
    }

    if (!EC_KEY_set_private_key(eckey, priv_key)) {
        printf("Error: Failed to set private key.\n");
        EC_KEY_free(eckey);
        return;
    }

    unsigned int sig_len = ECDSA_size(eckey);
    *sig = ECDSA_do_sign(msg, msg_len, eckey);
    if (*sig == NULL) {
        printf("Error: Failed to generate ECDSA signature.\n");
        EC_KEY_free(eckey);
        return;
    }

    EC_KEY_free(eckey);
}

int verify_ecdsa_signature(const unsigned char* msg, size_t msg_len, const EC_POINT* pub_key, const ECDSA_SIG* sig)
{
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return 0;
    }

    if (!EC_KEY_set_public_key(eckey, pub_key)) {
        //printf("Error: Failed to set public key.\n");
        EC_KEY_free(eckey);
        return 0;
    }

    int result = ECDSA_do_verify(msg, msg_len, sig, eckey);

    EC_KEY_free(eckey);
    return result;
}

void generate_symmetric_key(unsigned char* key, int key_length) {
    EVP_CIPHER_CTX* ctx;
    int success;

    /* initialize the cipher context */
    ctx = EVP_CIPHER_CTX_new();


    /* generate the key */
    success = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, key, key_length, 1, NULL, NULL);


    /* clean up the context */
    EVP_CIPHER_CTX_free(ctx);
}

int main()
{
    /* generate a random symmetric key */
    unsigned char symmetric_key[32];
    generate_symmetric_key(symmetric_key, 32);
    printf("Symmetric key: ");
    for (int i = 0; i < sizeof(symmetric_key); i++) {
        printf("%02x", symmetric_key[i]);
    }
    printf("\n");

    /* generate a random EC key pair */


    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) {
        printf("Error: Failed to create EC key object.\n");
        return 1;
    }

    if (!EC_KEY_generate_key(eckey)) {
        printf("Error: Failed to generate EC key pair.\n");
        return 1;

    }
    // Get the EC group and public key point from the EC key object
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    const EC_POINT* pub_key = EC_KEY_get0_public_key(eckey);
    const EC_POINT* priv_key = EC_KEY_get0_private_key(eckey);
    // Print the private key in hex format
    char* priv_key_hex = BN_bn2hex(priv_key);
    printf("ECDSA private key: %s\n", priv_key_hex);
    OPENSSL_free(priv_key_hex);

    // Print the public key in hex format
    char* pub_key_hex = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("ECDSA public key: %s\n", pub_key_hex);
    OPENSSL_free(pub_key_hex);
    // Generate a signature using the private key and the symmetric key
    ECDSA_SIG* sig;
    generate_ecdsa_signature(symmetric_key, sizeof(symmetric_key), priv_key, &sig);
    // Display the signature
    unsigned char* der_sig = NULL;
    size_t der_sig_len = i2d_ECDSA_SIG(sig, &der_sig);
    if (der_sig_len <= 0) {
        printf("Error: Failed to encode ECDSA signature.\n");
        return 1;
    }
    printf("ECDSA signature:\n");
    for (size_t i = 0; i < der_sig_len; i++) {
        printf("%02X", der_sig[i]);
    }
    printf("\n");
    EC_KEY* eckey1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    // Verify the signature using the public key and the symmetric key
    int verify_result = verify_ecdsa_signature(symmetric_key, sizeof(symmetric_key), pub_key, sig);
    if (verify_result == 1) {
        printf("Signature verification succeeded.\n");
    }
    else {
        printf("Signature verification failed.\n");
    }
    // Clean up
    ECDSA_SIG_free(sig);
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    return 0;}
