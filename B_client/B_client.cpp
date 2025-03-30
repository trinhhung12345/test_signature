// B_client.cpp
#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>

/**
 * Prints OpenSSL errors to the standard error stream and exits the program.
 *
 * @throws none
 *
 * @return none
 */
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

bool verify_signature() {
    // Đọc public key
    FILE* pub_file = fopen("public_A.pem", "rb");
    if (!pub_file) {
        std::cerr << "Khong tim thay public_A.pem\n";
        return false;
    }
    EVP_PKEY* public_key = PEM_read_PUBKEY(pub_file, nullptr, nullptr, nullptr);
    fclose(pub_file);
    if (!public_key) {
        std::cerr << "Doc public key that bai!\n";
        return false;
    }

    // Đọc message
    std::ifstream msg_file("message.txt", std::ios::binary);
    if (!msg_file) {
        std::cerr << "Khong tim thay message.txt\n";
        EVP_PKEY_free(public_key);
        return false;
    }
    std::vector<unsigned char> message(
        (std::istreambuf_iterator<char>(msg_file)),
        std::istreambuf_iterator<char>()
    );

    // Đọc chữ ký
    std::ifstream sig_file("signature.bin", std::ios::binary);
    if (!sig_file) {
        std::cerr << "Khong tim thay signature.bin\n";
        EVP_PKEY_free(public_key);
        return false;
    }
    std::vector<unsigned char> signature(
        (std::istreambuf_iterator<char>(sig_file)),
        std::istreambuf_iterator<char>()
    );

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(public_key);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    // Cấu hình PSS
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256()));
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    int result = EVP_DigestVerify(ctx, signature.data(), signature.size(),
        message.data(), message.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return result == 1;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "=== PHAN MEM XAC THUC (B_CLIENT) ===\n";
    std::cout << "Dang kiem tra...\n";

    bool verified = verify_signature();

    if (verified) {
        std::cout << "\n=== XAC THUC THANH CONG ===\n";
        std::cout << "File message.txt la chinh chu tu A!\n";
    }
    else {
        std::cerr << "\n=== CANH BAO AN NINH ===\n";
        std::cerr << "Phat hien file message.txt hoac chu ky bi thay doi!\n";
    }

    EVP_cleanup();
    std::cout << "\nNhan phim bat ky de thoat...";
    system("pause");
    return verified ? EXIT_SUCCESS : EXIT_FAILURE;
}