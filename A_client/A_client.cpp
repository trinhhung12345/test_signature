// A_client.cpp
#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void generate_rsa_key() {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) handle_openssl_error();

    // Ghi private key
    FILE* priv_file = fopen("private_A.pem", "wb");
    if (!priv_file || !PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Luu private key that bai!\n";
        handle_openssl_error();
    }
    fclose(priv_file);

    // Ghi public key
    FILE* pub_file = fopen("public_A.pem", "wb");
    if (!pub_file || !PEM_write_PUBKEY(pub_file, pkey)) {
        std::cerr << "Luu public key that bai!\n";
        handle_openssl_error();
    }
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    std::cout << "Da tao cap khoa thanh cong: private_A.pem va public_A.pem\n";
}

std::vector<unsigned char> sign_file(EVP_PKEY* private_key) {
    std::ifstream file("message.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Khong tim thay file message.txt\n";
        exit(EXIT_FAILURE);
    }

    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) handle_openssl_error();

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0)
        handle_openssl_error();

    // Cấu hình PSS
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256()));
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    size_t sig_len;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()) <= 0)
        handle_openssl_error();

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0)
        handle_openssl_error();

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);

    // Lưu chữ ký
    std::ofstream sig_file("signature.bin", std::ios::binary);
    sig_file.write(reinterpret_cast<char*>(signature.data()), signature.size());
    std::cout << "Da luu chu ky thanh cong vao signature.bin\n";

    return signature;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Tạo khóa
    std::cout << "=== PHAN MEM KY FILE (A_CLIENT) ===\n";
    generate_rsa_key();

    // Đọc private key
    std::cout << "Dang doc private key...\n";
    FILE* priv_file = fopen("private_A.pem", "rb");
    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);

    if (!private_key) {
        std::cerr << "Doc private key that bai!\n";
        return EXIT_FAILURE;
    }

    // Ký file
    std::cout << "Dang ky file message.txt...\n";
    sign_file(private_key);

    // Dọn dẹp
    EVP_PKEY_free(private_key);
    EVP_cleanup();

    std::cout << "Qua trinh ky hoan tat! Hay copy cac file sau sang B_client:\n";
    std::cout << "- public_A.pem\n- message.txt\n- signature.bin\n";
    system("pause");
    return EXIT_SUCCESS;
}