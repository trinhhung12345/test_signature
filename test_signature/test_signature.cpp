/**
 * @file rsa_pss_example.cpp
 * @brief Ví dụ ký và xác thực RSA-PSS sử dụng OpenSSL
 * @author [Tên của bạn]
 * @date 2024-03-30
 * @copyright Copyright (c) 2024
 */

#define _CRT_SECURE_NO_DEPRECATE
#include <openssl/applink.c>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>

 /**
  * @brief Xử lý lỗi OpenSSL và thoát chương trình
  * @note In thông báo lỗi ra stderr và exit với code EXIT_FAILURE
  */
void handle_openssl_error() {
    ERR_print_errors_fp(stderr); ///< In toàn bộ lỗi từ OpenSSL error queue
    exit(EXIT_FAILURE);
}

/**
 * @brief Tạo cặp khóa RSA và lưu ra file
 * @param private_key_file Đường dẫn file private key (PEM)
 * @param public_key_file Đường dẫn file public key (PEM)
 * @note Sử dụng EVP_RSA_gen() để tạo khóa 2048-bit
 */
void generate_rsa_key(const char* private_key_file, const char* public_key_file) {
    // Tạo khóa RSA 2048-bit
    EVP_PKEY* pkey = EVP_RSA_gen(2048); ///< EVP_PKEY chứa cặp khóa
    if (!pkey) handle_openssl_error();

    // Ghi private key
    FILE* priv_file = fopen(private_key_file, "wb");
    if (!PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr))
        handle_openssl_error();
    fclose(priv_file);

    // Ghi public key
    FILE* pub_file = fopen(public_key_file, "wb");
    if (!PEM_write_PUBKEY(pub_file, pkey))
        handle_openssl_error();
    fclose(pub_file);

    EVP_PKEY_free(pkey); ///< Giải phóng bộ nhớ
}


/**
 * @brief Ký file sử dụng RSA-PSS
 * @param private_key Con trỏ EVP_PKEY chứa private key
 * @param file_path Đường dẫn file cần ký
 * @return std::vector<unsigned char> Chứa chữ ký
 * @note Sử dụng SHA-256 cho digest và MGF1
 */
std::vector<unsigned char> sign_file(EVP_PKEY* private_key, const char* file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << file_path << std::endl;
        exit(EXIT_FAILURE);
    }

    // Đọc toàn bộ nội dung file vào vector
    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    EVP_MD_CTX* ctx = EVP_MD_CTX_new(); ///< Context cho quá trình ký
    if (!ctx) handle_openssl_error();

    // Khởi tạo context với SHA-256
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0)
        handle_openssl_error();

    // Cấu hình tham số PSS
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(private_key, nullptr); ///< Context riêng cho PKEY
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING); ///< Thiết lập padding PSS
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256())); ///< Salt length = 32 bytes
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()); ///< MGF1 dùng SHA-256

    // Xác định kích thước chữ ký
    size_t sig_len;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, data.data(), data.size()) <= 0)
        handle_openssl_error();

    // Thực hiện ký
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(ctx, signature.data(), &sig_len, data.data(), data.size()) <= 0)
        handle_openssl_error();

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return signature;
}

/**
 * @brief Xác thực chữ ký RSA-PSS
 * @param public_key Con trỏ EVP_PKEY chứa public key
 * @param file_path Đường dẫn file gốc
 * @param signature Chữ ký cần xác thực
 * @return true Nếu chữ ký hợp lệ
 * @return false Nếu chữ ký không hợp lệ
 * @note Tham số PSS phải giống với lúc ký
 */
bool verify_signature(EVP_PKEY* public_key, const char* file_path,
    const std::vector<unsigned char>& signature) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << file_path << std::endl;
        return false;
    }

    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) handle_openssl_error();

    // Khởi tạo xác thực
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0)
        handle_openssl_error();

    // Cấu hình PSS (phải giống lúc ký)
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256()));
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    // Xác thực chữ ký
    int result = EVP_DigestVerify(ctx, signature.data(), signature.size(),
        data.data(), data.size());

    EVP_MD_CTX_free(ctx);
    return result == 1; ///< Trả về 1 nếu xác thực thành công
}


/**
 * @brief Hàm main thực hiện quy trình ký và xác thực
 * @return int Exit code
 * @note Khởi tạo và dọn dẹp OpenSSL
 */
int main() {
    // Khởi tạo OpenSSL
    OpenSSL_add_all_algorithms(); ///< Load tất cả algorithms và hash functions
    ERR_load_crypto_strings(); ///< Load thông báo lỗi

    // Tạo cặp khóa
    generate_rsa_key("private_A.pem", "public_A.pem");

    // Đọc private key
    FILE* priv_file = fopen("private_A.pem", "rb");
    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr); ///< Đọc PEM private key
    fclose(priv_file);

    // Ký file
    std::vector<unsigned char> signature = sign_file(private_key, "document.txt");

    // Lưu chữ ký
    std::ofstream sig_file("signature.bin", std::ios::binary);
    sig_file.write(reinterpret_cast<char*>(signature.data()), signature.size());

    // Đọc public key
    FILE* pub_file = fopen("public_A.pem", "rb");
    EVP_PKEY* public_key = PEM_read_PUBKEY(pub_file, nullptr, nullptr, nullptr); ///< Đọc PEM public key
    fclose(pub_file);

    // Xác thực
    bool verified = verify_signature(public_key, "document.txt", signature);

    std::cout << "Xac thuc " << (verified ? "thanh cong" : "that bai") << std::endl;

    // Dọn dẹp
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    EVP_cleanup(); ///< Giải phóng tài nguyên OpenSSL
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}