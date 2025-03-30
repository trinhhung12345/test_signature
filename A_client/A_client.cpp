/**
 * @file A_client.cpp
 * @brief Ứng dụng tạo chữ ký số cho file sử dụng RSA-PSS
 * @author [Trịnh Hữu Hưng (definitely not vibe coding all of these)]
 * @date 2024-03-01
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
  * @note In thông báo lỗi ra stderr và thoát với mã EXIT_FAILURE
  */
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/**
 * @brief Tạo và lưu cặp khóa RSA 2048-bit
 * @details Tạo cặp khóa RSA và lưu vào 2 file:
 * - private_A.pem: Khóa bí mật
 * - public_A.pem: Khóa công khai
 * @throws std::runtime_error nếu không thể ghi file
 */
void generate_rsa_key() {
    // Tạo khóa RSA
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) handle_openssl_error();

    // Ghi private key
    FILE* priv_file = fopen("private_A.pem", "wb");
    if (!priv_file || !PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Lỗi: Không thể ghi private key\n";
        handle_openssl_error();
    }
    fclose(priv_file);

    // Ghi public key
    FILE* pub_file = fopen("public_A.pem", "wb");
    if (!pub_file || !PEM_write_PUBKEY(pub_file, pkey)) {
        std::cerr << "Lỗi: Không thể ghi public key\n";
        handle_openssl_error();
    }
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    std::cout << "-> Đã tạo thành công cặp khóa:\n   - private_A.pem\n   - public_A.pem\n";
}

/**
 * @brief Ký file message.txt bằng private key
 * @param private_key Con trỏ EVP_PKEY chứa khóa bí mật
 * @return std::vector<unsigned char> Chứa chữ ký số
 * @details Sử dụng thuật toán SHA-256 với padding PSS
 * @throws std::runtime_error nếu không đọc được file hoặc lỗi ký
 */
std::vector<unsigned char> sign_file(EVP_PKEY* private_key) {
    // Đọc nội dung file
    std::ifstream file("message.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Lỗi: Không tìm thấy file message.txt\n";
        exit(EXIT_FAILURE);
    }

    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    // Khởi tạo context ký
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) handle_openssl_error();

    // Cấu hình thuật toán ký
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0)
        handle_openssl_error();

    // Thiết lập tham số PSS
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);      // Sử dụng PSS padding
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256())); // Salt length = 32 bytes
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());              // MGF1 dùng SHA-256

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

    // Lưu chữ ký
    std::ofstream sig_file("signature.bin", std::ios::binary);
    sig_file.write(reinterpret_cast<char*>(signature.data()), signature.size());
    std::cout << "-> Đã lưu chữ ký thành công: signature.bin\n";

    return signature;
}

/**
 * @brief Hàm chính thực hiện quy trình ký file
 * @return int Mã trạng thái thoát
 * @details Các bước thực hiện:
 * 1. Khởi tạo OpenSSL
 * 2. Tạo cặp khóa
 * 3. Đọc private key
 * 4. Ký file message.txt
 * 5. Dọn dẹp tài nguyên
 */
int main() {
    // Khởi tạo thư viện OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "=== ỨNG DỤNG KÝ FILE (A_CLIENT) ===\n";

    // Tạo cặp khóa
    std::cout << "\n[1/3] Đang tạo cặp khóa RSA...\n";
    generate_rsa_key();

    // Đọc private key
    std::cout << "\n[2/3] Đang đọc khóa bí mật...\n";
    FILE* priv_file = fopen("private_A.pem", "rb");
    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);

    if (!private_key) {
        std::cerr << "Lỗi: Đọc private key thất bại\n";
        return EXIT_FAILURE;
    }

    // Ký file
    std::cout << "\n[3/3] Đang ký file message.txt...\n";
    sign_file(private_key);

    // Dọn dẹp
    EVP_PKEY_free(private_key);
    EVP_cleanup();

    std::cout << "\nHOÀN TẤT! Vui lòng copy các file sau sang B_client:\n";
    std::cout << " - public_A.pem\n - message.txt\n - signature.bin\n";
    system("pause");
    return EXIT_SUCCESS;
}