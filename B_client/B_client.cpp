/**
 * @file B_client.cpp
 * @brief Ứng dụng xác thực chữ ký số RSA-PSS
 * @author [Trịnh Hữu Hưng (definitely not vibe coding all of these)]
 * @date 2025-03-31
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
 * @brief Xác thực chữ ký số
 * @return true Nếu chữ ký hợp lệ
 * @return false Nếu chữ ký không hợp lệ
 * @details Thực hiện các bước:
 * 1. Đọc public key từ file
 * 2. Đọc nội dung file gốc
 * 3. Đọc chữ ký từ file
 * 4. Xác thực bằng thuật toán SHA-256 với PSS padding
 * @throws std::runtime_error nếu không đọc được file
 */
bool verify_signature() {
    // Đọc public key
    FILE* pub_file = fopen("public_A.pem", "rb");
    if (!pub_file) {
        std::cerr << "Lỗi: Không tìm thấy file public_A.pem\n";
        return false;
    }
    EVP_PKEY* public_key = PEM_read_PUBKEY(pub_file, nullptr, nullptr, nullptr);
    fclose(pub_file);
    if (!public_key) {
        std::cerr << "Lỗi: Đọc public key thất bại\n";
        return false;
    }

    // Đọc nội dung file gốc
    std::ifstream msg_file("message.txt", std::ios::binary);
    if (!msg_file) {
        std::cerr << "Lỗi: Không tìm thấy file message.txt\n";
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
        std::cerr << "Lỗi: Không tìm thấy file signature.bin\n";
        EVP_PKEY_free(public_key);
        return false;
    }
    std::vector<unsigned char> signature(
        (std::istreambuf_iterator<char>(sig_file)),
        std::istreambuf_iterator<char>()
    );

    // Khởi tạo context xác thực
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(public_key);
        return false;
    }

    // Cấu hình thuật toán xác thực
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    // Thiết lập PSS (phải giống với bên ký)
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, EVP_MD_size(EVP_sha256()));
    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256());

    // Thực hiện xác thực
    int result = EVP_DigestVerify(ctx, signature.data(), signature.size(),
        message.data(), message.size());

    // Dọn dẹp
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return result == 1;
}

/**
 * @brief Hàm chính thực hiện quy trình xác thực
 * @return int Mã trạng thái thoát
 * @details Các bước thực hiện:
 * 1. Khởi tạo OpenSSL
 * 2. Xác thực chữ ký
 * 3. Hiển thị kết quả
 * 4. Dọn dẹp tài nguyên
 */
int main() {
    // Khởi tạo thư viện OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "=== ỨNG DỤNG XÁC THỰC (B_CLIENT) ===\n";
    std::cout << "\nĐang kiểm tra chữ ký...\n";

    bool verified = verify_signature();

    // Hiển thị kết quả
    if (verified) {
        std::cout << "\n=== KẾT QUẢ: THÀNH CÔNG ===\n";
        std::cout << "File message.txt có chữ ký hợp lệ từ A!\n";
    }
    else {
        std::cerr << "\n=== CẢNH BÁO: THẤT BẠI ===\n";
        std::cerr << "Chữ ký không hợp lệ hoặc file đã bị thay đổi!\n";
    }

    // Dọn dẹp tài nguyên
    EVP_cleanup();
    std::cout << "\nNhấn phím bất kỳ để thoát...";
    system("pause");
    return verified ? EXIT_SUCCESS : EXIT_FAILURE;
}