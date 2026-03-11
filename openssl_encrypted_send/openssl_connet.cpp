#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

void printHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n"
              << "Options:\n"
              << "  --cafile <file>     Path to CA file (default: ca.pem)\n"
              << "  --cert <file>       Path to client certificate (default: client.pem)\n"
              << "  --key <file>        Path to client private key (default: client.key)\n"
              << "  --host <ip>         Server IP (default: 192.168.1.11)\n"
              << "  --port <port>       Server port (default: 443)\n"
              << "  --ssid <value>      WiFi SSID (default: abc)\n"
              << "  --password <value>  WiFi password (default: 123)\n"
              << "  --help              Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::string cafile = "ca.pem";
    std::string certfile = "client.pem";
    std::string keyfile = "client.key";
    std::string host = "192.168.1.11";
    int port = 443;
    std::string ssid = "abc";
    std::string password = "123";

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            printHelp(argv[0]);
            return 0;
        } else if (arg == "--cafile" && i + 1 < argc) {
            cafile = argv[++i];
        } else if (arg == "--cert" && i + 1 < argc) {
            certfile = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            keyfile = argv[++i];
        } else if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--ssid" && i + 1 < argc) {
            ssid = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            printHelp(argv[0]);
            return 1;
        }
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    if (!SSL_CTX_load_verify_locations(ctx, cafile.c_str(), nullptr)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, certfile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match certificate\n";
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "Connected with " << SSL_get_cipher(ssl) << "\n";

    // Build JSON with command-line ssid and password
    std::string jsonData = std::string("{\"ssid\":\"") + ssid + "\",\"password\":\"" + password + "\"}";

    // Generate AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    // Encrypt JSON with AES
    EVP_CIPHER_CTX* ctx_aes = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx_aes, EVP_aes_256_cbc(), NULL, aes_key, iv);
    unsigned char enc_json[1024];
    int enc_len = 0, final_len = 0;
    EVP_EncryptUpdate(ctx_aes, enc_json, &enc_len, (unsigned char*)jsonData.c_str(), jsonData.size());
    EVP_EncryptFinal_ex(ctx_aes, enc_json + enc_len, &final_len);
    int total_enc_len = enc_len + final_len;
    EVP_CIPHER_CTX_free(ctx_aes);

    // Get server's public key
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "Failed to get server certificate\n";
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    X509_free(cert);

    // Encrypt AES key with RSA
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(pctx);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
    unsigned char enc_aes_key[256];
    size_t enc_key_len = sizeof(enc_aes_key);
    int ret = EVP_PKEY_encrypt(pctx, enc_aes_key, &enc_key_len, aes_key, sizeof(aes_key));
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pubkey);

    if (ret <= 0) {
        std::cerr << "Failed to encrypt AES key\n";
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Prepare message: 4 bytes len_enc_key (big endian) + enc_aes_key + iv + enc_json
    uint32_t len_enc_key_be = htonl(enc_key_len);
    std::string message;
    message.append((char*)&len_enc_key_be, 4);
    message.append((char*)enc_aes_key, enc_key_len);
    message.append((char*)iv, 16);
    message.append((char*)enc_json, total_enc_len);

    int bytes = SSL_write(ssl, message.c_str(), message.size());
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "Sent encrypted data\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}