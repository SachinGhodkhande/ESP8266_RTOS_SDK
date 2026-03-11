/* openSSL server example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
//#include "protocol_examples_common.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include <sys/socket.h>

#include "openssl/ssl.h"
#include "mbedtls/pk.h"
#include "mbedtls/aes.h"

extern const uint8_t ca_pem_start[] asm("_binary_ca_pem_start");
extern const uint8_t ca_pem_end[]   asm("_binary_ca_pem_end");
extern const uint8_t server_pem_start[] asm("_binary_server_pem_start");
extern const uint8_t server_pem_end[]   asm("_binary_server_pem_end");
extern const uint8_t server_key_start[] asm("_binary_server_key_start");
extern const uint8_t server_key_end[]   asm("_binary_server_key_end");

/*
Fragment size range 2048~8192
| Private key len | Fragment size recommend |
| RSA2048         | 2048                    |
| RSA3072         | 3072                    |
| RSA4096         | 4096                    |
*/
#define OPENSSL_SERVER_FRAGMENT_SIZE 2048

/* Local server tcp port */
#define OPENSSL_SERVER_LOCAL_TCP_PORT 443

//#define OPENSSL_SERVER_REQUEST "{\"path\": \"/v1/ping/\", \"method\": \"GET\"}\r\n"

/* receive length */
#define OPENSSL_SERVER_RECV_BUF_LEN 4096

#define WIFI_SSID "SSG_IOT"

//static char send_data[] = OPENSSL_SERVER_REQUEST;
//static int send_bytes = sizeof(send_data);

static char recv_buf[OPENSSL_SERVER_RECV_BUF_LEN];

static char* WIFI_PASS = "12345678";

static void openssl_server_task(void* p)
{
    int ret;

    SSL_CTX* ctx;
    SSL* ssl;

    struct sockaddr_in sock_addr;
    int sockfd, new_sockfd;
    int recv_bytes = 0;
    socklen_t addr_len;

    printf("OpenSSL server thread start...\n");

    printf("create SSL context ......");
    ctx = SSL_CTX_new(TLSv1_2_server_method());

    if (!ctx) {
        printf("failed\n");
        goto failed1;
    }

    printf("OK\n");

    printf("load server crt ......");
    ret = SSL_CTX_use_certificate_ASN1(ctx, server_pem_end - server_pem_start, server_pem_start);

    if (ret) {
        printf("OK\n");
    } else {
        printf("failed\n");
        goto failed2;
    }

    printf("load server private key ......");
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, server_key_start, server_key_end - server_key_start);

    if (ret) {
        printf("OK\n");
    } else {
        printf("failed\n");
        goto failed2;
    }

    printf("set verify mode verify peer\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    printf("create socket ......");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        printf("failed\n");
        goto failed2;
    }

    printf("OK\n");

    printf("socket bind ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(OPENSSL_SERVER_LOCAL_TCP_PORT);

    ret = bind(sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

    if (ret) {
        printf("bind failed\n");
        goto failed3;
    }

    printf("bind OK\n");

    printf("server socket listen ......");
    ret = listen(sockfd, 32);

    if (ret) {
        printf("failed\n");
        goto failed3;
    }

    printf("OK\n");

reconnect:
    printf("SSL server create ......");
    ssl = SSL_new(ctx);

    if (!ssl) {
        printf("failed\n");
        goto failed3;
    }

    printf("OK\n");

    printf("SSL server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr*)&sock_addr, &addr_len);

    if (new_sockfd < 0) {
        printf("failed");
        goto failed4;
    }

    printf("OK\n");

    SSL_set_fd(ssl, new_sockfd);

    printf("SSL server accept client ......");
    ret = SSL_accept(ssl);

    if (!ret) {
        printf("failed\n");
        goto failed5;
    }

    printf("OK\n");

    //printf("send data to client ......");
    //ret = SSL_write(ssl, send_data, send_bytes);

    //if (ret <= 0) {
    //    printf("failed, return [-0x%x]\n", -ret);
    //    goto failed5;
    //}

    //printf("OK\n\n");

    // Receive encrypted data
    ret = SSL_read(ssl, recv_buf, OPENSSL_SERVER_RECV_BUF_LEN);

    if (ret <= 0) {
        printf("SSL_read failed\n");
        goto failed5;
    }

    // Parse the received data
    // Format: 4 bytes (big endian) len_enc_key + enc_key + 16 bytes IV + enc_json
    if (ret < 4) {
        printf("Received data too short\n");
        goto failed5;
    }

    uint32_t len_enc_key = (recv_buf[0] << 24) | (recv_buf[1] << 16) | (recv_buf[2] << 8) | recv_buf[3];
    if (ret < 4 + len_enc_key + 16) {
        printf("Received data incomplete\n");
        goto failed5;
    }

    unsigned char* enc_aes_key = (unsigned char*)recv_buf + 4;
    unsigned char* iv = (unsigned char*)recv_buf + 4 + len_enc_key;
    unsigned char* enc_json = iv + 16;
    int enc_json_len = ret - 4 - len_enc_key - 16;

    // Decrypt AES key using RSA private key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_key(&pk, server_key_start, server_key_end - server_key_start, NULL, 0);
    if (ret != 0) {
        printf("Failed to parse private key\n");
        goto failed5;
    }

    // Set RSA padding to OAEP
    if (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA) {
        mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    }

    unsigned char aes_key[32]; // 256 bits
    size_t aes_key_len = sizeof(aes_key);
    ret = mbedtls_pk_decrypt(&pk, enc_aes_key, len_enc_key, aes_key, &aes_key_len, sizeof(aes_key), NULL, NULL);
    if (ret != 0) {
        printf("Failed to decrypt AES key\n");
        mbedtls_pk_free(&pk);
        goto failed5;
    }

    // Decrypt JSON using AES
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx, aes_key, 256);
    unsigned char decrypted[OPENSSL_SERVER_RECV_BUF_LEN];
    ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, enc_json_len, iv, enc_json, decrypted);
    if (ret != 0) {
        printf("Failed to decrypt JSON\n");
        mbedtls_pk_free(&pk);
        mbedtls_aes_free(&aes_ctx);
        goto failed5;
    }

    // Remove PKCS7 padding
    int pad_len = decrypted[enc_json_len - 1];
    if (pad_len > 16 || pad_len <= 0) {
        pad_len = 0;
    } else {
        int valid = 1;
        for (int i = 1; i <= pad_len; i++) {
            if (decrypted[enc_json_len - i] != pad_len) {
                valid = 0;
                break;
            }
        }
        if (!valid) pad_len = 0;
    }
    int actual_len = enc_json_len - pad_len;
    decrypted[actual_len] = '\0';

    printf("Decrypted JSON: %s\n", decrypted);

    mbedtls_pk_free(&pk);
    mbedtls_aes_free(&aes_ctx);

    SSL_shutdown(ssl);
failed5:
    close(new_sockfd);
    new_sockfd = -1;
failed4:
    SSL_free(ssl);
    ssl = NULL;
    goto reconnect;
failed3:
    close(sockfd);
    sockfd = -1;
failed2:
    SSL_CTX_free(ctx);
    ctx = NULL;
failed1:
    vTaskDelete(NULL);
    printf("task exit\n");

    return ;
}


static const char *TAG = "wifi softAP";

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}

void wifi_init_softap()
{
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = WIFI_SSID,
            .ssid_len = strlen(WIFI_SSID),
            .password = "111111", //WIFI_PASS,
            .max_connection = 4 ,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK
        },
    };
    if (strlen(WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s password:%s",
             WIFI_SSID, WIFI_PASS);
}


void app_main(void)
{
   
    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_LOGI(TAG, "ESP_WIFI_MODE_AP");
    wifi_init_softap();
    //    ESP_ERROR_CHECK(nvs_flash_init());
    //ESP_ERROR_CHECK(esp_netif_init());
    //ESP_ERROR_CHECK(esp_event_loop_create_default());

    //ESP_ERROR_CHECK(example_connect());

    xTaskCreate(&openssl_server_task, "openssl_server", 8192, NULL, 6, NULL);
}
