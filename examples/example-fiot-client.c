#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ak_fiot.h>

int main(int argc, char *argv[]) {

    if (argc != 6) {
        printf("Usage: example-fiot-client <server IP-address> <port number> <UDP or TCP> <FIOT or ESP> <default, max or random>\n");
        return 0;
    }

    bool_t ESP_flag = ak_false;
    osi_transport_protocol_t OSI_transport;
    padding_t padding_policy = undefined_padding;

    /* Выбираем транспортный протокол OSI: */
    if (strncmp(argv[3], "UDP", 3) == 0)
        OSI_transport = UDP;
    else
        if (strncmp(argv[3], "TCP", 3) == 0)
            OSI_transport = TCP;
        else {
            printf("Wrong OSI transport protocol argument\n");
            return 0;
        }
    printf("\nOSI transport protocol: ");
    if (OSI_transport == TCP)
        printf("TCP\n");
    else
        printf("UDP\n");

    /* Выбираем транспортный протокол FIOT или ESP: */
    if (strncmp(argv[4], "ESP", 3) == 0)
        ESP_flag = ak_true;
    else
        if (strncmp(argv[4], "FIOT", 4) != 0) {
            printf("Wrong crypto transport protocol argument\n");
            return 0;
        }
    printf("Crypto transport protocol: ");
    if (ESP_flag)
        printf("ESP\n");
    else
        printf("FIOT\n");

    /* Выбираем политику заполнения: */
    if (strncmp(argv[5], "max", 3) == 0)
        padding_policy = max_padding;
    else
        if (strncmp(argv[5], "default", 7) == 0)
            padding_policy = default_padding;
        else
            if (strncmp(argv[5], "random", 6) == 0)
                padding_policy = random_padding;
            else {
                printf("Wrong padding policy argument\n");
                return 0;
            }
    printf("Padding policy: ");
    switch (padding_policy) {
        case default_padding:
            printf("default padding\n\n");
        break;
        case max_padding:
            printf("max padding\n\n");
        break;
        case random_padding:
            printf("random padding\n\n");
    }

    /* Переведем номер порта в числовой формат: */
    unsigned long ulongServerPort = strtoul(argv[2], NULL, 0);
    if (ulongServerPort > 65535) {
        printf("Port number can't be bigger than 65535\n");
        return 0;
    }
    unsigned short serverPort = ulongServerPort;

    /* Инициализируем библиотеку libakrypt
     * с выводом сообщений аудита в стандартный поток ошибок: */
    if (!ak_libakrypt_create(ak_function_log_stderr))
        return ak_libakrypt_destroy();

    /* Инициализация контекста защищенного взаимодействия sp fiot
     * и аутентификация сервера */

    struct fiot fiotContext;
    /* Создание контекста взаимодействия: */
    if (ak_fiot_context_create(&fiotContext) != ak_error_ok) {
        printf("FIOT context creation error\n");
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем роль (клиент, в данном случае): */
    if (ak_fiot_context_set_role(&fiotContext, client_role) != ak_error_ok) {
        printf("User role setting error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем идентификатор клиента: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, client_role, "Annoying client", 15) != ak_error_ok) {
        printf("Client ID setting error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем идентификатор сервера: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, server_role, "Lazy server", 11) != ak_error_ok) {
        printf("Server ID setting error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем идентификатор ключа аутентификации
     * (ePSK - предварительно распределенный симметричный ключ аутентификации): */
    if (ak_fiot_context_set_psk_identifier(&fiotContext, ePSK_key, "Pre-shared auth key", 19) != ak_error_ok) {
        printf("Setting ID of ePSK authentication key error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем эллиптическую кривую
     * (256-битная эллиптическая кривая, заданная в форме скрученной кривой Эдвардса): */
    if (ak_fiot_context_set_curve(&fiotContext, tc26_gost3410_2012_256_paramsetA) != ak_error_ok) {
        printf("Setting elliptic curve error (256-bit twisted Edwards curve)\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем изначальный набор криптографических алгоритмов,
     * используемых в ходе протокола выработки ключей
     * (симметричному ключу ePSK будет присвоено значение в соответствии с
     * установленным ранее идентификатором): */
    if (ak_fiot_context_set_initial_crypto_mechanism(&fiotContext, magmaGOST3413ePSK) != ak_error_ok) {
        printf("Setting initial crypto mechanisms error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем нужный транспортный (по OSI) протокол: */
    if (ak_fiot_context_set_osi_transport_protocol(&fiotContext, OSI_transport) != ak_error_ok) {
        printf("Setting TCP as OSI transport protocol error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем для передачи прикладных данных протокол FIOT или ESP: */
    if (ESP_flag)
        if (ak_fiot_context_set_esp_transport_protocol(&fiotContext, kuznechikESPAEAD) != ak_error_ok) {
            printf("Enabling ESP protocol in FIOT error\n");
            ak_fiot_context_destroy(&fiotContext);
            return ak_libakrypt_destroy();
        }

    /* Устанавливаем выравнивание пакетов: */
    if (ak_fiot_context_set_padding_policy(&fiotContext, padding_policy) != ak_error_ok) {
        printf("Setting max padding policy error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Выполнение протокола выработки ключей: */
    if (ak_fiot_context_keys_generation_protocol(&fiotContext, argv[1], serverPort) != ak_error_ok) {
        printf("Keys generation protocol error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    } else
        printf("Server authentication is successful\n");

    /* Обмен сообщениями */

    char sent[2048];
    ak_uint8 *received;
    size_t receivedLength;
    bool_t done = ak_false;
    int error;
    do {
        printf("/* --------------------------------------------------------------------------- */\n");
        memset(sent, 0, sizeof(sent));
        printf("Enter a message for the server (or \"done\" for finish)\n");
        printf("Message: ");
        if (fgets(sent, sizeof(sent), stdin) == NULL) {
            printf("The message input error\n");
            continue;
        }
        /* fgets() оканчивает чтение входной строки, когда встречает символ новой строки,
         * при этом \n записывается в str, а после него - \0. Запишем в введенную строку
         * \0 вместо \n: */
        sent[strlen(sent) - 1] = '\0';

        /* Отправляем сообщение серверу: */
        if ((error = ak_fiot_context_write_application_data(&fiotContext, sent, strlen(sent) + 1)) != ak_error_ok) {
            ak_error_message(error, __func__, "Sending the message to server error");
            /* Сбрасываем ошибку: */
            ak_error_set_value(ak_error_ok);
        }
        else {
            printf("The message with %zu bytes length has been sent to the server\n", strlen(sent) + 1);
            /* Получаем ответ: */
            if ((received = ak_fiot_context_read_application_data(&fiotContext, &receivedLength)) == NULL) {
                ak_error_message(ak_error_get_value(), __func__, "Error of getting answer from the server");
                /* Сбрасываем ошибку: */
                ak_error_set_value(ak_error_ok);
            }
            else
                printf("Answer \"%s\" with %zu bytes length has been gotten from the server\n", received, receivedLength);
        }

        /* Если пользователь ввел "done", то завершаем работу: */
        if (strncmp(sent, "done", 4) == 0)
            done = ak_true;
    } while (!done);

    ak_fiot_context_destroy(&fiotContext);
    return ak_libakrypt_destroy();
}
