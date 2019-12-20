#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ak_fiot.h>

int main(int argc, char *argv[]) {

    if (argc != 6) {
        printf("Usage: example-fiot-server <server IP-address> <port number> <UDP or TCP> <FIOT or ESP> <default, max or random>\n");
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
     * и аутентификация клиента */

    struct fiot fiotContext;
    /* Создание контекста взаимодействия: */
    if (ak_fiot_context_create(&fiotContext) != ak_error_ok) {
        printf("FIOT context creation error\n");
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем роль (сервер, в данном случае): */
    if (ak_fiot_context_set_role(&fiotContext, server_role) != ak_error_ok) {
        printf("User role setting error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем идентификатор сервера: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, server_role, "Lazy server", 11) != ak_error_ok) {
        printf("Server ID setting error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем нужный транспортный (по OSI) протокол: */
    if (ak_fiot_context_set_osi_transport_protocol(&fiotContext, OSI_transport) != ak_error_ok) {
        printf("Setting OSI transport protocol error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем для передачи прикладных данных протокол FIOT или ESP: */
    if (ESP_flag)
        if (ak_fiot_context_set_esp_transport_protocol(&fiotContext, magmaESPAEAD) != ak_error_ok) {
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
    printf("Waiting for a client connection...\n");
    if (ak_fiot_context_keys_generation_protocol(&fiotContext, argv[1], serverPort) != ak_error_ok) {
        printf("Keys generation protocol error\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    } else
        printf("Client authentication is successful\n");

    /* Обмен сообщениями */

    ak_uint8 *received;
    size_t receivedLength;
    bool_t done = ak_false;
    int error;
    do {
        printf("/* --------------------------------------------------------------------------- */\n");
        /* Ожидаем сообщение от клиента: */
        printf("Waiting for a message from the client... \n");
        if ((received = ak_fiot_context_read_application_data(&fiotContext, &receivedLength)) == NULL) {
            /* Если сообщение не поступило, то сбрасываем ошибку и ждем дальше: */
            if (ak_error_get_value() == ak_error_read_data_timeout)
                ak_error_set_value(ak_error_ok);
            else
                /* Иначе выводим сообщение об ошибке: */
                ak_error_message(ak_error_get_value(), __func__, "Getting message from a client error");
            continue;
        } else {
            printf("Message \"%s\" with %zu bytes length has been received from the client\n", received, receivedLength);
            /* Отправляем сообщение обратно: */
            if ((error = ak_fiot_context_write_application_data(&fiotContext, received, receivedLength)) != ak_error_ok) {
                ak_error_message(error, __func__, "Sending message back error");
                /* Сбрасываем ошибку: */
                ak_error_set_value(ak_error_ok);
            } else
                printf("Message with %zu bytes length has been sent back to client\n", receivedLength);
        }

        /* Если было получено сообщение "done", то завершаем работу: */
        if (strncmp((char *)received, "done", 4) == 0)
            done = ak_true;
    } while (!done);

    ak_fiot_context_destroy(&fiotContext);
    return ak_libakrypt_destroy();
}
