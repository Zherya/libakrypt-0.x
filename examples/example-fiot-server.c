#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ak_fiot.h>

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Использование: example-fiot-server <IP-адрес сервера> <номер порта сервера>\n");
        return 0;
    }
    /* Переведем номер порта в числовой формат: */
    unsigned long ulongServerPort = strtoul(argv[2], NULL, 0);
    if (ulongServerPort > 65535) {
        printf("Значение номера порта не может превышать значение 65535\n");
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
        printf("Ошибка создания контекста защищенного взаимодействия\n");
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем роль (сервер, в данном случае): */
    if (ak_fiot_context_set_role(&fiotContext, server_role) != ak_error_ok) {
        printf("Ошибка установки роли пользователя\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем идентификатор сервера: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, server_role, "Lazy server", 11) != ak_error_ok) {
        printf("Ошибка установки идентификатора сервера\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем нужный транспортный (по OSI) протокол: */
    if (ak_fiot_context_set_osi_transport_protocol(&fiotContext, UDP) != ak_error_ok) {
        printf("Ошибка установки протокола UDP как транспортного протокола (по OSI) sp fiot\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем для передачи прикладных данных протокол ESP: */
    if (ak_fiot_context_set_esp_transport_protocol(&fiotContext, kuznechikESPAEAD) != ak_error_ok) {
        printf("Ошибка установки протокола ESP как транспортного протокола sp fiot\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем выравнивание пакетов по максимальной длине: */
    if (ak_fiot_context_set_padding_policy(&fiotContext, max_padding) != ak_error_ok) {
        printf("Ошибка установки политики использования максимального заполнения\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Выполнение протокола выработки ключей: */
    printf("Ожидание подключения клиента...\n");
    if (ak_fiot_context_keys_generation_protocol(&fiotContext, argv[1], serverPort) != ak_error_ok) {
        printf("Ошибка выполнения протокола выработки ключей\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    } else
        printf("Аутентификация клиента успешна\n");

    /* Обмен сообщениями */

    ak_uint8 *received;
    size_t receivedLength;
    bool_t done = ak_false;
    int error;
    do {
        printf("/* --------------------------------------------------------------------------- */\n");
        /* Ожидаем сообщение от клиента: */
        printf("Ожидание сообщения от клиента... \n");
        if ((received = ak_fiot_context_read_application_data(&fiotContext, &receivedLength)) == NULL) {
            /* Если сообщение не поступило, то сбрасываем ошибку и ждем дальше: */
            if (ak_error_get_value() == ak_error_read_data_timeout)
                ak_error_set_value(ak_error_ok);
            else
                /* Иначе выводим сообщение об ошибке: */
                ak_error_message(ak_error_get_value(), __func__, "Ошибка получения сообщения от клиента");
            continue;
        } else {
            printf("Сообщение \"%s\" длиной %zu байт(а) получено от клиента\n", received, receivedLength);
            /* Отправляем сообщение обратно: */
            if ((error = ak_fiot_context_write_application_data(&fiotContext, received, receivedLength)) != ak_error_ok) {
                ak_error_message(error, __func__, "Ошибка отправки сообщения обратно клиенту");
                /* Сбрасываем ошибку: */
                ak_error_set_value(ak_error_ok);
            } else
                printf("Сообщение длиной %zu байт(а) отправлено обратно клиенту\n", receivedLength);
        }

        /* Если было получено сообщение "done", то завершаем работу: */
        if (strncmp((char *)received, "done", 4) == 0)
            done = ak_true;
    } while (!done);

    ak_fiot_context_destroy(&fiotContext);
    return ak_libakrypt_destroy();
}
