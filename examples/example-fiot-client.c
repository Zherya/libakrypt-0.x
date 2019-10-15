#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <ak_fiot.h>

int main(int argc, char *argv[]) {

    /* Инициализируем библиотеку libakrypt
     * с выводом сообщений аудита в стандартный поток ошибок: */
    if (!ak_libakrypt_create(ak_function_log_stderr))
        return ak_libakrypt_destroy();

    /* Инициализация контекста защищенного взаимодействия sp fiot
     * и аутентификация сервера */

    struct fiot fiotContext;
    /* Создание контекста взаимодействия: */
    if (ak_fiot_context_create(&fiotContext) != ak_error_ok) {
        printf("Ошибка создания контекста защищенного взаимодействия\n");
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем роль (клиент, в данном случае): */
    if (ak_fiot_context_set_role(&fiotContext, client_role) != ak_error_ok) {
        printf("Ошибка установки роли пользователя\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем идентификатор клиента: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, client_role, "Annoying client", 15) != ak_error_ok) {
        printf("Ошибка установки идентификатора клиента\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем идентификатор сервера: */
    if (ak_fiot_context_set_user_identifier(&fiotContext, server_role, "Lazy server", 11) != ak_error_ok) {
        printf("Ошибка установки идентификатора сервера\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем идентификатор ключа аутентификации
     * (ePSK - предварительно распределенный симметричный ключ аутентификации): */
    if (ak_fiot_context_set_psk_identifier(&fiotContext, ePSK_key, "Pre-shared auth key", 19) != ak_error_ok) {
        printf("Ошибка установки идентификатора ключа аутентификации ePSK\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем эллиптическую кривую
     * (256-битная эллиптическая кривая, заданная в форме скрученной кривой Эдвардса): */
    if (ak_fiot_context_set_curve(&fiotContext, tc26_gost3410_2012_256_paramsetA) != ak_error_ok) {
        printf("Ошибка установки эллиптической кривой (256-битная скрученная кривая Эдвардса)\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }
    /* Устанавливаем изначальный набор криптографических алгоритмов,
     * используемых в ходе протокола выработки ключей
     * (симметричному ключу ePSK будет присвоено значение в соответствии с
     * установленным ранее идентификатором): */
    if (ak_fiot_context_set_initial_crypto_mechanism(&fiotContext, magmaGOST3413ePSK) != ak_error_ok) {
        printf("Ошибка установки начального набора криптографических алгоритмов\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Устанавливаем нужный транспортный (по OSI) протокол: */
    if (ak_fiot_context_set_osi_transport_protocol(&fiotContext, UDP) != ak_error_ok) {
        printf("Ошибка установки протокола UDP как транспортного протокола sp fiot\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    }

    /* Выполнение протокола выработки ключей: */
    if (ak_fiot_context_keys_generation_protocol(&fiotContext, "192.168.1.37", 50014) != ak_error_ok) {
        printf("Ошибка выполнения протокола выработки ключей\n");
        ak_fiot_context_destroy(&fiotContext);
        return ak_libakrypt_destroy();
    } else
        printf("Аутентификация сервера успешна\n");

    /* Обмен сообщениями */

    char sent[2048];
    ak_uint8 *received;
    size_t receivedLength;
    message_t messageType = undefined_message;
    bool_t done = ak_false;
    int error;
    do {
        memset(sent, 0, sizeof(sent));
        printf("Введите сообщение для отправки серверу (или \"done\" для завершения работы)\n");
        printf("Сообщение: ");
        if (fgets(sent, sizeof(sent), stdin) == NULL) {
            printf("Ошибка ввода сообщения\n");
            continue;
        }
        /* fgets() оканчивает чтение входной строки, когда встречает символ новой строки,
         * при этом \n записывается в str, а после него - \0. Запишем в введенную строку
         * \0 вместо \n: */
        sent[strlen(sent) - 1] = '\0';

        /* Отправляем сообщение серверу: */
        if ((error = ak_fiot_context_write_application_data(&fiotContext, sent, strlen(sent) + 1)) != ak_error_ok)
            ak_error_message(error, __func__, "Ошибка отправки сообщения серверу");
        else {
            printf("Сообщение длиной %zu байт(а) отправлено серверу\n", strlen(sent) + 1);
            /* Получаем ответ: */
            if ((received = ak_fiot_context_read_frame(&fiotContext, &receivedLength, &messageType)) == NULL)
                ak_error_message(ak_error_get_value(), __func__, "Ошибка получения ответа от сервера");
            else
                printf("Ответ \"%s\" длиной %zu байт(а) получен от сервера\n", received, receivedLength);
        }

        /* Если пользователь ввел "done", то завершаем работу: */
        if (strncmp(sent, "done", 4) == 0)
            done = ak_true;
    } while (!done);

    ak_fiot_context_destroy(&fiotContext);
    return ak_libakrypt_destroy();
}
