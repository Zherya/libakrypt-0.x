/* ----------------------------------------------------------------------------------------------- */
/*                                                                                                 */
/*  Файл ak_esp.c                                                                                  */
/*  - содержит определения функций по работе с контекстом протокола ESP.                           */
/* ----------------------------------------------------------------------------------------------- */
#include <ak_esp.h>
#ifdef LIBAKRYPT_HAVE_STDLIB_H
    #include <stdlib.h>
#else
    #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
    #include <string.h>
#else
    #error Library cannot be compiled without string.h header
#endif
/* Для функций hton(s)/(l): */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
    #include <winsock2.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации контекста протокола ESP
 *
 * @param espContext указатель на контекст протокола ESP
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_create(ak_esp espContext) {
    int error = ak_error_ok;
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");

    /* Заполним поля ESP-заголовка: */
    espContext->header.SPI = 0;
    espContext->header.SeqNum = 1;

    /* Установим начальное состояние синхропосылки отсылаемых пакетов: */
    espContext->out_iv.i1 = espContext->out_iv.i2 = espContext->out_iv.i3 = 0;
    espContext->out_iv.pnum[0] = espContext->out_iv.pnum[1] = espContext->out_iv.pnum[2] = 0;

    /* Теперь получаемых пакетов: */
    espContext->in_iv.i1 = espContext->in_iv.i2 = espContext->in_iv.i3 = 0;
    espContext->in_iv.pnum[0] = espContext->in_iv.pnum[1] = espContext->in_iv.pnum[2] = 0;

    /* Установим неопределенный трансформ: */
    espContext->transform = undefined_transform;

    /* Массивы ключей и буферы соли: */
    for (short i = 0; i < 32; ++i) {
        espContext->out_root_key[i] = 0;
        espContext->in_root_key[i] = 0;
    }

    if ((error = ak_buffer_create(&(espContext->out_salt))) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer creation");
    if ((error = ak_buffer_create(&(espContext->in_salt))) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer creation");

    /* Начальное (пустое) заполнение "скользящего окна" со стандартным размером в 32 элемента: */
    espContext->seqnum_window.window = malloc(sizeof(bool_t) * 32);
    for (size_t i = 0; i < 32; ++i)
        espContext->seqnum_window.window[i] = ak_false;
    espContext->seqnum_window.size = 32;
    espContext->seqnum_window.right_bound = 0;

    /* Не используем TFC-заполнение: */
    espContext->tfclen = 0;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция уничтожения (очистки) контекста протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_destroy(ak_esp espContext) {
    int error = ak_error_ok;
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");

    /* Если контекст ключа шифрования был инициализирован, уничтожаем его: */
    if (espContext->transform != undefined_transform)
        if ((error = ak_bckey_context_destroy(&espContext->msg_key)) != ak_error_ok)
            return ak_error_message(error, __func__, "error of destroying bckey context");
    espContext->transform = undefined_transform;

    /* Уничтожаем контексты буферов секретной соли: */
    if ((error = ak_buffer_destroy(&espContext->out_salt)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer destroying");
    if ((error = ak_buffer_destroy(&espContext->in_salt)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer destroying");

    /* Обнулим массивы ключей: */
    for (short i = 0; i < 32; ++i) {
        espContext->out_root_key[i] = 0;
        espContext->in_root_key[i] = 0;
    }

    /* Очищаем память под "скользящее окно": */
    free(espContext->seqnum_window.window);
    espContext->seqnum_window.size = 0;
    espContext->seqnum_window.right_bound = 0;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \briefФункция устанавливает или сбрасывает использование TFC-заполнения.
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param tfcFlag Устанавливаемое значение длины,
 * до которой выравниваются (значение от 256 до 65535)
 * полезные данные с помощью TFC-заполнения
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_tfc_length(ak_esp espContext, size_t tfclen) {
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
    if (tfclen != 0 && tfclen < 256)
        return ak_error_message(ak_error_invalid_value, __func__, "potentialy short TFC length value");
    if (tfclen > 65535)
        return ak_error_message(ak_error_invalid_value, __func__, "too large TFC length value");

    espContext->tfclen = tfclen;
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает новый трансформ контекста ESP, при этом обнуляются все параметры
 * и данные (если имеются) контекста, в том числе и ключи шифрования, и секретная соль.
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param transform Идентификатор устанавливаемого трансформа
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_transform(ak_esp espContext, transform_t transform) {
    int error = ak_error_ok, saltSize;
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
    if (transform == undefined_transform)
        return ak_error_message(ak_error_undefined_value, __func__, "using undefined transform value");
    if (transform == espContext->transform)
        /* Если трансформ не меняется, то ничего не делаем: */
        return ak_error_ok;

    /* Если до этого уже был установлен трансформ, то обнуляем его и все данные: */
    if (espContext->transform != undefined_transform) {
        if ((error = ak_esp_context_destroy(espContext)) != ak_error_ok)
            return ak_error_message(error, __func__, "error of ESP context destroying");
        if ((error = ak_esp_context_create(espContext)) != ak_error_ok)
            return ak_error_message(error, __func__, "error of ESP context creation");
    }

    espContext->transform = transform;

    /* Установим соответствующую трансформу длину секретной соли и инициализируем ключ: */
    if (transform == encr_kuznyechik_mgm_ktree || transform == encr_kuznyechik_mgm_mac_ktree) {
        /* Для "Кузнечика" длина соли - 12 байт = 96 бит: */
        saltSize = 12;
        if (ak_bckey_context_create_kuznechik(&espContext->msg_key) != ak_error_ok)
            return ak_error_message(ak_error_get_value(), __func__, "Error of creation bckey Kuznechik context");
    } else {
        /* Для "Магмы" - 4 байта = 32 бита: */
        saltSize = 4;
        if (ak_bckey_context_create_magma(&espContext->msg_key) != ak_error_ok)
            return ak_error_message(ak_error_get_value(), __func__, "Error of creation bckey Magma context");
    }

    /* Установим новый размер секретной соли: */
    if ((error = ak_buffer_set_size(&espContext->out_salt, saltSize)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer allocation");
    if ((error = ak_buffer_set_size(&espContext->in_salt, saltSize)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong salt buffer allocation");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение идентификатора текущего используемого трансформа
 * (криптографического алгоритма)
 *
 * @param espContext Указатель на контекст протокола ESP
 *
 * @return В cлучае успеха возвращается идентификатор трансформа. В случае ошибки -
 * undefined_transform, а код ошибки может быть получен с помощью функции
 * ak_error_get_value()
 */
transform_t ak_esp_context_get_transform(ak_esp espContext) {
    if (espContext == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
        return undefined_transform;
    }
    return espContext->transform;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция меняет текущий трансформ на симметричный (с шифрованием/без шифрования),
 * оставляя неизменным используемый блочный алгоритм ("Магма" или "Кузнечик") и все параметры
 * и ключевые данные контекста протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_switch_transform(ak_esp espContext) {
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");

    switch (espContext->transform) {
        case encr_magma_mgm_ktree:
            espContext->transform = encr_magma_mgm_mac_ktree;
        break;
        case encr_magma_mgm_mac_ktree:
            espContext->transform = encr_magma_mgm_ktree;
        break;
        case encr_kuznyechik_mgm_ktree:
            espContext->transform = encr_kuznyechik_mgm_mac_ktree;
        break;
        case encr_kuznyechik_mgm_mac_ktree:
            espContext->transform = encr_kuznyechik_mgm_ktree;
        break;
        case undefined_transform:
            return ak_error_message(ak_error_undefined_value, __func__, "using ESP context with undefined transform");
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает значение SPI (Security Parameter Index) заголовка ESP
 * в контекст протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param SPI Устанавливаемое значение SPI
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_spi(ak_esp espContext, ak_uint32 SPI) {
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");

    /* Значения SPI от 0 до 255 не должны использоваться: */
    if (SPI <= 255)
        return ak_error_message(ak_error_invalid_value, __func__, "using wrong ESP SPI value");

    espContext->header.SPI = SPI;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает корневой ключ для заданного направления трафика
 * в контекст протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param key указатель на данные, из которых берется корневой ключ
 * @param size размер key в байтах
 * @param direct направление трафика, для которого устанавливается ключ
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_root_key(ak_esp espContext, ak_pointer const key, const size_t size, packet_direct_t direct) {
    int error = ak_error_ok;
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
    if (key == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to root key");
    if (size < 32)
        return ak_error_message(ak_error_invalid_value, __func__, "using too short root key");

    /* В качестве корневого ключа берутся младшие 32 байта key: */
    switch (direct) {
        case out_packet:
            for (short i = 0; i < 32; ++i)
                espContext->out_root_key[i] = ((ak_uint8 *)key)[i];
            /* Обнуляем соответствующую синхропосылку: */
            espContext->out_iv.i1 = espContext->out_iv.i2 = espContext->out_iv.i3 = 0;
            espContext->out_iv.pnum[0] = espContext->out_iv.pnum[1] = espContext->out_iv.pnum[2] = 0;
        break;
        case in_packet:
            for (short i = 0; i < 32; ++i)
                espContext->in_root_key[i] = ((ak_uint8 *)key)[i];
            /* Обнуляем соответствующую синхропосылку: */
            espContext->in_iv.i1 = espContext->in_iv.i2 = espContext->in_iv.i3 = 0;
            espContext->in_iv.pnum[0] = espContext->in_iv.pnum[1] = espContext->in_iv.pnum[2] = 0;
    }
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает секретную соль для заданного направления трафика
 * в контекст протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param salt Указатель на данные, из которых берется секретная соль
 * @param size Размер salt в байтах
 * @param direct направление трафика, для которого устанавливается секретная соль
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_salt(ak_esp espContext, ak_pointer const salt, const size_t size, packet_direct_t direct) {
    int error = ak_error_ok;
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
    if (salt == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to salt");
    if (espContext->transform == undefined_transform)
        return ak_error_message(ak_error_undefined_value, __func__, "setting salt for undefined transform");

    size_t saltSize = ak_buffer_get_size(&(espContext->in_salt));
    if (size < saltSize)
        return ak_error_message(ak_error_invalid_value, __func__, "using too short salt");

    /* В качестве соли берутся младшие байты salt: */
    switch (direct) {
        case out_packet:
            if ((error =ak_buffer_set_ptr(&(espContext->out_salt), salt, saltSize, ak_true)) != ak_error_ok)
                return ak_error_message(error, __func__, "wrong salt setting");
        break;
        case in_packet:
            if ((error =ak_buffer_set_ptr(&(espContext->in_salt), salt, saltSize, ak_true)) != ak_error_ok)
                return ak_error_message(error, __func__, "wrong salt setting");
    }
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет заданный номер последовательности с помощью
 * механизма "скользящего окна"
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param seqnum Значение проверяемого номера последовательности
 *
 * @return Если пакет может быть принят, возвращается ak_true, иначе - ak_false
 */
static bool_t ak_esp_context_check_seqnum(ak_esp espContext, ak_uint32 seqnum) {
    bool_t *window = espContext->seqnum_window.window;
    ak_uint32 bound = espContext->seqnum_window.right_bound;
    size_t size = espContext->seqnum_window.size;
    size_t shift;

    /* Если принятый номер последовательности меньше левой границы или равен
     * правой границе (старшему обработанному номеру), то отбрасываем пакет: */
    if (seqnum <= (bound <= size ? 0 : bound - size) || seqnum == bound)
        return ak_false;

    /* Если номер больше правой границы, то обрабатываем и сдвигаем окно: */
    if (seqnum > bound) {
        /* Если номер больше правой границы на величину, большую или
         * равную размеру окна, то "обнуляем" все окно: */
        if ((shift = seqnum - bound) >= size)
            for (size_t i = 0; i < size; ++i)
                window[i] = ak_false;
        else {
            /* Иначе нужно сдвинуть окно вправо на величину разности, то есть
             * сдвинуть старшие элементы влево, а их "места" пометить, как необработанные: */
            for (size_t i = shift; i < size; ++i)
                window[i - shift] = window[i];
            for (size_t i = size - shift; i < size; ++i)
                window[i] = ak_false;
        }
        /* Устанавливаем принятый номер в качестве правой границы: */
        espContext->seqnum_window.right_bound = seqnum;
        /* А также помечаем правую границу, как обработанную: */
        window[size - 1] = ak_true;
        return ak_true;
    }

    /* Иначе номер последовательности попадает в окно. Проверяем, был ли пакет с таким номером
     * уже принят:
     * Разность границы и номера равна 0 - индекс в окне равен size - 1
     * Разность 1 - индекс size - 2
     * Разность 2 - индекс size - 3
     * Разность 3 - индекс size - 4
     * Разность 4 - индекс size - 5
     * ....
     * Разность 30 - индекс size - 31
     * Разность 31 - индекс size - 32
     * и т.д. */
     /* Индекс номера последовательности - (размер окна минус 1) минус
      * разность номера с границей (которая не нулевая): */
    shift = size - 1 - (bound - seqnum);
    if (window[shift])
         return ak_false;
    else {
        /* Устанавливаем успешную обработку номера: */
        window[shift] = ak_true;
        return ak_true;
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает размер "скользящего окна" контекста протокола ESP
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param size Новый размер окна (в байтах)
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
int ak_esp_context_set_seqnum_window_size(ak_esp espContext, size_t size) {
    if (espContext == NULL)
        return ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");

    size_t old_size = espContext->seqnum_window.size;
    /* Если текущий размер больше или равен указанному, то ничего не делаем: */
    if (old_size >= size)
        return ak_error_ok;

    /* Выделяем новую память */
    bool_t *temp = malloc(sizeof(bool_t) * size);
    /* Копируем старое окно в конец нового: */
    memcpy(temp + (size - old_size), espContext->seqnum_window.window, sizeof(bool_t) * old_size);
    /* Так как теперь в новом окне левая граница сдвинулась в сторону меньших номеров
     * последовательностей, информации о которых в старом окне уже нет и они
     * отбрасывались, то заполним начало нового окна флагом обработанных номеров: */
    for (size_t i = 0, end = size - old_size; i < end; ++i)
        temp[i] = ak_true;

    free(espContext->seqnum_window.window);
    espContext->seqnum_window.window = temp;
    espContext->seqnum_window.size = size;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инкремент значения синхропосылки (IV) исходящего трафика
 *
 * @param espContext Указатель на контекст протокола ESP
 *
 * @return В случае успеха возвращается ak_error_ok, иначе - код ошибки
 */
static int ak_esp_context_increment_iv(ak_esp espContext) {
    struct esp_iv *iv = &(espContext->out_iv);
    /* pnum - 3-ёх-байтное число в сетевом порядке байт, будем инкрементировать pnum
     * с младшего (правого) байта, при необходимости прибавляя значения в старших разрядах. */
    bool_t pnumOverflow = ak_false;
    /* Если после инкремента младщий разряд равен нулю (значение переполнилось), то прибавляем
     * единицу к следующему и т.д. до последнего разряда: */
    if (++iv->pnum[2] == 0)
        if (++iv->pnum[1] == 0)
            if (++iv->pnum[0] == 0)
                /* Произошло переполнение счетчика pnum */
                pnumOverflow = ak_true;
    /* При переполнении pnum мы должны увеличить значение i3, а при его переполнении - i2,
     * а при переполнении i2 - i1: */
    if (pnumOverflow == ak_true)
        if (++iv->i3 == 0)
            if (++iv->i2 == 0)
                if (++iv->i1 == 0)
                    /* При переполнении i1 необходимо сменить корневой ключ */
                    return ak_error_message(ak_error_low_key_resource, __func__, "low resource of ESP root key");

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление значения функции ESPTREE(K, i1, i2, i3) из стандарта использования ESP.
 * Функция используется для вычисления ключей шифрования по заданным параметрам диверсификации
 * и корневого ключа
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param direct Направление трафика, для которого вычисляется ключ шифрования
 * @param out Указатель на область памяти, в которую помещается результат (размера 32 байта).
 * Может быть равен NULL.
 *
 * @return Если out равен NULL, то функция возвращает указатель на буфер (ak_buffer) с результатом.
 * Буфер должен быть позже очищен с помощью ak_buffer_delete(). Иначе возвращается NULL.
 * В случае неудачи возвращается NULL, а код ошибки проверяется с помощью ak_error_get_value()
 */
static ak_buffer ak_esp_context_esptree(ak_esp espContext, packet_direct_t direct, ak_pointer out) {
    /* Выбираем, какую синхропосылку и корневой ключ использовать: */
    struct esp_iv *iv;
    ak_uint8 *key;
    if (direct == out_packet) {
        iv = &(espContext->out_iv);
        key = espContext->out_root_key;
    }
    else {
        iv = &(espContext->in_iv);
        key = espContext->in_root_key;
    }
    /* Определяем константы дерева ключей: */
    ak_uint8 l1[6] = "level1"; ak_uint8 l2[6] = "level2"; ak_uint8 l3[6] = "level3";
    /* И параметры диверсификации в сетевом порядке байт: */
    unsigned short i1 = iv->i1;
    /* Так как 1 байт i1 из IV записался в двубайтный i1 для ESP_TREE в принятом, возможно,
     * на хосте формате little-endian (то есть этот байт записался в левый разряд,
     * что увеличивает значение, которое выходит за диапазон 255), поэтому развернем полученный
     * двубайтный i1 в сетевой формат */
    i1 = htons(i1);
    /* Остальные параметры i1 и i2 развернем сразу: */
    unsigned short i2 = htons(iv->i2), i3 = htons(iv->i3);

    /* Определим массивы под промежуточные результаты: */
    ak_uint8 lvl1Out[32], lvl2Out[32];

    ak_hmac_context_kdf256(key, 32, l1, 6, (ak_uint8*)&i1, 2, lvl1Out);
    if (ak_error_get_value() != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "kdf256 computation error");
        return NULL;
    }
    ak_hmac_context_kdf256(lvl1Out, 32, l2, 6, (ak_uint8*)&i2, 2, lvl2Out);
    if (ak_error_get_value() != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "kdf256 computation error");
        return NULL;
    }
    return ak_hmac_context_kdf256(lvl2Out, 32, l3, 6, (ak_uint8*)&i3, 2, out);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение одноразового вектора (nonce) для AEAD-режима шифрования.
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param direct Направление трафика, для которого вырабатывается nonce
 * @param out Указатель на область памяти (размер должен быть равен 4 + размер буфера соли),
 * в которую помещается nonce. Может быть равен NULL
 *
 * @return Если out равен NULL, то функция возвращает указатель на буфер (ak_buffer) со значением nonce.
 * Буфер должен быть позднее очищен с помощью ak_buffer_delete(). Иначе возвращается NULL.
 * В случае неудачи возвращается NULL, а код ошибки проверяется с помощью ak_error_get_value()
 */
static ak_buffer ak_esp_context_get_nonce(ak_esp espContext, packet_direct_t direct, ak_pointer out) {
    /* Формат nonce: zero | pnum | salt, где zero - 1 нулевой байт, pnum - порядковый номер из IV, 3 байта
     *                                   salt - секретная соль */
    ak_uint8 *salt, *pnum;
    size_t nonceSize = 1 + 3; /* zero и pnum */
    ak_buffer nonce = NULL;
    ak_uint8 *outPtr = out;
    /* Выбираем, какую секретную соль и pnum использовать: */
    if (direct == out_packet) {
        salt = ak_buffer_get_ptr(&(espContext->out_salt));
        nonceSize += ak_buffer_get_size(&(espContext->out_salt));
        pnum = espContext->out_iv.pnum;
    } else {
        salt = ak_buffer_get_ptr(&(espContext->in_salt));
        nonceSize += ak_buffer_get_size(&(espContext->in_salt));
        pnum = espContext->in_iv.pnum;
    }

    /* Выделим под nonce буфер, если out равен NULL: */
    if (out == NULL) {
        if ((nonce = ak_buffer_new_size(nonceSize)) == NULL) {
            ak_error_message(ak_error_get_value(), __func__, "wrong out buffer allocation");
            return NULL;
        }
        /* Укажем outPtr в качестве указателя на данные буфера: */
        outPtr = ak_buffer_get_ptr(nonce);
    }
    /* Заполним nonce соответствующим образом: */
    outPtr[0] = 0;
    /* pnum представлен в сетевом порядке байт, в таком виде в nonce его и записываем: */
    outPtr[1] = pnum[0];
    outPtr[2] = pnum[1];
    outPtr[3] = pnum[2];
    /* Теперь секретная соль: */
    memcpy(outPtr + 4, salt, nonceSize - 4);
    /* Возвращаем результат: */
    if (out == NULL)
        return nonce;
    else
        return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция записывает текущие значения заголовка протокола ESP в исходящий пакет
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param opacket Указатель на пакет, в который записываются значения
 */
static void ak_esp_context_write_header(ak_esp espContext, ak_uint8 *opacket) {
    /* SPI и SeqNum должны быть записаны в сетевом порядке байт: */
    ak_uint32 SPI = htonl(espContext->header.SPI),
              SeqNum = htonl(espContext->header.SeqNum);
    memcpy(opacket, &SPI, 4);
    memcpy(opacket + 4, &SeqNum, 4);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция записывает текущие значения исходящей синхропосылки (IV)
 * протокола ESP в исходящий пакет
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param opacket Указатель на пакет, в который записываются значения
 */
static void ak_esp_context_write_iv(ak_esp espContext, ak_uint8 *opacket) {
    opacket[0] = espContext->out_iv.i1;
    /* i2 и i3 записываются в сетевом порядке байт
     * (сначала старший байт, потом младший): */
    opacket[1] = espContext->out_iv.i2 >> 8;
    opacket[2] = espContext->out_iv.i2 % 256;
    opacket[3] = espContext->out_iv.i3 >> 8;
    opacket[4] = espContext->out_iv.i3 % 256;
    /* pnum также записывается в сетевом порядке байт, в котором он и записан в памяти: */
    opacket[5] = espContext->out_iv.pnum[0];
    opacket[6] = espContext->out_iv.pnum[1];
    opacket[7] = espContext->out_iv.pnum[2];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция генерирует и записывает в исходящий пакет ESP Trailer с обязательным
 * дополнением по заданному идентификатору протокола вложенных данных и длине полезных данных
 * исходящего пакета
 *
 * @param payloadLen Длина полезных данных исходящего пакета
 * @param protoID Идентификатор протокола, помещаемого в поле Next Header
 * @param opacket Указатель на исходящий пакет, в который записывается ESP Trailer
 *
 * @return В случае успеха функция возвращает длину ESP Trailer в байтах, иначе - 0
 */
static size_t ak_esp_context_write_trailer(const size_t payloadLen, ak_uint8 protoID, ak_uint8 *opacket) {
    /*  - ESP-Trailer:
   *      - Padding, 0-255 байт - заполнение (первый байт = 1, второй = 2 и т.д.)
   *                              для кратности четырем передаваемых данных,
   *                              заполнения, его длины и поля Next Header
   *      - Pad Length (1 байт) - длина заполнения
   *      - Next Header (1 байт) - ID протокола в поле передаваемых данных */
    /* Определим минимальную длину заполнения, удовлетворяющую условию кратности четырем: */
    size_t trailerLen, alignedDataLen = payloadLen + 2; // 2 байта на Pad Length и Next Header
    if (alignedDataLen % 4 != 0)
        /* Делим длину нацело на 4, прибавляем единицу, и затем умножаем на 4,
         * в итоге получая длину, большую исходной, и кратной 4 */
        alignedDataLen = ((alignedDataLen >> 2) + 1) << 2;
    trailerLen = alignedDataLen - payloadLen;
    // Заполним Padding по указаному выше правилу:
    for (unsigned char i = 0, padLen = trailerLen - 2; i < padLen; ++i)
        opacket[i] = i + 1;
    // Заполним Pad Length и Next Header:
    opacket[trailerLen - 2] = trailerLen - 2;
    opacket[trailerLen - 1] = protoID;
    return trailerLen;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает значение синхропосылки (IV) из входящего пакета
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param inpacket Указатель на входящий пакет
 */
static void ak_esp_context_read_iv(ak_esp espContext, ak_uint8 *inpacket) {
    espContext->in_iv.i1 = inpacket[0];
    /* i2 и i3 имеют сетевой порядок байт: */
    espContext->in_iv.i2 = 256 * inpacket[1] + inpacket[2];
    espContext->in_iv.i3 = 256 * inpacket[3] + inpacket[4];
    /* pnum также имеет сетевой порядок байт, и в таком виде и копируется: */
    memcpy(espContext->in_iv.pnum, inpacket + 5, 3);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Основная функция, формирующая ESP-пакет на основе параметров контекста протокола ESP
 * и прикладных данных. Сформированный пакет записывается в указанную область памяти
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param data Указатель на прикладные данные, помещаемые в ESP-пакет
 * @param datalen Размер прикладных данных в байтах
 * @param protoID Идентификатор протокола, содержащегося в прикладных данных
 * @param opacket Указатель на область памяти, куда записывается сформированный ESP-пакет
 *
 * @return В случае успеха возвращается размер ESP-пакета в байтах, иначе - 0
 */
size_t ak_esp_context_write_packet(ak_esp espContext, ak_pointer data, size_t datalen,
                                   ak_uint8 protoID, ak_uint8 *opacket) {
    if (espContext == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
        return 0;
    }
    if (datalen < 1 || datalen > 65535) {
        ak_error_message(ak_error_zero_length, __func__, "sending wrong length data");
        return 0;
    }
    if (data == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to payload data");
        return 0;
    }
    if (opacket == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to output packet");
        return 0;
    }
    // Шифруются: передаваемые данные и ESP-Trailer.
    // Имитозащита (считается контрольная сумма от): ESP-заголовок, IV, payload и ESP-Trailer
    ak_uint8 *curPacketOffset = opacket;
    ak_uint8 ICVLen;
    size_t trailerLen, packetLen, AADLen;

    /* 1. Копируем данные заголовка: */
    ak_esp_context_write_header(espContext, curPacketOffset);
    /* И сдвигаем указатель на пакет: */
    curPacketOffset += 8;

    /* 2. Копируем IV, на котором шифруется пакет: */
    ak_esp_context_write_iv(espContext, curPacketOffset);
    curPacketOffset += 8;

    /* 3. Копируем полезные данные: */
    /* 3.A Случай использования TFC-заполнения. */
    if (espContext->tfclen != 0) {
        /* Сначала записываем длину истинных полезных данных (2 байта),
        * затем сами данные, а потом - заполнение: */
        if (datalen + 2 > espContext->tfclen) {
            ak_error_message(ak_error_invalid_value, __func__, "data is too large for current TFC value");
            return 0;
        }
        /* Длина полезных данных в сетевом порядке байт: */
        *(curPacketOffset++) = (datalen >> 8) % 256;
        *(curPacketOffset++) = datalen % 256;
        /* Сами данные: */
        memcpy(curPacketOffset, data, datalen);
        curPacketOffset += datalen;
        /* TFC-заполнение: */
        memset(curPacketOffset, 255, espContext->tfclen - datalen - 2);
        curPacketOffset += espContext->tfclen - datalen - 2;
        /* Устанавливаем новую длину полезных данных: */
        datalen = espContext->tfclen;
    } else {
        /* 3.B Случай без TFC-заполнения: */
        /* Копируем полезные данные: */
        memcpy(curPacketOffset, data, datalen);
        curPacketOffset += datalen;
    }

    /* 4. Записываем ESP Trailer с обязательным заполнением: */
    trailerLen = ak_esp_context_write_trailer(datalen, protoID, curPacketOffset);
    curPacketOffset += trailerLen;

    /* 5. Вычисляем длину ICV: */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_kuznyechik_mgm_mac_ktree)
        // Для Кузнечика ICV имеет размер 96 бит (12 байт):
        ICVLen = 12;
    else
        // Для Магмы - 64 бита (8 байт):
        ICVLen = 8;

    /* 6. Вычисляем длину всего пакета: */
    packetLen = 8 /* ESP Header */ + 8 /* IV */ + datalen + trailerLen + ICVLen;

    /* 7. Получаем ключ шифрования сообщения: */
    ak_buffer msgKey = ak_esp_context_esptree(espContext, out_packet, NULL);
    if (msgKey == NULL) {
        ak_error_message(ak_error_get_value(), __func__, "error of getting message key");
        return 0;
    }

    /* 8. Получаем значение одноразового (инициализирующего) вектора nonce: */
    ak_buffer nonce = ak_esp_context_get_nonce(espContext, out_packet, NULL);
    if (nonce == NULL) {
        ak_error_message(ak_error_get_value(), __func__, "error of getting nonce");
        ak_buffer_delete(msgKey);
        return 0;
    }

    /* 10. Определяем размер дополнительных аутентифицируемых данных (AAD): */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_magma_mgm_ktree)
        /* Если производится шифрование, то AAD - это ESP Header: */
        AADLen = 8;
    else
        /* Иначе, AAD - это весь пакет (без ICV, очевидно): */
        AADLen = packetLen - ICVLen;

    /* 11. Устанавливаем ключ шифрования сообщения: */
    if (ak_bckey_context_set_key(&espContext->msg_key, msgKey->data, msgKey->size, ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "Error of setting block cipher key");
        ak_buffer_delete(msgKey);
        ak_buffer_delete(nonce);
        return 0;
    }
    ak_buffer_delete(msgKey);

    /* 12. Наконец, шифруем и/или вычисляем имитовставку от пакета: */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_magma_mgm_ktree)
        ak_bckey_context_encrypt_mgm(&espContext->msg_key, // Ключ для шифрования (для режимов без шифрования - NULL)
                                     &espContext->msg_key, // Ключ для вычисления имитовставки
                                                  opacket, // Указатель на начало AAD
                                                   AADLen, // Размер AAD
                        opacket + 16 /* заголовок и IV */, // Начало открытого текста (для режимов без шифрования - NULL)
                                             opacket + 16, // Куда сохранять шифртекст (для режимов без шифрования - NULL)
                                     datalen + trailerLen, // Размер открытого текста (для режимов без шифрования - 0)
                                              nonce->data, // Указатель на начало одноразового вектора
                                              nonce->size, // Размер одноразового вектора
                                          curPacketOffset, // Указатель на область данных, куда сохранять ICV
                                                  ICVLen); // Ожидаемая длина ICV. Для Кузнечика она меньше длины блока,
                                                           // и усекаются младшие (правые) биты,
                                                           // что и требуется стандартом ESP
    else
        ak_bckey_context_encrypt_mgm(NULL, // Ключ для шифрования (для режимов без шифрования - NULL)
                     &espContext->msg_key, // Ключ для вычисления имитовставки
                                  opacket, // Указатель на начало AAD
                                   AADLen, // Размер AAD
                                     NULL, // Начало открытого текста (для режимов без шифрования - NULL)
                                     NULL, // Куда сохранять шифртекст (для режимов без шифрования - NULL)
                                        0, // Размер открытого текста (для режимов без шифрования - 0)
                              nonce->data, // Указатель на начало одноразового вектора
                              nonce->size, // Размер одноразового вектора
                          curPacketOffset, // Указатель на область данных, куда сохранять ICV
                                  ICVLen); // Ожидаемая длина ICV. Для Кузнечика она меньше длины блока,
                                           // и усекаются младшие (правые) биты,
                                           // что и требуется стандартом ESP

    ak_buffer_delete(nonce);
    /* Если указатель на область данных, куда сохранять ICV, не равен NULL (как сейчас), то
     всегда возвращается NULL, поэтому проверим наличие ошибок с помощью соотв. функции: */
    if (ak_error_get_value() != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "packet encryption error");
        return 0;
    }

    /* 13. Изменяем счетчики в заголовке и в IV: */
    ++espContext->header.SeqNum;
    ak_esp_context_increment_iv(espContext);
    return packetLen;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Основная функция чтения (расшифрования и проверки) ESP-пакета
 * и получения прикладных данных пакета
 *
 * @param espContext Указатель на контекст протокола ESP
 * @param inpacket Указатель на ESP-пакет, который необходимо расшифровать и/или проверить
 * @param packetLen Длина ESP-пакета в байтах
 * @param outdata Указатель на область памяти, куда записываются прикладные данные ESP-пакета
 *
 * @return В случае успеха возвращается размер прикладных данных в байтах, иначе - 0
 */
size_t ak_esp_context_read_packet(ak_esp espContext, ak_uint8 *inpacket, size_t packetLen, ak_uint8 *outdata) {
    if (espContext == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to ESP context");
        return 0;
    }
    if (inpacket == NULL) {
        ak_error_message(ak_error_null_pointer, __func__, "using null pointer to input packet");
        return 0;
    }
    ak_uint8 *curPacketOffset = inpacket;
    ak_uint8 ICVLen;
    size_t AADLen, datalen;
    ak_uint32 seqNum;
    bool_t check = ak_false;

    /* 1. Чтение заголовка. Пропускаем значение SA и считываем значение sequence number: */
    memcpy(&seqNum, curPacketOffset += 4, 4);
    /* Изменяем порядок байт с сетевого на порядок хоста: */
    seqNum = htonl(seqNum);
    /* Проверяем номер последовательности: */
    if (!ak_esp_context_check_seqnum(espContext, seqNum)) {
        ak_error_message(ak_error_invalid_value, __func__, "receiving packet with wrong sequence number");
        return 0;
    }
    curPacketOffset += 4;

    /* 2. Чтение IV: */
    ak_esp_context_read_iv(espContext, curPacketOffset);
    curPacketOffset += 8;

    /* 3. Получаем ключ шифрования сообщения: */
    ak_buffer msgKey = ak_esp_context_esptree(espContext, in_packet, NULL);
    if (msgKey == NULL) {
        ak_error_message(ak_error_get_value(), __func__, "error of getting message key");
        return 0;
    }

    /* 4. Получаем значение одноразового (инициализирующего) вектора nonce: */
    ak_buffer nonce = ak_esp_context_get_nonce(espContext, in_packet, NULL);
    if (nonce == NULL) {
        ak_error_message(ak_error_get_value(), __func__, "error of getting nonce");
        ak_buffer_delete(msgKey);
        return 0;
    }

    /* 5. Вычисляем длину ICV: */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_kuznyechik_mgm_mac_ktree)
        // Для Кузнечика ICV имеет размер 96 бит (12 байт):
        ICVLen = 12;
    else
        // Для Магмы - 64 бита (8 байт):
        ICVLen = 8;

    /* 6. Определяем длину данных для расшифрования: */
    datalen = packetLen - 16 /* Заголовок и IV */ - ICVLen;

    /* 7. Определяем размер дополнительных аутентифицируемых данных (AAD): */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_magma_mgm_ktree)
        /* Если производится шифрование, то AAD - это ESP Header: */
        AADLen = 8;
    else
        /* Иначе, AAD - это весь пакет (без ICV, очевидно): */
        AADLen = packetLen - ICVLen;

    /* 8. Устанавливаем ключ шифрования сообщения: */
    if (ak_bckey_context_set_key(&espContext->msg_key, msgKey->data, msgKey->size, ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "Error of setting block cipher key");
        ak_buffer_delete(msgKey);
        ak_buffer_delete(nonce);
        return 0;
    }
    ak_buffer_delete(msgKey);

    /* 9. Расшифровываем и/или вычисляем имитовставку от пакета.
     * Заметим, что расшифрованные данные (если шифрование имеет место быть)
     * на данном этапе при расшифровании помещаются на место шифртекста: */
    if (espContext->transform == encr_kuznyechik_mgm_ktree ||
        espContext->transform == encr_magma_mgm_ktree)
        check = ak_bckey_context_decrypt_mgm(&espContext->msg_key, // Ключ для расшифрования (для режимов без шифрования - NULL)
                                             &espContext->msg_key, // Ключ для вычисления имитовставки
                                                         inpacket, // Указатель на начало AAD
                                                           AADLen, // Размер AAD
                                                  curPacketOffset, // Начало шифртекста (для режимов без шифрования - NULL)
                                                  curPacketOffset, // Куда сохранять открытый текст (для режимов без шифрования - NULL)
                                                          datalen, // Размер шифртекста (для режимов без шифрования - 0)
                                                      nonce->data, // Указатель на начало одноразового вектора
                                                      nonce->size, // Размер одноразового вектора
                                    inpacket + packetLen - ICVLen, // Указатель на ICV, с которым сравнивается вычисленная ICV
                                                          ICVLen); // Ожидаемая длина ICV. Для Кузнечика она меньше длины блока,
                                                                   // и усекаются младшие (правые) биты,
                                                                   // что и требуется стандартом ESP
    else
        check = ak_bckey_context_decrypt_mgm(NULL, // Ключ для расшифрования (для режимов без шифрования - NULL)
                             &espContext->msg_key, // Ключ для вычисления имитовставки
                                         inpacket, // Указатель на начало AAD
                                           AADLen, // Размер AAD
                                             NULL, // Начало шифртекста текста (для режимов без шифрования - NULL)
                                             NULL, // Куда сохранять открытый текст (для режимов без шифрования - NULL)
                                                0, // Размер шифртекста текста (для режимов без шифрования - 0)
                                      nonce->data, // Указатель на начало одноразового вектора
                                      nonce->size, // Размер одноразового вектора
                    inpacket + packetLen - ICVLen, // Указатель на ICV, с которым сравнивается вычисленная ICV
                                          ICVLen); // Ожидаемая длина ICV. Для Кузнечика она меньше длины блока,
                                                   // и усекаются младшие (правые) биты,
                                                   // что и требуется стандартом ESP
    ak_buffer_delete(nonce);

    /* 10. Проверяем успешность расшифрования: */
    if (check == ak_false) {
        ak_error_message(ak_error_get_value(), __func__, "wrong integrity code value");
        return 0;
    }

    /* 11.A Если используется TFC-заполнение, то отбрасываем его,
     * а также ESP Trailer с обязательным заполнением: */
    if (espContext->tfclen != 0) {
        /* Определяем реальную длину полезных данных: */
        datalen = 256 * curPacketOffset[0] + curPacketOffset[1];
        curPacketOffset += 2;
        /* Копируем полезные данные в выходной буфер: */
        memcpy(outdata, curPacketOffset, datalen);
        /* Так из-за использования TFC нам уже известна длина самих полезных данных,
         * то проверять ESP Trailer нет смысла */
    } else {
        /* 11.B Если TFC-заполнение не используется,
         * то отбрасываем ESP Trailer: */
        /* Поcледний байт расшифрованных данных - это поле Next Header,
         * а предпоследний байт - поле Pad Length, найдем его
         * и вычислим истинную длину полезных данных: */
        datalen -= curPacketOffset[datalen - 2] + 2 /* Next Header и Pad Len */;
        /* Копируем полезные данные в выходной буфер: */
        memcpy(outdata, curPacketOffset, datalen);
    }

    /* 12. Возвращаем длину полезных данных: */
    return datalen;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                        ak_esp.c */
/* ----------------------------------------------------------------------------------------------- */
