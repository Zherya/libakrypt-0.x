/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_key_manager.h                                                                          */
/*  - содержит определение интерфейса для механизмов хранения ключевой информации                  */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef    __AK_KEY_MANAGER_H__
 #define    __AK_KEY_MANAGER_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDIO_H
 #include <stdio.h>
#else
 #error Library cannot be compiled without stdio.h header
#endif
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип ключа, помещаемого в ключевое хранилище */
 typedef enum {
  /*! \brief Ключ симметричного криптографического преобразования.
      \details К симметричным ключам относятся объекты классов skey, bckey, hmac, omac и mgm. */
  symmetric_key,
 /*! \brief Секретный ключ асимметричного криптографического алгоритма.
     \details К открытым ключам относятся объекты класса signkey. */
  secret_key,
 /*! \brief Открытый ключ асимметричного криптографического алгоритма.
     \details К открытым ключам относятся объекты класса verifykey. */
  public_key
} stored_key_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Формат хранения ключевой информации. */
 typedef enum {
  /*! \brief Простой формат хранения секретных ключей, реализуемый библиотекой libakrypt.
      \details В данном фомате ключевой контекст преобразуется в последовательность октетов,
      которая зашифровывается при помощи ключа, выработанного из пароля. Предполагается,
      что для каждого ключа используется свой собственный пароль 
      (ebpp, encrypt by personal password). */
   ebpp_plain_secret_key_storage_format

} key_storage_format_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Флаги получения ключевой информации. */
 typedef enum {
   /*! \brief Флаг точного соответствия номера ключа. */
    exact_key_number_flag = 0x01uLL
} key_storage_flags_t;

/* ----------------------------------------------------------------------------------------------- */
 typedef struct key_manager *ak_key_manager;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавления ключа.
    \details Функция должна добавлять ключ, на который указывает \ref ak_pointer, в ключевое хранилище.
    В случае успешного добавления должно возвращаться значение \ref ak_error_ok.

    Тип добавляемого ключа определяется переменной типа \ref oid_engines_t. Ключевой менеджер должен
    поддерживать сохранение ключей хотя бы одного типа. Если тип не поддерживается, должна
    возвращаться ошибка \ref ak_error_key_engine.

    Формат, в котором будет храниться ключ, определяется переменной типа \ref key_storage_format_t.
    Ключевой менеджер должен поддерживать сохранение ключей хотя бы в одном формате. Если заданный
    формат не поддерживается, должна возвращаться ошибка \ref ak_error_key_format.

    Последний параметр функции определяет указатель на произвольную структуру (область памяти),
    в которой передаются параметры, необходимые для сохранения ключа в ключевом хранилище.
    Конкретный вид передаваемых параметров должен определяться типом \ref key_storage_format_t.
    В случае, если дополнительные данные не нужны, должно использоваться значение NULL.            */
/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_add_key )
               ( ak_key_manager , ak_pointer , oid_engines_t , key_storage_format_t , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция для поиска ключа.
    \details Функция предназначена для поиска ключа с заданным номером. Для передачи значения номера
    ключа должен использоваться буффер (\ref ak_buffer), содержащий либо номер ключа,
    либо последовательность байт, задающую маску поиска номера ключа.

    В случае успешного поиска функция должна возвращать \ref ak_error_ok. Также должны
    инициализироваться следующие значения:
     - struct \ref ak_buffer , содержащий точный номер найденного ключа,
     - \ref oid_engines_t , содержащий тип криптографического преобразования для найденного ключа,
     - \ref key_storage_format_t , формат,  в котором сохранен найденный ключ.

    В случае, если ключ с запрашиваемым номером не найден, должно возвращаться
    значение \ref ak_error_key_search.

    Этому же типу должна удовлетворять функция поиска следующего ключа.                            */
/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_find_key )
              ( ak_key_manager , ak_buffer , ak_buffer , oid_engines_t *, key_storage_format_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получения ключа по его номеру.
    \details По заданному номеру ключа, передаваемому в объекте класса buffer,
    функция должна возвращать указатель на созданный контекст ключа, размещенный в оперативной памяти.

    Тип создаваемого ключа определяется переменной типа \ref oid_engines_t. Ключевой менеджер должен
    поддерживать создание ключей хотя бы одного типа. Если тип не поддерживается, должна
    возвращаться ошибка \ref ak_error_key_engine.

    Формат, в котором хранится создаваемый ключ, определяется переменной типа \ref key_storage_format_t.
    Ключевой менеджер должен поддерживать создание ключей хотя бы в одном формате. Если заданный пользователем
    формат не поддерживается, должна возвращаться ошибка \ref ak_error_key_format.

    Узнать тип хранящегося ключа по его номеру, а также формат хранения можно с помощью
    функции типа \ref ak_function_find_key_buffer.

    Последний аргумент функции является указателем на произвольную структуру (область памяти),
    в которой передаются параметры, необходимые для создания ключа из ключевого хранилища.
    Конкретный вид передаваемых параметров должен определяться типом \ref key_storage_format_t.

    Созданный ключ должен быть позднее удален с помощью вызова ak_<тип ключа>_delete().

    В случае ошибки, функция должна возвращать NULL и устанавливать значение ощибки, которое
    можно получить с помощью функции ak_error_get_value(). */
/* ----------------------------------------------------------------------------------------------- */
 typedef ak_pointer ( ak_function_get_key )
                 ( ak_key_manager , ak_buffer , oid_engines_t , key_storage_flags_t , ak_pointer );


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, описывающая общий интерфейс к менеджерам хранения ключевой инфорации.
    \details Менеджер хранения ключевой информации представляет собой совокупность функций, позволяющих
    сохранять ключевую информацию, получать доступ к ключам по их номеру,
    искать ключи, экспортировать и импортировать ключевую информацию. */
/* ----------------------------------------------------------------------------------------------- */
 struct key_manager {
  /*! \brief Идентификатор конкретного объекта мененджера ключевой информации.
      \details Может содержать любую последовательность октетов, в частности,
      имя файла, каталога или уникальный идентифкатор UUID. */
   ak_uint8 name[FILENAME_MAX];
  /*! \brief Функция добавления ключа. */
   ak_function_add_key *add;
  /*! \brief Функция поиска ключа. */
   ak_function_find_key *find;
  /*! \brief Функция поиска следующего ключа. */
   ak_function_find_key *find_next;
  /*! \brief Функция получения ключа из ключевого хранилища. */
   ak_function_get_key *get;
};

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                               ak_key_manager.h  */
/* ----------------------------------------------------------------------------------------------- */
