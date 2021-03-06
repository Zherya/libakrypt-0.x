/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hash.h                                                                                 */
/*  - содержит реализацию общих механизмов, используемых в алгоритмах бесключевого хэширования.    */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct hash в значения по-умолчанию.

    @param ctx указатель на структуру struct hash
    @param data_size Размер внутренних данных контекста в байтах
    @param block_size Размер блока обрабатываемых данных в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create( ak_hash ctx, const size_t data_size, const size_t block_size )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to hash context" );
  if( block_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using a zero length of data block length" );
  if( data_size != 0 ) {
    if(( ctx->data = malloc( data_size )) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                      "incorrect internal data memory allocation" );
  } else ctx->data = NULL;

  ctx->bsize =  block_size;
  ctx->hsize =           0;
  ctx->oid =          NULL;
  ctx->clean =        NULL;
  ctx->update =       NULL;
  ctx->finalize =     NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct hash.

  @param ctx указатель на структуру struct hash
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_destroy( ak_hash ctx )
{
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "destroying null pointer to hash context" );
  if( ctx->data != NULL ) free( ctx->data );

  ctx->bsize =       0;
  ctx->hsize =       0;
  ctx->data =     NULL;
  ctx->oid =      NULL;
  ctx->clean =    NULL;
  ctx->update =   NULL;
  ctx->finalize = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx указатель на контекст хеширования
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hash_context_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_hash_context_destroy(( ak_hash ) ctx );
      free( ctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hash context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В случае инициализации контекста алгоритма ГОСТ Р 34.11-94 (в настоящее время выведен из
    действия) используются фиксированные таблицы замен, определяемые константой
    `id-gosthash94-rfc4357-paramsetA`. Для создания контекста функции хеширования ГОСТ Р 34.11-94
    с другими таблицами замен нужно пользоваться функцией ak_hash_create_gosthash94().

    @param ctx указатель на структуру struct hash
    @param oid OID алгоритма бесключевого хеширования.

    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_context_create_oid( ak_hash ctx, ak_oid oid )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to hash context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to hash function OID" );
 /* проверяем, что OID от бесключевой функции хеширования */
  if( oid->engine != hash_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );
 /* проверяем, что производящая функция определена */
  if( oid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using oid with undefined constructor" );
 /* инициализируем контекст */
  if(( error = (( ak_function_hash_create *)oid->func.create )( ctx )) != ak_error_ok )
      return ak_error_message( error, __func__, "invalid creation of hash function context");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    \b Внимание. После завершения вычислений контекст функции хеширования инициалищируется
    в начальное состояние.

    @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_context_ptr( ak_hash ctx, const ak_pointer in, const size_t size, ak_pointer out )
{
  ak_buffer result = NULL;
  size_t quot = 0, offset = 0;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hash context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }

  /* вычищаем результаты предыдущих вычислений */
  ctx->clean( ctx );
  quot = size/ctx->bsize;
  offset = quot*ctx->bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 ) ctx->update( ctx, in, offset );
  /* обрабатываем хвост */
  result = ctx->finalize( ctx, (unsigned char *)in + offset, size - offset, out );
  /* очищаем за собой данные, содержащиеся в контексте */
  ctx->clean( ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданного файла. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает указатель на
    созданный буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_context_file( ak_hash ctx, const char *filename, ak_pointer out )
{
  struct mac ictx;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hash context" );
    return NULL;
  }

  if(( error = ak_mac_context_create_hash( &ictx, ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of mac context" );
    return NULL;
  }

  result = ak_mac_context_file( &ictx, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect hash code calculation" );

  ak_mac_context_destroy( &ictx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-internal-hash01.c
    \example test-internal-hash02.c
    \example test-internal-hash03.c                                                                */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
