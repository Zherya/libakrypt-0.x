/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
/* ----------------------------------------------------------------------------------------------- */
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

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    @return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_oid( ak_hmac hctx, ak_oid oid )
{
  ak_oid hashoid = NULL;
  int error = ak_error_ok;

 /* выполняем проверку */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to hash function OID" );
 /* проверяем, что OID от правильного алгоритма выработки */
  if( oid->engine != hmac_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* получаем oid бесключевой функции хеширования */
  if(( hashoid = ak_oid_context_find_by_name( oid->name+5 )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect searching of hash fuction oid" );
 /* проверяем, что производящая функция определена */
  if( hashoid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                        "using hash function oid with undefined constructor" );
 /* инициализируем контекст функции хеширования */
  if(( error =
           (( ak_function_hash_create *)hashoid->func.create )( &hctx->ctx )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                               "invalid creation of %s hash function context", hashoid->name );

 /* инициализируем контекст секретного ключа */
  if(( error = ak_skey_context_create( &hctx->key, hctx->ctx.bsize, 8 )) != ak_error_ok ) {
    ak_hash_context_destroy( &hctx->ctx );
    return ak_error_message( error, __func__, "wrong creation of secret key" );
  }

 /* доопределяем oid ключа */
  hctx->key.oid = oid;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog256( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog256" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog512( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog512" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_destroy( ak_hmac hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_hash_context_destroy( &hctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of hash context" );
  if((  error = ak_skey_context_destroy( &hctx->key )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of secret key context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hmac_context_delete( ak_pointer hctx )
{
  if( hctx != NULL ) {
      ak_hmac_context_destroy(( ak_hmac ) hctx );
      free( hctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hmac context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения укзателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key( ak_hmac hctx, const ak_pointer ptr,
                                                            const size_t size, const bool_t cflag )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
 /* вспоминаем, что если ключ длиннее, чем длина входного блока хэш-функции, то в качестве
                                                                      ключа используется его хэш */
  if( size > hctx->ctx.bsize ) {
    ak_uint8 out[64];
    if( hctx->ctx.hsize > 64 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                        "using hash function with very huge integrity code" );
    ak_hash_context_ptr( &hctx->ctx, ptr, size, out );
    if(( error = ak_error_get_value( )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect calculation of integrity code" );
    if(( error = ak_skey_context_set_key( &hctx->key, out,
                                               hctx->ctx.hsize, ak_true )) != ak_error_ok )
      return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
    ak_ptr_wipe( out, sizeof( out ), &hctx->key.generator, ak_true );

  } else { /* здесь ключ используется в явном виде */
      if(( error = ak_skey_context_set_key( &hctx->key, ptr, size, cflag )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
  }

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_context_set_resource( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param hctx Контекст алгоритма HMAC выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key_random( ak_hmac hctx, ak_random generator )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_context_set_key_random( &hctx->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_context_set_resource( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param hctx Контекст алгоритма HMAC выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах.
    @param salt Случайная последовательность, представленная в виде строки символов.
    @param salt_size Длина случайной последовательности в байтах.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key_from_password( ak_hmac hctx,
                                                const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_context_set_key_from_password( &hctx->key,
                                          pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_context_set_resource( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_clean( ak_pointer ctx )
{
  int error = ak_error_ok;
  size_t idx = 0, len = 0;
  ak_hmac hctx = ( ak_hmac ) ctx;
  ak_uint8 buffer[64]; /* буффер для хранения промежуточных значений */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );

  if( hctx->key.resource.value.counter <= 1 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );
                      /* нам надо два раза использовать ключ => ресурс должен быть не менее двух */
  if( hctx->ctx.bsize > sizeof( buffer )) return ak_error_message( ak_error_wrong_length,
                                            __func__, "using hash function with huge block size" );

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->ctx.bsize, hctx->key.key.size );
  for( idx = 0; idx < len; idx++ ) {
     buffer[idx] = ((ak_uint8 *)hctx->key.key.data)[idx] ^ 0x36;
     buffer[idx] ^= ((ak_uint8 *)hctx->key.mask.data)[idx];
  }
  for( ; idx < hctx->ctx.bsize; idx++ ) buffer[idx] = 0x36;

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* обновляем состояние контекста хеширования */
  if(( error = hctx->ctx.update( &hctx->ctx, buffer, hctx->ctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( buffer, sizeof( buffer ), &hctx->key.generator, ak_true );

 /* перемаскируем ключ и меняем его ресурс */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @param data Указатель на обрабатываемые данные.
    @param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_update( ak_pointer ctx, const ak_pointer data, const size_t size )
{
  ak_hmac hctx = ( ak_hmac ) ctx;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->ctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
  if( hctx->key.resource.value.counter <= 0 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );

  return hctx->ctx.update( &hctx->ctx, data, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @param data блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_context_finalize( ak_pointer ctx, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  size_t idx = 0, len = 0;
  ak_hmac hctx = ( ak_hmac ) ctx;
  ak_buffer result = NULL;
  ak_uint8 temporary[128]; /* первый буффер для хранения промежуточных значений */
  ak_uint8 keybuffer[128]; /* второй буффер для хранения промежуточных значений */

 /* выполняем проверки */
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac context" );
    return NULL;
  }
 /* ограничение в связи с константным размером временного буффера */
  if( hctx->ctx.hsize > sizeof( temporary )) {
    ak_error_message( ak_error_wrong_length,
                   __func__, "using a hash context with unsupported huge integrity code size" );
    return NULL;
  }
  if( size >= hctx->ctx.bsize ) {
    ak_error_message( ak_error_zero_length,
                                       __func__ , "using wrong length for authenticated data" );
    return NULL;
  }
 /* проверяем наличие ключа (ресурс проверен при вызове clean) */
  if( !((hctx->key.flags)&skey_flag_set_key )) {
    ak_error_message( ak_error_key_value, __func__ , "using hmac key with unassigned value" );
    return NULL;
  }

 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, sizeof( temporary ));
  error = ak_error_ok;
  hctx->ctx.finalize( &hctx->ctx, data, size, temporary );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong updating of finalized data" );
    return NULL;
  }

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->ctx.bsize, hctx->key.key.size );
  for( idx = 0; idx < len; idx++ ) {
     keybuffer[idx] = ((ak_uint8 *)hctx->key.key.data)[idx] ^ 0x5C;
     keybuffer[idx] ^= ((ak_uint8 *)hctx->key.mask.data)[idx];
  }
  for( ; idx < hctx->ctx.bsize; idx++ ) keybuffer[idx] = 0x5C;

 /* возвращаем контекст хеширования в начальное состояние */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong cleaning of hash function context" );
    return NULL;
  }

 /* обновляем состояние контекста хеширования */
  if(( error = hctx->ctx.update( &hctx->ctx, keybuffer, hctx->ctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( keybuffer, sizeof( keybuffer ), &hctx->key.generator, ak_true );

 /* ресурс ключа */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 /* последний update/finalize и возврат результата */
  if( hctx->ctx.bsize == hctx->ctx.hsize ) {
    hctx->ctx.update( &hctx->ctx, temporary, hctx->ctx.hsize );
    result = hctx->ctx.finalize( &hctx->ctx, NULL, 0, out );
  } else result = hctx->ctx.finalize( &hctx->ctx, temporary, hctx->ctx.hsize, out );

 /* очищаем контекст функции хеширования, ключ не трогаем */
  hctx->ctx.clean( &hctx->ctx );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    \b Внимание. После завершения вычислений контекст функции хеширования инициализируется
    в начальное состояние.

    @param hctx Контекст алгоритма HMAC выработки имитовставки.
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
 ak_buffer ak_hmac_context_ptr( ak_hmac hctx, const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  size_t quot = 0, offset = 0;

  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hmac context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }

  /* вычищаем результаты предыдущих вычислений */
  if(( error = ak_hmac_context_clean( hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect cleaning hmac context" );
    return NULL;
  }
  quot = size/hctx->ctx.bsize;
  offset = quot*hctx->ctx.bsize;

  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 )
    if(( error = ak_hmac_context_update( hctx, in, offset )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "incorrect updating hmac context" );
      return NULL;
    }

  /* обрабатываем хвост и возвращаем результат */
 return ak_hmac_context_finalize( hctx, (ak_uint8 *)in + offset, size - offset, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает указатель на
    созданный буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_context_file( ak_hmac ctx, const char *filename, ak_pointer out )
{
  struct mac ictx;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hmac context" );
    return NULL;
  }

  if(( error = ak_mac_context_create_hmac( &ictx, ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of mac context" );
    return NULL;
  }

  result = ak_mac_context_file( &ictx, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect integrity code calculation" );

  ak_mac_context_destroy( &ictx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает ключевой вектор из заданного пользователем пароля и инициализационного
    вектора в соответствии с алгоритмом, описанным в отечественных рекомендациях Р 50.1.111-2016.
    При выработке используется алгоритм hmac-streebog512.

    Пароль должен представлять собой ненулевую строку символов в utf8
    кодировке. Размер вырабатываемого ключевого вектора может колебаться от 32-х до 64-х байт.

    @param pass Пароль, строка символов в utf8 кодировке.
    @param pass_size Размер пароля в байтах, должен быть отличен от нуля.
    @param salt Строка с инициализационным вектором (произвольная область памяти). Данное значение
    не является секретным и может храниться или передаваться в открытом виде.
    @param salt_size Размер инициализионного вектора в байтах.
    @param cnt Параметр, определяющий количество однотипных итераций для выработки ключа; данный
    параметр определяет время работы алгоритма; параметр не является секретным и может храниться или
    передаваться в открытом виде.
    @param dklen Длина вырабатываемого ключевого вектора в байтах, величина должна принимать
    значение от 32-х до 64-х.
    @param out Указатель на массив, куда будет помещен результат; под данный массив должна быть
    заранее выделена память не менее, чем dklen байт.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_pbkdf2_streebog512( const ak_pointer pass,
         const size_t pass_size, const ak_pointer salt, const size_t salt_size, const size_t cnt,
                                                               const size_t dklen, ak_pointer out )
{
  struct mac ictx;
  struct hmac hctx;
  ak_uint8 result[64];
  int error = ak_error_ok;
  size_t idx = 0, jdx = 0;

 /* в начале, многочисленные проверки входных параметров */
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                   "using a zero length password" );
  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using null pointer to salt" );
  if(( dklen < 32 ) || ( dklen > 64 )) return ak_error_message( ak_error_wrong_length,
                                       __func__ , "using a wrong length for resulting key vector" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to resulting key vector" );
 /* создаем контекст алгоритма hmac и определяем его ключ */
  if(( error = ak_hmac_context_create_streebog512( &hctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of hmac-streebog512 key context" );
  if(( error = ak_hmac_context_set_key( &hctx, pass, pass_size, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of hmac-streebog512 secret key" );
    goto lab_exit;
  }

 /* начальная инициализация промежуточного вектора */
  memset( result, 0, 64 );
  result[3] = 1;

  if(( error = ak_mac_context_create_hmac( &ictx, &hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of mac key context" );
    goto lab_exit;
  }

 /* вычисляем значение первой строки U1  */
  if(( error = ak_mac_context_clean( &ictx )) != ak_error_ok ) {
    ak_mac_context_destroy( &ictx );
    ak_error_message( error, __func__, "incorrect cleaning of internal mac context");
    goto lab_exit;
  }
  if(( error = ak_mac_context_update( &ictx, salt, salt_size )) != ak_error_ok ) {
    ak_mac_context_destroy( &ictx );
    ak_error_message( error, __func__, "incorrect updating of internal mac context");
    goto lab_exit;
  }
  ak_mac_context_finalize( &ictx, result, 4, result );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    ak_mac_context_destroy( &ictx );
    ak_error_message( error, __func__, "incorrect finalizing of internal mac context");
    goto lab_exit;
  }
  ak_mac_context_destroy( &ictx );
  memcpy( out, result+64-dklen, dklen );

 /* теперь основной цикл по значению аргумента c */
  for( idx = 1; idx < cnt; idx++ ) {
     ak_hmac_context_ptr( &hctx, result, 64, result );
     for( jdx = 0; jdx < dklen; jdx++ ) ((ak_uint8 *)out)[jdx] ^= result[64-dklen+jdx];
  }
  memset( result, 0, 64 );

  lab_exit: ak_hmac_context_destroy( &hctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции для тестирования алгоритма hmac                              */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_hmac_test_streebog( void )
{
  ak_uint8 key[32] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  ak_uint8 data[16] = {
   0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
  };

  ak_uint8 R256[32] = {
   0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
   0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
  };

  ak_uint8 R512[64] = {
   0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
   0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b, 0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
   0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96, 0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
   0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6
  };

  struct hmac hkey;
  char *str = NULL;
  ak_uint8 out[64];
  int error = ak_error_ok;
  bool_t result = ak_true;
  int audit = ak_log_get_level();

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_hmac_context_create_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_context_set_key( &hkey, key, 32, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R256, 32 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog256 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R256, 32, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog256 from R 50.1.113-2016 is Ok" );
  ak_hmac_context_destroy( &hkey );

 /* 2. тестируем HMAC на основе Стрибог 512 */
  if(( error = ak_hmac_context_create_streebog512( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog512 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_context_set_key( &hkey, key, 32, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R512, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog512 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R512, 64, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog512 from R 50.1.113-2016 is Ok" );
 lab_exit:
  ak_hmac_context_destroy( &hkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_hmac_test_pbkdf2( void )
{
  ak_uint8 R1[64] = {
   0x64, 0x77, 0x0a, 0xf7, 0xf7, 0x48, 0xc3, 0xb1, 0xc9, 0xac, 0x83, 0x1d, 0xbc, 0xfd, 0x85, 0xc2,
   0x61, 0x11, 0xb3, 0x0a, 0x8a, 0x65, 0x7d, 0xdc, 0x30, 0x56, 0xb8, 0x0c, 0xa7, 0x3e, 0x04, 0x0d,
   0x28, 0x54, 0xfd, 0x36, 0x81, 0x1f, 0x6d, 0x82, 0x5c, 0xc4, 0xab, 0x66, 0xec, 0x0a, 0x68, 0xa4,
   0x90, 0xa9, 0xe5, 0xcf, 0x51, 0x56, 0xb3, 0xa2, 0xb7, 0xee, 0xcd, 0xdb, 0xf9, 0xa1, 0x6b, 0x47
  };

  ak_uint8 R2[64] = {
   0x5a, 0x58, 0x5b, 0xaf, 0xdf, 0xbb, 0x6e, 0x88, 0x30, 0xd6, 0xd6, 0x8a, 0xa3, 0xb4, 0x3a, 0xc0,
   0x0d, 0x2e, 0x4a, 0xeb, 0xce, 0x01, 0xc9, 0xb3, 0x1c, 0x2c, 0xae, 0xd5, 0x6f, 0x02, 0x36, 0xd4,
   0xd3, 0x4b, 0x2b, 0x8f, 0xbd, 0x2c, 0x4e, 0x89, 0xd5, 0x4d, 0x46, 0xf5, 0x0e, 0x47, 0xd4, 0x5b,
   0xba, 0xc3, 0x01, 0x57, 0x17, 0x43, 0x11, 0x9e, 0x8d, 0x3c, 0x42, 0xba, 0x66, 0xd3, 0x48, 0xde
  };

  ak_uint8 R3[64] = {
   0xe5, 0x2d, 0xeb, 0x9a, 0x2d, 0x2a, 0xaf, 0xf4, 0xe2, 0xac, 0x9d, 0x47, 0xa4, 0x1f, 0x34, 0xc2,
   0x03, 0x76, 0x59, 0x1c, 0x67, 0x80, 0x7f, 0x04, 0x77, 0xe3, 0x25, 0x49, 0xdc, 0x34, 0x1b, 0xc7,
   0x86, 0x7c, 0x09, 0x84, 0x1b, 0x6d, 0x58, 0xe2, 0x9d, 0x03, 0x47, 0xc9, 0x96, 0x30, 0x1d, 0x55,
   0xdf, 0x0d, 0x34, 0xe4, 0x7c, 0xf6, 0x8f, 0x4e, 0x3c, 0x2c, 0xda, 0xf1, 0xd9, 0xab, 0x86, 0xc3
  };

  ak_uint8 R4[64] = {
   0x50, 0xdf, 0x06, 0x28, 0x85, 0xb6, 0x98, 0x01, 0xa3, 0xc1, 0x02, 0x48, 0xeb, 0x0a, 0x27, 0xab,
   0x6e, 0x52, 0x2f, 0xfe, 0xb2, 0x0c, 0x99, 0x1c, 0x66, 0x0f, 0x00, 0x14, 0x75, 0xd7, 0x3a, 0x4e,
   0x16, 0x7f, 0x78, 0x2c, 0x18, 0xe9, 0x7e, 0x92, 0x97, 0x6d, 0x9c, 0x1d, 0x97, 0x08, 0x31, 0xea,
   0x78, 0xcc, 0xb8, 0x79, 0xf6, 0x70, 0x68, 0xcd, 0xac, 0x19, 0x10, 0x74, 0x08, 0x44, 0xe8, 0x30
  };

  ak_uint8 password_one[8] = "password",
           password_two[9] = { 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' },
           salt_one[4]     = "salt",
           salt_two[5]     = { 's', 'a', 0, 'l', 't' };

  ak_uint8 out[64];
  char *str = NULL;
  int error = ak_error_ok;
  int audit = ak_log_get_level();

 /* первый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_context_pbkdf2_streebog512( password_one, 8,
                                                     salt_one, 4, 1, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R1, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 1st test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R1, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 1st test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* второй тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_context_pbkdf2_streebog512( password_one, 8,
                                                     salt_one, 4, 2, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R2, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 2nd test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R2, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 2nd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* третий тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_context_pbkdf2_streebog512( password_one, 8,
                                                  salt_one, 4, 4096, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R3, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 3rd test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R3, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 3rd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* четвертый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_context_pbkdf2_streebog512( password_two, 9,
                                                  salt_two, 5, 4096, 64, out )) != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R4, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 4th test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R4, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 4th test for pbkdf2 from R 50.1.111-2016 is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление значения функции KDF256(Kin, label, seed) диверсификации секретного ключа
 * из документа Р 50.1.113–2016.
 *
 * @param keyIn Указатель на область памяти, содержащей значение входного ключа
 * @param keySize Размер входного ключа в байтах
 * @param label Указатель на область памяти, содержащей значение метки диверсификации
 * @param labelSize Размер метки диверсификации в байтах
 * @param seed Указатель на область памяти, содержащей значение "начального значения" (seed)
 * диверсификации
 * @param seedSize Размер seed в байтах
 * @param out Указатель на область памяти (размера не меньше 32-х байт),
 * в которую помещается значение функции KDF256. Может быть равен NULL.
 * @return Если out равен NULL, то функция возвращает указатель на буфер (ak_buffer)
 * со значением функции KDF256. Буфер должен быть очищен с помощью ak_buffer_delete().
 * Иначе возвращается NULL. В случае неудачи возвращается NULL,
 * а код ошибки проверяется с помощью ak_error_get_value()
 */
ak_buffer ak_hmac_context_kdf256(const ak_pointer keyIn, const size_t keySize,
                                 const ak_pointer label, const size_t labelSize,
                                 const ak_pointer seed, const size_t seedSize, ak_pointer out) {
    struct hmac HMAC256;
    ak_buffer res;
    if ((ak_hmac_context_create_streebog256(&HMAC256)) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "wrong hmac256 creation");
        return NULL;
    }
    /* Формируем входные данные для HMAC256 согласно определению KDF256: */
    const size_t inDataSize = labelSize + seedSize + 4;
    ak_uint8 *inData = malloc(inDataSize);
    inData[0] = 0x01;
    memcpy(inData + 1, label, labelSize);
    inData[labelSize + 1] = 0x00;
    memcpy(inData + labelSize + 2, seed, seedSize);
    inData[labelSize + seedSize + 2] = 0x01;
    inData[labelSize + seedSize + 3] = 0x00;

    if (ak_hmac_context_set_key(&HMAC256, keyIn, keySize, ak_true) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "error of setting hmac key");
        return NULL;
    }

    /* Вычисляем значение, очищаем контекст и возвращаем результат: */
    res = ak_hmac_context_ptr(&HMAC256, inData, inDataSize, out);
    if (ak_hmac_context_destroy(&HMAC256) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "wrong hmac256 context destroy");
        return NULL;
    }
    return res;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование функции KDF256 согласно документу Р 50.1.113–2016
 *
 * @return Возвращает ak_true в случае успешного тестирования KDF256 и ak_false - иначе
 */
bool_t ak_hmac_test_kdf256 ( void ) {
    /* ТЕСТ KDF256:
     * Ключ диверсификации Kin (из стандарта):
     * 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
     * 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
     * Запись ключа, как есть: */
    ak_uint8 Kin[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    /* label (из стандарта):
     * 26 bd b8 78
     * Запись label, как есть: */
    ak_uint8 label[4] = {0x26, 0xbd, 0xb8, 0x78};

    /* seed (из стандарта):
     * af 21 43 41 45 65 63 78
     * Запись seed, как есть: */
    ak_uint8 seed[8] = {0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78};

    /* KDF256(Kin, label, seed) (из стандарта):
     * a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
     * 01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
     * Запись результата, как есть: */
    ak_uint8 GOSTResPtr[32] = {0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45,
                               0x34,
                               0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e,
                               0xd9};
    ak_buffer KDFOut;
    if ((KDFOut = ak_hmac_context_kdf256(Kin, 32, label, 4, seed, 8, NULL)) == NULL) {
        ak_error_message(ak_error_get_value(), "KDF256", "wrong kdf256 computation");
        return ak_false;
    }
    bool_t res = ak_ptr_is_equal(GOSTResPtr, ak_buffer_get_ptr(KDFOut), ak_buffer_get_size(KDFOut));
    ak_buffer_delete(KDFOut);
    return res;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_hmac.с */
/* ----------------------------------------------------------------------------------------------- */
