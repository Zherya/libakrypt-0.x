/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_sign.h                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_SIGN_H__
#define    __AK_SIGN_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>
 #include <ak_curves.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ алгоритма формирования электронной подписи согласно ГОСТ Р 34.10-2012. */
 struct signkey {
 /*! \brief контекст секретного ключа */
  struct skey key;
 /*! \brief контекст функции хеширования */
  struct hash ctx;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на структуру секретного ключа алгоритма выработки электронной подписи ГОСТ Р 34.10-2012. */
 typedef struct signkey *ak_signkey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_signkey_create_streebog256( ak_signkey , ak_wcurve );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_signkey_create_streebog512( ak_signkey , ak_wcurve );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2001. */
 int ak_signkey_create_gosthash94( ak_signkey , ak_handle , ak_wcurve );
/*! \brief Уничтожение контекста секретного ключа. */
 int ak_signkey_destroy( ak_signkey );
/*! \brief Освобождение памяти из под контекста секретного ключа. */
 ak_pointer ak_signkey_delete( ak_pointer );

/*! \brief Присвоение контексту ключа алгоритма выработки электронной подписи константного значения. */
 int ak_signkey_context_set_key( ak_signkey , const ak_pointer , const size_t );

/*! \brief Выработка электронной подписи для заданного случайного числа и хеш-значения. */
 ak_buffer ak_signkey_context_sign_values( ak_signkey , ak_uint64 *, ak_pointer , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Открытый ключ алгоритма проверки электронной подписи ГОСТ Р 34.10-2012. */
/* ----------------------------------------------------------------------------------------------- */
 struct pubkey {
 /*! \brief контекст функции хеширования */
  struct hash ctx;
 /*! \brief контекст эллиптической кривой */
  ak_wcurve wc;
 /*! \brief OID алгоритма проверки */
  ak_oid oid;
 /*! \brief точка кривой, являющаяся открытым ключом */
  struct wpoint qpoint;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на структуру открытого ключа алгоритма проверки электронной подписи ГОСТ Р 34.10-2012. */
 typedef struct pubkey *ak_pubkey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста открытого ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_pubkey_create_streebog256( ak_pubkey , ak_wcurve );
/*! \brief Уничтожение контекста открытого ключа. */
 int ak_pubkey_destroy( ak_pubkey );
/*! \brief Освобождение памяти из под контекста открытого ключа. */
 ak_pointer ak_pubkey_delete( ak_pointer );



/*! \brief Инициализация контекста открытого ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_pubkey_create_signkey( ak_pubkey , ak_signkey );


 ak_bool ak_pubkey_context_verify_values( ak_pubkey , ak_pointer , ak_pointer );


/*! \brief Функция тестирует процедуры выработки и проверки электронной подписи соглдастно ГОСТ Р 34.10-2012. */
 ak_bool ak_signkey_test( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.h  */
/* ----------------------------------------------------------------------------------------------- */