<?php

declare(strict_types=1);

namespace AppAttest\Cbor;

use RuntimeException;

/** CBOR 解析失敗。呼叫端應視為「輸入不可信」，不要嘗試修復。 */
final class CborException extends RuntimeException
{
}
