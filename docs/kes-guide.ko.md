# KES 문법 가이드

[English](kes-guide.md) | [**한국어**](kes-guide.ko.md)

**KES(Karity Extended Syntax)**는 Lua 코드를 더 짧고 편하게 쓰는 Karity의 확장 문법입니다. 별도 설정 없이 사용할 수 있으며, Karity가 표준 Lua로 변환합니다. GUI의 **소스 실행(F5)**에서도 사용할 수 있습니다.

[README](../README.ko.md) · [상세 명세(영문)](kes.md) · [성능 측정(영문)](performance/kes.md)

## 한눈에 보기

```lua
local player = nil
local name = player?.profile?.name ?? "Guest"

local total = 0
for i = 1, 5 do
    if i % 2 == 0 then continue end
    total += i
end

local result = total >= 9 ? "PASS" : "FAIL"
print(name, total, result) -- Guest  9  PASS
```

## 복합 대입

| KES | 의미 |
|---|---|
| `a += b` | `a = a + b` |
| `a -= b` | `a = a - b` |
| `a *= b` | `a = a * b` |
| `a /= b` | `a = a / b` |
| `a %= b` | `a = a % b` |
| `a ^= b` | `a = a ^ b` — 거듭제곱 |
| `a ..= b` | `a = a .. b` — 문자열 연결 |
| `a //= b` | `a = a // b` — 내림 나눗셈, Lua 5.3 전용 |

테이블에도 사용할 수 있습니다. `items[getIndex()] += 1`의 `getIndex()`는 한 번만 실행됩니다. 평가 순서는 **테이블 → 키 → 기존 값 → 우변 → 대입**입니다.

## nil 처리와 조건식

| 문법 | 동작 |
|---|---|
| `value ?? fallback` | `value`가 nil일 때만 `fallback` 사용 |
| `config.timeout ??= 30` | 기존 값이 nil일 때만 대입 |
| `user?.profile?.name` | 각 `?.`의 왼쪽이 nil이면 해당 접근 결과는 nil |
| `condition ? yes : no` | 조건이 참이면 `yes`, 거짓이면 `no` |

```lua
local enabled = false ?? true       -- false 유지
local count = 0 ?? 10               -- 0 유지
local name = nil ?? "Guest"         -- "Guest"
local result = true ? false : "no"  -- false 유지
```

필요한 우변이나 선택된 분기만 실행합니다. `?.`는 nil만 처리하므로 `false?.name`은 일반 Lua처럼 인덱싱 오류가 납니다. Optional 호출·메서드·`?.[key]` 문법은 지원하지 않습니다.

우선순위는 낮은 순서로 **삼항식 → `??` → `or` → `and` → 기존 Lua 연산자**입니다. 삼항식과 `??`는 오른쪽부터 묶입니다. 섞어 쓸 때는 괄호로 의도를 드러내면 읽기 쉽습니다.

삼항식의 `:` 양옆에는 공백을 권장합니다: `ok ? obj:read() : fallback()`. `??`, `?.`, 삼항식의 결과는 항상 **값 하나**입니다.

## continue

`continue`는 현재 반복의 남은 부분을 건너뜁니다. `for`, `while`, `repeat`와 중첩 루프를 지원하며, 가장 가까운 루프에 적용됩니다.

```lua
for i = 1, 5 do
    if i % 2 == 0 then continue end
    print(i) -- 1, 3, 5
end
```

`repeat`에서는 `continue`를 만나도 `until` 조건을 검사합니다. 건너뛴 지역 변수 선언의 값은 해당 조건에서 nil입니다. `break`와 `return`은 기존 의미를 유지합니다.

## 숫자 표기

```lua
local flags = 0b1010_1010 -- 170
local budget = 1_000_000  -- 1000000
local mask = 0xFF_FF      -- 65535
```

`_`는 숫자 사이에만 넣습니다. `1__000`, `1_`, `0x_FF`는 오류입니다. 큰 숫자의 정밀도와 정수 처리는 선택한 Lua 버전의 규칙을 따릅니다.

## VM 전용 API

아래 API는 **실제로 VM으로 실행되는 코드 안에서만** 사용할 수 있습니다. 일반 KES 문법과 달리 GUI의 소스 실행(F5)에서는 사용할 수 없습니다. VM 설정이나 [선택 영역 마커](selective-obfuscation.md)로 VM 영역을 지정하세요.

| 호출 | 동작 |
|---|---|
| `KARITY_GET_SCRIPT_HASH()` | 런타임 무결성 값. 원본 파일의 해시는 아님 |
| `KARITY_GET_VM_COUNT()` | 현재 런타임의 VM 개수 |
| `KARITY_GET_VM_ID()` | 현재 함수가 속한 VM 번호, 0부터 시작 |
| `KARITY_GET_LAYOUT_HASH()` | 명령 인코딩 레이아웃의 해시 |
| `KARITY_GET_CODE_LENGTH()` | 현재 함수의 물리 VM 명령 개수 |
| `KARITY_ABORT()` | 현재 실행을 오류로 중단 |
| `KARITY_ASSERT(condition)` | 조건이 nil 또는 false이면 중단 |
| `KARITY_UNREACHABLE()` | 도달하면 항상 중단 |
| `KARITY_PANIC()` | 공유 런타임 인스턴스를 무효화하고 중단 |

**Abort**는 오류를 잡은 뒤 다른 호출을 계속할 수 있습니다. **Panic**은 오류를 잡아도 같은 런타임을 다시 사용할 수 없으며, 그 런타임의 다른 VM·반환된 클로저·코루틴에도 적용됩니다. 별도로 새로 로드한 인스턴스는 독립적입니다.

API는 이름 그대로 직접 호출해야 합니다. 별칭 저장, 같은 이름의 변수 선언, 잘못된 인자 개수, `NO_VM`·`NO_OBF` 영역의 호출은 빌드 오류입니다. API를 썼다는 이유로 VM이 자동 활성화되지는 않습니다.

## 사용 범위

- 일반 KES 문법은 VM 없이도 사용할 수 있습니다. Lua 5.1/5.3을 지원하되 `//=`는 5.3 전용입니다.
- VM API 9개는 Classic·Karity·MOV의 Lua 5.1/5.3에서 지원합니다. 기존 패스와 선택적 VM의 버전 제한은 [상세 명세(영문)](kes.md#support-matrix-and-diagnostics)를 따릅니다.
- KES 소스를 일반 Lua 인터프리터에 직접 넣으려면 먼저 Karity에서 변환해야 합니다. 문자열과 주석 안의 문법 표시는 바꾸지 않습니다.
- Lazy 표현식은 추가 함수 호출 비용이 있습니다. 자세한 의미와 제한은 [상세 명세(영문)](kes.md), 측정값은 [성능 문서(영문)](performance/kes.md)를 참고하세요.
