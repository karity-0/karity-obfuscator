# Karity Obfuscator

[English](README.md) | [**한국어**](README.ko.md)

GUI와 선택적 소스 보호를 제공하는 Lua 5.3 난독화 도구입니다.
**Karity**, **Classic**, **MOV** 세 가지 VM 백엔드를 지원합니다.

## 빠른 시작

**Python 3.12 이상**이 필요합니다. Python 3.15에서는 무거운 처리 모듈을
필요할 때 불러오는 지연 임포트로 시작 부담을 줄입니다. Python 3.12–3.14도 지원합니다.

```sh
python -m pip install -r requirements.txt
python obfuscator_gui.py
```

1. Lua 파일을 열거나 코드를 붙여넣습니다.
2. 보호 프리셋과 VM 백엔드를 선택합니다. **Balanced + Karity**로 시작할 수 있습니다.
3. **난독화(Obfuscate)**를 누른 뒤 결과를 복사하거나 저장합니다.

Windows용 Lua 도구는 `bin/`에 포함되어 있습니다. 다른 플랫폼에서는
버전이 맞는 Lua 5.3과 `luac` 5.3을 설치하고 `PATH`에서 사용할 수 있게 설정하세요.

![GUI](images/6.png)

## 보호 프리셋

| 프리셋 | 용도 |
|---|---|
| **Fast · 빠르게** | 가벼운 VM 보호. 무거운 소스 변환은 마커로 지정한 곳에 적용합니다. |
| **Balanced · 균형** | 가벼운 소스 변환과 더 다양한 VM 구성을 제공합니다. |
| **Strong · 강하게** | StringObf와 CFF를 포함한 전체 소스 보호를 적용합니다. |
| **Maximum · 최대** | 보호 예산과 VM 변형을 늘리고 패킹을 적용합니다. |

모든 프리셋은 VM 출력에 NumberObf와 MemeStrings를 적용합니다. 프리셋과
백엔드는 독립적으로 선택하며, 고급 설정에서 각각 조정할 수 있습니다.
보호가 강해질수록 빌드 시간, 출력 크기, 실행 비용이 늘어납니다.

**＋ Marker**로 중요한 코드, VM 영역, 보호 제외 영역을 지정합니다.
**F5**는 소스 실행, **Shift+F5**는 결과 실행입니다. 마커 사용법은
[선택적 보호 가이드(영문)](docs/selective-obfuscation.md)를 참고하세요.

## CLI와 JSON

스크립트나 자동화 빌드에서는 CLI를 사용할 수 있습니다.

```sh
python main.py input.lua -o protected.lua -c config.example.json --profile builtin:balanced
python main.py input.lua -c obf_gui_config.json
```

GUI에서 저장한 설정은 CLI에서도 사용할 수 있습니다. 기존 JSON 프로필인
`dev`, `fast-vm`, `high`, `max`의 의미는 유지하며, `dev`는 개발·진단용입니다.
[사용자 프리셋(영문)](docs/user-presets.md)과 [설정 레퍼런스(영문)](docs/configuration.md)를 참고하세요.

## 문서

- [KES 문법 가이드](docs/kes-guide.ko.md) · [상세 명세(영문)](docs/kes.md)
- [프리셋과 백엔드 선택(영문)](docs/user-presets.md)
- [설정 레퍼런스(영문)](docs/configuration.md)
- [선택적 보호(영문)](docs/selective-obfuscation.md)
- [백엔드 구조와 지원 옵션(영문)](docs/backends.md)
- [Lua 대상 버전과 호환성(영문)](docs/lua-targets.md)
- [프리셋 성능 측정(영문)](docs/performance/user-presets.md)

패스별 가이드(영문): [문자열](docs/passes/stringObfuscation.md),
[함수](docs/passes/functionObfuscation.md),
[전역 변수 지역화](docs/passes/localizeGlobals.md),
[Packer](docs/passes/packer.md), [Anti-debug](docs/passes/antiDebug.md).

## 예제

- Hello: [원본](examples/hello.lua), [난독화 결과](examples/hello.protected.lua), [비교](images/1.png).
- 선택적 보호: [원본](examples/selective.lua), [난독화 결과](examples/selective.protected.lua).

## 테스트

```sh
python -m pip install -r requirements-dev.txt
python test/run_ci.py
```

로컬 검증과 CI는 같은 테스트 목록을 사용합니다. 배포 전에 실제 사용 환경에서
난독화된 스크립트를 실행해 확인하세요.

원본과 VM 실행을 비교하고 입력·옵션·생성 코드·케이스별 차이를 저장하려면 다음 명령을 사용합니다.

```sh
python tools/explore_vm_semantics.py --seeds 124 7719 20261016 --generated 8 --output local/vm-audit/run
python tools/explore_vm_semantics.py --inputs my-script.lua --versions 5.3 --generated 0 --output local/vm-audit/my-script
```

생성한 프로그램과 경계 조건 예제는 두 Lua 버전과 세 백엔드에서 각각 새 런타임
프로세스로 실행하며, 실행 시간 제한을 적용합니다. 유한한 사례를 검사하므로
결과가 같다는 사실만으로 모든 입력의 의미론적 동등성을 보장하지는 않습니다.
`vm_chunk_interface.lua` 입력에 `--harness test/fixtures/vm_chunk_interface_harness.lua`를
함께 사용하면 청크 반환값, 환경, `require` 동작을 확인할 수 있습니다.
Packer 경계도 검사하려면 `--pack --versions 5.3`을 추가하세요.

## 라이선스

[MIT License](LICENSE). 소유하거나 보호 권한을 가진 코드에만 사용하세요.
