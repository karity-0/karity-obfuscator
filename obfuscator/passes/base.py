from abc import ABC, abstractmethod
from dataclasses import dataclass
from luaparser import ast


@dataclass
class Replacement:
    start: int
    end: int        # inclusive
    new_text: str


class BasePass(ABC):
    """
    모든 obfuscation pass의 기반 클래스.

    run()은 스크립트 원문과 AST를 받아
    적용할 Replacement 목록을 반환한다.
    실제 문자열 치환은 Pipeline이 일괄 처리한다.
    """

    @abstractmethod
    def run(self, script: str, tree) -> list[Replacement]:
        ...

    # 편의 메서드: 서브클래스에서 AST를 순회할 때 사용
    @staticmethod
    def walk(tree):
        return ast.walk(tree)