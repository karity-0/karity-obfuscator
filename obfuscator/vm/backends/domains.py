"""Execution domains are independent of source language and host environment."""
from enum import Enum


class ExecutionDomain(str, Enum):
    LUA = 'lua'
    VM = 'vm'
    NATIVE = 'native'
    HOST = 'host'
