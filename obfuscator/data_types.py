"""Shared value types; importing these aliases does not load Lua tooling."""

type LuaNumber = int | float
type LuaString = str | bytes
type LuaConstant = None | bool | LuaNumber | LuaString
type JSONValue = None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]
type ProfileDetail = dict[str, JSONValue]
