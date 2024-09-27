import ast
import re

from idaapi import *
from .pattern import *
from .idas import *


def get_game_info():
    match = re.search(r"/\*{5}ff14\*{6}rev\d+_(\d{4})/(\d{2})/(\d{2})".encode(), game_data)
    game_build_date: str = f"{match.group(1).decode()}.{match.group(2).decode()}.{match.group(3).decode()}.0000.0000"
    match = re.search(r'(\d{3})\\trunk\\prog\\client\\Build\\FFXIVGame\\x64-Release\\ffxiv_dx11.pdb'.encode(), game_data)
    game_version: tuple[int, ...] = tuple(b - 48 for b in match.group(1))
    return game_version, game_build_date


def exec_ret(script, globals=None, locals=None, *, filename="<string>"):
    '''Execute a script and return the value of the last expression'''
    stmts = list(ast.iter_child_nodes(ast.parse(script)))
    globals = globals or {}
    locals = locals or {}
    if not stmts:
        return None
    if isinstance(stmts[-1], ast.Expr):
        # the last one is an expression and we will try to return the results
        # so we first execute the previous statements
        if len(stmts) > 1:
            exec(compile(ast.Module(body=stmts[:-1], type_ignores=[]), filename=filename, mode="exec"), globals, locals)
        # then we eval the last one
        return eval(compile(ast.Expression(body=stmts[-1].value), filename=filename, mode="eval"), globals, locals)
    else:
        # otherwise we just execute the entire code
        return exec(compile(script, filename=filename, mode='exec'), globals, locals)
