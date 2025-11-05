from functools import cache

from idc import *
from idaapi import *
from idautils import *
from .pattern import *


@cache
def map_switch_jumps(_si: int):
    si = ida_nalt.switch_info_t()
    res = {}
    if ida_nalt.get_switch_info(si, _si):
        results = calc_switch_cases(_si, si)
        for idx in range(len(results.cases)):
            s = res.setdefault(results.targets[idx], set())
            for _idx in range(len(cases := results.cases[idx])):
                s.add(cases[_idx])
    return res


@cache
def big_switch_replay():
    _func = get_func(pattern_scanner.find_val("e8 * * * * 80 bb ? ? ? ? ? 77")[0])
    return range(_func.start_ea, _func.end_ea)


@cache
def big_switch_zone_down():
    try:
        _func = get_func(pattern_scanner.find_address("45 ? ? ? ? 4d ? ? 44 ? ? 48 ? ?"))
    except:
        _func = get_func(pattern_scanner.find_address("48 89 85 ? ? ? ? 45 ? ? ? ? 4d ? ? 8b ?"))
    return range(_func.start_ea, _func.end_ea)


# fl_U  : 'Data_Unknown',
# ida_xref.dr_O  : 'Data_Offset',
# ida_xref.dr_W  : 'Data_Write',
# ida_xref.dr_R  : 'Data_Read',
# ida_xref.dr_T  : 'Data_Text',
# ida_xref.dr_I  : 'Data_Informational',
# fl_CF : 'Code_Far_Call',
# fl_CN : 'Code_Near_Call',
# fl_JF : 'Code_Far_Jump',
# fl_JN : 'Code_Near_Jump',
# 20 : 'Code_User',
# fl_F : 'Ordinary_Flow'

def find_xrefs_to(ea: int) -> dict:
    xrefs = {}
    for xref in XrefsTo(ea, 0):
        xrefs.setdefault(xref.type, []).append(xref.frm)
    return xrefs


def get_expr(ea) -> cexpr_t | None:
    class PtrOffsetFinder(ctree_visitor_t):
        def __init__(self, line):
            ctree_visitor_t.__init__(self, CV_FAST)
            self.line = line
            self.func = get_func(line)
            self.cfunc = decompile(self.func.start_ea)
            self.start_ea = self.func.start_ea
            self.end_ea = self.func.end_ea
            self.res = None

        def apply(self):
            self.apply_to(self.cfunc.body, None)

        def visit_expr(self, expr: cexpr_t) -> "int":
            if expr.ea == self.line:
                self.res = expr
                return 1
            return 0

    (finder := PtrOffsetFinder(ea)).apply()
    return finder.res


def find_zone_down_switch_values(ea: int, max_recursion: int = 50, limit_big_switch=False):
    res = set()
    xrefs = find_xrefs_to(ea)
    if fl_JN in xrefs and dr_O in xrefs:
        new_eas = []
        for si in xrefs[fl_JN]:
            if (not limit_big_switch or si in big_switch_zone_down() or si in big_switch_replay()) and (_res := map_switch_jumps(si).get(ea, set())):
                res |= _res
            else:
                new_eas.append(si)
        xrefs[fl_JN] = new_eas
    if (next_rec := max_recursion - 1) < 0:
        return res
    for type_ in (fl_CF, fl_CN, fl_F):
        if type_ in xrefs:
            for _ea in xrefs[type_]:
                res |= find_zone_down_switch_values(_ea, next_rec, limit_big_switch)
    for type_ in (fl_JF, fl_JN):
        if type_ in xrefs:
            for _ea in xrefs[type_]:
                if (_ea in big_switch_zone_down() or _ea in big_switch_replay()) and print_insn_mnem(_ea) == 'jz':
                    if (expr := get_expr(_ea)) and expr.x and expr.x.op == cot_var and expr.y and expr.y.op == cot_num:
                        res.add(expr.y.n._value)
                        continue
                res |= find_zone_down_switch_values(_ea, next_rec, limit_big_switch)
    return res


def trace_small_switch(p_ea, max_trace=50):
    func = get_func(p_ea)
    insn = insn_t()
    walk = [
        (_xref.frm, _xref.type) for _xref in XrefsTo(p_ea, 0)
        if _xref.type in (fl_JN, fl_F) and
           func.start_ea <= _xref.frm <= func.end_ea
    ]
    if len(walk) > 1:
        raise ValueError(f'branch in {p_ea:#X}, cant trace')
    used_reg = None
    reg_val = 0
    look_at = 0
    while walk:
        if (max_trace := max_trace - 1) <= 0:
            raise ValueError(f'not end')
        ea, fl_type = walk.pop()
        decode_insn(insn, ea)
        mnem = insn.get_canon_mnem()
        # print(hex(ea), mnem, look_at, used_reg, reg_val)
        match mnem:
            case 'jz' | 'jnz' | 'ja':
                look_at = 2
            case 'sub' | 'add' | 'cmp':
                modify = True
                is_new = False
                if used_reg is None:
                    if look_at:
                        is_new = True
                        used_reg = insn.ops[0].reg
                    else:
                        modify = False
                elif insn.ops[0].reg != used_reg:
                    modify = False

                if modify:
                    match mnem:
                        case 'sub':
                            reg_val += insn.ops[1].value
                        case 'add':
                            reg_val -= insn.ops[1].value
                        case 'cmp' if is_new:
                            reg_val = insn.ops[1].value
            case 'movzx' | 'mov' if used_reg == insn.ops[0].reg:
                break
        if look_at:
            look_at -= 1
        v_from = [
            (_xref.frm, _xref.type) for _xref in XrefsTo(ea, 0)
            if _xref.type in (fl_JN, fl_F) and
               func.start_ea <= _xref.frm <= func.end_ea
        ]
        if len(v_from) > 1:
            raise ValueError(f'branch in {ea:#X}, cant trace')
        walk.extend(v_from)
    if used_reg is None:
        raise ValueError(f'no reg select')
    return reg_val


def analyze_switch_case_by_fifth_arg(ea, key_call, max_depth=100):
    def find_next_insn_mnem(ea, key, max_depth=50):
        for i in range(max_depth):
            ea = next_head(ea, BADADDR)
            if ea == BADADDR: return BADADDR
            if print_insn_mnem(ea) == key:
                return ea

    def reverse_fifth_arg(ea, max_depth=10):
        if get_operand_type(ea, 0) == 4 and get_operand_type(ea, 1) == 5 and get_operand_value(ea, 0) == 0x20:
            return [get_operand_value(ea, 1)]
        if max_depth == 0: return 0, 0
        xrefs = find_xrefs_to(ea)
        res = []
        for ea in xrefs.get(19, []):
            res.extend(reverse_fifth_arg(ea, max_depth - 1))
        for ea in xrefs.get(21, []):
            res.extend(reverse_fifth_arg(ea, max_depth - 1))
        return res

    def find_prob_cond(_ea, _get_nums, _nums, _depth):
        _res = {}
        last_mod = 0

        def get_val(ea_, idx):
            if get_operand_type(ea_, idx) == 1:
                return _nums.get(get_operand_value(ea_, idx))
            return get_operand_value(ea_, idx)

        while (insn_mnem := print_insn_mnem(_ea)) != "retn" and _depth < max_depth:
            _depth += 1
            # print(f'{ea:X}: {insn_mnem} {get_operand_type(_ea, 0)}:{get_operand_value(_ea, 0)} {get_operand_type(_ea, 1)}:{get_operand_value(_ea, 1)}')
            if insn_mnem.startswith("mov"):
                if val := get_val(_ea, 1):
                    k = get_operand_value(_ea, 0)
                    _get_nums[k] = _nums[k] = val
            elif insn_mnem.startswith("sub"):
                op = get_operand_value(_ea, 0)
                _get_nums[op] = _nums[op] = _nums.setdefault(op, 0) + get_operand_value(_ea, 1)
                last_mod = op
            elif insn_mnem.startswith("cmp"):
                op = get_operand_value(_ea, 0)
                _get_nums[op] = _nums.setdefault(op, 0) + get_val(_ea, 1)
                last_mod = op
            elif insn_mnem == 'jz':
                _res[_get_nums[last_mod]] = get_operand_value(_ea, 0)
            elif insn_mnem == 'ja':
                _res |= find_prob_cond(get_operand_value(_ea, 0), _get_nums.copy(), _nums.copy(), _depth)
            elif insn_mnem == 'jnz':
                # default = get_operand_value(_ea, 0)
                _res[_get_nums[last_mod]] = next_head(_ea, BADADDR)
            if (_ea := next_head(_ea, BADADDR)) == BADADDR: break
        return _res

    res1 = find_prob_cond(ea, {8: 0}, {8: 0}, 0)

    # print(f'found {len(res1)} cases for {ea:#X}')
    # for k, v in res1.items():
    #     print(f'{k:#X} -> {v:X}')

    res2 = {}
    for k, _ea in res1.items():
        next_call_ea = find_next_insn_mnem(_ea, "call")
        if get_operand_value(next_call_ea, 0) != key_call: continue
        res2[k] = reverse_fifth_arg(next_call_ea)
    return res1, res2


def safe(func, *args, _handle=BaseException, _default=None, **kwargs):
    try:
        return func(*args, **kwargs)
    except _handle:
        return _default


class Matcher:
    def __init__(self, _checker=None, **kwargs):
        self.checker = _checker
        self.things = list(kwargs.items())

    def match(self, t): return safe(all, (
        v == getattr(t, k) for k, v in self.things
    ), _handle=AttributeError, _default=False) and (self.checker is None or self.checker(t))

    def __eq__(self, other): return self.match(other)

    def __class_getitem__(cls, item: typing.Type): return lambda **kwargs: MatcherCheckInstance(item, **kwargs)

    def filter(self, iterable): return filter(self.match, iterable)


class MatcherCheckInstance(Matcher):
    def __init__(self, class_: typing.Type, **kwargs):
        self.class_ = class_
        super().__init__(**kwargs)

    def match(self, t): return isinstance(t, self.class_) and super().match(t)


def analyze_send_function(func_ea, send_func_ea):
    res = set()
    res_size = {}
    call_matcher = Matcher(op=cot_call, _checker=lambda expr: get_operand_value(expr.ea, 0) == send_func_ea)
    rs = set()

    class CV(ctree_visitor_t):
        def visit_expr(self, expr: cexpr_t) -> int:
            if call_matcher.match(expr):
                rs.add(get_operand_value(expr.a[1].ea, 1))
            return 0

    func = get_func(func_ea)
    CV(CV_FAST).apply_to(decompile(func.start_ea).body, None)
    point_ea = func_ea
    last_opc = 0
    while point_ea != BADADDR:
        if get_operand_type(point_ea, 0) == o_displ and get_operand_type(point_ea, 1) == o_imm:
            # print(get_operand_value(point_ea, 0), get_operand_value(point_ea, 1))
            if (reg := get_operand_value(point_ea, 0)) in rs:
                res.add(last_opc := get_operand_value(point_ea, 1))
            elif (reg := reg - 8) in rs:
                # print(reg, last_opc)
                if reg in res_size:
                    raise Exception('map send size failed')
                res_size[last_opc] = get_operand_value(point_ea, 1)
        point_ea = next_head(point_ea, func.end_ea)
    return sorted(res, key=lambda n: res_size.get(n, 0))


def analyze_send_function_no_sort(func_ea, send_func_ea):
    res = []
    call_matcher = Matcher(op=cot_call, _checker=lambda expr: get_operand_value(expr.ea, 0) == send_func_ea)
    rs = []

    class CV(ctree_visitor_t):
        def visit_expr(self, expr: cexpr_t) -> int:
            if call_matcher.match(expr):
                rs.append(get_operand_value(expr.a[1].ea, 1))
            return 0

    func = get_func(func_ea)
    CV(CV_FAST).apply_to(decompile(func.start_ea).body, None)
    point_ea = func_ea
    while point_ea != BADADDR:
        if get_operand_type(point_ea, 0) == o_displ and get_operand_type(point_ea, 1) == o_imm and get_operand_value(point_ea, 0) in rs:
            res.append(get_operand_value(point_ea, 1))
        point_ea = next_head(point_ea, func.end_ea)
    return res


def get_real_ref(t):
    if isinstance(t, cexpr_t):
        if t.op == cot_memref and t.m == 0:
            return get_real_ref(t.x)
        if t.op == cot_cast:
            return get_real_ref(t.x)
    return t
