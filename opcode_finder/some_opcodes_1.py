import functools
import itertools

from . import *


@functools.cache
def replay_module_record_packet_at():
    return pattern_scanner.find_val('e8 * * * * 84 ? 74 ? 33 ? 38 87')[0]


@opcode(range(0x10035, 0x10037 + 1))
def _():
    pno = {}
    insn = ida_ua.insn_t()
    for xref in XrefsTo(pattern_scanner.find_address("0f ? ? 44 ? ? ? 44 ? ? ? 8b ? ? c6 44 24"), 0):
        if xref.type == fl_F:
            ea = xref.frm
        elif xref.type == fl_JN:
            ea = prev_head(xref.frm, 0)
        else:
            continue
        decode_insn(insn, ea)
        dtype = insn.ops[0].dtype
        if dtype == dt_dword:
            if 0x10035 in pno: raise Exception('0x10035 found twice')
            pno[0x10035] = sorted(find_zone_down_switch_values(ea))
        elif dtype == dt_qword:
            if 0x10037 in pno:
                raise Exception('0x10037 found twice')
            # print(hex(ea))
            pno[0x10037] = sorted(find_zone_down_switch_values(ea))
    pno[0x10036] = sorted(find_zone_down_switch_values(pattern_scanner.find_address("0f ? ? b8 ? ? ? ? 44 ? ? ? 44 ? ? ? 8b ? ? c6 44 24")))
    return pno


@opcode(range(0x10005, 0x10009 + 1))
def _():
    pno = {}
    pno[0x10006], pno[0x10007], pno[0x10008], pno[0x10009] = map(sorted, map(find_zone_down_switch_values, sorted(
        pattern_scanner.find_addresses('48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 48 ? ? 8b ? 8b ? 48 ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? 48 ? ? 74 ? 48 ? ? ? ? ? ?'),
        key=lambda ea: get_operand_value(ea + 0x2a, 1)
    )))
    pno[0x10005] = sorted(find_zone_down_switch_values(pattern_scanner.find_address("48 89 5c 24 ? 57 48 ? ? ? 48 ? ? 8b ? 8b ? 48 ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? ? 48 ? ?")))
    return pno


@opcode(0x1002F)
@opcode(0x30002)
def _():
    pno = {}
    ea = pattern_scanner.find_address('48 89 9c 24 ? ? ? ? 48 ? ? ? 48 ? ? 74 ? 41')
    pno[0x1002F] = trace_small_switch(ea),
    try:
        ea = pattern_scanner.find_address('41 ? ? ? ? 48 ? ? b9 ? ? ? ? 49 ? ? 8b ?')
    except KeyError:
        ea = pattern_scanner.find_address('44 ? ? ? ? 48 ? ? 8b ? 41 ? ? ? ? ? ? 74 ?')
    pno[0x30002] = sorted(
        v for v in find_zone_down_switch_values(ea) if v not in pno[0x1002F]
    )
    return pno


@opcode(range(0x10001, 0x10004 + 1))
def _():
    main_xrefs = find_xrefs_to(pattern_scanner.find_address("48 ? ? 44 88 40 ? 89 48"))
    ea = 0
    for type_ in (fl_JF, fl_JN, fl_CF, fl_CN):
        for ea_ in main_xrefs.get(type_, []):
            ea_ = find_xrefs_to(ea_).get(fl_F, [])[0]
            while True:
                if print_insn_mnem(ea_) == 'call':
                    ea = get_operand_value(ea_, 0)
                    break
                try:
                    ea_ = find_xrefs_to(ea_).get(fl_F, [])[0]
                except IndexError:
                    break
            if ea: break
        if ea: break
    if not ea: raise Exception('not found')
    res1, res2 = analyze_switch_case_by_fifth_arg(ea, replay_module_record_packet_at())
    pno = {}
    pno[0x10001], pno[0x10002], pno[0x10003], pno[0x10004] = [[k] for k in sorted(res1.keys(), key=res2.__getitem__)]
    return pno


@opcode(0x30001)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address("40 ? 41 ? 41 ? 48 ? ? ? 83 3d")))


@opcode(range(0x10018, 0x1001C + 1))
def _():
    ea, = pattern_scanner.find_val('48 ? ? ? ? ? ? e8 * * * * 44 ? ? ? ? 4c ? ? ? 8b ? ? 8b')
    res1, res2 = analyze_switch_case_by_fifth_arg(ea, replay_module_record_packet_at())
    pno = {}
    pno[0x10018], pno[0x10019], pno[0x1001A], pno[0x1001B], pno[0x1001C] = [[k] for k in sorted(res1.keys(), key=res2.__getitem__)]
    return pno


@opcode(range(0x10029, 0x1002B + 1))
@opcode(0x10072)
def _():
    special_type_func = pattern_scanner.find_address("44 ? ? ? 45 ? ? 44 ? ? b8 ? ? ? ? ")
    base_func = pattern_scanner.find_address("40 ? 41 ? 41 ? 41 ? 48 ? ? ? 8b ? 4c ? ?")

    class OperandLine(typing.NamedTuple):
        ea: int
        insn: str
        op1: int
        op2: int
        val1: int
        val2: int

        a = property(lambda self: (self.op1, self.val1))
        b = property(lambda self: (self.op2, self.val2))

    get_op = lambda ea: OperandLine(
        ea,
        print_insn_mnem(ea),
        get_operand_type(ea, 0),
        get_operand_type(ea, 1),
        get_operand_value(ea, 0),
        get_operand_value(ea, 1)
    )

    def is_calling_special_type_func(ea):
        for xref in XrefsFrom(ea, 0):
            if xref.type in (fl_JF, fl_JN, fl_CF, fl_CN) and get_operand_value(xref.frm, 0) == special_type_func:
                return True
        return False

    def find_types(func_ea):
        func_ = get_func(func_ea)
        ea = func_.start_ea
        end = func_.end_ea
        res = set()

        last_type = 0
        while ea < end:
            line = get_op(ea)
            if line.a == (o_reg, 0x12) and line.op2 == o_imm:
                last_type = line.val2
            elif is_calling_special_type_func(ea):
                res.add(last_type)
            ea = next_head(ea, BADADDR)

        return sorted(res)

    pno = {}
    for func in (xref.frm for xref in XrefsTo(base_func, 0) if xref.type in (fl_JF, fl_JN, fl_CF, fl_CN)):
        _types = find_types(func)
        if _types == []:
            k = 0x10029
        elif _types == [1, 2, 3]:
            k = 0x1002A
        elif _types == [4, 5]:
            k = 0x1002B
        elif _types == [6, 7, 8]:
            k = 0x10072
        else:
            raise Exception(f'Unknown types {_types}')
        pno[k] = find_zone_down_switch_values(func)
    return pno


@opcode(0x1005C)
def _():
    xrefs = find_xrefs_to(pattern_scanner.find_address("48 89 5c 24 ? 57 48 ? ? ? 80 79 ? ? 8b ? 48 ? ? 0f 84"))
    res = set()
    for ea in itertools.chain(xrefs.get(fl_CF, []), xrefs.get(fl_CN, [])):
        res |= find_zone_down_switch_values(get_func(ea).start_ea)
    return sorted(res)


@opcode(0x1001D)
@opcode(0x1001E)
def _():
    pno = {}
    context_work_maybe = set(pattern_scanner.find_addresses('48 ? ? ? 48 ? ? ? ? ? ? 4c ? ? ? ? ? ? 49 ? ? 0f 84 ? ? ? ? 48 89 5c 24 ?'))
    for ea in pattern_scanner.find_addresses('48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 49 ? ? 48 ? ? 0f ? ? e8'):
        if get_operand_value(prev_head(find_func_end(ea), 0), 0) in context_work_maybe:
            pno[0x1001D] = sorted(find_zone_down_switch_values(ea))
        else:
            pno[0x1001E] = sorted(find_zone_down_switch_values(ea))
    return pno


@opcode(0x10030)
@opcode(0x10031)
def _():
    pno = {}
    try:
        pno[0x10030] = pattern_scanner.find_val("81 7b ? <? ? ? ?> 75 ? 48 ? ? ? ? 83 ? ?")
    except KeyError:
        pno[0x10030] = pattern_scanner.find_val("83 7b ? <?> 75 ? 48 ? ? ? ? 83 ? ? 7d ? ")  # handle when opcode is lower than 0x7f
    pno[0x10031] = sorted(find_zone_down_switch_values(get_func(
        pattern_scanner.find_address("89 4c 24 ? 48 ? ? ? 48 89 4c 24 ? 48 ? ? ? 0f ? ? 89 53 ?")
    ).start_ea).difference(pno[0x10030]))
    return pno


@opcode([
    0x10061,
    0x1005D,
    0x10065,
    0x10062,
    0x10042,
])
def _():
    def find_straight_ecx(ea, max_lv=10):
        if get_operand_type(ea, 0) == 1 and get_operand_type(ea, 1) in (4, 5) and get_operand_value(ea, 0) == 1:
            return [(ea, get_operand_value(ea, 1))]
        if max_lv <= 0: return []
        xrefs_ = find_xrefs_to(ea)
        res = []
        for ea_ in itertools.chain(xrefs_.get(fl_F, []), xrefs_.get(fl_JN, []), xrefs_.get(fl_JF, []), ):
            res.extend(find_straight_ecx(ea_, max_lv - 1))
        return res

    xrefs = find_xrefs_to(pattern_scanner.find_address("48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 8b ? 41 ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? "))
    map_ = {}
    for ea in itertools.chain(xrefs.get(fl_CF, []), xrefs.get(fl_CN, []), xrefs.get(fl_JN, []), xrefs.get(fl_JF, [])):
        for ea_, t_ in find_straight_ecx(ea):
            map_.setdefault(t_, set()).add(ea_)
    pno = {}
    for t_, eas_ in map_.items():
        res = set()
        for ea_ in eas_: res |= find_zone_down_switch_values(ea_)
        if len(res) != 1: continue
        match t_:
            case 7:
                pno[0x10061] = sorted(res)
            case 8:
                pno[0x1005D] = sorted(res)
            case 9:
                pno[0x10065] = sorted(res)
            case 11:
                pno[0x10062] = sorted(res)
            case 17:
                pno[0x10042] = sorted(res)

    return pno


@opcode([
    0x10050,
    0x10051,
    0x10053,
    0x10058,
])
def _():
    pno = {}
    for ea in pattern_scanner.find_addresses("40 ? 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 48 ? ? 41 ff 90 ? ? ? ? 48 ? ? ba"):
        match int.from_bytes(get_bytes(ea + 43, 4), 'little'):
            case 5:
                pno[0x10051] = sorted(find_zone_down_switch_values(ea))
            case 6:
                pno[0x10050] = sorted(find_zone_down_switch_values(ea))
            case 8:
                pno[0x10058] = sorted(find_zone_down_switch_values(ea))
            case 24:  # case 23:
                pno[0x10053] = sorted(find_zone_down_switch_values(ea))
    return pno


@opcode(range(0x10011, 0x10014 + 1))
def _():
    pno = {}
    for xref in XrefsTo(pattern_scanner.find_address("40 ? 48 ? ? ? 44 ? ? ? 0f ? ? 8b")):
        if xref.type in (fl_JF, fl_JN, fl_CF, fl_CN):
            ea = ea_ = xref.frm
            for i in range(10):
                ea = next_head(ea, BADADDR)
                if get_bytes(ea, 3) == b'\xc7\x44\x24':
                    match get_operand_value(ea, 1):
                        case 1:
                            pno[0x10014] = sorted(find_zone_down_switch_values(ea_) | set(pno.get(0x10014, [])))
                        case 2:
                            pno[0x10011] = sorted(find_zone_down_switch_values(ea_) | set(pno.get(0x10011, [])))
                        case 3:
                            pno[0x10012] = sorted(find_zone_down_switch_values(ea_) | set(pno.get(0x10012, [])))
                        case v:
                            raise Exception(f'Unknown CreateObject type {v}')
                    break
    pno[0x10013] = sorted(find_zone_down_switch_values(pattern_scanner.find_address("83 3d ? ? ? ? ? 0f 84 ? ? ? ? e8 ? ? ? ? 84 ? 75 ?")))
    return pno


@opcode(0x10038)
def _():
    res = set()
    for ea in pattern_scanner.find_addresses("48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 48 ? ? 48 ? ? ? 33 ? 0f 1f 84 00"):
        res |= find_zone_down_switch_values(ea)
    return sorted(res)


@opcode(range(0x10024, 0x10027 + 1))
@opcode(0x10073)
def _():
    pno = {}
    pno[0x10027] = sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 83 3d ? ? ? ? ? 41 ? ? ? 48"
    )))
    pno[0x10025] = sorted(find_zone_down_switch_values(get_func(pattern_scanner.find_address(
        "84 ? 74 ? 44 ? ? 48 ? ? b2 02"
    )).start_ea))
    pno[0x10026] = sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 6c 24 ? 48 89 74 24 ? 57 48 ? ? ? 83 3d ? ? ? ? ? 41 ? ? ? 48 ? ? 8b ?"
    )))
    pno[0x10073] = sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "84 ? 74 ? 44 ? ? 48 ? ? b2 06"
    )))
    pno[0x10024] = sorted(find_zone_down_switch_values(get_func(pattern_scanner.find_address(
        "84 ? ? ? ? 0f ? ? 48 ? ? ? ? ? ? e8 ? ? ? ? 0f ? ? ? 8b ? ? ?"
    )).start_ea).difference(
        pno[0x10027]
    ).difference(
        pno[0x10025]
    ).difference(
        pno[0x10026]
    ).difference(
        pno[0x10073]
    ))
    return pno


@opcode(0x10043)
@opcode(0x1006F)
def _():
    pno = {}
    extend_status = get_func(pattern_scanner.find_address("74 ? 48 ? ? 48 ? ? ff 90 ? ? ? ? 4c ? ? ? ? ? ? 48")).start_ea  # 7.3
    status_funcs = set(pattern_scanner.find_addresses("48 89 5c 24 ? 57 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 ? ? 74 ? 48 ? ? 48 ? ? ff 90"))
    normal_status_func = status_funcs.difference({extend_status})
    assert len(normal_status_func) == 1, 'normal_status_func len != 1'
    pno[0x10043] = sorted(find_zone_down_switch_values(next(iter(normal_status_func))))
    pno[0x1006F] = sorted(find_zone_down_switch_values(extend_status))
    return pno


@opcode(0x10044)
@opcode(0x10045)
@opcode(0x10047)
def _():
    pno = {}
    pno[0x10045] = sorted(find_zone_down_switch_values(
        get_func(pattern_scanner.find_address("75 ? 0f ? ? 48 ? ? ? ? ? ? 41 ? ? ? 0f ? ? ? 41 0f 11 48 ? 48")).start_ea
    ))
    pno[0x10047] = sorted(find_zone_down_switch_values(
        pattern_scanner.find_address("48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 57 48 ? ? ? 0f ? ? 4c ? ? ? ? ? ? 48 ? ?")
    ))
    res = set()
    for ea in pattern_scanner.find_addresses("40 ? 48 ? ? ? 48 ? ? e8 ? ? ? ? 84 ? 74 ? e8 ? ? ? ? 48 ? ? e8 ? ? ? ? 84 ? 74 ? e8 ? ? ? ? 48 ? ? 48 ? ? ? 48 ? ? ? ? ? ? 48"):
        res |= find_zone_down_switch_values(ea)
    pno[0x10044] = res.difference(pno[0x10045]).difference(pno[0x10047])
    return pno


@opcode(0x10057)
def _():
    idx, = pattern_scanner.find_val('ba <? ? ? ?> e8 ? ? ? ? 48 ? ? ? 48 89 86 ? ? ? ?')
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        f"40 ? 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 48 ? ? 41 ff 90 ? ? ? ? 48 ? ? ba "
        f"{idx.to_bytes(4, 'little').hex(' ')} e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 48"
    )))


@opcode(0x10052)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "40 ? 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 48 ? ? 41 ff 90 ? ? ? ? 48 ? ? ba ? ? ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 41"
    )))


"""
# TODO: in switch 40 ? 53 56 41 ? 48 ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 45 ? 4c ? ? 48
@opcode(0x10066)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "83 ? ? 48 89 7c 24 ? 66 89 44 24"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x10067)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "4c ? ? 4d 89 7b ? 48 ? ? ff 90"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x10068)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 ? ? ? 0f 85 ? ? ? ? 4d ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 89 4c 24 ? 4d"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x10069)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 ? ? ? 0f 85 ? ? ? ? 4d ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 89 4c 24 ? 4c"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x1006A)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 89 84 24 ? ? ? ? 48 ? ? 48 ? ? 48 ? ? ? ? e8 ? ? ? ? 33"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x1006B)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 89 86 ? ? ? ? e8 ? ? ? ? 49 ? ? ? 49"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x1006C)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 89 84 24 ? ? ? ? 4c ? ? 4c ? ? 48 ? ? ? 48"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x1006D)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 89 45 ? 48 83 b9 ? ? ? ? ? 4c ? ? 48"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x1006E)
def _():
    return [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(get_func(pattern_scanner.find_address(
            "48 89 84 24 ? ? ? ? 8b ? ? 48 ? ? 48 ? ? 85"
        )).start_ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]
"""


@opcode(0x1005F)
def _():
    ea = get_func(pattern_scanner.find_address("48 ? ? ? 48 ? ? 48 ? ? ff 90 ? ? ? ? 48 ? ? ? ? ? ? 41")).start_ea
    return sorted(find_zone_down_switch_values(ea, 20)) or [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x10060)
def _():
    ea = get_func(pattern_scanner.find_address("48 ? ? 48 ? ? ? 49 89 7b ? 4d 89 73 ? 4c ? ? 48")).start_ea
    return sorted(find_zone_down_switch_values(ea, 20)) or [
        trace_small_switch(xref.frm)
        for xref in XrefsTo(ea, 0)
        if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
    ]


@opcode(0x10022)
@opcode(0x10046)
def _():
    pno = {}
    p_airship_info_offset, = next(pattern_scanner.find_vals("48 ? ? <?> 48 ? ? ? 48 89 6c 24 ? 8b ? 4c 89 64 24 ? 8b ?"))
    p_submarine_info_offset, = next(pattern_scanner.find_vals("48 ? ? <?> 48 ? ? ? 48 89 6c 24 ? 8b ? 4c 89 64 24 ? 4c ? ?"))
    for _ea, (off,) in pattern_scanner.search("45 ? ? 33 ? b9 ? ? ? ? e8 ? ? ? ? 48 ? ? 74 (*:48 ? ? <? ? ? ?> ?) 0f ? ? 0f ? ? 0f ? ? ? 0f 11 48 ?"):
        if off == p_airship_info_offset:
            pno[0x10022] = sorted(find_zone_down_switch_values(get_func(_ea).start_ea))
        elif off == p_submarine_info_offset:
            pno[0x10046] = sorted(find_zone_down_switch_values(get_func(_ea).start_ea))
        else:
            continue
        if len(pno) == 2:
            break
    else:
        raise Exception("not found")
    return pno


@opcode(0x30008)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "e8 ? ? ? ? 0f ? ? ? 48 ? ? ? 0f ? ? ? 44 ? ? ? 44"
    )))


@opcode(0x10070)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "40 ? 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 74 ? 4c ? ? 48 ? ? 41 ff 90 ? ? ? ? 48 ? ? 33 ? e8 ? ? ? ? 48 ? ? 74 ? f6 05 ? ? ? ? ?"
    )))


@opcode(0x10071)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 7c 24 ? 41 ff 90 ? ? ? ? 48 ? ? 33 ?"
    )))


@opcode(0x10034)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 44 24 ? 0f ? ? ? 44 ? ? ? ? 48"
    )))


@opcode(0x10063)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 48 89 7c 24 ? 41 ? 48 ? ? ? 48 ? ? ? ? ? ? 45 ? ? 49 ? ?"
    )))


@opcode(0x10015)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 57 48 ? ? ? 0f ? ? 48 ? ? 4c ? ? ? ? ? ? 8b"
    )))


@opcode(0x1000E)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 33 ? e8 ? ? ? ? 0f"
    )))


@opcode(0x10021)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "80 79 ? ? 0f ? ? 48 ? ? ? ? ? ? 41 ? ? ? e9"
    )))


@opcode(0x1004D)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? ? 48 ? ? 48 ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? 48 ? ? ff 92"
    )))


@opcode(0x1004A)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 84 24 ? ? ? ? 48 ? ? ? ? ? ? 41 ? ? ? 88 5c 24 ?"
    )))


@opcode(0x1005A)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? ? ? ? ? 41 ? ? ? 88 5c 24 ? 48 ? ?"
    )))


@opcode(0x30007)
def _():
    return sorted(itertools.chain(
        *map(find_zone_down_switch_values, pattern_scanner.find_addresses(
            "40 ? 56 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 84 24 ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8"
        )),
    ))


@opcode(0x10010)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "e8 ? ? ? ? 48 ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 0f ? ? e8 ? ? ? ? 33 ? 44 ? ? "
    )))


@opcode(0x10049)
def _():
    return [] # seems not used in 7.2
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 0f ? ? ? 0f ? ? ? f6"
    )))


@opcode(0x10032)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f ? ? 0f ? ? ? ba ? ? ? ? 48 ? ? ? ? ? ? e8 ? ? ? ? 33"
    ), limit_big_switch=True))


@opcode(0x10064)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "44 ? ? 4c ? ? ? 48 ? ? ? 48 ? ? ? ? ? ? e9 <* * * *:40>"
    )))


@opcode(0x1003F)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "45 ? ? f6 40 ? ? 0f 29 b4 24"
    )))


@opcode(0x1000F)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? ? ? ? ? e8 ? ? ? ? 80 be ? ? ? ? ? 0f 8c"
    )))


@opcode(0x10033)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 57 48 ? ? ? 4c ? ? ? ? ? ? 48 ? ? 33 ?"
    )))


@opcode(0x1004B)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f ? ? f3 ? ? ? ? ? ? ? f3 ? ? ? ? ? ? ? f3 ? ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? 48 ? ? 0f 84"
    )))


@opcode(0x1000A)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f ? ? ? ? ? ? 3c ? 73 ? 44 ? ? 48"
    )))


@opcode(0x1000B)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "66 89 47 ? 48 89 47 ? 8b ?"
    )))


@opcode(0x1000C)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 6c 24 ? 56 57 41 ? 41 ? 41 ? 48 ? ? ? 48 ? ? ? ? ? ? c6 81"
    )))


@opcode(0x10017)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 0f ? ? ? 48 ? ? 48 ? ? ? ? ? ? 48 ? ? ? 48"
    )))


@opcode(0x10028)
@opcode(0x1005E)
def _():
    pno = {
        0x10028: sorted(find_zone_down_switch_values(pattern_scanner.find_address(
            "41 ? ? e8 * * * * b0 ? 48 ? ? ? ? 48 ? ? ? ? 48 ? ? ?"
        )))
    }
    pno[0x1005E] = sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 4c 24 ? 55 41 ? 48 ? ? ? 48 ? ? 4c"
    )).difference(pno[0x10028]))
    return pno


@opcode(0x30005)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f ? ? ? 4c ? ? ? 44 ? ? ? ? 0f ? ? ? 8b ? ? 88 44 24"
    )))


@opcode(0x1003D)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 57 48 ? ? ? 41 ? ? 41 ? ? 0f ? ? 8b"
    )))


@opcode(0x1003E)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "e8 ? ? ? ? 0f ? ? ? 44 ? ? ? 44 ? ? ? ? 48 ? ? ? 8b"
    )))


@opcode(0x30004)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "e8 ? ? ? ? 0f ? ? ? 48 ? ? ? 4c ? ? ? 44 ? ? ? ? 48 ? ? ?"
    )))


@opcode(0x10054)
def _():
    return sorted(find_zone_down_switch_values(get_func(pattern_scanner.find_address(
        "48 ? ? ff 90 ? ? ? ? 48 ? ? ba ? ? ? ? e8 ? ? ? ? 48 ? ? 48 ? ? 74 ? 48 ? ? ? 75 ? 48"
    )).start_ea))


@opcode(0x10055)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "4c ? ? 48 ? ? ? 48 ? ? 75 ? 48 ? ? ff 50 ?"
    )))


@opcode(0x1002C)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f 85 ? ? ? ? 49 ? ? 48 ? ? 48 ? ? ? ? 48 ? ? ? 5f e9 * * * *"
    )))


@opcode(0x1002D)
@opcode(0x1002E)
def _():
    try:
        ea = pattern_scanner.find_address("81 7b ? * * * * 0f 85 ? ? ? ? 8b ? ? 81 ? ? ? ? ?")
    except KeyError:
        ea = pattern_scanner.find_address("83 7b ? ? 0f 85 ? ? ? ? 8b ? ? 81 ? ? ? ? ? ")  # handle when opcode is lower than 0x7f
    pno = {
        0x1002D: [get_operand_value(ea, 1)],
    }
    pno[0x1002E] = sorted(find_zone_down_switch_values(
        get_func(next(
            xref.frm for xref in XrefsTo(
                get_func(ea).start_ea
            ) if xref.type in (fl_JN, fl_JF, fl_CN, fl_CF,)
        )).start_ea
    ).difference(pno[0x1002D]))
    return pno


@opcode(0x10016)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 6c 24 ? 48 89 74 24 ? 57 48 ? ? ? 8b ? 41 ? ? ? 48 ? ? b3"
    )))


@opcode(0x10059)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "74 ? 44 ? ? 48 ? ? 0f ? ? ? e8"
    )))


@opcode(0x10056)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "40 ? 41 ? 48 ? ? ? 83 ? ? 4c ? ? 48 ? ? 0f 84"
    )))


@opcode(0x1004E)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? 48 89 45 ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 4c ? ? 48 ? ? 0f 84 ? ? ? ? 48"
    )))


@opcode(0x1004F)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 74 24 ? 48 89 7c 24 ? 41 ? 48 ? ? ? 48 ? ? ? ? ? ? 33 ? 4c ? ? 48 ? ? 74"
    )))


@opcode(0x1001F)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "44 ? ? ? f3 ? ? ? ? ? ? ? 49 ? ? ? 49 ? ? ? 4c"
    )))


@opcode(0x10020)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "0f ? ? 4c ? ? f3 ? ? ? ? ? ? ? 24 ? 88 81"
    )))


@opcode(0x10039)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "40 ? 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 48 ? ? ? ? ? ? e8"
    )))


@opcode(0x1000D)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? 33 ? 48 ? ? 8b ? e8"
    )))


@opcode(0x1004C)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 57 48 ? ? ? f6 42 ? ? 45"
    )))


@opcode(0x10041)
def _():
    return [pattern_scanner.find_val("3d <? ? ? ?> 0f 85 ? ? ? ? 0f ? ? ? 4c")[0]]


@opcode(0x30003)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 ? ? 48 89 45 ? 49 ? ? 4c 89 4d ?"
    )))


@opcode(0x30006)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 57 48 ? ? ? 49 ? ? 41 ? ? ? e8 ? ? ? ? 48 ? ? 74 ? 66 39 58"
    )))


@opcode(0x10040)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 48 89 6c 24 ? 56 48 ? ? ? 83 3d ? ? ? ? ? 41 ? ? ? 48 ? ? 8b ? 0f 84 ? ? ? ? 48 89 7c 24"
    )))


@opcode(0x10048)
def _():
    return sorted(find_zone_down_switch_values(get_func(pattern_scanner.find_address(
        "e8 ? ? ? ? 84 ? 74 ? 33 ? 89 05 ? ? ? ?"
    )).start_ea))


@opcode(0x1005B)
def _():
    return sorted(find_zone_down_switch_values(pattern_scanner.find_address(
        "48 89 5c 24 ? 57 48 ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? 48 ? ? 0f 84 ? ? ? ? 4c"
    )))


@opcode(0x10023)
def _():
    return sorted(find_zone_down_switch_values(get_func(pattern_scanner.find_address(
        "40 ? 53 41 ? 41 ? 41 ? 48 ? ? ? ? ? ? ? b8"
    )).start_ea))


def find_event_packets(func_ea, sender):
    class OperandLine(typing.NamedTuple):
        ea: int
        insn: str
        op1: int
        op2: int
        val1: int
        val2: int

        a = property(lambda self: (self.op1, self.val1))
        b = property(lambda self: (self.op2, self.val2))

    get_op = lambda ea: OperandLine(
        ea,
        print_insn_mnem(ea),
        get_operand_type(ea, 0),
        get_operand_type(ea, 1),
        get_operand_value(ea, 0),
        get_operand_value(ea, 1)
    )

    func = get_func(func_ea)

    def find_set(ea, o, v):
        analyzed = set()
        to_analyze = [ea]

        while to_analyze:
            analyzed.add(cur := to_analyze.pop())

            op = get_op(cur)

            if op.op1 == o and op.val1 == v:
                if op.insn == "lea":
                    if op.op2 == o_displ:
                        yield from find_set(cur, o_displ, op.val2)
                        continue
                    else:
                        raise ValueError(f"Unexpected instruction at {hex(cur)}")
                elif op.insn == "mov":
                    if op.op2 == o_imm:
                        yield cur, op.val2
                        continue
                    else:
                        raise ValueError(f"Unexpected instruction at {hex(cur)}")

            for xref in XrefsTo(cur):
                if xref.type in (fl_JN, fl_JF, fl_F) and func.contains(xref.frm) and xref.frm not in analyzed:
                    to_analyze.append(xref.frm)

    set_vals = {}

    class CV(ctree_visitor_t):
        def visit_expr(self, expr: cexpr_t) -> int:
            if expr.op == cot_call and get_operand_value(expr.ea, 0) == sender:
                for ea, v in find_set(expr.ea, o_reg, 2):
                    assert ea not in set_vals
                    set_vals[ea] = v
            return 0

    CV(CV_FAST).apply_to(decompile(func.start_ea).body, None)

    def find_cond(start_ea, end_eas):
        analyzed = set()
        to_analyze = [(start_ea, [], None)]

        while to_analyze:
            cur, conds, last_cond = to_analyze.pop()
            analyzed.add(cur)
            if cur in end_eas:
                yield cur, conds
                continue
            op = get_op(cur)
            xrefs = [xref for xref in XrefsFrom(cur) if xref.type in (fl_JN, fl_JF, fl_F) and func.contains(xref.to)]
            if len(xrefs) == 2:
                for xref in xrefs:
                    to_analyze.append((xref.to, conds + [(cur, op.insn, last_cond, xref.type == fl_F)], last_cond))
            elif len(xrefs) <= 1:
                if op.insn in ("test", "cmp"): last_cond = op
                to_analyze.extend((xref.to, conds, last_cond) for xref in xrefs if xref.to not in analyzed)
            else:
                raise ValueError(f"Unexpected number of xrefs at {hex(cur)}")

    for ea, conds in find_cond(func.start_ea, set_vals):
        v = set_vals[ea]
        last_op = conds[-1][2]
        if last_op.op2 != o_imm:
            raise ValueError(f"Last condition is not an immediate value at {hex(ea)}")
        max_va = 255
        min_val = 0
        for ea_, insn, op, is_def in reversed(conds):
            if op.a != last_op.a: break
            if op.op2 != o_imm: continue  # no need to handle this case
            if op.insn == "test":
                raise ValueError(f"Should not have test instruction at {hex(ea_)}")
                # if insn == "jnz":
                #     desc = "!&" if is_def else "&"
                # elif insn == "jz":
                #     desc = "&" if is_def else "!&"
                # else:
                #     raise ValueError(f"Unexpected instruction at {hex(ea_)}")
            elif op.insn == "cmp":
                if insn == "jge":
                    desc = "<" if is_def else ">="
                elif insn == "jle":
                    desc = ">" if is_def else "<="
                elif insn == "jg":
                    desc = "<=" if is_def else ">"
                elif insn == "jl":
                    desc = ">=" if is_def else "<"
                elif insn == "ja":
                    desc = "<=" if is_def else ">"
                elif insn == "jae":
                    desc = "<" if is_def else ">="
                elif insn == "jb":
                    desc = ">=" if is_def else "<"
                elif insn == "jbe":
                    desc = ">" if is_def else "<="
                elif insn == "je":
                    desc = "!=" if is_def else "=="
                elif insn == "jne":
                    desc = "==" if is_def else "!="
                else:
                    raise ValueError(f"Unexpected instruction at {hex(ea_)}")
            else:
                raise ValueError(f"Unexpected instruction at {hex(ea_)}")
            match desc:
                case "<":
                    max_va = min(max_va, op.val2 - 1)
                case ">":
                    min_val = max(min_val, op.val2 + 1)
                case "<=":
                    max_va = min(max_va, op.val2)
                case ">=":
                    min_val = max(min_val, op.val2)
                case "==":
                    max_va = min(max_va, op.val2)
                    min_val = max(min_val, op.val2)
                    break
        yield v, min_val, max_va, conds


send_game_packet_immediate = send_game_packet = send_info_packet = send_system_packet = push_send_packet = is_init_send_funcs = 0


def init_send_funcs():
    global send_game_packet_immediate, send_game_packet, send_info_packet, send_system_packet, push_send_packet, is_init_send_funcs
    if is_init_send_funcs: return
    send_game_packet_immediate, send_game_packet = pattern_scanner.find_val(
        "66 89 5c 24 ? 48 89 6c 24 ? 44 38 84 24 ? ? ? ? 74 ? e8 * * * * eb 05 e8 * * * *"
    )
    send_info_packet, = pattern_scanner.find_val("e8 * * * * 84 ? 74 ? 48 ? ? ? ? ? ? 48 c7 83")
    send_system_packet, = pattern_scanner.find_val("e8 * * * * 48 ? ? ? ? ? ? 80 78 ? ? 74 ? c7")
    push_send_packet, = pattern_scanner.find_val("e8 * * * * 84 ? 74 ? 48 ? ? c7 87")
    is_init_send_funcs = 1


init_send_funcs()


@opcode(range(0x20012, 0x20019 + 1))
def _():
    pno = {}
    for v, _, n, _ in find_event_packets(pattern_scanner.find_val("45 ? ? ? 40 88 7c 24 ? e8 * * * *")[0], send_game_packet):
        k = {
            2: 0x20012,
            4: 0x20013,
            8: 0x20014,
            16: 0x20015,
            32: 0x20016,
            64: 0x20017,
            128: 0x20018,
            255: 0x20019,
        }[n]
        if k in pno:
            raise ValueError(f"Duplicate value for {hex(k)}")
        pno[k] = v
    return pno


@opcode(range(0x20007, 0x2000F + 1))
def _():
    pno = {}
    for v, _, n, conds in find_event_packets(pattern_scanner.find_val("48 89 74 24 ? 40 88 6c 24 ? e8 * * * * eb ?")[0], send_game_packet):
        if any(
                op.insn == "test" and op.a == op.b and (insn == "jz" and is_def or insn == "jnz" and not is_def)
                for ea_, insn, op, is_def in conds
        ):  # string
            k = 0x2000F
        else:
            k = {
                2: 0x20007,
                4: 0x20008,
                8: 0x20009,
                16: 0x2000A,
                32: 0x2000B,
                64: 0x2000C,
                128: 0x2000D,
                255: 0x2000E,
            }[n]
        if k in pno:
            raise ValueError(f"Duplicate value for {hex(k)}")
        pno[k] = v
    return pno


@opcode(0x20023)
def _():
    init_send_funcs()
    return analyze_send_function(pattern_scanner.find_val(
        "e8 (* * * *:48 ? ? ? 48 ? ? 0f 85 <* * * *> 32 ? c3) 48 ? ? ? ? ? ? e8 ? ? ? ? c6 05 ? ? ? ? ? e9"
    )[0], push_send_packet)


@opcode(0x2001C)
@opcode(0x2001D)
def _():
    pno = {}
    pno[0x2001C], pno[0x2001D] = zip(analyze_send_function(pattern_scanner.find_val(
        "33 ? 48 ? ? e8 * * * * c6 46 ? ? eb ?"
    )[0], send_info_packet))
    return pno


@opcode(0x20024)
def _():
    return [pattern_scanner.find_val("c7 44 24 ? <? ? ? ?> 48 ? ? 49 ? ? ? ? ? ? 89 45 ? ")[0]]


@opcode(0x20026)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 ? ? 48 89 84 24 ? ? ? ? 80 b9 ? ? ? ? ? 48 ? ? 74 ? 48")).start_ea,
        send_system_packet
    )


@opcode(0x20027)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 89 74 24 ? 48 ? ? c7 44 24 ? ? ? ? ? e8 ? ? ? ? 84 ? 74 ? 48 ? ? ? ? ? ? b2")).start_ea,
        send_system_packet
    )


@opcode(0x20028)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 ? ? ? ? ? ? 48 ? ? 48 89 84 24 ? ? ? ? 48 ? ? ? ? ? ? 41 ? ? 45")).start_ea,
        send_system_packet
    )


@opcode(0x20025)
def _():
    return analyze_send_function(
        pattern_scanner.find_val("89 85 ? ? ? ? 48 ? ? ff 90 ? ? ? ? 48 ? ? ba ? ? ? ? e8 ? ? ? ? 48 ? ? 74 ? 48 ? ? ? 4c ? ? ? 48 ? ? e8 * * * *")[0],
        send_system_packet
    )


@opcode(0x20029)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("80 b9 ? ? ? ? ? 41 ? ? 48 ? ? 48 ? ? 74 ? 48 ? ? ? ? ? ? e8")).start_ea,
        send_system_packet
    )


@opcode(0x2001F)
@opcode(0x20020)
def _():
    pno = {}
    pno[0x20020], pno[0x2001F], = zip(analyze_send_function_no_sort(
        get_func(pattern_scanner.find_address("55 56 57 48 ? ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 85 ? ? ? ? 48 ? ? 0f")).start_ea,
        send_system_packet
    ))
    return pno


@opcode(0x20021)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 89 5c 24 ? 48 89 74 24 ? 55 57 41 ? 48 ? ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 85 ? ? ? ? 48 ? ? 40 ? ?")).start_ea,
        push_send_packet
    )


@opcode(0x20003)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 ? ? 48 89 84 24 ? ? ? ? 41 ? ? ? 48 ? ? 44")).start_ea,
        send_game_packet
    )


@opcode(0x20022)
def _():
    return analyze_send_function(
        get_func(pattern_scanner.find_address("48 ? ? 48 89 84 24 ? ? ? ? 8b ? 89 81")).start_ea,
        push_send_packet
    )


@opcode(0x20010)
def _():
    a = get_func(pattern_scanner.find_address("41 ? ? ? 48 ? ? ? ? ? ? 41 ? ? 0f ? ? e8 ? ? ? ? 4c ? ? 48 ? ? 0f 84")).start_ea  # 7.3
    return analyze_send_function(a, send_game_packet)


@opcode(0x20001)
def _():
    a = get_func(pattern_scanner.find_address("41 ? ? 0f ? ? e8 ? ? ? ? 4c ? ? 48 ? ? 74")).start_ea  # 7.3
    return analyze_send_function(a, send_game_packet)


@opcode(0x2001E)
def _():
    return analyze_send_function(
        pattern_scanner.find_val("48 89 44 24 ? f3 0f 11 44 24 ? f3 0f 11 4c 24 ? e8 * * * * 48")[0],
        push_send_packet
    )


@opcode(0x20002)
def _():
    return analyze_send_function(
        pattern_scanner.find_val("b9 ? ? ? ? e8 * * * * 66 66 0f 1f 84 00 ? ? ? ?")[0],
        send_game_packet
    )


@opcode(0x20011)
def _():
    return analyze_send_function(
        # pattern_scanner.find_val("44 89 25 ? ? ? ? e8 * * * *")[0],
        pattern_scanner.find_address("48 ? ? ? ? ? ? 48 ? ? 85 ? 0f 88 ? ? ? ? 3b ? ? ? ? ?"),  # 7.1
        send_game_packet
    )


@opcode(0x20004)
def _():
    return analyze_send_function(
        pattern_scanner.find_val("8b ? ? ? ? ? 8b ? 89 44 24 ? 8b ? ? ? 89 44 24 ? e8 * * * *")[0],
        send_game_packet
    )


@opcode(0x2001A)
def _():
    return analyze_send_function(
        pattern_scanner.find_val("48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? ? 5b e9 * * * *")[0],
        send_info_packet
    )


@opcode(0x20006)
def _():
    try:
        a, = pattern_scanner.find_val("66 89 44 24 ? 48 ? ? e8 * * * * eb ?")  # 7.1
    except KeyError:
        a, = pattern_scanner.find_val("45 ? ? 88 44 24 ? 48 ? ? e8 * * * * eb ?")  # 7.0
    return analyze_send_function(a, send_game_packet)


@opcode(0x20005)
def _():
    return analyze_send_function(
        # pattern_scanner.find_val("40 88 7c 24 ? 48 ? ? ? ? 48 ? ? e8 * * * *")[0], # 7.0
        # pattern_scanner.find_val("66 89 44 24 ? e8 ? ? ? ? 45 ? ? 66 89 44 24 ? 48 ? ? ? ? 48 ? ? e8 * * * *")[0], # 7.1
        pattern_scanner.find_address(
            "48 89 5c 24 ? 48 89 74 24 ? 57 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 84 24 ? ? ? ? 48 ? ? 41 ? ? 48 ? ? ? ? ? ? 48 ? ? e8 ? ? ? ? 8b ? ?"
        ),
        send_game_packet
    )


@opcode(0x2001B)
def _():
    return analyze_send_function(
        pattern_scanner.find_address("40 ? 48 ? ? ? ? ? ? 48 ? ? ? ? ? ? 48 ? ? 48 89 84 24 ? ? ? ? 48 ? ? 48 ? ? ? ? ? ? e8 ? ? ? ? 48 ? ? 74 ? 8b"),
        send_info_packet
    )
