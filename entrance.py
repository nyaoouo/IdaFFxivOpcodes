import idaapi


def reload_pkg(name):
    import sys
    import importlib
    for k in [k for k in sys.modules.keys() if k == name or k.startswith(name + '.')]:
        importlib.reload(sys.modules[k])


def main(exit_=True):
    idaapi.auto_wait()
    reload_pkg('opcode_finder')
    import opcode_finder
    opcode_finder.exec()
    if exit_:
        idaapi.qexit(0)


if __name__ == '__main__':
    main(False)
