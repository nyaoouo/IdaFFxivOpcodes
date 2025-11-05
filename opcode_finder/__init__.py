import importlib
import logging
import pathlib
import pkgutil
from .utils import *

_opcode_finders = {}
_names: typing.Dict[str, dict] = {}


def opcode(identifier):
    def wrapper(func: typing.Callable[[], int | typing.Iterable[int]]):
        try:
            iter(identifier)
        except TypeError:
            identifires = (identifier,)
        else:
            identifires = identifier
        for i in identifires:
            if i in _opcode_finders:
                raise ValueError(f'opcode identifier {i:#X} already exists')
            _opcode_finders[i] = func
        return func

    return wrapper


def load_all():
    current_dir = os.path.dirname(__file__)
    for i, mod in enumerate(pkgutil.iter_modules([current_dir])):
        importlib.import_module(f'{__name__}.{mod.name}')
    logging.info(f'loaded {len(_opcode_finders)} opcode finders')

    parent_dir = os.path.dirname(current_dir)
    for file in pathlib.Path(parent_dir).glob('name_*.py'):
        opcode_enum = exec_ret(file.read_text('utf-8'), filename=str(file))
        if not isinstance(opcode_enum, dict):
            raise TypeError(f'{file} must return a dict')
        _names[file.stem[5:]] = opcode_enum


def parse_one(identifier):
    if identifier not in _opcode_finders:
        raise ValueError(f'opcode identifier {identifier:#x} not found')
    func = _opcode_finders[identifier]
    try:
        if hasattr(func, '__opcode_error__'):
            raise func.__opcode_error__
        elif hasattr(func, '__opcode__'):
            o = func.__opcode__
        else:
            func.__opcode__ = o = func()
    except Exception as e:
        func.__opcode_error__ = e
        logging.error(f'error in finding {identifier:#X}: {e}', exc_info=True)
        return ()
    if isinstance(o, dict):
        if identifier not in o:
            logging.error(f'opcode {identifier:#x} not found in {o=}')
            return ()
        o = o[identifier]
        if not isinstance(o, int) and len(o) == 0:
            logging.error(f'opcode {identifier:#x} not found')
    return (o,) if isinstance(o, int) else tuple(o)


def parse_all():
    res = {i: parse_one(i) for i in _opcode_finders.keys()}  # maybe use multithread or multiprocessing...
    game_version, game_build_date = get_game_info()
    export_dir = pathlib.Path(__file__).parent.parent / "parsed_opcodes" / f"opcodes_{''.join(str(i) for i in game_version)}_{game_build_date}"
    export_dir.mkdir(exist_ok=True, parents=True)
    for key, names in _names.items():
        with open(export_dir / f'{key}.txt', 'w', encoding='utf-8') as f:
            for name, identifier in names.items():
                if identifier not in res:
                    # logging.warning(f'opcode {key} - {name} with {identifier=:#x} not found')
                    continue
                opcodes = ', '.join(f'0x{o:X}' for o in res[identifier])
                f.write(f'{name} = {opcodes}\n')


def exec():
    from .utils.loggings import install
    install(use_color=False)
    load_all()
    parse_all()
    logging.info('done')


if __name__ == '__main__':
    exec()
