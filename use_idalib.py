import argparse
import pathlib

work_dir = pathlib.Path(__file__).parent.resolve().absolute()
args = argparse.ArgumentParser()
args.add_argument('--gp', nargs='?', help='game exe path, for .i64 or .exe')
args.add_argument('--gd', nargs='?', help='game exe dir, auto find ffxiv_dx11.exe or ffxiv_dx11.exe.i64')


def tk_select_file():
    if not hasattr(tk_select_file, 'root'):
        import tkinter as tk
        tk_select_file.root = tk.Tk()
        tk_select_file.root.withdraw()
    from tkinter import filedialog
    p = filedialog.askopenfilename()
    if not p:
        raise ValueError('file not selected')
    return p


def main():
    args_ = args.parse_args()
    if args_.gp:
        exe_path = pathlib.Path(args_.gp).resolve().absolute()
    elif args_.gd:
        exe_path = pathlib.Path(args_.gd).resolve().absolute() / 'ffxiv_dx11.exe.i64'
        if not exe_path.exists():
            exe_path = pathlib.Path(args_.gd).resolve().absolute() / 'ffxiv_dx11.exe'
    else:
        exe_path = pathlib.Path(tk_select_file()).resolve().absolute()
    import idapro
    idapro.open_database(str(exe_path), True)
    import entrance
    entrance.main(False)
    idapro.close_database()


if __name__ == '__main__':
    main()
