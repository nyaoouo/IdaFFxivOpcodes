import argparse
import pathlib
import subprocess

work_dir = pathlib.Path(__file__).parent.resolve().absolute()
args = argparse.ArgumentParser()
args.add_argument('--idat', nargs='?', help='idat path')
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
    idat_path = pathlib.Path(args_.idat or tk_select_file()).resolve().absolute()
    if args_.gp:
        exe_path = pathlib.Path(args_.gp).resolve().absolute()
    elif args_.gd:
        exe_path = pathlib.Path(args_.gd).resolve().absolute() / 'ffxiv_dx11.exe.i64'
        if not exe_path.exists():
            exe_path = pathlib.Path(args_.gd).resolve().absolute() / 'ffxiv_dx11.exe'
    else:
        exe_path = pathlib.Path(tk_select_file()).resolve().absolute()
    subprocess.run([idat_path, '-A', f'-S"{work_dir / "entrance.py"}"', exe_path], shell=True, check=True)


if __name__ == '__main__':
    main()
