IDA-FFxiv-Opcodes
===
> 这是一个使用ida反汇编二进制获取opcode的脚本，是自动化工作流的一部分

如何运行
---

* ida 内执行 `entrance.py  `
* 命令行传递二进制以及idat.exe的路径使用 `main.py  `
* TODO: 使用ida的外部库功能

输出
---
* 路径： `/opcodes_{game_version}_{build_date}/{name}.txt`
* 内容： 
* ```
  ActorCast = 0x9B
  ActorControl = 0x65
  ActorControlSelf = 0x127
  ActorControlTarget = 0xB9
  ActorFreeSpawn = 0x351
  ActorGauge = 0x10A
  ActorMove = 0x2A0
  ...
  ```

如何拓展
---

* 如果你需要添加新的opcode，在 `opcode_finder/` 下新建一个py文件，内容如下

```python
import typing  # this line is only for type hinting
from opcode_finder import *


@opcode("A hashable global key")
def _() -> int | typing.Iterable[int]:
    # for a single opcode
    ...


@opcode(["Iterable of hashable global key"])
def _() -> typing.Dict[typing.Hashable, int | typing.Iterable[int]]:
    # for multiple opcode
    ...


@opcode("A hashable global key")
@opcode("Another hashable global key")
@opcode("More hashable global key")
def _() -> typing.Dict[typing.Hashable, int | typing.Iterable[int]]:
    # for multiple opcode
    ...
```

* 如果需要输出你需要的opcode键，在根目录下新建一个 `name_{xxx}.py` 文件，内容如下

```python
name = {
    "A readable name": "A hashable global key",
    "Another readable name": "Another hashable global key",
    "More readable name": "More hashable global key",
}
name # this line is to assign which variable to use
```
