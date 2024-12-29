# Summary
Code that will help you develop scripts for [Hexrays IDA Pro](https://hex-rays.com/ida-pro)
community_base turns IDA Python into a [DWIM (Do What I Mean)](https://en.wikipedia.org/wiki/DWIM) style and I try to follow ["Principle of least astonishment"](https://en.wikipedia.org/wiki/Principle_of_least_astonishment)

You can think of this script as padding between the user created scripts and the IDA Python API.
If you develop scripts with this script as base, then if (when) Hexrays change something in their API, instead of fixing EVERY script out there
the community can fix this script and all the user created scripts (that depends on this script) will work again.

I try to have a low cognitive load. "What matters is the amount of confusion developers feel when going through the code." Quote from <https://minds.md/zakirullin/cognitive>

# Why you should use this script
- Easier to write plugins and scripts for IDA Python
- Type hints on everything! 
- Strong typing. I use [Pydantic](https://docs.pydantic.dev/latest/) to force types. This makes the code much easier to read since you get an idea what a function expects and what it returns. I try to follow [PEP 484](https://peps.python.org/pep-0484/) as much as I can.
- Full function/variable names. This makes variables and functions easy to read at a glance.
- Properly documented. I try to document as extensive I can without making redundent comments.
- Easy to debug (hopefully!). All functions that are non-trivial have the last argument named ```arg_debug``` which is a bool that if set, prints out helpful information that is happening in the code.
- Good default values set. E.g. ```ida_idp.assemble(ea, 0, ea, True, 'mov eax, 1')``` have many arguments you don't know that they should be.
- Understands what the user wants. I have type checks and treat input different depending on what you send in. E.g. addresses vs labels. In my script, everywhere you are expecting an address, you can send in a label (or register) that is then resolved. See ```address()``` and ```eval_expression()``` (same with where tinfo_t (type info) is expected, you can also send in a C-type string)
- I have written the code as easy I can to READ (hopefully), it might not be the most Pythonic way (or the fastest) but I have focused on readability. However, I do understand that this is subjective.
- Do _NOT_ conflict with other plugins. I am very careful to only overwrite things like docstrings, otherwise I add to the classes that are already in the IDA Python
- I have wrappers around some of IDAs Python APIs that actually honors the type hints they have written. You can find them with this simple code:
```python
[wrapper for wrapper in dir(community_base) if wrapper.startswith("_idaapi_")]
```
- Cancel scripts that take too long. You can copy the the string "abort.ida" into the clipboard and within 30 seconds, the script will stop. Check out ```_check_if_long_running_script_should_abort()``` for implementation
- Easy bug reporting. See the function ```bug_report()```
- Get some good links to helpful resources. See the function ```links()```
- when developing, it's nice to have a fast and easy way to reload the script and all it's dependencies, see the function ```reload_module()```
- Load shellcode into the running process. See ```load_file_into_memory()``` using [AppCall](https://www.youtube.com/watch?v=GZUHXkV0vdM)
- Help with [AppCall](https://www.youtube.com/watch?v=GZUHXkV0vdM) to call functions that are inside the executable. (Think of decrypt functions) E.g. ```win_LoadLibraryA()```
- Simple and fast way to get info about APIs, see ```google()```
- 3 new hotkeys:
- - w --> marked bytes will be dumped to disk
- - alt + Ins --> Copy current address into clipboard (same as [x64dbg](https://x64dbg.com/))
- - shift + c --> Copy selected bytes into clipboard as hex text (same as [x64dbg](https://x64dbg.com/))
- Much more that I can't think of right now as I need to publish this script before new years eve!

# Installation
To use this script, put is somewhere that IDA can find it. A good place is this filename:
```python
import idaapi
import os
print(os.path.join(os.path.dirname(idaapi.__file__), "community_base.py"))
```
It is strongly advised to edit your idapythonrc.py which can be found by typing the following in IDA:
```python
import idaapi
import os
print(os.path.join(idaapi.get_user_idadir(), "idapythonrc.py"))
```
and to get easy access to this script, add the line:
```python
import community_base as cb
```
Read more: <https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr>


# Tested with
```Windows 10 + IDA 9.0 + Python 3.12``` and ```Windows 10 + IDA 8.4 + Python 3.8```

# Future
- All functions that are named ```_experimental_XX``` are not to be used, they are my playground and are not done
- I have not had the time to polish everything as much as I would have liked. Keep an eye on this repo and things will get updated!
- I'm planning on doing some short clips on how the script is thought to be used, this takes time and video editing is not my strong side
- Need help with more testing
- More of everything :-D
