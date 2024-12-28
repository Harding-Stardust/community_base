# Summary
Code that will help you develop scripts for Hexrays IDA Pro.
community_base turns IDA Python into a [DWIM (Do What I Mean)](https://en.wikipedia.org/wiki/DWIM) style and I try to follow ["Principle of least astonishment"](https://en.wikipedia.org/wiki/Principle_of_least_astonishment)

You can think of this script as padding between the user created scripts and the IDA Python API.
If you develop scripts with this script as base, then if (when) Hexrays change something in their API, instead of fixing EVERY script out there
the community can fix this script and all the user created scripts (that depends on this script) will work again.

I try to have a low cognitive load. "What matters is the amount of confusion developers feel when going through the code." Quote from <https://minds.md/zakirullin/cognitive>

Everywhere an EA (Effective Address) is expected you can also send in a label/name/register.
Everywhere a tinfo_t (type info) is expected, you can also send in a C-type string.

I have written a comment on my functions that replace the IDA API ones so if you know what API that is not working as you want,
you can search for that name in this file and hopefully you will find a replacement function

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

# Why
Things that this script helps you with:
- Easier to write plugins and scripts for IDA Python
- Cancel scripts that take to long. You can copy the the string "abort.ida" into the clipboard and within 30 seconds, the script will stop. Check out the function ```_check_if_long_running_script_should_abort()```
- Easy bug reporting. See the function ```bug_report()```
- Get some good links to helpful resources. See the function ```help()```
- when developing, it's nice to have a fast and easy way to reload the script and all it's dependencies, see the function ```reload_module()```
- Load shellcode into the running process. See ```load_file_into_memory()```
- Help with AppCall to call functions that are inside the executable. (Think of decrypt functions) See ```win_LoadLibraryA()```
- Simple way to search on APIs, see ```google()```
- 3 new hotkeys: w --> marked bytes will be dumped to disk, alt+Ins --> copy current address into clipboard (just like x64dbg), shift+c --> Copy selected bytes into clipboard as hex text (just like x64dbg)


# What
This script:
- use [Pydantic](https://docs.pydantic.dev/latest/) to force types. This makes the code much easier to read since you have an idea what a function expects and what it returns. I try to follow [PEP 484](https://peps.python.org/pep-0484/) as much as I can.
- use full names. This makes variables and functions easy to read at a glance.
- check types. We can do different things if the user gives different types.
- is properly documented. I try to document as extensive I can without making redundent comments.
- is easy to debug (hopefully!). All functions that are non-trivial have the last argument named ```arg_debug``` which is a bool that if set, prints out helpful information that is happening in the code.
- have good default values set. E.g. ```ida_idp.assemble(ea, 0, ea, True, 'mov eax, 1')``` have many arguments you don't know that they should be.
- use full imported named. I do _NOT_ use any ```from <module> import *``` I have ```import community_base``` and if you don't like long names: ```import community_base as cb```
- understands what the user wants. I have type checks and treat input different depending on what you send in. Ex. addresses vs labels. In my scripts everywhere you are expecting an address, you can send in a label (or register) that is then resolved.
- use easy to read code. I have written the code as easy I can to READ (hopefully), it might not be the most Pythonic way (or the fastest) but I have focused on readability. However, I do understand that this is subjective.
- do _NOT_ conflict with other plugins. I am very careful to only overwrite things like docstrings, otherwise I add to the classes that are already in the IDAPython

# Tested
```IDA 8.4 + Python 3.8``` and ```IDA 9.0 + Python 3.12```

# Future
- All functions that are named ```_experimental_XX``` are not to be used, they are my playground and are not done
- I have not had the time to polish everything as much as I would ahve liked. Keep an eye on this repo and things will get updated!
- I'm planning on doing some short clips on how the script is thought to be used, this takes time and video editing is not my strong side
- More of everything
