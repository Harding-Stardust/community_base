# Summary
This Python script will help you develop scripts for [Hex-Rays IDA Pro](https://hex-rays.com/ida-pro)
community_base turns IDA Python into a [DWIM (Do What I Mean)](https://en.wikipedia.org/wiki/DWIM) style and I try to follow ["Principle of least astonishment"](https://en.wikipedia.org/wiki/Principle_of_least_astonishment)

You can think of this script as padding between the user created scripts and the IDA Python API.
If you develop scripts with this script as base, then if (when) Hex-Rays change something in their API, instead of fixing EVERY script out there
the community can fix this script and all the user created scripts (that depends on this script) will work again.

I try to have a low cognitive load. "What matters is the amount of confusion developers feel when going through the code." Quote from <https://minds.md/zakirullin/cognitive>

# Why you should use this script
- Easier to write plugins and scripts for IDA Python
- Type hints on everything!
- Strong typing. I use [Pydantic](https://docs.pydantic.dev/latest/) to force types. This makes the code much easier to read since you get an idea what a function expects and what it returns. I try to follow [PEP 484](https://peps.python.org/pep-0484/) as much as I can. I also use [mypy](https://www.mypy-lang.org/) to check my code.
- Full function/variable names. This makes variables and functions easy to read at a glance.
- Properly documented. I try to document as extensive I can without making redundent comments.
- Easy to debug (hopefully!). All functions that are non-trivial have the last argument named ```arg_debug``` which is a bool that if set, prints out helpful information on what is happening in the code.
- Good default values set. E.g. ```ida_idp.assemble(ea, 0, ea, True, 'mov eax, 1')``` have many arguments you don't know that they should be.
- Understands what the user wants. I have type checks and treat input different depending on what you send in. E.g. addresses vs labels. In my script, everywhere you are expecting an address, you can send in a label (or register) that is then resolved. See ```address()``` and ```eval_expression()``` (same with where tinfo_t (type info) is expected, you can also send in a C-type string)
- I have written the code as easy I can to READ (hopefully), it might not be the most Pythonic way (or the fastest) but I have focused on readability. However, I do understand that this is subjective.
- Do _NOT_ conflict with other plugins. I am very careful to only overwrite things like docstrings, otherwise I add to the classes that are already in the IDA Python
- I have wrappers around some of IDAs Python APIs that actually honors the type hints they have written. You can find them with this code:
```python
import community_base; print("\n".join([wrapper.replace("_idaapi_","") for wrapper in dir(community_base) if wrapper.startswith("_idaapi_")]))
```
- Cancel scripts that take too long. You can copy the the string "abort.ida" into the clipboard and within 10 seconds, the script will stop. Check out ```_check_if_long_running_script_should_abort()``` for implementation
- Easy bug reporting. See the function ```bug_report()```
- Get some good links to helpful resources. See the function ```links()```
- when developing, it's nice to have a fast and easy way to reload the script and all it's dependencies, see the function ```reload_python_module()```
- Load shellcode into the running process. See ```load_file_into_memory()``` using [AppCall](https://www.youtube.com/watch?v=GZUHXkV0vdM)
- Help with [AppCall](https://www.youtube.com/watch?v=GZUHXkV0vdM) to call functions that are inside the executable. (Think of decrypt functions) E.g. ```win_LoadLibraryA()```
- Simple and fast way to get info about APIs, see ```google()```
- 4 new hotkeys:
- - w --> Selected bytes will be dumped to disk
- - alt + ins --> Copy current address into clipboard (same as [x64dbg](https://x64dbg.com/))
- - shift + c --> Copy selected bytes into clipboard as hex text (same as [x64dbg](https://x64dbg.com/))
- - delete --> smart delete. If the selected bytes are in code then make then NOPS (Intel only!) and if you press delete again (or if you are in data) then write 0x00

# Installation
There are 2 ways to use this script, the recommended way is to download this file and put it in the plugins folder. That way you get access to the library and you get the new hotkeys. The plugins folder can be found like this:
```python
import idaapi; print(idaapi.get_ida_subdirs("plugins")[0])
```

If you do __NOT__ want to add the new hotkeys and just use it as a library, download the file and put it somewhere IDA can find it:
```python
import idaapi; print(idaapi.__file__.replace("idaapi.py", "community_base.py"))
```

Read more: <https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr>

# it _should_ work on all OSes but I have only tested on:

| OS | IDA | Python | Comment
|--|--|--|--|
| Windows 10 | 8.4 | 3.8  | Should be OK
| Windows 10 | 9.1 | 3.12 | OK
| Windows 10 | 9.2 | 3.12 | OK

# Future
- I have not had the time to polish everything as much as I would have liked. Keep an eye on this repo and things will get updated!
- I'm planning on doing some short clips on how the script is supposed to be used, this takes time and video editing is not my strong side
- Need help with more testing
- More of everything :-D