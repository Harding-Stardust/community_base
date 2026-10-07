r''' This code is from <https://github.com/Harding-Stardust/community_base>

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
- Properly documented. I try to document as extensive I can without making redundant comments.
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
There are 2 ways to use this script, the recommended way is to download this file and put it in the plugins directory. That way you get access to the library and you get the new hotkeys. The plugins directory can be found like this:
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
| Windows 10 | 8.4 | 3.8  | OK
| Windows 10 | 9.1 | 3.12 | OK
| Windows 10 | 9.2 | 3.12 | OK
| Windows 10 | 9.3 BETA 1 | 3.10 | OK
| Windows 10 | 9.3 | 3.10 | OK
| Windows 10 | 9.3sp2 | 3.10 | OK
| Windows 10 | 9.4 BETA 1 | 3.14 | OK
| Windows 10 | 9.4 | 3.14 | OK
| Windows 10 | 9.4sp1 | 3.14 | OK
| Windows 10 | 9.5 BETA 1 | 3.14 | OK

# Future
- I have not had the time to polish everything as much as I would have liked. Keep an eye on this repo and things will get updated!
- I'm planning on doing some short clips on how the script is supposed to be used, this takes time and video editing is not my strong side
- Need help with more testing
- More of everything :-D
'''

from __future__ import annotations

__version__ = "2026-10-07 03:04:33"
__author__ = "Harding"
__description__ = __doc__
__copyright__ = "Copyright 2026"
__credits__ = ["https://www.youtube.com/@allthingsida",
               "https://github.com/grayhatacademy/ida/blob/master/plugins/shims/ida_shims.py",
               "https://github.com/arizvisa/ida-minsc",
               "https://github.com/Shizmob/ida-tools",
               "https://github.com/synacktiv/bip/",
               "https://github.com/tmr232/Sark"]
__license__ = "GPL 3.0"
__maintainer__ = "Harding"
__email__ = "not.at.the.moment@example.com"
__status__ = "Development"
__url__ = "https://github.com/Harding-Stardust/community_base"

import os as _os
import sys as _sys
import re as _re
import time as _time
import platform as _platform
from datetime import datetime as _datetime
from datetime import timezone as _timezone
import logging as _logging
import ctypes as _ctypes
import importlib.util as _importlib_util
import importlib.machinery as _importlib_machinery
import json as _json # TODO: Change to json5?
from typing import Union, List, Dict, Tuple, Any, Optional, Callable, Set
from types import ModuleType
import inspect as _inspect
_missing_imports: List[str] = []
try:
    from pydantic import validate_call
except ImportError:
    _missing_imports.append("pydantic")
try:
    import pyperclip as _pyperclip # type: ignore[import-untyped]
except ImportError:
    _missing_imports.append("pyperclip")
try:
    import chardet as _chardet
except ImportError:
    _missing_imports.append("chardet")
try:
    from dateutil.relativedelta import relativedelta as _relativedelta
except ImportError:
    _missing_imports.append("python-dateutil")

if _missing_imports:
    l_error_msg = f"{__file__}: You are missing some needed modules, you can run the following to install them: pip install {' '.join(_missing_imports)}"
    print(l_error_msg)
    raise ImportError(l_error_msg)

import ida_allins as _ida_allins # type: ignore[import-untyped]
import ida_auto as _ida_auto # type: ignore[import-untyped]
import ida_bytes as _ida_bytes # type: ignore[import-untyped]
import ida_dbg as _ida_dbg # type: ignore[import-untyped]
import ida_dirtree as _ida_dirtree # type: ignore[import-untyped]
import ida_expr as _ida_expr # type: ignore[import-untyped]
import ida_funcs as _ida_funcs # type: ignore[import-untyped]
import ida_fpro as _ida_fpro # type: ignore[import-untyped]
import ida_hexrays as _ida_hexrays # type: ignore[import-untyped]
import ida_idaapi as _ida_idaapi # type: ignore[import-untyped]
import ida_ida as _ida_ida # type: ignore[import-untyped]
import ida_idc as _ida_idc # type: ignore[import-untyped]
import ida_idd as _ida_idd # type: ignore[import-untyped] # The interface consists of structures describing the target debugged processor and a debugging API. https://python.docs.hex-rays.com/namespaceida__idd.html
import ida_idp as _ida_idp # type: ignore[import-untyped] # The interface consists of two structures: definition of target assembler: ::ash and definition of current processor: ::ph. These structures contain information about target processor and assembler features.
import ida_kernwin as _ida_kernwin # type: ignore[import-untyped]
import ida_lines as _ida_lines # type: ignore[import-untyped]
import ida_loader as _ida_loader # type: ignore[import-untyped]
import ida_name as _ida_name # type: ignore[import-untyped]
import ida_nalt as _ida_nalt # type: ignore[import-untyped] # Definitions of various information kept in netnodes. Each address in the program has a corresponding netnode: netnode(ea).
import ida_netnode as _ida_netnode # type: ignore[import-untyped] # Functions that provide the lowest level public interface to the database.
import ida_pro as _ida_pro # type: ignore[import-untyped]
import ida_range as _ida_range # type: ignore[import-untyped]
import ida_registry as _ida_registry # type: ignore[import-untyped]
import ida_search as _ida_search # type: ignore[import-untyped]
import ida_segment as _ida_segment # type: ignore[import-untyped]
import idc as _idc # type: ignore[import-untyped]
import ida_typeinf as _ida_typeinf # type: ignore[import-untyped]
import ida_ua as _ida_ua # type: ignore[import-untyped] # ua stands for UnAssembly (I think...)  Functions that deal with the disassembling of program instructions. https://python.docs.hex-rays.com/namespaceida__ua.html
import ida_xref as _ida_xref # type: ignore[import-untyped]
import idautils as _idautils # type: ignore[import-untyped]
import ida_diskio as _ida_diskio # type: ignore[import-untyped]

_G_QT_IS_AVAILABLE: bool = _ida_kernwin.is_idaq()
if _G_QT_IS_AVAILABLE:
    try:
        # IDA 9.2+ uses PySide6 while earlier versions use PyQt5
        from PySide6.QtWidgets import QApplication, QWidget, QMainWindow # type: ignore[import-untyped, import-not-found]
    except ImportError:
        try:
            from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow # type: ignore[import-untyped, import-not-found]
        except NotImplementedError:
            _G_QT_IS_AVAILABLE = False

BufferType = Union[str, bytes, bytearray, List[str], List[bytes], List[bytearray]]
BoolishType = Union[bool, int, str] # Can be evaluted to a bool by my function named _bool()
# EvaluateType is anything that can be evaluated to an int. E.g. the address() function can take this type and then try to resolve an address. Give it a str (a label) and it will work, give it a ida_segment.segment_t object and it will give the address to the start of the segment
_BaseEvaluateType = Union[str, int, _ida_idp.reg_info_t, _ida_ua.insn_t, _ida_hexrays.cinsn_t, _ida_hexrays.cfuncptr_t, _ida_hexrays.cfunc_t, _ida_funcs.func_t, _ida_idaapi.PyIdc_cvt_int64__, _ida_segment.segment_t, _ida_ua.op_t, _ida_typeinf.funcarg_t, _idautils.Strings.StringItem, _ida_dbg.bpt_t, _ida_idd.modinfo_t, _ida_hexrays.carg_t, _ida_hexrays.cexpr_t, _ida_range.range_t]
try:
    # TODO: Make sure the tests work without ida_domain, jupyter, qtconsole, jupyter-client
    import ida_domain as _ida_domain  # type: ignore[import-untyped, import-not-found]
    EvaluateType = Union[_BaseEvaluateType, _ida_domain.pseudocode.PseudocodeFunction, _ida_domain.microcode.MicroBlockArray, _ida_domain.microcode.MicroBlock, _ida_domain.strings.StringItem]
except ImportError:
    EvaluateType = _BaseEvaluateType  # type: ignore[misc]
del _BaseEvaluateType

# BaseEvaluateType = Union[str, int, _ida_idp.reg_info_t, _ida_ua.insn_t, _ida_hexrays.cinsn_t, _ida_hexrays.cfuncptr_t, _ida_hexrays.cfunc_t, _ida_funcs.func_t, _ida_idaapi.PyIdc_cvt_int64__, _ida_segment.segment_t, _ida_ua.op_t, _ida_typeinf.funcarg_t, _idautils.Strings.StringItem, _ida_dbg.bpt_t, _ida_idd.modinfo_t, _ida_hexrays.carg_t, _ida_hexrays.cexpr_t, _ida_range.range_t]
# try:
#     import ida_domain as _ida_domain  # type: ignore[import-untyped, import-not-found]
#     _PseudocodeFunc = _ida_domain.pseudocode.PseudocodeFunction
#     _MicroBlockArray = _ida_domain.microcode.MicroBlockArray
#     _MicroBlock = _ida_domain.microcode.MicroBlock
#     _StringItem = _ida_domain.strings.StringItem
# except ImportError:
#     class _PseudocodeFunc: pass  # type: ignore[no-redef]
#     class _MicroBlockArray: pass  # type: ignore[no-redef]
#     class _MicroBlock: pass  # type: ignore[no-redef]
#     class _StringItem: pass  # type: ignore[no-redef]
# EvaluateType = Union[BaseEvaluateType, _PseudocodeFunc, _MicroBlockArray, _MicroBlock, _StringItem]





# EvaluateType = Union[str, int, _ida_idp.reg_info_t, _ida_ua.insn_t, _ida_hexrays.cinsn_t, _ida_hexrays.cfuncptr_t, _ida_hexrays.cfunc_t, _ida_funcs.func_t, _ida_idaapi.PyIdc_cvt_int64__, _ida_segment.segment_t, _ida_ua.op_t, _ida_typeinf.funcarg_t, _idautils.Strings.StringItem, _ida_dbg.bpt_t, _ida_idd.modinfo_t, _ida_hexrays.carg_t, _ida_hexrays.cexpr_t, _ida_range.range_t]
_G_LOG_EVERYTHING = False # If this is set to True, then all calls to log_print() will be printed, this can cause massive logs but good for hard to find bugs
_G_DEFAULT_ENCODING: str = "utf-8"
_G_DEFAULT_TIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _send_text_to_jupyter(arg_text: str) -> None:
    ''' Send text directly to the Jupyter frontend with colors preserved.
        Writes directly to the Jupyter kernel's iopub socket, bypassing IDA's stdout.
        @param arg_text: text to send to the Jupyter frontend
        @return: None
    '''
    if _sys.modules.get('ipykernel') is None:
        return

    arg_text = arg_text.rstrip() + "\n"
    try:
        from ipykernel.kernelapp import IPKernelApp
        if IPKernelApp.initialized():
            l_app = IPKernelApp.instance()
            l_kernel = l_app.kernel

            # Get parent header from the current execution context. Kernel._parent_header is deprecated since ipykernel 6, use get_parent()
            l_get_parent = getattr(l_kernel, 'get_parent', None)
            l_parent_header = l_get_parent("shell") if callable(l_get_parent) else getattr(l_kernel, '_parent_header', {})
            if not l_parent_header:
                # Try to get it from the shell's execution info
                if hasattr(l_kernel, 'shell') and hasattr(l_kernel.shell, 'execution_count'):
                    l_parent_header = {
                        'msg_id': f'execute_{l_kernel.shell.execution_count}',
                        'msg_type': 'execute_request'
                    }

            # Write directly to the kernel's iopub stream
            if hasattr(l_kernel, 'iopub_socket') and l_kernel.iopub_socket:
                l_kernel.session.send(
                    l_kernel.iopub_socket,
                    'stream',
                    {
                        'name': 'stdout',
                        'text': arg_text
                    },
                    l_parent_header
                )
    except Exception as e:
        print(f"Error sending to Jupyter: {e}")
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _send_text_to_ida_output(arg_text: str) -> None:
    ''' Send text to IDA's output window with colors stripped.
        IDA's Qt5/Qt6 text widget does not support ANSI colors.
        @param arg_text: text to send to IDA's output window
        @return: None
    '''
    _ida_kernwin.msg(_strip_ansi(arg_text.rstrip()+'\n'))
    return

# Global regex for stripping ANSI/terminal escape sequences.
# Matches: ESC[ followed by parameters and a command letter (CSI sequences)
#          ESC] followed by content and BEL or ST (OSC sequences)
#          Other escape sequences
_g_ANSI_STRIP_RE: _re.Pattern[str] = _re.compile(
    r'\x1b'                        # ESC
    r'(?:'                         # non-capturing group for variations
    r'\[[0-9;?]*[A-Za-z]'          # CSI [...] (Control Sequence Introducer)
    r'|'                           # OR
    r'\]'                          # OSC (Operating System Command start)
    r'[^\x1b\x07]*'                # content (not ESC or BEL)
    r'(?:\x07|\x1b\\)'             # BEL or ST terminator
    r'|'                           # OR other escapes
    r'[PX^_].*?\x1b\\'             # DCS/PM/APC ... terminated by ST
    r')',
    flags=_re.DOTALL,
)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _strip_ansi(arg_text: str) -> str:
    '''
    Remove ANSI / terminal escape sequences from arg_text.

    @param arg_text: text possibly containing ANSI escapes
    @return: text with ANSI escapes removed
    '''
    return _g_ANSI_STRIP_RE.sub('', arg_text)

class ColoredFormatter(_logging.Formatter):
    ''' Formatter that adds ANSI color codes based on log level.
        Colors are added for Jupyter console, and will be stripped for IDA output.
    '''

    l_colors_dict: Dict[str, str] = {
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "magenta": "\x1b[35m",
        "cyan": "\x1b[36m",
        "grey": "\x1b[37m",
        "bold": "\x1b[1m",
        "underline": "\x1b[4m",
        "reverse": "\x1b[7m",
        "concealed": "\x1b[8m",
        "black": "\x1b[30m",
        "brown": "\x1b[33m",
        "orange": "\x1b[33m",
        "purple": "\x1b[35m",
        "light_gray": "\x1b[37m",
        "dark_gray": "\x1b[90m",
        "light_red": "\x1b[91m",
        "light_green": "\x1b[92m",
        "light_yellow": "\x1b[93m",
        "light_blue": "\x1b[94m",
        "light_magenta": "\x1b[95m",
        "light_cyan": "\x1b[96m",
        "light_white": "\x1b[97m",
        "reset": "\x1b[0m",
    }
    l_level_to_color = {
        'DEBUG': 'cyan',
        'INFO': 'light_white',
        'WARNING': 'yellow',
        'ERROR': 'magenta',
        'CRITICAL': 'light_white',
    }

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def format(self, arg_record: _logging.LogRecord) -> str:
        ''' Format the log record with color codes based on level.

            @param arg_record: the log record to format
            @return: formatted string with ANSI color codes
        '''
        l_formatted: str = super().format(arg_record)
        l_level_name: str = arg_record.levelname
        if l_level_name in self.l_level_to_color:
            l_color = self.l_colors_dict[self.l_level_to_color[l_level_name]]
            l_formatted = f"{l_color}{l_formatted}{self.l_colors_dict['reset']}"

        return l_formatted

class DualOutputHandler(_logging.Handler):
    '''
    Logging handler that emits formatted log records to two outputs:
    - Jupyter frontend (accepts ANSI)
    - IDA's output window (no color; ANSI removed)

    It preserves the formatted message produced by the handler's Formatter.
    '''

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __init__(
        self,
        arg_level: int = _logging.NOTSET,
        arg_jupyter_sender: Callable[[str], None] = _send_text_to_jupyter,
        arg_ida_sender: Callable[[str], None] = _send_text_to_ida_output,
    ) -> None:
        ''' Initialize the handler.

            @param arg_level: logging level for the handler
            @param arg_jupyter_sender: callable to send text to Jupyter frontend
            @param arg_ida_sender: callable to send text to IDA output window

            @return: None
        '''
        super().__init__(arg_level)
        self._jupyter_sender: Callable[[str], None] = arg_jupyter_sender
        self._ida_sender: Callable[[str], None] = arg_ida_sender

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def emit(self, arg_record: _logging.LogRecord) -> None:
        ''' Emit a LogRecord to both outputs. Jupyter gets the text with ANSI colors, IDA output always receives the text with the ANSI escapes stripped.

            @param arg_record: the logging.LogRecord to emit

            @return: None
        '''
        try:
            l_formatted: str = self.format(arg_record)
            l_jupyter_text: str = l_formatted
            l_ida_text: str = _strip_ansi(l_formatted)
            try:
                self._jupyter_sender(l_jupyter_text)
            except Exception:
                pass # Avoid raising from the secondary sender

            try:
                self._ida_sender(l_ida_text)
            except Exception:
                pass # Avoid raising from the secondary sender

        except Exception:
            self.handleError(arg_record)

_g_logger = _logging.getLogger(__name__)
_g_logger.setLevel(_logging.DEBUG)
# Remove existing handlers to avoid duplicates on reload
while _g_logger.handlers:
    _g_logger.removeHandler(_g_logger.handlers[0])

# Create the dual output handler, Jupyter supports ANSI colors, IDA does not
_g_dual_handler = DualOutputHandler(arg_level=_logging.DEBUG, arg_jupyter_sender=_send_text_to_jupyter, arg_ida_sender=_send_text_to_ida_output)
_g_dual_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d - %(message)s', datefmt=_G_DEFAULT_TIME_FORMAT))
_g_logger.addHandler(_g_dual_handler)
_g_logger.propagate = False


# Helpers ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- Helpers


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _timestamped_line(arg_str: str) -> str:
    ''' Add a timestamp at the beginning of the line
     e.g. 2024-12-31 13:59:59 This is the string I send in as argument
    '''
    return _time.strftime(_G_DEFAULT_TIME_FORMAT, _datetime.timetuple(_datetime.now())) + " " + arg_str

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _simulate_long_running_task() -> None:
    ''' Simulate some long running task so I can test _check_if_long_running_script_should_abort()
    copy the string "abort.ida" into the clipboard to raise a TimeoutError exception
    '''
    for i in range(0, 1_000_000):
        log_print(f"Simulating a long running task: {i}")
        _time.sleep(1.0)
    return

_g_timestamp_of_last_checked = _time.time()
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _check_if_long_running_script_should_abort() -> None:
    ''' Scripts that take long time to run can be aborted by copying any of the following strings into the clipboard: "abort.ida", "ida.abort", "ida.stop", "stop.ida"
        This is checked every 10 seconds and raises a TimeoutError() exception

        WARNING! If you have multiple instances of IDA running with this script then the string check will be done in all instances and abort the first script to check the clipboard!
    '''
    global _g_timestamp_of_last_checked
    l_now = _time.time()
    if (l_now - _g_timestamp_of_last_checked) > 10:
        _g_timestamp_of_last_checked = l_now
        try:
            l_clipboard_content = (_pyperclip.paste() or "").strip()
        except Exception: # The clipboard can be locked by another program (Windows) or not exist at all (headless Linux). Never let this break log_print()
            return
        if l_clipboard_content in ["abort.ida", "ida.abort", "ida.stop", "stop.ida"]:
            try:
                _pyperclip.copy("") # Clear the clipboard
            except Exception:
                pass
            l_log_message = f"Found the string '{l_clipboard_content}' in the clipboard that will abort the script"
            log_print(l_log_message, arg_type="INFO")
            raise TimeoutError(l_log_message)

    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def log_print(arg_string: Union[str, int, bool], arg_actually_print: bool = True, arg_type: str = "DEBUG") -> None:
    ''' Log a message to both IDA's output window and the Jupyter console (if one is connected).
    It ALSO checks if the user wants to abort a long running script (see _check_if_long_running_script_should_abort()),
    so call this function in every loop that can take time, even with arg_actually_print=False.

    @param arg_string The message to log
    @param arg_actually_print If False, then nothing is printed (unless _G_LOG_EVERYTHING is set). Usually you send in arg_debug here
    @param arg_type "DEBUG", "INFO", "WARNING", "ERROR" or "CRITICAL"
    '''
    _check_if_long_running_script_should_abort()
    if arg_actually_print or _G_LOG_EVERYTHING:
        arg_type = arg_type.upper()
        if arg_type == "DEBUG":
            _g_logger.debug(arg_string, stacklevel=4)
        elif arg_type == "INFO":
            _g_logger.info(arg_string, stacklevel=4)
        elif arg_type == "WARNING":
            _g_logger.warning(arg_string, stacklevel=4)
        elif arg_type == "ERROR":
            _g_logger.error(arg_string, stacklevel=4)
        elif arg_type == "CRITICAL":
            _g_logger.critical(arg_string, stacklevel=4)
        else:
            _g_logger.debug(arg_string, stacklevel=4)
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _bool(arg_user_input: BoolishType) -> bool:
    ''' Try to convert a user input to a boolean True or False in a smart way.
    If I cannot parse it, I will return False (and print an error message)
    @param arg_user_input if it's a str, then check for "Y", "YES", "ON", "1", "TRUE", "T"
    @return True if I can parse it to something the user want to be true, False otherwise (incl. a string I cannot parse anything useful from)
    '''
    if isinstance(arg_user_input, str):
        arg_user_input = arg_user_input.upper()
        if arg_user_input in ("Y", "YES", "ON", "1", "TRUE", "T"):
            return True

        if arg_user_input in ("N", "NO", "OFF", "0", "FALSE", "F"):
            return False

        log_print(f"I could not figure out what you want with the input: '{arg_user_input}'", arg_type="ERROR")
        return False

    return bool(arg_user_input)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _int_to_str_dict_from_module(arg_module: Union[ModuleType, str], arg_regexp: str) -> Dict[int, str]:
    ''' Internal function. Used to build dict from module enums.
        e.g. _int_to_str_dict_from_module(ida_ua, 'o_.*') -> {0: 'o_void', 1: 'o_reg', 2: 'o_mem', 3: 'o_phrase', 4: 'o_displ', 5: 'o_imm',  6: 'o_far',  7: 'o_near', ... }

        @param arg_module The module to find the values in
        @param arg_regexp Regexp to find the enum prefix
    '''
    l_module: ModuleType = _sys.modules[arg_module] if isinstance(arg_module, str) else arg_module
    return {getattr(l_module, key): key for key in dir(l_module) if _re.fullmatch(arg_regexp, key) and isinstance(getattr(l_module, key), int)}

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _dict_swap_key_and_value(arg_dict: Dict[Any, Any]) -> Dict[Any, Any]:
    ''' Used to swap the key and the value.
    e.g. int_to_str = _int_to_str_dict_from_module(ida_ua, 'o_.*') # -> {0: 'o_void', 1: 'o_reg', 2: 'o_mem', 3: 'o_phrase', 4: 'o_displ', 5: 'o_imm',  6: 'o_far',  7: 'o_near', ... }
    str_to_int = _dict_swap_key_and_value(int_to_str) # -> {'o_void': 0, 'o_reg': 1, 'o_mem': 2, 'o_phrase': 3, 'o_displ': 4, 'o_imm': 5, 'o_far': 6, 'o_near': 7, ... }
    '''
    res = {}
    for k,v in arg_dict.items():
        res[v] = k
    return res

_g_abbreviations: Dict[str, str] = {
    'ASG': "Assign",
    'BPU': "Bytes Per Unit",
    'CC' : "Calling Convention or Compiler, depending on context of the CC",
    'CHCOL' : "Chooser Column",
    'EA' : "Effective Address, just an address in the process",
    'MBA': "Microcode",
    'MD' : "MetaData",
    'PEB': "Process Environment Block",
    'TEB': "Thread Environment Block, a.k.a. TIB (Thread Information Block)",
    'TIB': "Thread Information Block, a.k.a. TEB (Thread Environment Block)",
    'tid': 'Type ID',
    'TIF': "type info. E.g. int*, wchar_t* and so on",
    'TIL': "Type Information Library, IDAs internal name for it's database with types in it. It's like a huge .h file but in IDAs own format",
    "udt" : "user-defined type : a structure or union - but not enums. Read more at [the official docs](https://python.docs.hex-rays.com/ida_typeinf/index.html#ida_typeinf.udt_type_data_t)",
    "udm" : "udt member : i.e., a structure or union member. See ida_typeinf.udm_t",
    "edm": "enum member : i.e., an enumeration member - i.e., an enumerator. See ida_typeinf.edm_t",
    "vdui": "Visual Decompiler User Interface. vd prefix is the internal name for the decompiler. (Visual Decompiler)"
    }

_g_links: Dict[str, str] = {}
_g_links["official_python_documentation"] =      "https://python.docs.hex-rays.com"
_g_links["official_cpp_documentation"] =         "https://cpp.docs.hex-rays.com/"
_g_links["developer_guide"] =                    "https://docs.hex-rays.com/developer-guide"
_g_links["getting_started_with_idapython"] =     "https://docs.hex-rays.com/developer-guide/idapython/idapython-getting-started"
_g_links["idapython_examples"] =                 "https://docs.hex-rays.com/developer-guide/idapython/idapython-examples"
_g_links["porting_guide"] =                      "https://docs.hex-rays.com/developer-guide/idapython/idapython-porting-guide-ida-9"
_g_links["HexRays_official_Youtube_channel"] =   "https://www.youtube.com/@HexRaysSA"
_g_links["AllThingsIDA_Youtube_channel"] =       "https://www.youtube.com/@allthingsida"
_g_links["AllThingsIDA_github"] =                "https://github.com/allthingsida/allthingsida"
_g_links["HexRays_official_plugins_repository"] ="https://plugins.hex-rays.com/"
_g_links["how_to_create_a_plugin"] =             "https://docs.hex-rays.com/developer-guide/idapython/how-to-create-a-plugin"
_g_links["appcall_guide"] =                      "https://docs.hex-rays.com/user-guide/debugger/debugger-tutorials/appcall_primer"
_g_links["appcall_practical_examples"] =         "https://hex-rays.com/blog/practical-appcall-examples/"
_g_links["community_forums"] =                   "https://community.hex-rays.com/"
_g_links["HexRays_github_examples"] =            "https://github.com/HexRaysSA/IDAPython/tree/9.0sp1/examples"
_g_links["ida_domain"] =                         "https://ida-domain.docs.hex-rays.com/"
_g_links["plugins"] =                            "https://plugins.hex-rays.com/"

_g_batch_mode = {}
_g_batch_mode["command_line"] = "<full_path_to>ida.exe -A -S<script_I_want_to_run.py> -L<full_path_to>ida.log <full_path_to_input_file>"
_g_batch_mode["official_link"] = "https://docs.hex-rays.com/user-guide/configuration/command-line-switches"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def links(arg_open_browser_at_official_python_docs: bool = False) -> Dict[str, Dict[str, str]]:
    ''' Various information to help you develop your own scripts.

        Read more: <https://python.docs.hex-rays.com/>
    '''
    res = {}
    res["links"] = _g_links
    res["abbreviations"] = _g_abbreviations
    res["batch_mode"] = _g_batch_mode

    if arg_open_browser_at_official_python_docs:
        _ida_kernwin.open_url(_g_links["official_python_documentation"])

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _official_python_doc_url(arg_function: Callable) -> str:
    ''' Create an URL to the IDA Python docs '''
    l_module: str = arg_function.__module__
    l_function: str =  arg_function.__name__
    return f"{_g_links['official_python_documentation']}/{l_module}/index.html#{l_module}.{l_function}"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def open_url(arg_text_blob_with_urls_in_it_or_function: Union[str, Callable]) -> None:
    ''' Opens the default web browser with all URLs in the given text blob.
        Works well on the docstrings I have enriched with URLs e.g. open_url(ida_kernwin.process_ui_action)

        ida_kernwin.open_url docs: <https://python.docs.hex-rays.com/ida_kernwin/index.html#ida_kernwin.open_url>
        Replacement for ida_kernwin.open_url()
    '''
    if isinstance(arg_text_blob_with_urls_in_it_or_function, str):
        l_url_regex: str = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))" # https://www.geeksforgeeks.org/python-check-url-string/
        urls = _re.findall(l_url_regex, arg_text_blob_with_urls_in_it_or_function)
        if not urls:
            log_print(f"No URLs found in '{arg_text_blob_with_urls_in_it_or_function}'", arg_type="ERROR")
        for url in urls:
            _ida_kernwin.open_url(url[0])
        return

    # Check the docstring
    open_url(getattr(arg_text_blob_with_urls_in_it_or_function, "__doc__", None) or "")

# TODO: Implement?
# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def ask_yn(arg_question: str) -> bool:
#     ''' Asked the use a yes or no question. Works with Qt and with headless '''
#     if __QT_IS_AVAILABLE:
#         _ida_kernwin.ask_yn
#     else:
#         from IPython import get_ipython
#         get_ipython().ask_yes_no("yes or no")

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def bug_report(arg_bug_description: str, arg_module_to_blame: Union[str, ModuleType, None] = None) -> str:
    ''' If you find a bug in IDA or community_base (or any other plugin) you can easy save info about the bug by using this function.
    I will save what file you have open, the version of IDA pro, version of community_base and the bug description.
    I will write a JSON file in the same directory as the IDB

    @param arg_bug_description A long description of the bug. Preferably on how to reproduce it.
    @param arg_module_to_blame The name of the module that is buggy, usually it's the plugin name or "IDA Pro"

    @return The full path to the bug report '''

    # TODO: Add all running plugins and maybe all loaded python modules that are not standard?
    l_timestamp_for_filename: str = _time.strftime(_G_DEFAULT_TIME_FORMAT.replace('-','_').replace(' ','_').replace(':','_').replace('/','_'), _datetime.timetuple(_datetime.now()))
    l_bug_report_file: str = f"{input_file.idb_path}.{l_timestamp_for_filename}.bug_report.json"
    l_bug_report: Dict[str, str] = {}
    l_bug_report["bug_in_module"] = _python_module_to_str(arg_module_to_blame)
    l_bug_report["IDA_version"] = str(ida_version())
    l_bug_report["decompiler_version"] = _ida_hexrays.get_hexrays_version() or "<<< No decompiler >>>"
    l_bug_report["community_base_version"] = __version__
    l_bug_report["python_version"] = _sys.version
    l_bug_report["os_version"] = f"{_platform.uname().system} {_platform.uname().version} {_platform.uname().machine}"
    l_bug_report["datetime"] = _timestamped_line("").strip()
    for key, value in input_file._as_dict().items():
        l_bug_report["input_file_" + key] = value
    l_bug_report["bug_description"] = arg_bug_description

    l_bug_report_as_str = _json.dumps(l_bug_report, ensure_ascii=False, indent=4, default=str)
    with open(l_bug_report_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(l_bug_report_as_str)

    log_print(f"Wrote bug report in {l_bug_report_file}", arg_type="INFO")
    log_print("Please post this bug report to the creator of the module so they can fix it. Thank you!", arg_type="INFO")

    # deprecated, no one wants another popup
    # l_github_issues: str = __url__ + "/issues/new"
    # First argument is the default button that will be pressed if the user press ENTER as soon as the box popups
    # if _ida_kernwin.ask_yn(_ida_kernwin.ASKBTN_YES , f"Open a new issue on Github? ( {l_github_issues} )") == _ida_kernwin.ASKBTN_YES:
        # _ida_kernwin.open_url(l_github_issues + f"?title=bug&body={l_bug_report_as_str}")

    return l_bug_report_file

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def help(arg_search: str) -> List[Tuple[str, str]]:
    ''' Search for a given string and show what function it is in.
        @param arg_search is the text to search for

        @return a list of tuples with the line of the match as the first member and the function name as the second value
    '''
    res = []
    with open(__file__, "r", encoding="utf-8") as fp:
        l_whole_file: List[str] = fp.readlines()

    l_last_function: str = "<<< unknown function >>>"
    for l_line in l_whole_file:
        if "def " in l_line:
            l_last_function = l_line.strip()

        if arg_search in l_line:
            res.append((l_line.strip(), l_last_function))

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _dict_sort(arg_dict: Dict, arg_sort_by_value: bool = False, arg_descending: bool = False) -> Dict:
    ''' Internal function. Returns a new sorted dictionary, can sort by value and can sort ascending or descending '''
    res = {}
    if arg_sort_by_value:
        res = dict(sorted(arg_dict.items(), key=lambda item: item[1])) # Sort by value ( lower -> higher )
    else:
        _list = sorted(arg_dict.items())
        for _t in _list:
            res[_t[0]] = _t[1]

    if arg_descending:
        res = {k: res[k] for k in reversed(res)} # Just reverse the dict
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_version() -> int:
    ''' Returns the version of IDA currently running. e.g. 8.4 --> 840, 9.0 --> 900, 9.2 --> 920, 9.4 --> 940 '''
    return _ida_pro.IDA_SDK_VERSION

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_user_dir() -> str:
    ''' Returns the path IDA is using as base when it looks for user files
     Read more <https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr>
    '''
    return _ida_diskio.get_user_idadir()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_plugin_dirs() -> List[str]:
    ''' Returns a list of directories where IDA looks for plugins
    For more info, see <https://hex-rays.com/blog/igors-tip-of-the-week-103-sharing-plugins-between-ida-installs>
    '''
    return _ida_diskio.get_ida_subdirs("plugins")

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_is_in_gui_mode() -> bool:
    ''' True if IDA is started with the GUI.
    There are 3 cases:
    ida.exe (normal mode with GUI) --> True
    ida.exe -A -Smy_script.py (before the GUI is painted) --> True
    ida_domain (lib-mode) --> False
    '''
    # TODO: Hex-Rays tell us to use os.environ.get("IDA_IS_INTERACTIVE")=="1"? see https://community.hex-rays.com/t/how-to-check-if-idapythonrc-py-is-running-in-ida-pro-or-idalib/297
    return _ida_kernwin.is_idaq()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_is_running_in_batch_mode() -> bool:
    ''' Are we running in batch mode? a.k.a. headless
    Credits goes to [arizvisa](https://github.com/arizvisa) for [my first issue](https://github.com/Harding-Stardust/community_base/issues/1)
    There are 3 cases:
    ida.exe (normal mode with GUI) --> False
    ida.exe -A -Smy_script.py (before the GUI is painted) --> True
    ida_domain (lib-mode) --> True
    '''
    return _bool(_ida_kernwin.cvar.batch)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_arguments() -> List[str]:
    ''' The arguments to the IDA Process when it was launched. Can be used to start ida with custom arguments.
    E.g. ida.exe C:\\temp\\example.exe --extra_option_that_ida_dont_understand=3

    You can then use this function to parse your own arguments. Useful in batch mode
    OBS! Cannot be used in ida_domain mode
    '''
    # TODO: Delete this function?
    # TODO: check idc.ARGV? idc.ARGV is writeable, maybe use that?
    # TODO: IDA 9.3 added: plugins/idapython: make ida's -S command line arguments accessible from sys.argv  https://docs.hex-rays.com/release-notes/9_3#idapython
    if _G_QT_IS_AVAILABLE:
        return QApplication.arguments()
    log_print("QT is not available, atm we cannot get the program arguments", arg_type="ERROR")
    return ["<<< invalid arguments >>>"]

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_config(arg_key: str, arg_value: str) -> bool:
    ''' in ida.cfg (and hexrays.cfg), there are many settings that one can set.
    There is no way to read what the settings are set to (more than parsing the file yourself)

    OBS! There are some IDA settings saved in the registry, see ida_registry_read() on how to read them

    Replacement for ida_idp.process_config_directive()

    [Read more at Hex-Rays blog](https://hex-rays.com/blog/igors-tip-of-the-week-116-ida-startup-files)
    '''
    arg_key = arg_key.upper()
    arg_value = arg_value.upper()

    if "STACK" in arg_key and ("POINTER" in arg_key or "OFFSET" in arg_key): # Options -> General -> Disassembly -> Disassembly line parts -> Stack pointer
        _ = _ida_ida.inf_set_prefix_show_stack(_bool(arg_value))
        return True

    if arg_key == "PACK_DATABASE" and arg_value not in ("0", "1", "2"):
        log_print("PACK_DATABASE only accepts values '0', '1' or '2'", arg_type="ERROR")
        return False

    if arg_key in ("COLLECT_GARBAGE", "ABANDON_DATABASE"):
        arg_value = "YES" if _bool(arg_value) else "NO"

    _ida_idp.process_config_directive(f"{arg_key}={arg_value}")
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_save_database(arg_new_filename: str = "",
                      arg_database_flags: int = -1,
                      arg_snapshot_root: Optional[_ida_loader.snapshot_t] = None,
                      arg_snapshot_attribute: Optional[_ida_loader.snapshot_t] = None) -> bool:
    ''' Save current database using a new file name.

    @param arg_new_filename: output database file name; not set means the current path
    @param arg_database_flags: -1 means the current flags, See ida_loader.DBFL_* for flags
    @param arg_snapshot_root: optional, snapshot tree root
    @param arg_snapshot_attribute: optional, snapshot attributes
    @return success
    '''
    # TODO: Check how this plays with ida_domain
    # TODO: How does this work with the flags? Like compression and so on? Should the user be able to set that in this function?
    l_new_filename: str = arg_new_filename or input_file.idb_path
    l_my_extension = _os.path.splitext(input_file.idb_path)[1] # IDA 8.4 can have IDB, otherwise its always I64
    if l_new_filename and not l_new_filename.endswith(l_my_extension):
        l_new_filename += l_my_extension

    if ida_version() >= 930:
        if arg_database_flags == -1: # IDA 9.3 have changed the default database flags
            arg_database_flags = 0

        return _ida_loader.save_database(l_new_filename, arg_database_flags, arg_snapshot_root, arg_snapshot_attribute)
    return _ida_loader.save_database(l_new_filename, _ida_idaapi.as_uint32(arg_database_flags), arg_snapshot_root, arg_snapshot_attribute) # IDA 8.4 does not have keyword parameters

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_exit(arg_exit_code: int = 0,
             arg_save_database: bool = True,
             arg_compress_database: bool = True,
             arg_collect_garbage: bool = True) -> None:
    ''' Exit IDA and optionally save the IDB
    A good use for this function is as the last call in a script run in batch mode.
    See links() for more info about batch mode

    To exit without saving the IDB, see: <https://docs.hex-rays.com/9.0sp1/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/197>
    and <https://hex-rays.com/blog/igors-tip-of-the-week-116-ida-startup-files>

    Read more at [the official docs](https://python.docs.hex-rays.com/ida_idp/index.html#ida_idp.process_config_directive)
    '''
    # TODO: Check how this plays with ida_domain
    # TODO: Can I take a memory snapshot in case we are in a live debugging session?
    if not arg_save_database:
        _ = ida_config("ABANDON_DATABASE", "YES")
        _ida_pro.qexit(arg_exit_code)
        return # We will never reach this line

    _ = ida_config("COLLECT_GARBAGE", "YES" if _bool(arg_collect_garbage) else "NO") # TODO: _ida_loader.set_database_flag(_ida_loader.DBFL_COMP, True) ?
    _ = ida_config("PACK_DATABASE", "2" if arg_compress_database else "1") # set the default database packing option to "deflate" in old IDA and "zstd" in 9.1+;

    _ida_pro.qexit(arg_exit_code)
    return # We will never reach this line

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_get_ida_notepad_text() -> str:
    ''' Wrapper around ida_nalt.get_ida_notepad_text() that actually honors the type hints.
    Read more in [the official docs](https://python.docs.hex-rays.com/ida_nalt/index.html#ida_nalt.get_ida_notepad_text)
    '''
    return _ida_nalt.get_ida_notepad_text() or ""

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def notepad_text(arg_text: Optional[str] = None) -> str:
    ''' IDA has a text field that the user can write whatever they want in.
    This function can read and write this text field. '''

    if arg_text is not None:
        _ida_nalt.set_ida_notepad_text(str(arg_text))

    return _idaapi_get_ida_notepad_text()

# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def _decompiler_version_deprecated() -> str:
#     ''' What version of Hexrays decompiler we are running '''
#     l_arch = f"{input_file.format}, {input_file.bits} bits, {input_file.endian} endian"
#     l_error_str: str = f"<<< No decompiler for {l_arch} is loaded >>>"
#     if not _ida_hexrays.init_hexrays_plugin():
#         log_print(l_error_str, arg_type="ERROR")
#         return l_error_str
#     res = _ida_hexrays.get_hexrays_version() or ""
#     if not res:
#         log_print(l_error_str, arg_type="ERROR")
#         return l_error_str
#     return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _python_module_to_str(arg_module: Union[str, ModuleType, None] = None) -> str:
    ''' Internal function. Get a Python module name from the argument. If argument is None, then return the module name of ourself '''

    return arg_module if isinstance(arg_module, str) else getattr(arg_module, '__name__', __name__)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def reload_python_module(arg_python_module: Union[str, ModuleType, None] = None) -> bool:
    '''  During development, it's nice to have an easy way to reload the script and update all changes
    [Blog post about it](https://hex-rays.com/blog/loading-your-own-modules-from-your-idapython-scripts-with-idaapi-require)

    @param arg_python_module if this is set to None, then reload ourself

    @return Returns True if we reloaded successfully, False if the module could not be found. Other exceptions (e.g. a SyntaxError in the module) are raised

    Replacement for ida_idaapi.require()
    '''
    l_module_name: str = _python_module_to_str(arg_python_module)
    log_print(f"Reloading '{l_module_name}' ( {getattr(_sys.modules.get(l_module_name, ''), '__file__', '<<< no file found >>>')} ) using ida_idaapi.require('{l_module_name}')", arg_type="INFO")
    try:
        _ida_idaapi.require(l_module_name)
        res = True
    except ModuleNotFoundError as exc:
        log_print(f"Could NOT reload {l_module_name}, exception: {exc}", arg_type="ERROR")
        res = False
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _python_load_module(arg_filepath: str, arg_name: Optional[str] = None) -> Optional[ModuleType]:
    ''' Import a module from an absolute path and register it so Jupyter/IPython tab-completion sees it.
    @param arg_filepath: full path to .py file or package directory (contains __init__.py).
    @param arg_name: optional module name to register in sys.modules and IPython user namespace.
    @return The imported module or None if the file could not be found. Exceptions from running the module (e.g. SyntaxError) are raised.
    '''
    arg_filepath = _os.path.abspath(arg_filepath)
    if arg_name is None:
        arg_name = _os.path.splitext(_os.path.basename(arg_filepath))[0]

    if _os.path.isdir(arg_filepath): # If it's a package directory
        # ensure it's a package (has __init__.py)
        l_init_path = _os.path.join(arg_filepath, "__init__.py")
        if not _os.path.exists(l_init_path):
            log_print(f"Directory '{arg_filepath}' is not a package (missing __init__.py)", arg_type="ERROR")
            return None
        loader = _importlib_machinery.SourceFileLoader(arg_name, l_init_path)
        # OBS! spec_from_file_location() and NOT spec_from_loader(origin=...), the latter does not set __file__ in the module
        spec = _importlib_util.spec_from_file_location(arg_name, l_init_path, loader=loader, submodule_search_locations=[arg_filepath])
    else:
        if not arg_filepath.endswith(".py") or not _os.path.exists(arg_filepath): # assume it's a .py file
            log_print(f"File '{arg_filepath}' not found or not a .py file", arg_type="ERROR")
            return None
        loader = _importlib_machinery.SourceFileLoader(arg_name, arg_filepath)
        spec = _importlib_util.spec_from_file_location(arg_name, arg_filepath, loader=loader) # This sets __file__ in the module, spec_from_loader(origin=...) does not

    if spec is None:
        log_print(f"spec is None for '{arg_filepath}'", arg_type="ERROR")
        return None
    l_module = _importlib_util.module_from_spec(spec)
    _sys.modules[arg_name] = l_module # Must be registered BEFORE exec_module(), a package that does "from . import x" looks itself up in sys.modules
    try:
        loader.exec_module(l_module)
    except BaseException:
        _sys.modules.pop(arg_name, None) # Don't leave a half loaded module behind
        raise

    # If running inside IPython/Jupyter, also put into user namespace for tab-completion
    try:
        from IPython import get_ipython as _get_ipython
        l_ipython = _get_ipython()
        if l_ipython is None:
            raise ModuleNotFoundError
        l_ipython.user_ns[arg_name] = l_module
    except ModuleNotFoundError:
        pass

    return l_module

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_is_64bit() -> bool:
    ''' Is the IDA process you are running in a 64 bit process? This function is needed for IDA 8.4 '''
    return bool(_ida_idaapi.__EA64__)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _ida_DLL() -> Any: #  This used to be Union[_ctypes.CDLL, _ctypes.WinDLL] but WinDLL is not supported on Linux, I guess I can't do anything useful here.
    ''' Load correct version of ida.dll. Works on IDA 8.4, 9.X  Example of how to use ctypes.

    [Read more at Hex-Rays blog about it (OBS! Outdated!)](https://hex-rays.com/blog/calling-ida-apis-from-idapython-with-ctypes)
    '''

    l_bits: str = "64" if ida_is_64bit() else ""
    if ida_version() >= 900:
        l_bits = "" # IDA 9.0 removed the ida64.dll and (32-bits) ida.dll and just calls it ida.dll now

    if _sys.platform == 'win32':
        res = _ctypes.windll[f'ida{l_bits}.dll'] # windll is STDCALL
    elif 'linux' in _sys.platform.lower():
        res = _ctypes.cdll[f'libida{l_bits}.so'] # type: ignore [assignment] # cdll is CDECL. For some strange reason, when I renamed sys --> _sys, mypy fails to understand the code?!
    elif _sys.platform == 'darwin':
        res = _ctypes.cdll[f'libida{l_bits}.dylib'] # type: ignore [assignment] # Not tested, cdll is CDECL. For some strange reason, when I renamed sys --> _sys, mypy fails to understand the code?!
    else:
        log_print(f"You are using an OS I do not know how to handle: {_sys.platform}", arg_type="ERROR")
        return None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _loader_name() -> str:
    ''' Internal function. Example of how to use ctypes to call IDA C api.
    Hex-Rays blog about it (OBS! Outdated!): <https://hex-rays.com/blog/calling-ida-apis-from-idapython-with-ctypes>
    [get_loader_name](https://cpp.docs.hex-rays.com/loader_8hpp.html#a9c79e47be0a36e47363409f3ce9ce6c5)
    '''
    l_IDA_dll = _ida_DLL()
    l_buf_size: int = 0x100
    l_buf = _ctypes.create_string_buffer(l_buf_size)
    l_exported_function_name = 'get_loader_name'
    l_IDA_dll[l_exported_function_name].argtypes = _ctypes.c_char_p, _ctypes.c_size_t # Set the prototype
    l_IDA_dll[l_exported_function_name].restype = _ctypes.c_size_t # Set the return value
    l_IDA_dll[l_exported_function_name](l_buf, l_buf_size) # This is the weird way ctypes calls functions
    return l_buf.value.decode('utf-8') # buf.raw gives the whole buffer

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def hex_dump(arg_ea: Union[EvaluateType, bytes, bytearray], arg_len: Optional[EvaluateType] = None, arg_width: int = 0x10, arg_unprintable_char: str = '.', arg_debug: bool = False) -> None:
    ''' Prints the given data as <address> <byte value> <text> in the same style as IDAs hex view does '''

    l_addr: int = 0
    if isinstance(arg_ea, (bytes, bytearray)):
        l_len: Optional[int] = len(arg_ea) if arg_len is None else eval_expression(arg_len, arg_debug=arg_debug)
        if l_len is None:
            log_print(f'eval_expression({arg_len}) failed')
            return
        l_bytes: bytes = bytes(arg_ea[0:l_len])
    else:
        l_addr = address(arg_ea, arg_debug=arg_debug)
        if l_addr == _ida_idaapi.BADADDR:
            log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
            return

        l_len = 0x10 if arg_len is None else eval_expression(arg_len, arg_debug=arg_debug)
        if l_len is None:
            log_print(f'eval_expression({arg_len}) failed', arg_type="ERROR")
            return
        l_bytes_temp = read_bytes(arg_ea=l_addr, arg_len=l_len, arg_debug=arg_debug)
        if l_bytes_temp is None:
            log_print(f'read_bytes({_hex_str_if_int(arg_ea)}) failed', arg_type="ERROR")
            return
        l_bytes = l_bytes_temp

    l_temp: List[str] = []
    digits: int = 2

    l_len = len(l_bytes) if l_bytes is not None else 0x10
    for buf_offset in range(0, l_len, arg_width):
        s = l_bytes[buf_offset:buf_offset + arg_width]
        hexa = ' '.join(["%0*X" % (digits, x) for x in s]) # TODO: Make more readable...
        hexa = hexa.ljust(arg_width * (digits + 1), ' ')
        text = ''.join([chr(x) if 0x20 <= x < 0x7F else arg_unprintable_char for x in s])
        l_temp.append(f"{l_addr+buf_offset:08X}  {hexa}   {text}")

    print('\n'.join(l_temp))
    _idaapi_request_refresh()
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def hex_parse(arg_list_of_strs: BufferType, arg_debug: bool = False) -> List[str]:
    ''' Parse data that can be very messed up as good as I can
    @return List[hex_as_text: str]

    e.g.
    hex_parse('aa bb cc') --> ['aa', 'bb', 'cc']
    '''
    # Empty input, e.g. input_file.md5 / input_file.sha256 when no file is loaded: ida_nalt.retrieve_input_file_md5() returns None which the wrapper turns into b''.
    # OBS! ida_nalt.retrieve_input_file_crc32() returns 0 instead of None when no file is loaded, that becomes b'\x00\x00\x00\x00' which is NOT empty so input_file.crc32 is "00000000" then
    if not arg_list_of_strs:
        return []

    l_list_of_inputs = [arg_list_of_strs] if isinstance(arg_list_of_strs, (str, bytes, bytearray)) else arg_list_of_strs
    l_list_of_strs: List[str] = []
    if isinstance(l_list_of_inputs[0], (bytes, bytearray)):
        for line in l_list_of_inputs:
            hex_line: str = ""
            for b in line:
                hex_line += f"{b:02x}"
            l_list_of_strs.append(hex_line) # TODO: Rewrite the last 5 lines?
    else:
        l_list_of_strs = l_list_of_inputs # type: ignore[assignment] # I think this is correct but mypy does not like it

    log_print(f'l_list_of_strs is now: {l_list_of_strs}', arg_debug)

    res: List[str] = []
    hex_byte: str = "[0-9A-F][0-9A-F]"
    beginning_of_line: str = hex_byte + hex_byte + hex_byte + r" \s*?((?:" + hex_byte + "(?:[ -]{1,3}|$))+)"

    for line in l_list_of_strs:
        line = line.strip()
        if not line:
            continue

        m = _re.findall(beginning_of_line, line, _re.IGNORECASE)
        if len(m) == 0: # There is no "extra output from the host program" so we just parse the hex raw
            hex_data = _re.findall(hex_byte, line, _re.IGNORECASE)
        else:
            hex_data = _re.split(" |-", m[0].strip())

        for i in hex_data:
            if len(i):
                res.append(i)

    if not res:
        res = []
        log_print("Result is empty. Your input might be wrong?", arg_type="WARNING")

    log_print(f'res: {res}', arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _signed_hex_text(arg_expression: EvaluateType, arg_nbits: int = 0, arg_debug: bool = False) -> Optional[str]:
    ''' Easy way to get nice formatting on signed values.
        @param arg_nbits: The bit width of the variable. Since Python has no fixed bit width int types, you have to specify this. If you don't specify it, I assume it's the input_file.bits width
    '''
    l_nbits = arg_nbits if arg_nbits else input_file.bits
    l_value: Optional[int] = eval_expression(arg_expression=arg_expression, arg_debug=arg_debug)
    if l_value is None:
        log_print(f"'{arg_expression}' failed in eval_expression", arg_type="ERROR")
        return None
    res = hex(_ida_idaapi.as_signed(l_value, nbits=l_nbits))
    if not res.startswith('-'):
        res = '+' + res
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _register_info_from_index(arg_register_index: int, arg_size_in_bytes: int) -> Optional[_ida_idp.reg_info_t]:
    ''' Internal function. Register number + size --> ida_idp.reg_info_t (also for registers that are not in registers._as_dict) '''
    l_reg_name: str = (_ida_idp.get_reg_name(arg_register_index, arg_size_in_bytes) or "").replace('$', '').lower() # MIPS...
    if not l_reg_name:
        return None
    res = registers._as_dict.get(l_reg_name)
    if res is None:
        res = _ida_idp.reg_info_t()
        if not _ida_idp.parse_reg_name(res, l_reg_name):
            return None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _operand_parser(arg_operand: _ida_ua.op_t, arg_instruction: Optional[_ida_ua.insn_t] = None, arg_debug: bool = False) -> Optional[dict]:
    ''' Internal function. Split the operand into a dict with info about the parts of the operand

    @param arg_instruction The instruction the operand belongs to. On x64 this is needed to get r8-r15 right in [base + index * scale] operands,
    since the REX prefix bits are stored in the instruction and not in the operand. insn_t.operands_as_dict uses this.
    '''
    res = {}
    if arg_operand.type == _ida_ua.o_void:
        pass # I don't like this code but IDA use invalid operands with the type o_void to say that this is an invalid operand
    elif arg_operand.type == _ida_ua.o_reg:
        l_register = _register_info_from_index(arg_operand.reg, _G_DATA_TYPE_SIZES_IN_BYTES.get(arg_operand.dtype, 0))
        if l_register is None:
            log_print(f"Could not find the register with index {arg_operand.reg} and dtype {arg_operand.dtype}", arg_type="ERROR")
            return None
        res['register'] = l_register
    elif arg_operand.type in [_ida_ua.o_mem, _ida_ua.o_far, _ida_ua.o_near]:
        res['address'] = arg_operand.addr
    elif arg_operand.type in [_ida_ua.o_phrase, _ida_ua.o_displ]:
        if input_file.processor != 'metapc':
            log_print("This only works for Intel x86 and x64.", arg_type="ERROR")
            return None

        # This follows x86_base_reg(), x86_index_reg() and x86_scale() in the IDA SDK (intel.hpp):
        # op.specflag1 --> hasSIB, op.specflag2 --> the SIB byte, insn.insnpref --> the REX prefix (only in 64-bit code)
        REX_B = 0x01 # Extends the SIB base
        REX_X = 0x02 # Extends the SIB index
        R_SP = 4     # Index 4 (without REX.X) means "no index register" (intel.hpp: INDEX_NONE)
        AUX_USE64 = 0x10 # intel.hpp: aux_use64, insn.auxpref bit that says the instruction is in a 64-bit segment (mode64())
        l_address_size: int = input_file.bits // 8 # OBS! Does not handle the 0x67 address size override prefix
        l_rex: int = arg_instruction.insnpref if (arg_instruction is not None and arg_instruction.auxpref & AUX_USE64) else 0 # REX is only valid in 64-bit mode, per instruction (32-bit segments can exist in a 64-bit file)
        if arg_instruction is None and input_file.bits == 64 and arg_operand.specflag1:
            log_print("No instruction given, the REX prefix is unknown so r8-r15 in the SIB byte can be shown as rax-rdi. Use insn_t.operands_as_dict instead", arg_debug, arg_type="WARNING")

        if not arg_operand.specflag1: # No SIB byte, op.phrase is the (already REX extended) base register
            log_print("specflag1 == 0 (no SIB)", arg_debug)
            res['base_register'] = _register_info_from_index(arg_operand.phrase, l_address_size)
            res['displacement'] = arg_operand.addr
        else:
            l_sib: int = arg_operand.specflag2
            log_print(f"SIB byte (specflag2): {bin(l_sib)}, REX: {bin(l_rex)}", arg_debug)
            l_scale: int = 1 << ((l_sib >> 6) & 0x03) # ss == 00 --> scale 1 (and NOT 0)
            l_base_index: int = (l_sib & 0x07) | (8 if l_rex & REX_B else 0)
            l_index_index: int = ((l_sib >> 3) & 0x07) | (8 if l_rex & REX_X else 0)

            res['base_register'] = _register_info_from_index(l_base_index, l_address_size)
            res['index_register'] = None if l_index_index == R_SP else _register_info_from_index(l_index_index, l_address_size)
            res['scale'] = l_scale
            res['displacement'] = arg_operand.addr

    elif arg_operand.type == _ida_ua.o_imm:
        res['value'] = arg_operand.value
    elif arg_operand.type == _ida_ua.o_idpspec1:
        if input_file.processor == 'metapc':
            res['register'] = f"dr{arg_operand.reg}"
        return res
    elif arg_operand.type == _ida_ua.o_idpspec2:
        if input_file.processor == 'metapc':
            res['register'] = f"cr{arg_operand.reg}"
        return res
    elif input_file.processor == 'metapc' and arg_operand.type >= _ida_ua.o_idpspec0:
        # x86: o_trreg (idpspec0), o_fpreg (idpspec3), o_mmxreg (idpspec4), o_xmmreg (idpspec5), o_ymmreg, o_zmmreg, o_kreg (idpspec5+1..)
        # IDA can name all of these from the register number and the operand size
        l_register = _register_info_from_index(arg_operand.reg, _G_DATA_TYPE_SIZES_IN_BYTES.get(arg_operand.dtype, 0))
        l_reg_name = _ida_idp.get_reg_name(arg_operand.reg, _G_DATA_TYPE_SIZES_IN_BYTES.get(arg_operand.dtype, 0))
        if l_register is None and not l_reg_name:
            log_print(f"Could not name the special register operand type 0x{arg_operand.type:x} with reg {arg_operand.reg}", arg_type="ERROR")
            return None
        res['register'] = l_register if l_register is not None else l_reg_name
        return res
    else:
        l_operand_types = _int_to_str_dict_from_module('_ida_ua', 'o_.*')
        log_print(f"Unknown operand type, we got 0x{arg_operand.type:x}: {l_operand_types.get(arg_operand.type, '<unknown operand type>')} which I cannot handle.", arg_type="ERROR")
        return None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _hex_str_if_int(arg_in: Any, arg_debug: bool = False) -> str:
    ''' If arg_in is an int, then return the string with the hex value, the decimal value and if the int is an valid address: the name of that address
    e.g. '0x400000 (4194304) name: main'

        If arg_in is NOT an int, then we return str(arg_in)
    '''
    if not isinstance(arg_in, int) or isinstance(arg_in, bool): # bool is a subclass of int in Python, but IDA's SWIG ea_t does not accept a bool
        return str(arg_in)

    res: str = f"0x{arg_in:x} ({arg_in})"
    if arg_in == _ida_idaapi.BADADDR:
        res = f"0x{_ida_idaapi.BADADDR:x} (ida_idaapi.BADADDR)"
    elif 0 <= arg_in < _ida_idaapi.BADADDR and _ida_bytes.is_mapped(arg_in): # is_mapped() raises TypeError on negative ints and ints larger than ea_t
        res += f" name: {name(arg_in, arg_debug=arg_debug)}"
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def clipboard_copy_hex_text_to_clipboard(arg_ea_start: EvaluateType = 0, arg_len: EvaluateType = 0, arg_debug: bool = False) -> None:
    ''' Selected bytes will be copied as hex text to the clipboard '''
    _ = dump_to_disk(arg_ea_start=arg_ea_start, arg_len=arg_len, arg_filename="|clipboard|", arg_debug=arg_debug) # "|clipboard|" --> We don't actually dump to disk
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _whitespace_zapper(arg_in_string: str) -> str:
    ''' Internal function. If there are multiple spaces in a row in the input line, they are replaced by only 1 space '''
    res = arg_in_string
    while res != res.replace('  ', ' '):
        res = res.replace('  ', ' ')
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _lnot(arg_expression: _ida_hexrays.cexpr_t) -> _ida_hexrays.cexpr_t:
    ''' Logical NOT of expression. See <https://github.com/tmr232/idapython/blob/0028bac2975e9cfd68ce39e908d1fc923e94000b/examples/vds3.py#L94>
    a cexpr_t with "x == y" will return "x != y"
    '''
    return _ida_hexrays.lnot(_ida_hexrays.cexpr_t(arg_expression))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_request_refresh(arg_mask: int = _ida_kernwin.IWID_ALL, arg_dirty: bool = True) -> None:
    ''' Wrapper around ida_kernwin.request_refresh() and mark_builtin_widgets()
    @param arg_mask bit masks of windows. see ida_kernwin.IWID_* for windows you can ask to refresh
    '''
    if ida_version() >= 930:
        _ida_kernwin.mark_builtin_widgets(mask=arg_mask, dirty=arg_dirty)
        return

    _ida_kernwin.request_refresh(arg_mask)
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_retrieve_input_file_md5() -> bytes:
    ''' Wrapper around ida_nalt.retrieve_input_file_md5() but this we honor the type hints '''
    return _ida_nalt.retrieve_input_file_md5() or bytes()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_retrieve_input_file_sha256() -> bytes:
    ''' Wrapper around ida_nalt.retrieve_input_file_sha256() but we honor the type hints '''
    return _ida_nalt.retrieve_input_file_sha256() or bytes()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_execute_sync(arg_callable: Callable, arg_reqf: int) -> Any:
    ''' Wrapper around ida_kernwin.execute_sync() '''
    # TODO: Add the "batch" switch?
    return _ida_kernwin.execute_sync(arg_callable, arg_reqf)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _pretty_print_size(arg_input_size: int) -> Optional[str]:
    ''' Convert a large number to the correct postfix (KB, MB, GB, TB)
    e.g. _pretty_print_size(1231231332) --> '1.15G'
    Read more: <https://cpp.docs.hex-rays.com/group__conv.html#gab6147a3e263d08eb2b9c2439b4653526>
    Example on how to use the C api from Python.
    '''

    l_IDA_dll = _ida_DLL()
    l_buf_size = 8 # Enough according to the official docs
    l_buf = _ctypes.create_string_buffer(l_buf_size)
    l_exported_function_name = "pretty_print_size"
    l_IDA_dll[l_exported_function_name].argtypes = _ctypes.c_char_p, _ctypes.c_size_t, _ctypes.c_uint64
    l_IDA_dll[l_exported_function_name].restype = _ctypes.c_size_t
    l_IDA_dll[l_exported_function_name](l_buf, l_buf_size, arg_input_size)
    return l_buf.value.decode('utf-8') # l_buf.raw gives the whole buffer

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def google(arg_search: str) -> str:
    ''' Fast track to search '''
    l_search_engine_base: str = "https://www.google.com/search?q="
    res = l_search_engine_base + arg_search
    _ida_kernwin.open_url(res)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _is_running_as_plugin() -> bool:
    ''' Is the script running as a plugin? '''
    return __name__.startswith("__plugins__")

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _new_file_opened_notification_callback(arg_nw_code: int, arg_is_old_database: int) -> None:
    ''' Callback that is triggered whenever a file is opened in IDA Pro.

    @param arg_nw_code is the event number that caused this callback.
    @param arg_is_old_database == 1 if there was an IDB/I64 and 0 if it's a new file
    '''
    del arg_nw_code # This is never used but needed in the prototype
    del arg_is_old_database # This is never used but needed in the prototype

    global registers
    registers = _registers_object()
    global input_file
    input_file = _input_file_object()
    log_print(f"{__name__} is (re)loaded", arg_type="INFO")
    l_addon = _ida_kernwin.addon_info_t()
    l_addon.id = "Harding.community_base"
    l_addon.name = "community_base"
    l_addon.producer = __author__
    l_addon.url = __url__
    l_addon.version = __version__
    _ida_kernwin.register_addon(l_addon)

if not _is_running_as_plugin():
    # Remove the callback registered by a previous load of this module (reload_python_module()), otherwise every reload adds one more callback that runs the OLD module's code.
    # The reference is kept on the ida_idaapi module since our own globals are recreated on reload.
    _t_old_callback = getattr(_ida_idaapi, "_community_base_nw_openidb_callback", None)
    if _t_old_callback is not None:
        _ida_idaapi.notify_when(_ida_idaapi.NW_OPENIDB | _ida_idaapi.NW_REMOVE, _t_old_callback)
    del _t_old_callback
    _ida_idaapi.notify_when(_ida_idaapi.NW_OPENIDB, _new_file_opened_notification_callback) # See also : NW_INITIDA, NW_REMOVE, NW_CLOSEIDB, NW_TERMIDA
    setattr(_ida_idaapi, "_community_base_nw_openidb_callback", _new_file_opened_notification_callback)
    # TODO: If I am running as ONLY plugin, will that cause problem if the user change IDB ?

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _add_link_to_docstring(arg_function: Callable, arg_link: str = "") -> None:
    ''' If there is no link the official documentation for the given function then add a link to to the official documentation '''

    l_docstring: str = getattr(arg_function, "__doc__") or ""
    if _g_links["official_python_documentation"] in l_docstring:
        # log_print(f"Function already has a link, ignoring", arg_type="WARNING")
        return

    l_link = arg_link or _official_python_doc_url(arg_function)

    l_new_doc_string = l_docstring.strip() + "\n\nRead more: " + l_link
    setattr(arg_function, "__doc__", l_new_doc_string)
    return

for _t_name, _t_function in _inspect.getmembers(_ida_allins, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_auto, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_bytes, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_dbg, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_expr, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_funcs, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_fpro, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_hexrays, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_idaapi, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_ida, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_idc, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_idd, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_idp, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_kernwin, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_lines, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_loader, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_name, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_nalt, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_netnode, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_pro, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_range, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_registry, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_search, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_segment, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_idc, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_typeinf, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_ua, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_xref, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_idautils, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_diskio, _inspect.isfunction): _add_link_to_docstring(_t_function)
for _t_name, _t_function in _inspect.getmembers(_ida_dirtree, _inspect.isfunction): _add_link_to_docstring(_t_function)

if ida_version() >= 920:
    _add_link_to_docstring(_ida_typeinf.func_type_data_t.set_cc, f"{_g_links['official_python_documentation']}/ida_typeinf/index.html#ida_typeinf.func_type_data_t.set_cc")

if ida_version() >= 930:
    import ida_lumina as _ida_lumina # type: ignore[import-untyped, import-not-found]
    for _t_name, _t_function in _inspect.getmembers(_ida_lumina, _inspect.isfunction): _add_link_to_docstring(_t_function)

if ida_version() >= 950:
    import ida_license as _ida_license # type: ignore[import-untyped, import-not-found]
    for _t_name, _t_function in _inspect.getmembers(_ida_license, _inspect.isfunction): _add_link_to_docstring(_t_function)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _time_since(arg_timestamp_str: str, arg_now: str = "") -> str:
    """
    Returns a human-readable elapsed time since timestamp_str.
    @param arg_timestamp_str format: "YYYY-MM-DD HH:MM:SS" (same as _G_DEFAULT_TIME_FORMAT)
    @param arg_now has the format: "YYYY-MM-DD HH:MM:SS" (same as _G_DEFAULT_TIME_FORMAT), if you let it be empty, then take the current timestamp
    @return The time ago, e.g. _time_since(community_base.__version__) --> '22 hours, 9 minutes, 8 seconds ago'
    """
    arg_now = arg_now or _time.strftime(_G_DEFAULT_TIME_FORMAT, _datetime.timetuple(_datetime.now()))
    l_now = _datetime.strptime(arg_now, _G_DEFAULT_TIME_FORMAT)
    l_then = _datetime.strptime(arg_timestamp_str, _G_DEFAULT_TIME_FORMAT)
    l_diff = _relativedelta(l_now, l_then)
    l_past = True
    if l_then > l_now:
        l_then, l_now = l_now, l_then
        l_past = False
    l_parts: List[str] = []
    if l_diff.years:
        l_parts.append(f"{abs(l_diff.years)} year{'s' if abs(l_diff.years) != 1 else ''}")
    if l_diff.months:
        l_parts.append(f"{abs(l_diff.months)} month{'s' if abs(l_diff.months) != 1 else ''}")
    if l_diff.days:
        l_parts.append(f"{abs(l_diff.days)} day{'s' if abs(l_diff.days) != 1 else ''}")
    if l_diff.hours:
        l_parts.append(f"{abs(l_diff.hours)} hour{'s' if abs(l_diff.hours) != 1 else ''}")
    if l_diff.minutes:
        l_parts.append(f"{abs(l_diff.minutes)} minute{'s' if abs(l_diff.minutes) != 1 else ''}")
    if l_diff.seconds or not l_parts:
        l_parts.append(f"{abs(l_diff.seconds)} second{'s' if abs(l_diff.seconds) != 1 else ''}")
    return f"{', '.join(l_parts[:3])} {'ago' if l_past else 'from now'}"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _hotkey_str_fixer(arg_hotkey_str: str) -> str:
    ''' IDA is very picky on how you give the hotkey string '''
    return arg_hotkey_str.lower().replace('+', '-').replace(' ', '') # So very picky... >_<


# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def _last_errors() -> List[str]:
    # ''' Whenever I get an error that is not fatal, log it here so I can look it up later '''
    # TODO: Implement
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def plugins() -> Dict[str, ModuleType]:
    ''' List what plugins that are loading into IDA.
        @return {plugin_name: str -> plugin_module: ModuleType}
    '''
    res = {}
    for l_plugin_name, l_plugin_module in list(_sys.modules.items()): # Copy, another thread (e.g. a Jupyter kernel) can import modules while we iterate
        if "__plugins__" in l_plugin_name:
            l_plugin_name = l_plugin_name.replace("__plugins__", "")
            res[l_plugin_name] = l_plugin_module
    return res

# API extension ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- API extension


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_license_info(arg_delete_user_info_from_IDB: bool = False) -> Dict[str, str]:
    ''' Gets the license info. This function serves as example of 2 things:
    1. How to get info that is not easy to get in a real way.
    2. That your name is in every IDB, privacy warning!
    For a very extensive information about the user, see ida_license_info_ex()
    
    Since IDA 9.5 there is also a module named ida_license that can be used

    @return {serial_number: str, name_info: str}
    '''
    if arg_delete_user_info_from_IDB:
        _ = _ida_license_info_delete()

    res = {"serial_number": "Unknown", "name_info": "Unknown"}
    l_lines: List[str] =_idaapi_generate_disassembly(input_file.min_original_ea, arg_max_lines=100, arg_as_stack=False, arg_notag=True)[1]
    l_next_line_is_user_info: bool = False
    for l_line in l_lines:
        if l_next_line_is_user_info:
            l_next_line_is_user_info = False
            l_name_or_email_match = _re.match(r".*\s\s\s([^\s].*[^\s])\s\s\s", l_line)
            if l_name_or_email_match:
                res["name_info"] = l_name_or_email_match.group(1)
        else:
            l_license_info_match = _re.match(".*License info: (.*?) ", l_line)
            if l_license_info_match:
                res["serial_number"] = l_license_info_match.group(1)
                l_next_line_is_user_info = True
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_license_info_ex() -> Optional[str]:
    ''' Gets all info about the users licenses.
    To remove all this, see use ida_license_info(arg_delete_user_info_from_IDB=True)

    @returns a JSON string with all the info about the users license. (everything except the signature) '''
    l_json_text = ""
    l_node = _ida_netnode.netnode("$ original user")
    if l_node == _ida_netnode.BADNODE:
        log_print("Something went wrong", arg_type="ERROR")
        return None

    for i in range(16, 30):
        if l_node.supval(i):
            l_json_text += l_node.supstr(i)
        else:
            break

    l_json_dict = _json.loads(l_json_text or "{}")
    res = _json.dumps(l_json_dict, ensure_ascii=False, indent=4, default=str)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _ida_license_info_delete() -> bool:
    ''' Deletes the user info in the IDB, if you do not want your licence info to be in the database for NEW databases then edit ida.cfg and set STORE_USER_INFO = NO '''

    l_idc_return_value = _ida_expr.idc_value_t()
    _ida_expr.eval_idc_expr(l_idc_return_value, 0, "del_user_info()")
    if l_idc_return_value.vtype != chr(_ida_expr.VT_LONG): # https://cpp.docs.hex-rays.com/group___v_t__.html
        log_print("Unknown error", arg_type="ERROR")
        return False
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _compiler_info() -> _ida_ida.compiler_info_t:
    ''' Replacement for ida_ida.inf_get_cc()

    Official docs: <https://cpp.docs.hex-rays.com/structcompiler__info__t.html>
    [See more at AllthingsIDA: IDAPython: Retrieving global database information](https://youtu.be/2w8LdSCPUQc?t=1369)
    '''
    res = _ida_ida.compiler_info_t() # Create empty object
    _ida_ida.inf_get_cc(res) # Fill the object with info
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _compiler_str() -> str:
    ''' What compiler was used according to IDA?

    Official docs for compiler id: <https://cpp.docs.hex-rays.com/group___c_o_m_p__.html>
    [See more at AllthingsIDA: IDAPython: Retrieving global database information](https://youtu.be/2w8LdSCPUQc?t=1369)
    '''
    l_compiler_info: _ida_ida.compiler_info_t = _compiler_info()
    l_compiler_id: int = l_compiler_info.id & _ida_typeinf.COMP_MASK
    l_unsure: bool = _bool(l_compiler_info.id & _ida_typeinf.COMP_UNSURE)
    res = _ida_typeinf.get_compiler_name(l_compiler_id)
    res += " (unsure)" if l_unsure else " (sure)"
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pe_header() -> Optional[bytes]:
    ''' Returns the PE header saved in the IDB.

        returns The PE header as bytes if we are in a PE file and None if we don't have any PE header
    '''
    return _idautils.peutils_t().header()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pe_header_linker_version() -> Tuple[int, int]:
    ''' This is a rewrite of Rolf Rolles script to get the linker info from the PE header

        returns a tuple that looks like (major_version: int, minor_version: int)
        LLVM returns a major_version of 1 or 2, MSVC returns a major_version of 6+
    '''
    l_pe_header = pe_header()
    if l_pe_header is None:
        log_print("No PE header found", arg_type="ERROR")
        return (0, 0)

    l_major_version: int = l_pe_header[0x1A]
    l_minor_version: int = l_pe_header[0x1B]
    return (l_major_version, l_minor_version)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pe_header_os_version() -> Tuple[int, int]:
    ''' Get the OS version from the PE header '''
    l_pe_header = pe_header()
    if l_pe_header is None:
        log_print("No PE header found", arg_type="ERROR")
        return (0, 0)

    l_major_version: int = int.from_bytes(l_pe_header[0x40:0x42], byteorder="little") # MajorOperatingSystemVersion is a WORD
    l_minor_version: int = int.from_bytes(l_pe_header[0x42:0x44], byteorder="little") # MinorOperatingSystemVersion is a WORD
    return (l_major_version, l_minor_version)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _pe_is_reproducible_build(arg_debug: bool = False) -> Optional[bool]:
    ''' Internal function. Checks the PE debug directory for an IMAGE_DEBUG_TYPE_REPRO entry (linker switch /Brepro).
    If that entry exists, then the TimeDateStamp in the PE header is a hash and not a time.

    @return True/False, or None if the debug directory could not be read (e.g. not a PE or the debug directory is not loaded in the IDB)
    '''
    IMAGE_DEBUG_TYPE_REPRO = 16
    SIZE_OF_IMAGE_DEBUG_DIRECTORY = 0x1C
    l_pe_header = pe_header()
    if not l_pe_header:
        return None

    # OBS! pe_header() is NOT the header as it is in the file. IDA's PE loader converts 64-bit (PE32+) headers into its 32-bit layout
    # (pe64_to_pe() in the SDK ldr/pe/common.cpp) and saves that peheader_t. So the data directories are ALWAYS at 0x78 (SDK ldr/pe/pe.h)
    # even if OptionalHeader.Magic (at 0x18) still says 0x20B (PE32+)
    IDA_PEHEADER_DATA_DIRECTORIES_OFFSET = 0x78
    l_debug_directory_entry = IDA_PEHEADER_DATA_DIRECTORIES_OFFSET + 6 * 8 # IMAGE_DIRECTORY_ENTRY_DEBUG == 6 (peheader_t.debdir at 0xA8), each entry is (RVA: DWORD, Size: DWORD)
    if len(l_pe_header) < l_debug_directory_entry + 8:
        return None

    l_debug_rva: int = int.from_bytes(l_pe_header[l_debug_directory_entry:l_debug_directory_entry + 4], byteorder="little")
    l_debug_size: int = int.from_bytes(l_pe_header[l_debug_directory_entry + 4:l_debug_directory_entry + 8], byteorder="little")
    if not l_debug_rva or not l_debug_size:
        return False # No debug directory at all --> no REPRO entry

    l_debug_directory_ea: int = input_file.imagebase + l_debug_rva
    for l_offset in range(0, l_debug_size - SIZE_OF_IMAGE_DEBUG_DIRECTORY + 1, SIZE_OF_IMAGE_DEBUG_DIRECTORY):
        if not _ida_bytes.is_loaded(l_debug_directory_ea + l_offset + 0x0C):
            log_print(f"Debug directory at 0x{l_debug_directory_ea:x} is not loaded in the IDB", arg_debug)
            return None
        l_type: int = _ida_bytes.get_dword(l_debug_directory_ea + l_offset + 0x0C) # IMAGE_DEBUG_DIRECTORY.Type
        if l_type == IMAGE_DEBUG_TYPE_REPRO:
            return True
    return False

# (MajorLinkerVersion, MinorLinkerVersion, year of the first release). Only linkers where the version is not shared with other toolchains:
# GNU ld (2.x), Delphi (2.25), Go (3.0) and the old Microsoft linkers (< 6.0) are NOT in the list. lld-link always writes 14.0
_G_PE_LINKER_FIRST_RELEASE_YEAR: List[Tuple[int, int, int]] = [
    (6, 0, 1998),   # Visual Studio 6
    (7, 0, 2002),   # Visual Studio .NET 2002
    (7, 10, 2003),  # Visual Studio .NET 2003
    (8, 0, 2005),   # Visual Studio 2005
    (9, 0, 2007),   # Visual Studio 2008
    (10, 0, 2010),  # Visual Studio 2010
    (11, 0, 2012),  # Visual Studio 2012
    (12, 0, 2013),  # Visual Studio 2013
    (14, 0, 2015),  # Visual Studio 2015 (and lld-link)
    (14, 10, 2017), # Visual Studio 2017
    (14, 20, 2019), # Visual Studio 2019
    (14, 30, 2021), # Visual Studio 2022
    (14, 40, 2024), # Visual Studio 2022 17.10
    (14, 50, 2025), # Visual Studio 2026
    (48, 0, 2015),  # Roslyn (C#/VB.NET), deterministic builds also have a hash as timestamp
]

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _pe_linker_earliest_timestamp(arg_major_version: int, arg_minor_version: int) -> Optional[int]:
    ''' Internal function. A file can not be linked before its linker was released, so the linker version gives us the earliest valid TimeDateStamp.
    OBS! The linker version in the PE header is easy to forge, so this is only a sanity check.

    @param arg_major_version MajorLinkerVersion from the PE header, see pe_header_linker_version()
    @param arg_minor_version MinorLinkerVersion from the PE header
    @return The earliest valid timestamp (seconds since 1970, UTC), or None if we don't know the linker
    '''
    res: Optional[int] = None
    for l_major, l_minor, l_year in _G_PE_LINKER_FIRST_RELEASE_YEAR: # The list is sorted, so the last match is the newest release that is not newer than our linker
        if l_major == arg_major_version and l_minor <= arg_minor_version:
            res = int(_datetime(l_year - 1, 1, 1, tzinfo=_timezone.utc).timestamp()) # - 1 year since previews and betas are out before the release
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pe_header_compiled_time() -> str:
    ''' Reads "compile time" from the PE header. Warning! Files linked with repro have a hash here instead so we can get [reproducible builds](https://devblogs.microsoft.com/oldnewthing/20180103-00/?p=97705)
    That is detected by looking for an IMAGE_DEBUG_TYPE_REPRO entry in the debug directory.
    If that entry is missing we sanity check the timestamp: it can not be after the last known good date (__version__) and not before the linker was released.

    @return The compile time as a string in UTC, "" if there is no PE header or if the timestamp is not a valid time
    '''
    l_pe_header = pe_header()
    if l_pe_header is None:
        log_print("No PE header found", arg_type="ERROR")
        return ""

    l_is_reproducible = _pe_is_reproducible_build()
    if l_is_reproducible:
        log_print("This file is a reproducible build (IMAGE_DEBUG_TYPE_REPRO in the debug directory) so the timestamp is a hash and not a valid time", arg_type="ERROR")
        return ""
    if l_is_reproducible is None:
        log_print("Could not read the debug directory to check for reproducible builds, the timestamp might be a hash and not a valid time", arg_type="WARNING")

    l_timestamp_and_hash: bytes = l_pe_header[8:12]
    l_timestamp: int = int.from_bytes(l_timestamp_and_hash, byteorder="little")
    # OBS! Do NOT use time.time() here, the clock is often changed on malware analysis machines. __version__ is the last known good date
    l_last_known_good_timestamp: float = _datetime.strptime(__version__, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_timezone.utc).timestamp() + 24 * 60 * 60 # __version__ is in local time, + 1 day covers all timezones
    if l_timestamp > l_last_known_good_timestamp: # A compile time in the future can only be a hash (reproducible build even if we could not see the REPRO entry)
        log_print(f"The timestamp 0x{l_timestamp:x} is after the last known good date (__version__ = '{__version__}') so it's a hash (reproducible build) and not a valid time", arg_type="ERROR")
        return ""

    (l_linker_major, l_linker_minor) = pe_header_linker_version()
    l_earliest_timestamp: Optional[int] = _pe_linker_earliest_timestamp(l_linker_major, l_linker_minor)
    if l_earliest_timestamp is not None and l_timestamp < l_earliest_timestamp: # A compile time before the linker existed, ex: linker 14.x and year 1971
        log_print(f"The timestamp 0x{l_timestamp:x} is older than the linker (version {l_linker_major}.{l_linker_minor}) so it's a hash (reproducible build) or a forged timestamp and not a valid time", arg_type="ERROR")
        return ""

    l_datetime =_datetime.timetuple(_datetime.fromtimestamp(l_timestamp, tz=_timezone.utc))

    return _time.strftime(f"{_G_DEFAULT_TIME_FORMAT} (UTC)", l_datetime)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pdb_path() -> str:
    ''' Return the PDB filename from either 1. the loaded PDB or 2. the PDB path in the PE header
        Taken from <https://github.com/gaasedelen/lucid/blob/9f2480dc8e6bbb9421b5711533b0a98d2e9fb5af/plugins/lucid/util/ida.py#L23>
    '''
    l_pdb_node = _ida_netnode.netnode("$ pdb") # If we have a PDB loaded already, then use that info
    if l_pdb_node != _ida_netnode.BADNODE:
        PDB_DLLNAME_NODE_IDX: int = 0
        res = l_pdb_node.supstr(PDB_DLLNAME_NODE_IDX)
        if res:
            return res

    l_pe_netnode = _ida_netnode.netnode(_idautils.peutils_t().PE_NODE) # No PDB is loaded, let's read some info from the PE header
    if l_pe_netnode == _ida_netnode.BADNODE:
        return ""

    res = l_pe_netnode.supstr(0xFFFFFFFFFFFFFFF7)
    if not res:
        return ""

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pdb_load(arg_local_pdb_file: str = "",
             arg_image_base: Optional[EvaluateType] = None,
             arg_force_reload: bool = False,
             arg_local_symbol_cache: str = "",
             arg_debug: bool = False) -> Optional[bool]:
    ''' Try to load the PDB for this file.
    Code taken from <https://gist.github.com/patois/b3f329868934710fbc81218ce1d6d722>
    [Microsoft symbol server info](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols)

    @param arg_local_pdb_file If you have a local PDB file, then set this. If this is not set then download from Microsofts Symbol server
    @param arg_image_base If you have a specific image base, then set this. If this is not set then use the image base from the file
    @param arg_force_reload If you already have PDB data, force a new reload and parse
    @param arg_local_symbol_cache Save the PDB here on the disk, it not set, then use the same directory as where the IDB is

    @return True if everything went fine, False otherwise
    '''
    # These come from IDA SDK: pdb/common.h
    PDB_CC_USER_WITH_DATA = 3
    PDB_DLLBASE_NODE_IDX = 0
    PDB_DLLNAME_NODE_IDX = 0

    l_size: int = 0 # Not interesting, can be ignored
    l_create_if_not_exists: bool = True # Not interesting, can be ignored
    l_pdb_node = _ida_netnode.netnode("$ pdb", l_size, l_create_if_not_exists)
    if arg_force_reload:
        log_print("arg_force_reload set so I will delete the PDB node", arg_debug)
        l_pdb_node.altdel(PDB_DLLBASE_NODE_IDX)
        l_pdb_node.supdel(PDB_DLLNAME_NODE_IDX)

    if l_pdb_node.altval(PDB_DLLBASE_NODE_IDX) == 1:
        log_print("PDB info is already loaded", arg_type="ERROR")
        return False

    l_temp_imagebase: Optional[int] = input_file.imagebase if arg_image_base is None else eval_expression(arg_image_base, arg_debug=arg_debug)
    if l_temp_imagebase is None:
        log_print("arg_image_base resolved to None", arg_type="ERROR")
        return False
    l_imagebase: int = l_temp_imagebase

    l_local_symbol_cache: str = arg_local_symbol_cache or str(_os.path.dirname(input_file.idb_path))
    l_default_NT_SYMBOL_PATH = f"srv*{l_local_symbol_cache}*https://msdl.microsoft.com/download/symbols"

    l_we_set_NT_SYMBOL_PATH: bool = False
    if _os.environ.get('_NT_SYMBOL_PATH', None) is None:
        log_print(f"Your '_NT_SYMBOL_PATH' is not set at all, setting it to {l_default_NT_SYMBOL_PATH} while the PDB is loaded", arg_type="WARNING")
        _os.environ['_NT_SYMBOL_PATH'] = l_default_NT_SYMBOL_PATH
        l_we_set_NT_SYMBOL_PATH = True

    l_pdb_file = arg_local_pdb_file or pdb_path()
    log_print(f"l_imagebase: 0x{l_imagebase:x}, l_pdb_file: {l_pdb_file}", arg_debug)
    l_pdb_node.altset(PDB_DLLBASE_NODE_IDX, l_imagebase) # The alt* part is usually an int
    l_pdb_node.supset(PDB_DLLNAME_NODE_IDX, l_pdb_file) # the sup* part is usually a str

    # TODO: Verify that l_pdb_file actually is set to something

    try:
        plugin_load_and_run("pdb", PDB_CC_USER_WITH_DATA, arg_debug=arg_debug) # See https://reverseengineering.stackexchange.com/questions/8171/
    finally:
        if l_we_set_NT_SYMBOL_PATH: # Don't leave a process wide environment variable behind that changes how IDA loads all other PDBs
            _os.environ.pop('_NT_SYMBOL_PATH', None)

    l_return_code = l_pdb_node.altval(PDB_DLLBASE_NODE_IDX)
    if not l_return_code:
        log_print("Could NOT load PDB", arg_type="ERROR")
        return False

    # The log message window have something like this now, try to parse it
    # PDB: using PDBIDA provider
    # PDB: loading E:\temp\ntdll.pdb\9FF79BBA19EBED309623072EA067B20F1\ntdll.pdb
    # PDB: loaded 1265 types
    # PDB: total 5018 symbols loaded for "ntdll.pdb"

    l_pdb_load_result: Dict[str, str] = {}
    l_num_log_lines = 8
    l_output_msg_lines = ida_output_text(100) # Only 4 lines are output but I read some more if some other plugin/IDA writes to the log
    for l_line in l_output_msg_lines[::-1]:
        if l_line.startswith("PDB:"):
            l_line = l_line[5:] # Strip the "PDB: " prefix"

            if l_line.startswith("loading"):
                l_pdb_load_result["path"] = l_line[8:] # "loading E:\temp\ntdll.pdb\9FF79BBA19EBED309623072EA067B20F1\ntdll.pdb"
            elif l_line.startswith("loaded"):
                l_pdb_load_result["num_types"] = l_line[7:] # "l"oaded 1265 types"
            elif l_line.startswith("total"):
                l_pdb_load_result["total"] = l_line[6:] # 'total 5018 symbols loaded for "ntdll.pdb"'

            l_num_log_lines -= 1
            if l_num_log_lines <= 0:
                break

    log_print(f"Saved PDB to: {l_pdb_load_result.get('path', '<<< no path >>>')}, total: {l_pdb_load_result.get('total', '<<< no total >>>')}", arg_type="INFO")
    return True

class _input_file_object():
    ''' Information about the file that is loaded in IDA such as filename, file type and so on
        Please use the object created in community_base.input_file. E.g. print(community_base.input_file.idb_path)
        There are some entries that are hidden by having the first character '_'
    '''
    bits = property(fget=lambda self: _ida_ida.inf_get_app_bitness() or 0, doc='64/32/16: int')
    compiler = property(fget=lambda self: _compiler_str(), doc="What compiler was used to compile this code")
    crc32 = property(fget=lambda self: ''.join(hex_parse(_ida_nalt.retrieve_input_file_crc32().to_bytes(4, 'big'))), doc='CRC-32 as ascii string')
    endian = property(fget=lambda self: '<<< no file loaded >>>' if not self.filename else ('big' if _ida_ida.inf_is_be() else 'little'), doc='"big" or "little" (or "<<< no file loaded >>>" if no file is loaded)')
    entry_point = property(fget=lambda self: _ida_ida.inf_get_start_ip(), doc='Address of the first instruction that is executed')
    filename = property(fget=lambda self: _ida_nalt.get_input_file_path() or "", doc='Full path and filename to the file WHEN IT WAS LOADED INTO IDA. The file might been moved by the user and this path might not be valid.')
    format = property(fget=lambda self: _ida_loader.get_file_type_name() if self.filename else "<<< no file loaded >>>", doc='Basically PE or ELF. e.g. PE gives "Portable executable for 80386 (PE)"')
    _idb_creation_time = property(fget=lambda self: _time.strftime(_G_DEFAULT_TIME_FORMAT, _datetime.timetuple(_datetime.fromtimestamp(_ida_nalt.get_idb_ctime()))), doc='When the IDB was created')
    _idb_number_of_changes = property(fget=lambda self: _ida_ida.inf_get_database_change_count(), doc='Number of changes done in the IDB')
    _idb_opened_number_of_times = property(fget=lambda self: _ida_nalt.get_idb_nopens(), doc='Number of times the IDB have been opened')
    idb_path = property(fget=lambda self: _ida_loader.get_path(_ida_loader.PATH_TYPE_IDB), doc='Full path to the IDB. Replacement for ida_utils.GetIdbDir()')
    _idb_work_seconds = property(fget=lambda self: _ida_nalt.get_elapsed_secs(), doc='Number of seconds the IDB have been open')
    idb_version = property(fget=lambda self: _ida_ida.inf_get_version(), doc='The version that the IDB format is in. If you created the IDB in an older version of IDA Pro, then this will differ from ida_version()')
    _initial_ida_version = property(fget=lambda self: _ida_nalt.get_initial_ida_version(), doc="The version of IDA that created this IDB")
    imagebase = property(fget=lambda self: _ida_nalt.get_imagebase(), doc='The address the input file will be/is loaded at')
    is_dll = property(fget=lambda self: _ida_ida.inf_is_dll(), doc='Is the file a DLL file?')
    loader = property(fget=lambda self: _loader_name().upper() if self.filename else "<<< No file loaded >>>", doc='Name of the IDA loader that is parsing the file when loading it into IDA')
    main = property(fget=lambda self: _ida_ida.inf_get_main(), doc="If IDA can identy the main function, this is set. Otherwise it's set to BADADDR")
    min_ea = property(fget=lambda self: _ida_ida.inf_get_min_ea(), doc='Lowest Effective Address (EA) in the database. If the input file is started in a debugger, this value will be the lowest EA in the process.')
    max_ea = property(fget=lambda self: _ida_ida.inf_get_max_ea(), doc='Highest Effective Address (EA) in the database (but + 1). If the input file is started in a debugger, this value will be the higheest EA in the process.')
    min_original_ea = property(fget=lambda self: _ida_ida.inf_get_omin_ea(), doc='Lowest Effective Address (EA) in the database. If the input file is started in a debugger, this value will be the same as when the process is NOT started.')
    max_original_ea = property(fget=lambda self: _ida_ida.inf_get_omax_ea(), doc='Highest Effective Address (EA) in the database (but + 1). If the input file is started in a debugger, this value will be the same as when the process is NOT started')
    md5 = property(fget=lambda self: ''.join(hex_parse(_idaapi_retrieve_input_file_md5())), doc='MD5 as ascii string')
    processor = property(fget=lambda self: _ida_ida.inf_get_procname(), doc='IDAs name for the processor. E.g. "metapc" for Intel x64 assembly, "ARM" for ARM 32')
    size = property(fget=lambda self: _ida_nalt.retrieve_input_file_size(), doc='The target file size in bytes. _NOT_ the IDB size.')
    sha256 = property(fget=lambda self: ''.join(hex_parse(_idaapi_retrieve_input_file_sha256())), doc='SHA-256 as ascii string')

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _as_dict(self) -> Dict[str, str]:
        ''' Return all info about the file in a dict (JSON) '''
        res = {}
        for l_property in dir(self):
            if l_property.startswith('_'):
                continue
            l_property_value = getattr(self, l_property)

            if isinstance(l_property_value, int) and not l_property in ['bits', 'idb_version', 'is_dll', 'idb_work_seconds', 'idb_opened_number_of_times', 'idb_number_of_changes']: # These are printed as int and not hex
                l_property_value = f"0x{l_property_value:x}"
            else:
                l_property_value = str(l_property_value)
            res[l_property] = l_property_value
        return res

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __str__(self) -> str:
        ''' Print all the properties as string '''
        res = ""
        for k,v in self._as_dict().items():
            res += f"{k}: {v}\n"
        return res

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __repr__(self) -> str:
        ''' The type and all the properties, one per line '''
        return f"{type(self)} which has str(self):\n{str(self)}"

input_file = _input_file_object() # Recreated in the "new_file_opened_notification_callback" function

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def current_address() -> int:
    ''' Returns the address where cursor is. (OBS! Cursor in IDA is NOT the mouse cursor but where the blinking line is)
    Replacement for ida_kernwin.get_screen_ea()
    '''

    # TODO: check for ida_domain?
    return _ida_kernwin.get_screen_ea()

here = current_address

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_str2ea(arg_expression: str, arg_screen_ea: int = _ida_idaapi.BADADDR) -> int:
    '''  wrapper around ida_kernwin.str2ea() (without the exception)
    IDA < 8.3: ida_kernwin.str2ea() returns BADADDR, IDA >= 8.3: ida_kernwin.str2ea() returns None

    @return Returns ida_idaapi.BADADDR on failure
    '''
    try:
        l_ida_kernwin_str2ea_res: Optional[int] = _ida_kernwin.str2ea(arg_expression, arg_screen_ea)
        res = l_ida_kernwin_str2ea_res if l_ida_kernwin_str2ea_res is not None else _ida_idaapi.BADADDR
    except TypeError as exc:
        log_print(f'ida_kernwin.str2ea("{arg_expression}") failed. Exception: {exc}', arg_type="ERROR")
        res = _ida_idaapi.BADADDR
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def eval_expression(arg_expression: EvaluateType, arg_supress_error: bool = False, arg_debug: bool = False) -> Optional[int]:
    ''' This function tries to evaluate whatever you give it into an int. E.g. "esi + edx * 0x10 + 3" (if the debugger is active) or "0x11 + 0x11"

        Replacement for ida_kernwin.str2ea()

        OBS! This is NOT a pure replacement of ida_kernwin.str2ea()!
        ida_kernwin.str2ea("11") --> 0x11, eval_expression("11") --> 0x0B

        @return Returns the value (int) that the the input evaluated to
    '''
    if isinstance(arg_expression, int): # Can handle an address in int form i.e. ea_t
        log_print(f"arg_expression is of type int: 0x{arg_expression:x} ({arg_expression})", arg_debug)
        return arg_expression

    if isinstance(arg_expression, _ida_ua.op_t):
        log_print(f"arg_expression is a {type(arg_expression)} with sub type: {_operand_type[arg_expression.type]} which I can handle", arg_debug)
        if arg_expression.type in [_ida_ua.o_mem, _ida_ua.o_near, _ida_ua.o_far]:
            return arg_expression.addr

        if arg_expression.type in [_ida_ua.o_imm]:
            return arg_expression.value64 or arg_expression.value

        log_print(f"arg_expression is of type {type(arg_expression)} with sub type: {_operand_type[arg_expression.type]} which can NOT be converted into an int", arg_type="ERROR")
        return None

    if isinstance(arg_expression, _ida_typeinf.funcarg_t) and arg_expression.argloc.is_reg1():
        log_print(f"arg_expression is a {type(arg_expression)} with argloc == ALOC_REG1 which I can handle", arg_debug)
        return _register(arg_expression.register,arg_debug=arg_debug)

    if isinstance(arg_expression, _ida_idp.reg_info_t):
        log_print(f"arg_expression is a {type(arg_expression)} which I can handle", arg_debug)
        arg_expression = _register(arg_expression, arg_debug=arg_debug)
        return arg_expression

    if isinstance(arg_expression, _ida_hexrays.carg_t):
        log_print(f"arg_expression is a {type(arg_expression)} which I can handle", arg_debug)
        return arg_expression.ea

    l_known_address_attributes: List[str] = [   'ea',       # _ida_ua.insn_t, _ida_hexrays.cinsn_t, _ida_hexrays.cexpr_t
                                                'start_ea', # _ida_hexrays.cfuncptr_t, _ida_segment.segment_t, _ida_range.range_t
                                                'entry_ea', # _ida_funcs.func_t
                                                'value',    # _ida_idaapi.PyIdc_cvt_int64__ (from appcalls in x64)
                                                'defea',    # _ida_hexrays.lvar_t
                                                'base',     # _ida_idd.modinfo_t
                                                'address'   # _ida_domain.strings.StringItem
                                            ]

    for l_attribute in l_known_address_attributes:
        if hasattr(arg_expression, l_attribute):
            log_print(f"arg_expression is of type: {type(arg_expression)} which has an attribute called '{l_attribute}' which is what I use", arg_debug)
            return getattr(arg_expression, l_attribute)

    if not isinstance(arg_expression, str):
        if arg_debug or not arg_supress_error:
            log_print(f"arg_expression cannot be parsed in any meaningful way. You gave me {type(arg_expression)}", arg_type="ERROR")
        return None

    if arg_expression.lower() in ('here', 'cursor'):
        return current_address()

    if arg_expression.lower() == 'peb':
        return win_PEB(arg_debug=arg_debug)

    arg_expression = arg_expression.replace("`", "") # Handle WinDBGs funky address string.

    if arg_expression.startswith(('-', '+')): # ida_kernwin.str2ea() behaves strange when the first character is either - or +
        l_sign: str = arg_expression[0]
        log_print(f"calling eval_expression() recursive with '{arg_expression[1:]}'", arg_debug)
        res = eval_expression(arg_expression[1:], arg_debug=arg_debug)
        if res is None:
            log_print("recursive eval_expression() returned None", arg_type="ERROR")
            return None
        return res if l_sign == '+' else -res

    if "+" in arg_expression: # E.g. "library.dll + 0x20"
        log_print("Found '+' so going to split and recursive call", arg_debug)
        l_parts = [x.strip() for x in arg_expression.split('+') if x]
        res = 0
        for l_part in l_parts:
            _t = eval_expression(l_part, arg_supress_error=arg_supress_error, arg_debug=arg_debug)
            if _t is None:
                return None
            res += _t
        return res

    if _re.fullmatch(r"^\d+$", arg_expression): # This regexp just means "all digits"
        arg_expression = arg_expression + "." # Transform a number in string format (e.g. "22") --> "22." (parse as 22 in decimal and NOT in hex) This is done so eval_expression("11") == eval_expression("0+11"). ida_kernwin.str2ea("11") != ida_kernwin.str2ea("0+11")

    # Refreshing the debugger memory is VERY expensive, so only do it if the name could not be resolved.
    # (If you have allocated memory or loaded a DLL via appcall, then IDA doesn't know about the new names until we refresh)
    for l_refresh_first in (False, True):
        if l_refresh_first:
            if not debugger_is_active():
                break
            log_print(f"'{arg_expression}' could not be resolved, refreshing the debugger memory and trying again", arg_debug)
            debugger_refresh_memory_WARNING_VERY_EXPENSIVE()

        res = _idaapi_str2ea(arg_expression) # Is it a simple expression? This can handle register name as string
        if res != _ida_idaapi.BADADDR:
            log_print(f"Simple expression eval: ida_kernwin.str2ea('{arg_expression}') resolved to 0x{res:x}", arg_debug)
            return res

        res = _idaapi_str2ea(f"kernel32_{arg_expression}") # Simplify kernel32 API lookups e.g. GetProcAddress --> kernel32_GetProcAddress
        log_print(f"KERNEL32 API lookup: ida_kernwin.str2ea('kernel32_{arg_expression}') resolved to 0x{res:x}", arg_debug)
        if res != _ida_idaapi.BADADDR:
            return res

    # Try to regexp out something out of the strange string the user gave me
    l_regexp_label_and_address = "[0-9a-f]{4,16}|(?:[a-z_?][a-z_?0-9@$]+)" # IDA does allow you to use ':' in the name BUT it will be printed as '_' so to avoid confusion, I do NOT allow ':' nor '.'
    matches = _re.findall(l_regexp_label_and_address, arg_expression, _re.IGNORECASE)

    log_print("Following matches will be tested as a destination:", arg_debug)
    log_print(str(matches), arg_debug)

    # The following code snippet can parse a longer line and try to take out tokens that can be a name or address.
    # E.g. "This line has some strange prefix .text:000000018001EB2A                 mov     rdi, rax" --> 0x000000018001EB2A
    for match in matches: # Return the first match that can be parsed as an int
        res = _idaapi_str2ea(match)
        log_print(f"_ida_kernwin.str2ea('{match}') resolved to 0x{res:x}", arg_debug)
        if res != _ida_idaapi.BADADDR:
            return res

        # Only treat the token as a raw hex number if it contains at least one digit, otherwise words like "decade", "face" or "beef" would become addresses
        l_hex_candidate = match[1:] if match[0:1].lower() == 'x' else match
        if _re.fullmatch(r"[0-9a-f]+", l_hex_candidate, _re.IGNORECASE) and _re.search(r"\d", l_hex_candidate):
            return int(l_hex_candidate, 16)

    if arg_debug or not arg_supress_error:
        log_print(f"arg_expression cannot be parsed in any meaningful way. You gave me '{arg_expression}'", arg_type="ERROR")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def address(arg_label_or_address: EvaluateType, arg_supress_error: bool = False, arg_debug: bool = False) -> int:
    ''' Takes a name/label or register name (if the debugger is active)
    or address (int) and try to resolve it into an address (int) in a smart way.
    You can use the syntax +<num bytes> and -<num bytes> to jump down or up from the current_address()

    @return Returns a valid address (int) on success and ida_idaapi.BADADDR on fail

    Replacement for ida_name.get_name_ea()
    '''
    # _g_logger.debug("Called from", stacklevel=4) # Prints the caller of this function

    # Resolve cursor relative jmps such as "+0x10" meaning current_address() + 0x10
    res: Optional[int]
    if isinstance(arg_label_or_address, int):
        res = arg_label_or_address
    elif isinstance(arg_label_or_address, str) and arg_label_or_address.startswith(("+", "-")):
        l_offset: Optional[int] = eval_expression(arg_label_or_address[1:], arg_supress_error=arg_supress_error, arg_debug=arg_debug)
        if l_offset is None:
            return _ida_idaapi.BADADDR
        res = current_address() + l_offset if arg_label_or_address.startswith("+") else current_address() - l_offset
    else:
        res = eval_expression(arg_label_or_address, arg_supress_error=arg_supress_error, arg_debug=arg_debug)

    if res is None or not (0 <= res < _ida_idaapi.BADADDR) or not _ida_bytes.is_mapped(res): # is_mapped() raises on negative/too large ints
        return _ida_idaapi.BADADDR

    log_print(f"arg_label_or_address resolved to 0x{res:x}", arg_debug) # WARNING! Do NOT evaluate the arg_label_or_address variable in the string, this cause circular references
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def relative_virtual_address(arg_ea: EvaluateType, arg_from_DLL_base: bool = False, arg_debug: bool = False) -> Optional[int]:
    ''' Returns the offset from imagebase to the given address a.k.a RVA '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_from_DLL_base:
        l_module = module(l_addr, arg_debug=arg_debug)
        if l_module is None:
            log_print(f"Could not find any module at {_hex_str_if_int(arg_ea)}", arg_type="ERROR")
            return None
        return l_addr - l_module.base

    return l_addr - input_file.imagebase

rva = relative_virtual_address

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def virtual_address_to_module_and_offset(arg_ea: EvaluateType, arg_debug: bool = False) -> str:
    ''' Returns a string in the form: "module.dll + 0x1000" '''
    l_module_str: str = ""
    l_is_debugging: bool = debugger_is_active()
    if l_is_debugging:
        l_module = module(arg_ea, arg_debug=arg_debug)
        if l_module is None:
            return "<<< error: module() returned None >>>"
        l_module_str = l_module.name
    else:
        l_module_str = input_file.filename

    # Without a debugger there are no loaded modules, then the offset is from the imagebase of the input file
    l_rva = relative_virtual_address(arg_ea, arg_from_DLL_base=l_is_debugging, arg_debug=arg_debug)
    if l_rva is None:
        return f"<<< error: relative_virtual_address({_hex_str_if_int(arg_ea)}) returned None >>>"
    return f"{_os.path.basename(l_module_str)} + 0x{l_rva:x}"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def fileoffset_to_virtual_address(arg_file_offset: int) -> int:
    ''' Take in a file offset and return the Virtual Address that matches to

    @return ida_idaapi.BADADDR on fail, otherwise the virtual address
    '''
    return _ida_loader.get_fileregion_ea(arg_file_offset)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def virtual_address_to_fileoffset(arg_ea: EvaluateType) -> int:
    ''' Take in a virtual address and return the file offset

    @return -1 on fail, otherwise the file offset
    '''
    l_addr: int = address(arg_ea)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return -1
    return _ida_loader.get_fileregion_offset(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function(arg_ea: EvaluateType,
             arg_create_function: bool = False,
             arg_debug: bool = False) -> Optional[_ida_funcs.func_t]:
    ''' Get a function object (ida_funcs.func_t) at given address.
    OBS! The IDB is only changed (code + function created) if arg_create_function=True
    Exception: unknown bytes in memory that the debugger added (e.g. a DLL loaded in the debugged process) are always turned into code + function,
    those segments are temporary and not saved in the IDB. This way you can call e.g. decompile("kernelbase_LoadLibraryA") during debugging.

    Replacement for ida_funcs.get_func() and ida_funcs.add_func() '''

    if isinstance(arg_ea, _ida_funcs.func_t):
        log_print("arg_ea is already of type _ida_funcs.func_t.", arg_debug, arg_type="WARNING")
        return arg_ea

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if not arg_create_function and is_unknown(l_addr, arg_debug=arg_debug):
        l_segment: Optional[_ida_segment.segment_t] = _ida_segment.getseg(l_addr)
        if l_segment is not None and (l_segment.flags & _ida_segment.SFL_DEBUG):
            log_print(f"0x{l_addr:x} is unknown bytes in a debugger segment, creating code + function there", arg_debug)
            arg_create_function = True

    if arg_create_function:
        if not is_code(l_addr, arg_debug=arg_debug):
            make_code(l_addr, arg_debug=arg_debug)
        _ida_funcs.add_func(l_addr)
        _ida_auto.auto_wait()

    if not is_code(l_addr, arg_debug=arg_debug):
        log_print(f"The address: 0x{l_addr:x} is not marked as code. You can force this by adding arg_create_function=True in the arguments", arg_type="ERROR")
        return None

    res: Optional[_ida_funcs.func_t] = _ida_funcs.get_func(l_addr)
    if not res:
        log_print(f"_ida_funcs.get_func(0x{l_addr:x}) returned None.", arg_debug, arg_type="ERROR")
        return None

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_is_lumina_name(arg_function: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Did the name (and type) of the function come from a Lumina server? (ida_funcs.FUNC_LUMINA)

    @return True/False, None if there is no function at arg_function
    '''
    l_func: Optional[_ida_funcs.func_t] = function(arg_function, arg_debug=arg_debug)
    if l_func is None:
        log_print(f"Could not locate any function at {_hex_str_if_int(arg_function)}", arg_type="ERROR")
        return None
    return _bool(l_func.flags & _ida_funcs.FUNC_LUMINA)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_set_config(arg_key: str, arg_value: BoolishType) -> bool:
    ''' In hexrays.cfg, there are many settings that one can set. Use this function to change them '''
    arg_key = arg_key.upper()

    if arg_key in ("PSEUDOCODE_SYNCED", "PSEUDOCODE_SYNC_XPOS", "DISPLAY_WAIT_BOX", "COLLAPSE_LVARS", "GENERATE_EA_LABELS", "AUTO_UNHIDE", "GENERATE_EMPTY_LINES"):
        arg_value = "YES" if _bool(arg_value) else "NO"
    return _bool(_ida_hexrays.change_hexrays_config(f"{arg_key} = {arg_value}"))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_clear_cached_cfuncs() -> None:
    ''' Flush all cached decompilation results '''
    _ida_hexrays.clear_cached_cfuncs()
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompile(arg_ea: EvaluateType,
              arg_hf: Optional[_ida_hexrays.hexrays_failure_t] = None,
              arg_flags: int = _ida_hexrays.DECOMP_GXREFS_DEFLT,
              arg_create_function: bool = False,
              arg_force_fresh_decompilation: bool = False,
              arg_debug: bool = False
              ) -> Optional[_ida_hexrays.cfuncptr_t]:
    ''' The problem with the normal ida_hexrays.decompile() is that it's not done with the decompilation when the the function returns.
    You can see the difference if you run: cfunc = ida_hexrays.decompile(<function that has not been decompiled before>);print(f"len of treeitems: {len(cfunc.treeitems)}")

    @param arg_flags Default is ida_hexrays.DECOMP_GXREFS_DEFLT. Read more at [the official docs](https://python.docs.hex-rays.com/ida_hexrays/index.html#ida_hexrays.decompile)
    @param arg_force_fresh_decompilation Default False --> use the decompiler cache (fast). Set to True to throw away the cached result and decompile again (slow)

    Replacement for ida_hexrays.decompile()

    If you want to decompile many functions and save the result into a file, then use the function decompile_many()
    '''
    if not _ida_hexrays.init_hexrays_plugin():
        l_arch = f"{input_file.format}, {input_file.bits} bits, {input_file.endian} endian"
        log_print(f"The decompiler for this architecture ({l_arch}) is not loaded.", arg_debug, arg_type="ERROR")
        return None # Since the user will get many warning about it not being loaded when starting IDA pro, I suppress the log message unless the user explicitly asks for it

    _ida_auto.auto_wait() # We always want to have the auto analysis done before we start decompiling. This is mostly important when we call this function in batch mode

    l_func: Optional[_ida_funcs.func_t] = function(arg_ea, arg_create_function=arg_create_function, arg_debug=arg_debug)
    if l_func is None:
        log_print(f"Could not create a function at {_hex_str_if_int(arg_ea)}", arg_debug, arg_type="ERROR")
        return None
    l_function_address: int = address(l_func, arg_debug=arg_debug)

    if arg_force_fresh_decompilation:
        log_print(f"arg_force_fresh_decompilation set so we call ida_hexrays.mark_cfunc_dirty(0x{l_function_address:x})", arg_debug)
        l_was_cached = _ida_hexrays.mark_cfunc_dirty(l_function_address) # TODO: This is flaky, do I need to bring the sledgehammer _ida_hexrays.clear_cached_cfuncs() ?
        log_print(f"Function was cached: {l_was_cached}", arg_debug)

    try:
        l_cfunc = _ida_hexrays.decompile(ea=l_function_address, hf=arg_hf, flags=arg_flags) # This will _NOT_ populate the l_cfunc.treeitems
        _ = l_cfunc.get_pseudocode()                                  # Forces the l_cfunc.treeitems to be populated
        return l_cfunc
    except Exception as exc:
        log_print(f"0x{l_function_address:x} failed to decompile", arg_debug, arg_type="ERROR")
        log_print(str(exc), arg_debug, arg_type="ERROR")
        return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompile_many(arg_outfile: str = "",
                   arg_functions: Optional[List[EvaluateType]] = None,
                   arg_allow_overwrite_c_file: bool = True,
                   arg_allow_user_to_stop: bool = True,
                   arg_use_lumina: bool = False,
                   arg_debug: bool = False) -> bool:
    '''Decompile many (all) functions to a file on disk
       Replacement for ida_hexrays.decompile_many()

       @param arg_outfile Where to save the decompiled file. If this is not set, then create the C file in the same directory as the IDB
       @param arg_functions List of functions that should be decompiled, if this is empty then all functions that are not library functions are decompiled
       @param arg_allow_overwrite_c_file Default True. Create a new file or overwrite existing file, if this is False then the fail if the file already exists
    '''

    # TODO: This function does not work very well, it's slow and the output file is very hard to read. Maybe I should emulate the function with my own loop?

    _ida_auto.auto_wait() # We always want to have the auto analysis done before we start decompiling. This is important when we call this function in batch mode

    if not _ida_hexrays.init_hexrays_plugin():
        log_print(f"The decompiler for this architecture ({input_file.processor}) is not loaded.", arg_type="ERROR")
        return False

    if not arg_outfile:
        arg_outfile = input_file.idb_path + '.c'

    l_functions = [address(func, arg_debug=arg_debug) for func in arg_functions] if arg_functions else functions(arg_allow_library_functions=False, arg_debug=arg_debug)
    l_functions = [l_function for l_function in l_functions if l_function != _ida_idaapi.BADADDR]
    if not l_functions:
        log_print("No functions to decompile", arg_type="ERROR")
        return False
    log_print(f"Decompiling {len(l_functions)} functions", arg_type="INFO")

    l_flags: int = 0
    l_flags |= _ida_hexrays.VDRUN_NEWFILE if arg_allow_overwrite_c_file else _ida_hexrays.VDRUN_ONLYNEW
    if arg_allow_user_to_stop:
        l_flags |= _ida_hexrays.VDRUN_MAYSTOP
    if arg_use_lumina:
        l_flags |= _ida_hexrays.VDRUN_LUMINA

    if arg_debug:
        l_flags |= _ida_hexrays.VDRUN_STATS # Print statistics into vd_stats.txt
        l_flags |= _ida_hexrays.VDRUN_PERF # Print performance stats to ida.log

    # Should I collapse the lvars when the decompile_many() is done?
    import random
    l_num_random_funcs = 20
    l_randomly_picked_functions: List[int] = random.sample(l_functions, min(l_num_random_funcs, len(l_functions)))
    l_num_collapsed = 0
    for l_function in l_randomly_picked_functions:
        log_print(f"Checking function: {_hex_str_if_int(l_function)} if it got collapsed local variables", arg_debug)
        if "[COLLAPSED LOCAL DECLARATIONS." in decompiler_pseudocode(l_function, arg_force_fresh_decompilation=True, arg_debug=arg_debug):
            log_print("It does!", arg_debug)
            l_num_collapsed += 1

    _ = decompiler_set_config("COLLAPSE_LVARS", "NO") # If this is set to YES (which I usually have when I do manually work) the decompiled C file will have them collapsed also
    # Unfortunately, the "COLLAPSE_LVARS = NO" force us to recompile ALL functions that are gonna be decompiled... YIKES!
    try:
        log_print(f"starting decompile_many() --> {arg_outfile}", arg_type="INFO")
        decompiler_clear_cached_cfuncs()
        l_function_vector = (_ida_pro.uint64vec_t if hasattr(_ida_pro, "uint64vec_t") else _ida_pro.eavec_t)() # decompile_many() takes a uint64vec_t in IDA 9.x, older IDA used eavec_t
        for l_function in l_functions:
            l_function_vector.push_back(l_function)
        res = _bool(_ida_hexrays.decompile_many(arg_outfile, l_function_vector, l_flags))
        log_print(f"done with decompile_many() --> {arg_outfile}", arg_type="INFO")
    finally: # Always restore the users setting, even if decompile_many() raised
        if (l_num_collapsed / len(l_randomly_picked_functions)) >= 0.25 :
            log_print(f"{l_num_collapsed} / {len(l_randomly_picked_functions)} randomly picked functions have collapsed local variables so I'm going to collapse them again", arg_type="INFO")
            _ = decompiler_set_config("COLLAPSE_LVARS", "YES")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_pseudocode(arg_ea: EvaluateType,
               arg_force_fresh_decompilation: bool = False,
               arg_debug: bool = False) -> str:
    ''' Get the pseudo code for a function. To work with the object (ida_hexrays.cfunc_t) use decompile() '''

    l_cfunc = decompile(arg_ea, arg_force_fresh_decompilation=arg_force_fresh_decompilation, arg_debug=arg_debug)
    if l_cfunc is None:
        log_print(f"decompile({_hex_str_if_int(arg_ea)}) failed", arg_type="ERROR")
        return f"<<< Could NOT decompile function at {_hex_str_if_int(arg_ea)} >>>"
    return str(l_cfunc.get_pseudocode())

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_comments(arg_functions: Optional[Union[List[EvaluateType], EvaluateType]] = None,
                        arg_regexp: str = "",
                        arg_allow_library_functions: bool = True,
                        arg_debug: bool = False) -> Optional[Dict[int, str]]:
    ''' Returns all user set comments from decompiler view
    @param arg_regexp Filter to only include comments that match this regexp.
    If arg_regexp == "" then include all comments

    @return Dict[ea: int, comment: str]
    '''
    l_functions: List[int]
    if arg_functions is None:
        l_functions = functions(arg_allow_library_functions=arg_allow_library_functions, arg_debug=arg_debug)
    elif not isinstance(arg_functions, List):
        l_functions = [address(arg_functions, arg_debug=arg_debug)]
    else:
        l_functions = [address(l_func, arg_debug=arg_debug) for l_func in arg_functions]

    res: Dict[int, str] = {}
    for l_function in l_functions:
        l_comments = _ida_hexrays.restore_user_cmts(l_function)
        if l_comments is None:
            continue

        for l_tree_location, l_comment in l_comments.iteritems():
            if not arg_regexp or _re.fullmatch(arg_regexp, str(l_comment)):
                l_old_comment = res.get(l_tree_location.ea, "")
                l_old_comment += "; " if l_old_comment else ""
                res[l_tree_location.ea] = l_old_comment + str(l_comment) # Maybe interesting in the future: _int_to_str_dict_from_module("_ida_hexrays", "ITP_.*")[l_tree_location.itp]
        _ida_hexrays.user_cmts_free(l_comments)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_variable(arg_function: EvaluateType,
                        arg_variable_name: Union[str, _ida_hexrays.lvar_t],
                        arg_debug: bool = False
                        ) -> Optional[_ida_hexrays.lvar_t]:
    ''' Find the local variable (_ida_hexrays.lvar_t) given the function and the name seen in the pseudocode view '''
    if isinstance(arg_variable_name, _ida_hexrays.lvar_t):
        return arg_variable_name

    l_cfunc = decompile(arg_function, arg_debug=arg_debug)
    if l_cfunc is None:
        log_print("l_cfunc is None", arg_type="ERROR")
        return None

    for l_variable in l_cfunc.lvars:
        if l_variable.name == arg_variable_name:
            # The lvar_t is owned by the cfunc, if the cfunc is freed then the lvar_t points to freed memory (and IDA crashes when it's used).
            # Keep the cfunc alive until the next call to this function.
            global _g_keep_alive_cfunc_for_decompiler_variable
            _g_keep_alive_cfunc_for_decompiler_variable = l_cfunc
            return l_variable
    log_print(f"Could not find any variable with the name '{arg_variable_name}'", arg_type="ERROR")
    return None

_g_keep_alive_cfunc_for_decompiler_variable: Optional[_ida_hexrays.cfuncptr_t] = None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _decompiler_variable_locator(arg_function_address: int, arg_variable: Union[str, _ida_hexrays.lvar_t], arg_debug: bool = False) -> Optional[_ida_hexrays.lvar_locator_t]:
    ''' Internal function. Returns a COPY of the variables locator so it does not depend on the lifetime of the cfunc that owns the lvar_t '''
    l_lvar = decompiler_variable(arg_function_address, arg_variable, arg_debug=arg_debug)
    if l_lvar is None:
        return None
    return _ida_hexrays.lvar_locator_t(l_lvar.location, l_lvar.defea)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_variable_set_name(arg_function: EvaluateType,
                                 arg_variable: Union[str, _ida_hexrays.lvar_t],
                                 arg_new_variable_name: str,
                                 arg_debug: bool = False) -> Optional[bool]:
    ''' Rename a pseudocode local variable (ida_hexrays.lvar_t) in the decompiler view given the function and the name as it seen in the pseudo code view '''

    l_function_temp = function(arg_function, arg_debug=arg_debug)
    if l_function_temp is None:
        log_print(f"Not a function at the given arg_function: {_hex_str_if_int(arg_function)}", arg_type="ERROR")
        return None

    l_function_address = l_function_temp.start_ea
    l_locator = _decompiler_variable_locator(l_function_address, arg_variable, arg_debug=arg_debug)
    if l_locator is None:
        log_print("Could not find the local variable", arg_type="ERROR")
        return None
    l_lvar_saved_info = _ida_hexrays.lvar_saved_info_t()
    l_lvar_saved_info.ll = l_locator # ll --> Local variable Locator
    l_lvar_saved_info.name = arg_new_variable_name
    return _ida_hexrays.modify_user_lvar_info(l_function_address, _ida_hexrays.MLI_NAME, l_lvar_saved_info)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_variable_set_type(arg_function: EvaluateType,
                                 arg_variable: Union[str, _ida_hexrays.lvar_t],
                                 arg_new_type: Union[str, _ida_typeinf.tinfo_t],
                                 arg_debug: bool = False) -> Optional[bool]:
    ''' Change type of a pseudocode local variable (lvar) in the decompiler view given the function and the name as it seen in the pseudo code view '''

    l_function_temp = function(arg_function, arg_debug=arg_debug)
    if l_function_temp is None:
        log_print(f"Not a function at the given arg_function: {_hex_str_if_int(arg_function)}", arg_type="ERROR")
        return None
    l_function_address: int = l_function_temp.start_ea

    l_lvar_saved_info = _ida_hexrays.lvar_saved_info_t()
    l_locator = _decompiler_variable_locator(l_function_address, arg_variable, arg_debug=arg_debug)
    if l_locator is None:
        log_print("Could not find the local variable", arg_type="ERROR")
        return None
    l_lvar_saved_info.ll = l_locator
    l_type = get_type(arg_new_type, arg_debug=arg_debug)
    if l_type is None:
        log_print("l_type is not usable", arg_type="ERROR")
        return None
    l_lvar_saved_info.type = l_type
    return _ida_hexrays.modify_user_lvar_info(l_function_address, _ida_hexrays.MLI_TYPE, l_lvar_saved_info)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def dump_to_disk(arg_ea_start: EvaluateType = 0,
                 arg_len: EvaluateType = 0,
                 arg_filename: Optional[str] = None,
                 arg_xor_key: Optional[BufferType] = None,
                 arg_debug: bool = False
                 ) -> Optional[str]:
    ''' Dump bytes from the IDB to a file on disk.
    The hotkey is in the global variable _G_HOTKEY_DUMP_TO_DISK and is default set to 'w'
    If arg_ea_start is given, then that range is dumped. If not (e.g. from the hotkey), then the selected bytes (or the item under the cursor) are dumped.

    @param arg_filename is this is set to the magic value "|clipboard|" then we will copy the string to the clipboard instead of writing it to disk

    @return The filename we wrote the bytes to
    '''

    if arg_ea_start and not arg_len:
        log_print("You need to give arg_ea_start and arg_len OR select the range of bytes you want to dump.", arg_type="ERROR")
        return None

    l_valid_selection: bool = False
    if arg_ea_start: # The caller told us what to dump, this always wins over whatever is selected in the GUI
        arg_ea_start = address(arg_ea_start, arg_debug=arg_debug)
        l_temp_len = eval_expression(arg_len, arg_debug=arg_debug)
        if l_temp_len is None:
            log_print("eval_expression(arg_len) failed", arg_type="ERROR")
            return None
        l_len: int = l_temp_len
    else: # No arguments --> use the selected bytes (or the item under the cursor)
        if not _G_QT_IS_AVAILABLE:
            log_print("There is no GUI to read a selection from (batch mode?). Give arg_ea_start and arg_len.", arg_type="ERROR")
            return None
        l_valid_selection, l_selection_start, l_selection_end = _idaapi_read_range_selection(arg_TWidget=None, arg_allow_one_line=True)
        if not l_valid_selection:
            log_print("You need to give arg_ea_start and arg_len OR select the range of bytes you want to dump.", arg_type="ERROR")
            return None
        arg_ea_start = min(l_selection_start, l_selection_end)
        l_len = max(l_selection_end, l_selection_start) - arg_ea_start
        log_print(f"sel_start: 0x{l_selection_start:x}, sel_end: 0x{l_selection_end:x}, l_len: 0x{l_len:x}", arg_debug)

    if arg_ea_start == _ida_idaapi.BADADDR or not l_len:
        log_print("You need to give arg_ea_start and arg_len OR select the range of bytes you want to dump.", arg_type="ERROR")
        return None

    l_temp_bytes: Optional[bytes] = read_bytes(arg_ea_start, l_len, arg_debug=arg_debug)
    if l_temp_bytes is None:
        log_print(f'read_bytes({_hex_str_if_int(arg_ea_start)}) failed', arg_type="ERROR")
        return None

    bytes_from_IDB: bytearray = bytearray(l_temp_bytes)
    if arg_xor_key is not None:
        arg_xor_key = hex_parse(arg_xor_key, arg_debug=arg_debug)
        if not arg_xor_key:
            log_print("Invalid arg_xor_key, could not find any way to parse it as a hex string.", arg_type="ERROR")
            return None
        for i in range(0, len(bytes_from_IDB)):
            bytes_from_IDB[i] ^= bytearray.fromhex(arg_xor_key[i % len(arg_xor_key)])[0]
    else:
        arg_xor_key = []
    if not arg_filename:
        arg_filename = f"{input_file.idb_path}.0x{arg_ea_start:x}_0x{l_len:x}"

        if arg_xor_key:
            arg_filename += f".xor_key_{''.join(arg_xor_key)}"

        arg_filename += ".dump"

    if arg_filename == "|clipboard|":
        l_temp = hex_parse(bytes_from_IDB, arg_debug=arg_debug)
        l_hex_text = " ".join(l_temp)
        log_print(f"Going to copy the following string into the clipboard: {l_hex_text}", arg_debug)
        clipboard_copy(l_hex_text, arg_debug=arg_debug)
    else:
        with open(arg_filename, "wb") as f:
            f.write(bytes_from_IDB)

    log_print(f"{'selected bytes' if l_valid_selection else 'function call'} dumped 0x{l_len:x} bytes from 0x{arg_ea_start:x} to '{arg_filename}' XORed with '{' '.join(arg_xor_key)}' ", arg_type="INFO")
    return arg_filename

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def bookmark(arg_ea: EvaluateType, arg_description: Optional[str] = None, arg_debug: bool = False) -> Optional[str]:
    ''' Get bookmark at given EA (Effective Address), returns an empty str "" if there is no bookmark on that EA
    IDA has started to call these "marked positions"
    [Read more on get_marked_pos](https://python.docs.hex-rays.com/ida_idc/index.html#ida_idc.get_marked_pos)
    [Read more on mark_position](https://python.docs.hex-rays.com/ida_idc/index.html#ida_idc.mark_position)
    [Read more on the IDC module](https://python.docs.hex-rays.com/idc/index.html)
    [Read more on IDC reference](https://docs.hex-rays.com/developer-guide/idc)

    You can delete a bookmark by setting arg_description = ""
    @param arg_ea The address you want the bookmark on
    @param arg_description if this is set, then we create a bookmark on that ea (overwriting whatever was there before), if this is the empty str, the the bookmark is deleted
    @return description: str
    '''

    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_description is not None:
        # Taken from <https://docs.hex-rays.com/developer-guide/idc/idc-api-reference/alphabetical-list-of-idc-functions/367>
        # ea      - address to mark
        # lnnum   - number of generated line for the 'ea'
        # x       - x coordinate of cursor
        # y       - y coordinate of cursor
        # slot    - slot number: 0..1023
        #           if the specified value is not within the range, IDA will ask the user to select slot.
        # comment - description of the mark.
        #           Should be not empty.
        # returns: none

        # Need to find first empty slot for our bookmark
        for bookmark_slot in range(0, 1024):
            l_ea = _ida_idc.get_marked_pos(bookmark_slot)
            if l_ea in (_ida_idaapi.BADADDR, l_addr):
                break

        if l_ea == _ida_idaapi.BADADDR and arg_description == "":
            log_print("We got a delete bookmark on an ea that does not have a bookmark, ignoring", arg_type="WARNING")
            return ""

        _ida_idc.mark_position(ea=l_addr, lnnum=0, x=0, y=0, slot=bookmark_slot, comment=arg_description)

    if arg_description == "": # This means to delete a bookmark
        return ""

    for bookmark_slot in range(0, 1024):
        l_ea = _ida_idc.get_marked_pos(bookmark_slot)
        if l_ea == l_addr:
            return _ida_idc.get_mark_comment(bookmark_slot)
        if l_ea == _ida_idaapi.BADADDR:
            log_print(f"ida_idc.get_marked_pos({bookmark_slot}) returned BADADDR", arg_type="ERROR")
            return ""

    return None # We should never get there

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def bookmarks(arg_debug: bool = False) -> Optional[List[Tuple[int, str]]]:
    ''' Get all bookmarks as a list of tuples. The tuple looks like: (ea: int, description: str)
    Read more: <https://hex-rays.com/blog/igors-tip-of-the-week-80-bookmarks>
    @return List[(ea: int, description: str)]
    '''
    res = []
    for bookmark_slot in range(0, 1024):
        l_ea = _ida_idc.get_marked_pos(bookmark_slot)
        if l_ea == _ida_idaapi.BADADDR:
            log_print(f"ida_idc.get_marked_pos({bookmark_slot}) returned BADADDR", arg_actually_print=arg_debug, arg_type="ERROR")
            break # IDA does compress the list so the first empty is the marker for "no more bookmarks"
        res.append((l_ea, _ida_idc.get_mark_comment(bookmark_slot)))

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _struct_comments(arg_debug: bool = False) -> str:
    ''' When setting a comment on a struct member, you can use the ///< instead of the normal // in the c-style edit window '''
    # TODO: Maybe have a better example? Like in export_h_file() ?
    return "When setting a comment on a struct member, you can use the ///< instead of the normal // in the c-style edit window"


# -------------------------------------------------------------------------------------------------------------------------------------------------------
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _ea_to_hexrays_insn(arg_ea: EvaluateType,
                        arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                        arg_force_fresh_decompilation: bool = False,
                        arg_debug: bool = False
                        ) -> Optional[_ida_hexrays.cinsn_t]:
    ''' Internal function. The decompiled AST is made up of ida_hexrays.cinsn_t, this function finds the correct ida_hexrays.cinsn_t given an EA (Effective Address) '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if not arg_cached_cfunc:
        arg_cached_cfunc = decompile(l_addr, arg_force_fresh_decompilation=arg_force_fresh_decompilation, arg_debug=arg_debug)
    if not arg_cached_cfunc:
        return None

    # OBS! I know there is a shorter and faster way with arg_cached_cfunc.eamap.get(ea, None) but I used the long code to have debug output during development
    ea: int
    vector_of_insn: List[_ida_hexrays.cinsn_t]
    for ea, vector_of_insn in arg_cached_cfunc.eamap.items(): # eamap maps ea_t --> vector<ida_hexrays.cinsn_t>.
        vector_idx = 0
        res: _ida_hexrays.cinsn_t = _ida_hexrays.cinsn_t()

        for insn in vector_of_insn: # This can be multiple insn but they can be wrong. How to find the correct one? This is most probably a bug in IDA cause I get vectors that look like <return -1, call function, return -1> where the call is the expected and the "return -1"s are wrong
            if arg_debug:
                if insn.is_epilog():
                    log_print(f"ea: {ea:x} is INS_EPILOG", arg_debug)
                    continue
                log_print(f"ea: {ea:x} --> insn.ea: {insn.ea:x} --> vector_idx: {vector_idx} --> {_ida_lines.tag_remove(insn.print1(None))}", arg_debug)
                vector_idx += 1
            if ea == l_addr:
                log_print(f"Match l_addr: 0x{l_addr:x} --> take the longest (most info) and return that. len(vector_of_insn): {len(vector_of_insn)}", arg_debug)
                if insn.is_epilog():
                    log_print(f"l_addr 0x{l_addr:x} is epilog", arg_debug)
                    continue
                res = insn if len(str(insn)) > len(str(res)) else res
                log_print(f"res: {res}", arg_debug)
                log_print(f"res.ea: {_hex_str_if_int(res.ea)}", arg_debug)

            if ea > l_addr:
                log_print(f"ea: 0x{ea:x} > l_addr: 0x{l_addr:x} means we are past our address we are looking for", arg_debug)
                return None
        if res.ea != _ida_idaapi.BADADDR:
            return res

    log_print("Reached a point where I return None", arg_debug, arg_type="WARNING")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_line(arg_ea: EvaluateType, arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None, arg_debug: bool = False) -> str:
    ''' Sometimes you want only 1 line from the decompilation. See example in my plugins show_global_xrefs_hx.py and xor_finder.py '''

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return f"<<< Failed to find '{_hex_str_if_int(arg_ea)}' >>>"

    if arg_cached_cfunc is None:
        arg_cached_cfunc = decompile(l_addr, arg_debug=arg_debug)
    if not arg_cached_cfunc:
        log_print(f"{_hex_str_if_int(l_addr)} could not be decompiled", arg_debug, arg_type="ERROR")
        return "<<< Could not decompile >>>"

    # The "correct" way to do it is as follows:
    # return _ida_lines.tag_remove(arg_cached_cfunc.body.find_parent_of(arg_cached_cfunc.body.find_closest_addr(l_addr)).print1(arg_cached_cfunc))
    # BUT it's wrong. If you put in the address of a part of the epilog, then find_closest_addr() will return the line closest above it.
    # You can also put in any other address that is not a valid part of a function. This will return the last line in the function above that is correct. Test by taking the "align 10h" between functions as input address

    l_insn: Optional[_ida_hexrays.cinsn_t] = _ea_to_hexrays_insn(l_addr, arg_cached_cfunc, arg_debug=arg_debug)
    if l_insn is None:
        return f"<<< _ea_to_hexrays_insn(0x{l_addr:x}) returned None >>>"
    if l_insn.is_epilog(): # This means that the address that is given doesn't have any pseudo code since it's something the compiler added for maintenance
        return f"<<< _ea_to_hexrays_insn(0x{l_addr:x}).is_epilog() == True >>>"

    res = _ida_lines.tag_remove(l_insn.print1(arg_cached_cfunc))
    res = res.replace(';', '; ')
    res = _whitespace_zapper(res).strip()
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_prototype(arg_function_name_or_ea: EvaluateType,
                       arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                       arg_allow_comments: bool = True,
                       arg_force_fresh_decompilation: bool = False,
                       arg_debug: bool = False
                       ) -> str:
    ''' Returns the function prototype including the function name and the comments as 1 line.
    You can use str(get_type(ea)) but that command will NOT give the comments.
    '''

    if arg_force_fresh_decompilation or arg_cached_cfunc is None:
        # log_print(f"Calling decompile({arg_function_name_or_ea})")
        arg_cached_cfunc = decompile(arg_function_name_or_ea, arg_force_fresh_decompilation=arg_force_fresh_decompilation, arg_debug=arg_debug)
    if not arg_cached_cfunc:
        log_print(f"Since we failed to decompile {_hex_str_if_int(arg_function_name_or_ea)}, we are calling str(get_type({_hex_str_if_int(arg_function_name_or_ea)}, arg_debug={arg_debug}))", arg_type="INFO")
        l_temp = get_type(arg_function_name_or_ea, arg_debug=arg_debug)
        if l_temp is None:
            log_print(f"get_type({_hex_str_if_int(arg_function_name_or_ea)}) failed to get any type", arg_type="ERROR")
            return "<<< Error: No type found >>>"
        res = str(l_temp)
        log_print(f"Returning '{res}'", arg_debug)
        return res

    l_function_prototype: str = _ida_lines.tag_remove(arg_cached_cfunc.print_dcl()) + ';'
    if arg_allow_comments:
        l_comment: str = _comment_get(arg_cached_cfunc.entry_ea, arg_debug=arg_debug)
        if l_comment:
            l_function_prototype += " // " + l_comment.replace('\n', ', ')

    return l_function_prototype

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_get_func_name(arg_ea: int) -> str:
    ''' Wrapper for ida_funcs.get_func_name()
    IDA Bug: The docstring say "@return: length of the function name" which is wrong
    '''
    return _ida_funcs.get_func_name(arg_ea) or  ""

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def name(arg_ea: EvaluateType,
         arg_set_name: Optional[str] = None,
         arg_flags: int = _ida_name.SN_NOWARN | _ida_name.SN_NOCHECK,
         arg_force: bool = False,
         arg_demangle_name: bool = False,
         arg_debug: bool = False
         ) -> Optional[str]:
    ''' Gets or sets the name at the given EA (Effective Address)

    To remove a name (and give the function a name that IDA picks, use arg_set_name = ""
    @param arg_force: If the name exists, then append functionname_X incremental. Same as "Rename global item" in the decompiler.

    @return The name as str

    Replacement for ida_name.get_name_ea() and ida_name.set_name()

    '''
    # TODO: This will not work with setting name on lvar_t, modinfo_t, ida_ua_op_t, segment_t
    if isinstance(arg_ea, _ida_hexrays.lvar_t):
        res = arg_ea.name
        log_print(f"arg_ea is ida_hexrays.lvar_t, so instead of looking up the address, I use the member 'name' == {res}", arg_debug)
        return res

    if isinstance(arg_ea, _ida_idd.modinfo_t):
        res = arg_ea.name
        log_print(f"arg_ea is ida_idd.modinfo_t, so instead of looking up the address, I use the member 'name' == {res}", arg_debug)
        return res

    if isinstance(arg_ea, _ida_ua.op_t) and arg_ea.type == _ida_ua.o_reg:
        res = arg_ea.register.name
        log_print(f"arg_ea is ida_ua.op_t, so instead of looking up the address, use the register name == {res}", arg_debug)
        return res

    if isinstance(arg_ea, _ida_segment.segment_t):
        res = _ida_segment.get_segm_name(arg_ea)
        log_print(f"arg_ea is ida_segment.segment_t, so instead of looking up the address, use the segment name: {res}", arg_debug)
        return res

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_name is not None:
        res = _ida_name.set_name(l_addr, arg_set_name, arg_flags)
        if not res and arg_force:
            res = _ida_name.force_name(l_addr, arg_set_name) # If the name exists, then append functionname_X incremental
            log_print(f"ida_name.force_name() returned {res}", arg_debug)

    l_address_formatstring = "016X" if input_file.bits == 64 else "08X"

    l_function_name: str = _idaapi_get_func_name(l_addr)
    if l_function_name:
        log_print(f"_get_func_name(0x{l_addr:x}) returned {l_function_name}", arg_debug)
        l_func_start: int = _ida_funcs.get_func(l_addr).start_ea # Faster and safer than resolving the name again
        l_diff = l_addr - l_func_start
        l_name: str = l_function_name
        if arg_demangle_name:
            # demangle_name() returns None for names that are not mangled (e.g. "main" or "sub_401000"), then keep the name as it is
            l_name = _idaapi_demangle_name(l_function_name, 0, _ida_name.DQT_FULL) or l_function_name
        if not l_diff:
            return l_name
        return f"{l_name} + 0x{l_diff:x}"

    l_name = _ida_name.get_long_name(l_addr) if arg_demangle_name else _ida_name.get_name(l_addr)
    if l_name:
        return l_name

    l_item_head = _ida_bytes.get_item_head(l_addr)
    if l_item_head != l_addr:
        res = f"{name(l_item_head, arg_debug=arg_debug)} + 0x{l_addr - l_item_head:x}"
        return res

    return f"{l_addr:{l_address_formatstring}}"

label = name # Other programs use the term label

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_demangle_name(arg_name: str, arg_disable_mask: int, arg_demreq=_ida_name.DQT_FULL) -> str:
    ''' Wrapper around ida_name.demangle_name()
    IDA bug: Docstring say "demangle_name(name, disable_mask, demreq=DQT_FULL) -> int32" which is wrong
    In idc.py, we can read "If the input name cannot be demangled, returns None"

    @param arg_name: The string to demangle
    @param arg_disable_mask: No idea what this is
    @param arg_demreq: How to show the name, see ida_name.DQT_* for more info

    @return Returns the demangled name, empty str "" on fail
    '''
    return _ida_name.demangle_name(arg_name, arg_disable_mask, arg_demreq) or ""

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def demangle_string(arg_mangled_name: str,
                  arg_disable_mask: int =  _ida_name.MNG_IGN_JMP | _ida_name.MNG_IGN_ANYWAY, # MNG_IGN_JMP accepts the '.' prefix ("._ZdaPvm"), MNG_IGN_ANYWAY accepts the '_0' suffix ("_ZdaPvm_0")
                  arg_demangle_type: int =_ida_name.DQT_FULL,
                  arg_allow_brute_force: bool = False,
                  arg_debug: bool = False
                  ) -> str:
    ''' Demangles a string. Can try to brute force demangle some names that IDA usually doesn't like.
    @param arg_mangled_name: str, the string to demangle
    @param arg_disable_mask: int, ida_name.MNG_* flags to ida_name.demangle_name(). Most of them hide parts of the result (ex: MNG_NORETTYPE), the default flags make the demangler accept the '.' prefix and the '_0' suffix. Use ida_ida.inf_get_long_demnames() to get the same result as IDA shows
    @param arg_demangle_type: int, [How to demangle the name](https://cpp.docs.hex-rays.com/name_8hpp.html#afb78c30f35664f57311d5baa00360434)
    @param arg_allow_brute_force: If the name cannot be mangled as it is, I can try to "fuzzy" demangle it. Use on your own risk.

    @return Returns the demangled name, empty str "" on fail
    '''
    res = _idaapi_demangle_name(arg_mangled_name, arg_disable_mask, arg_demangle_type)
    if not res:
        if arg_allow_brute_force:
            for i in range(1, len(arg_mangled_name)):
                res = _idaapi_demangle_name(arg_mangled_name[i:], arg_disable_mask, arg_demangle_type)
                log_print(f"ida_name.demangle_name('{arg_mangled_name[i:]}', {arg_disable_mask}) resulted in {res} on try number {i}", arg_debug)
                if res != "":
                    return res
        log_print(f"Could not demangle the name '{arg_mangled_name}' in any meaningful way", arg_type="WARNING")
        return ""

    log_print(f"ida_name.demangle_name('{arg_mangled_name}', {arg_disable_mask}) resulted in {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def comment(arg_ea: EvaluateType,
            arg_set_comment: Optional[str] = None,
            arg_add_source: bool = True,
            arg_oneliner: bool = False,
            arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
            arg_type_of_comment: Optional[int] = None,
            arg_debug: bool = False
            ) -> Optional[str]:
    '''
    This is a unified entry to comments. There are 2 functions named _comment_get() and _comment_set() that can be used but this function should be the only one you need.

    Comments can be at many different levels at the same address.
    This function returns the user comments as one string reading in the order:
    1. decompiler
    2. disassembly
    3. disassembly repeatable
    4. function comment
    5. function repeatable comment

    arg_type_of_comment is one of ida_hexrays.ITP_* where _ida_hexrays.ITP_BLOCK1 is the line above. Default is None --> test all and take the first one working
    '''

    if arg_set_comment is not None:
        l_set_comment_res = _comment_set(arg_ea=arg_ea, arg_comment=arg_set_comment, arg_cached_cfunc=arg_cached_cfunc, arg_type_of_comment=arg_type_of_comment, arg_debug=arg_debug)
        if not l_set_comment_res:
            log_print(f"_comment_set({_hex_str_if_int(arg_ea)}, {arg_set_comment}) returned False", arg_type="ERROR")
            return None

    return _comment_get(arg_ea=arg_ea, arg_cached_cfunc=arg_cached_cfunc, arg_add_source=arg_add_source, arg_oneliner=arg_oneliner, arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_get_decompiler(arg_ea: int, arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None, arg_debug: bool = False) -> str:
    ''' Internal function. Only the decompiler comment(s) on the given address, joined with "; " '''
    if arg_ea == _ida_idaapi.BADADDR:
        return ""
    if not arg_cached_cfunc and is_code(arg_ea):
        arg_cached_cfunc = decompile(arg_ea, arg_debug=arg_debug)
    if not arg_cached_cfunc:
        return ""

    l_parts: List[str] = []
    insn: Optional[_ida_hexrays.cinsn_t] = _ea_to_hexrays_insn(arg_ea, arg_cached_cfunc, arg_debug=arg_debug)
    if insn and not insn.is_epilog():
        l_comments: Optional[_ida_hexrays.user_cmts_t] = _ida_hexrays.restore_user_cmts(arg_cached_cfunc.entry_ea)
        if l_comments is not None:
            l_tree_location: _ida_hexrays.treeloc_t
            for l_tree_location, l_comment in l_comments.items(): # tree_location == treeloc_t
                log_print(f"tree_location.ea: 0x{l_tree_location.ea:x} --> {str(l_comment)}", arg_debug)
                if l_tree_location.ea == insn.ea:
                    l_parts.append(str(l_comment).strip()) # There can be many comment on the same address, like after the ; and on the line before
            _ida_hexrays.user_cmts_free(l_comments)
    return "; ".join(l_parts)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_get(arg_ea: EvaluateType,
                arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                arg_add_source: bool = True,
                arg_oneliner: bool = False,
                arg_debug: bool = False) -> str:
    ''' Internal function. Use comment() instead '''

    l_addr = address(arg_ea, arg_debug=arg_debug)
    res = _comment_get_decompiler(l_addr, arg_cached_cfunc=arg_cached_cfunc, arg_debug=arg_debug)
    if res:
        res += "; "
        if arg_add_source:
            res += " [decompiler]; "

    # No decompiler comments, let's try the old ones
    l_is_repeatable = False
    l_disassembly_comment = _ida_bytes.get_cmt(l_addr, l_is_repeatable) # Get the comment on that line
    if l_disassembly_comment:
        res += l_disassembly_comment
        if arg_add_source:
            res += " [disassembly]; "

    l_is_repeatable = True
    _disassembly_comment_repeatable = _ida_bytes.get_cmt(l_addr, l_is_repeatable)
    if _disassembly_comment_repeatable:
        res += _disassembly_comment_repeatable
        if arg_add_source:
            res += " [disassembly repeatable]; "

    l_is_repeatable = False
    _function_comment = _ida_funcs.get_func_cmt(_ida_funcs.get_func(l_addr), l_is_repeatable)
    if _function_comment:
        res += _function_comment
        if arg_add_source:
            res += " [function]; "

    l_is_repeatable = True
    _function_comment_repeatable = _ida_funcs.get_func_cmt(_ida_funcs.get_func(l_addr), l_is_repeatable)
    if _function_comment_repeatable:
        res += _function_comment_repeatable
        if arg_add_source:
            res += " [function repeatable]; "

    if arg_oneliner:
        res = res.replace('\n', '; ')

    return res.strip()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_set_decompiler(arg_ea: EvaluateType,
                arg_comment: str,
                arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                arg_type_of_comment: Optional[int] = None,
                arg_debug: bool = False
                ) -> bool:
    ''' Internal function. Use comment() instead
    This function sets the decompiler comment
    @param arg_type_of_comment is one of ida_hexrays.ITP_* where ida_hexrays.ITP_BLOCK1 is the line above (same as pressing INSERT)

    @return True if everything is OK, False otherwise
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if not arg_cached_cfunc and is_code(l_addr, arg_debug=arg_debug):
        arg_cached_cfunc = decompile(l_addr, arg_debug=arg_debug)
    if arg_cached_cfunc is None:
        return False

    l_c_instruction = _ea_to_hexrays_insn(l_addr, arg_cached_cfunc=arg_cached_cfunc, arg_debug=arg_debug)
    if l_c_instruction is None:
        log_print(f"_ea_to_hexrays_insn(0x{l_addr:x}) returned None", arg_type="ERROR")
        return False

    if l_c_instruction.is_epilog():
        log_print("l_c_instruction.is_epilog() == True", arg_type="ERROR")
        return False

    l_tree_location = _ida_hexrays.treeloc_t()
    l_tree_location.ea = l_c_instruction.ea

    l_dict_of_types_of_comments: Dict[int, str] = {
        _ida_hexrays.ITP_SEMI :   "SEMI",   # ';'
        _ida_hexrays.ITP_CURLY1 : "CURLY1", # '{'
        _ida_hexrays.ITP_CURLY2 : "CURLY2", # '}'
        _ida_hexrays.ITP_BRACE1 : "BRACE1", # '(' Same as ida_hexrays.ITP_INNER_LAST
        _ida_hexrays.ITP_BRACE2 : "BRACE2", # ')'
        _ida_hexrays.ITP_COLON :  "COLON",  # ':'
        _ida_hexrays.ITP_ARG1 :   "ARG1",
        _ida_hexrays.ITP_ARG64 :  "ARG64",
        _ida_hexrays.ITP_CASE :   "CASE",
        _ida_hexrays.ITP_DO :     "DO",
        _ida_hexrays.ITP_ELSE :   "ELSE",
        _ida_hexrays.ITP_ASM :    "ASM",
        _ida_hexrays.ITP_EMPTY :  "EMPTY",
        _ida_hexrays.ITP_SIGN :   "SIGN",
        _ida_hexrays.ITP_BLOCK1 : "BLOCK1", # This means line above ( ITP_BLOCK1 == 74 )
        _ida_hexrays.ITP_BLOCK2 : "BLOCK2"  # No idea what this is  ( ITP_BLOCK2 == 75 )
        # _ida_hexrays.ITP_INNER_LAST : "INNER_LAST", # _ida_hexrays.ITP_INNER_LAST == _ida_hexrays.ITP_BRACE1 == 65, bug?
    }

    if ida_version() >= 900:
        l_dict_of_types_of_comments[_ida_hexrays.ITP_TRY] = "TRY" # New in IDA 9.0

    if arg_type_of_comment:
        if arg_type_of_comment not in l_dict_of_types_of_comments:
            log_print(f"arg_type_of_comment: {arg_type_of_comment} is not valid. It should be one of ida_hexrays.ITP_*", arg_type="ERROR")
            return False

        l_dict_of_types_of_comments = {l_key: l_value for l_key, l_value in l_dict_of_types_of_comments.items() if arg_type_of_comment == l_key}

    # The following for loop is REALLY ugly but I can't find any better way to do this :-(
    l_decompiler_comment_set_ok = False
    for l_itp in l_dict_of_types_of_comments:
        log_print(f"testing: arg_cached_cfunc.set_user_cmt(_addr = 0x{l_tree_location.ea:x}, itp = {l_dict_of_types_of_comments[l_itp]}, comment = '{arg_comment}')", arg_debug)
        l_tree_location.itp = l_itp
        arg_cached_cfunc.set_user_cmt(l_tree_location, arg_comment) # type: ignore[union-attr]
        arg_cached_cfunc.save_user_cmts() # type: ignore[union-attr]
        arg_cached_cfunc = decompile(l_addr, arg_force_fresh_decompilation=True) # Forced refresh
        if arg_cached_cfunc is None:
            log_print("Decompilation failed", arg_type="ERROR")
            return False

        if not arg_cached_cfunc.has_orphan_cmts(): # type: ignore[union-attr]
            l_decompiler_comment_set_ok = True
            arg_cached_cfunc.save_user_cmts() # type: ignore[union-attr]
            log_print(f"arg_cached_cfunc.set_user_cmt(_addr = 0x{l_tree_location.ea:x}, itp = {l_dict_of_types_of_comments[l_itp]}, comment = '{arg_comment}') worked!", arg_debug)
            break
        arg_cached_cfunc.del_orphan_cmts()
        arg_cached_cfunc.save_user_cmts()

    if not l_decompiler_comment_set_ok:
        log_print("Could NOT set the decompiler comment correct. l_decompiler_comment_set_ok == False", arg_type="ERROR")
        return False
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_set_disassembly(arg_ea: EvaluateType,
                arg_comment: str,
                arg_repeatable: bool = False,
                arg_debug: bool = False
                ) -> bool:
    ''' Internal function. Use comment(). This function sets the comment in the disassembly view

    @return True if everything is OK, False otherwise
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return False
    log_print(f"ida_bytes.set_cmt(0x{l_addr:x}, '{arg_comment}', is_repeatable = {arg_repeatable})", arg_debug)
    return _ida_bytes.set_cmt(l_addr, arg_comment, arg_repeatable) or False

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_set(arg_ea: EvaluateType,
                arg_comment: str,
                arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                arg_type_of_comment: Optional[int] = None,
                arg_debug: bool = False
                ) -> bool:
    ''' Internal function. Use comment(). Comments can be set at many different levels at the same address.
    This function sets the decompiler comment (if possible) and the disassembly view.
    @param arg_type_of_comment is one of ida_hexrays.ITP_* where ida_hexrays.ITP_BLOCK1 is the line above (same as pressing INSERT)

    @return True if everything is OK, False otherwise
    '''

    l_comment_set_decompiler_set_ok = _comment_set_decompiler(arg_ea=arg_ea, arg_comment=arg_comment, arg_cached_cfunc=arg_cached_cfunc, arg_type_of_comment=arg_type_of_comment, arg_debug=arg_debug)
    log_print(f"_comment_set_decompiler() returned {l_comment_set_decompiler_set_ok}", arg_debug)
    res = _comment_set_disassembly(arg_ea=arg_ea, arg_comment=arg_comment, arg_repeatable=False, arg_debug=arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_append(arg_ea: EvaluateType, arg_comment: str, arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None, arg_debug: bool = False) -> bool:
    ''' Comments can be set at many different levels at the same address.
    This function appends to the decompiler comment (if possible) and appends to the disassembly view
    If the comment you are appending already exists as comment at that address, then we do NOT append it again but still return True.
    '''

    # Each level is appended to on its own. (Reading the merged comment from _comment_get() and writing that back would copy
    # function comments into the line comment and duplicate the decompiler comment into the disassembly comment and vice versa.)
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return False

    res = True
    l_old_disassembly_cmt: str = _ida_bytes.get_cmt(l_addr, False) or ""
    if arg_comment not in l_old_disassembly_cmt:
        l_marker = '; ' if l_old_disassembly_cmt else ''
        res = _comment_set_disassembly(l_addr, f"{l_old_disassembly_cmt}{l_marker}{arg_comment}", arg_debug=arg_debug)

    if arg_cached_cfunc or is_code(l_addr, arg_debug=arg_debug):
        l_old_decompiler_cmt: str = _comment_get_decompiler(l_addr, arg_cached_cfunc=arg_cached_cfunc, arg_debug=arg_debug)
        if arg_comment not in l_old_decompiler_cmt:
            l_marker = '; ' if l_old_decompiler_cmt else ''
            l_decompiler_ok = _comment_set_decompiler(l_addr, f"{l_old_decompiler_cmt}{l_marker}{arg_comment}", arg_cached_cfunc=arg_cached_cfunc, arg_debug=arg_debug)
            log_print(f"_comment_set_decompiler() returned {l_decompiler_ok}", arg_debug) # Same as _comment_set(): the decompiler part is best effort
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_is_library_function(arg_ea: EvaluateType, arg_heavy_analysis: bool = False, arg_debug: bool = False) -> Optional[bool]:
    ''' Is the given EA (Effective Address) in a function IDA thinks is a library function that was compiled in?

    @param arg_heavy_analysis (NOT YET IMPLEMENTED!) Do some checks that can take long time
    '''

    # TODO: "heavy analysis" --> heuristic checks (if the function is not already marked as libfunc) that checks:
    # 1. Neighboring functions, are they libfuncs?
    # 2. Are there any calls to NON libfuncs coming from this function?

    if isinstance(arg_ea, _ida_funcs.func_t):
        l_func: _ida_funcs.func_t = arg_ea
    else:
        l_addr = address(arg_ea, arg_debug=arg_debug)
        l_func = _ida_funcs.get_func(l_addr) # TODO: Why am I not using function()? Does it call function_is_library_function()?
        if l_func is None:
            log_print(f"arg_ea '{_hex_str_if_int(arg_ea)}' is not a valid function", arg_type="ERROR")
            return None

    if arg_heavy_analysis:
        log_print("Not yet implemented the arg_heavy_analysis", arg_type="ERROR")
    # Each function that has both its neighbors as library functions will also be marked as library functions
        # for i in range(1, len(all_functions) - 1):
            # if not is_library_function(all_functions[i]) and is_library_function(all_functions[i-1]) and is_library_function(all_functions[i+1]):
                # all_functions[i].flags = all_functions[i].flags | _ida_funcs.FUNC_LIB
                # _ida_funcs.update_func(all_functions[i])
                # log_print(f"function '{all_functions[i].name}' was changed to library function", arg_debug)



    return (l_func.flags & _ida_funcs.FUNC_LIB) != 0

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def functions(arg_allow_library_functions: bool = True, arg_debug: bool = False) -> List[int]:
    ''' List of functions in the program.
    Can be used to filter out library functions

    @return List[function_start_address: int]
    '''
    l_all_functions: List[int] = []
    for func_addr in _idautils.Functions():
        l_all_functions.append(func_addr)

    if arg_allow_library_functions:
        return l_all_functions

    return [func for func in l_all_functions if not function_is_library_function(func, arg_debug=arg_debug)]

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def imports(arg_debug: bool = False) -> Dict[str, Dict[str, Tuple[int, int]]]:
    ''' Returns a dict with key: the module name and as value: another dict
    with key: function_name, value: tuple (function_ea, function_ordinal)
    ex: {'KERNEL32': {'CreateFileW': (0xaabbccdd, 0)}}
    '''

    l_tmp_imported_function_info_dict = {}
    res = {}

    def __import_callback(arg_ea, arg_name, arg_ordinal):
        ''' Called by ida_nalt.enum_import_names() for every imported function in the current module. Returns True to continue the enumeration '''
        if arg_name is None:
            arg_name = f"no_function_name_ordinal_{arg_ordinal}"

        l_tmp_imported_function_info_dict[arg_name] = (arg_ea, arg_ordinal)
        return True # return True -> Continue enumeration, return False -> Stop enumeration

    l_num_imported_modules = _ida_nalt.get_import_module_qty()
    for i in range(0, l_num_imported_modules):
        l_module_name = _ida_nalt.get_import_module_name(i)
        log_print(f"Found imported module: {l_module_name} with index {i}", arg_debug)
        _ida_nalt.enum_import_names(i, __import_callback)
        res[l_module_name] = l_tmp_imported_function_info_dict
        # log_print(f"Module: {module_name} have the following imports: {[function_name for function_name in res[module_name]]}", arg_debug)
        l_tmp_imported_function_info_dict = {}

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def exports(arg_debug: bool = False) -> Dict[int, Tuple[int, int, str]]:
    ''' Get all exported functions including start/entrypoint. The dict returned is Dict[ea: int, (index: int, ordinal: int, name: str)] '''
    res = {}
    for l_index, l_ordinal, l_ea, l_name in _idautils.Entries():
        if l_name is None: l_name = name(l_ea) # TODO: IDA (at least) 9.2 gives invalid names in e.g. ntoskrnl.exe
        if l_name is None: l_name = f"<<< no name found for ordinal 0x{l_ordinal:x} >>>"
        res[l_ea] = (l_index, l_ordinal, l_name)
    log_print(f"Len of exports: {len(res)}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def byte(arg_ea: EvaluateType, arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Reads a byte (8 bits) from the IDB. OBS! The IDB might not match the file on disk or active memory

    Replacement for ida_bytes.get_byte() and ida_bytes.patch_byte()

    OBS! See ida_idd.dbg_read_memory(ea, size) for some other memory read
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_value is not None:
        l_value = eval_expression(arg_set_value, arg_debug=arg_debug)
        if l_value is None:
            log_print("arg_set_value evaluated to None", arg_type="ERROR")
            return None

        if l_value > 0xFF:
            log_print(f"arg_set_value is too large for BYTE: 0x{l_value:x}", arg_type="ERROR")
            return None

        _ida_bytes.patch_byte(l_addr, l_value)

    return _ida_bytes.get_byte(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def word(arg_ea: EvaluateType, arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Reads a word (16 bits) from the IDB. OBS! The IDB might not match the file on disk or active memory

    Replacement for ida_bytes.get_word() and ida_bytes.patch_word()

    OBS! See ida_idd.dbg_read_memory(ea, size) for some other memory read
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_value is not None:
        l_value = eval_expression(arg_set_value, arg_debug=arg_debug)
        if l_value is None:
            log_print("arg_set_value evaluated to None", arg_type="ERROR")
            return None

        if l_value > 0xFFFF:
            log_print(f"arg_set_value is too large for WORD: 0x{l_value:x}", arg_type="ERROR")
            return None

        _ida_bytes.patch_word(l_addr, l_value)

    return _ida_bytes.get_word(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def dword(arg_ea: EvaluateType, arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Reads a dword (32 bits) from the IDB. OBS! The IDB might not match the file on disk or active memory

    Replacement for ida_bytes.get_dword() and ida_bytes.patch_dword()

    OBS! See ida_idd.dbg_read_memory(ea, size) for some other memory read
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_value is not None:
        l_value = eval_expression(arg_set_value, arg_debug=arg_debug)
        if l_value is None:
            log_print("arg_set_value evaluated to None", arg_type="ERROR")
            return None

        if l_value > 0xFFFFFFFF:
            log_print(f"arg_set_value is too large for DWORD: 0x{l_value:x}", arg_type="ERROR")
            return None

        _ida_bytes.patch_dword(l_addr, l_value)

    return _ida_bytes.get_dword(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def qword(arg_ea: EvaluateType, arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Reads a qword (64 bits) from the IDB. OBS! The IDB might not match the file on disk or active memory

    Replacement for ida_bytes.get_qword() and ida_bytes.patch_qword()

    OBS! See ida_idd.dbg_read_memory(ea, size) for some other memory read
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_value is not None:
        l_value = eval_expression(arg_set_value, arg_debug=arg_debug)
        if l_value is None:
            log_print("arg_set_value evaluated to None", arg_type="ERROR")
            return None

        if l_value > 0xFFFFFFFFFFFFFFFF:
            log_print(f"arg_set_value is too large for QWORD: 0x{l_value:x}", arg_type="ERROR")
            return None

        _ida_bytes.patch_qword(l_addr, l_value)

    return _ida_bytes.get_qword(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def read_bytes(arg_ea: EvaluateType, arg_len: EvaluateType, arg_debug: bool = False) -> Optional[bytes]:
    ''' Read bytes from the IDB. OBS! The IDB might not match the file on disk or active memory

    Replacement for ida_bytes.get_bytes()

    OBS! See ida_idd.dbg_read_memory(ea, size) for some other memory read
    '''
    l_len: Optional[int] = eval_expression(arg_len, arg_debug=arg_debug)
    if l_len is None:
        log_print(f"arg_len is invalid. arg_len: '{arg_len}' could not be parsed by eval_expression()", arg_type="ERROR")
        return None
    if l_len == 0:
        log_print("arg_len is 0. This is very strange.", arg_debug, arg_type="WARNING")
        return bytes()
    if l_len > 0x400:
        log_print(f"arg_len is VERY large: {_hex_str_if_int(l_len)}. This is very strange.", arg_debug, arg_type="WARNING")

    l_addr: int = address(arg_ea, arg_supress_error=True, arg_debug=arg_debug)
    if (l_addr == _ida_idaapi.BADADDR or not _ida_bytes.is_mapped(l_addr + l_len - 1)) and debugger_is_active():
        # If you have allocated memory via appcall, then IDA doesn't know about it until we refresh. Refreshing is VERY expensive so only do it when needed
        log_print("Address range is not known to IDA, refreshing the debugger memory and trying again", arg_debug)
        debugger_refresh_memory_WARNING_VERY_EXPENSIVE()
        l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_bytes: bytes = _ida_bytes.get_bytes(l_addr, l_len)
    if arg_debug:
        l_parsed_hex = " ".join(hex_parse(l_bytes))
        log_print(f"arg_ea = 0x{l_addr:x}, arg_len = 0x{l_len:x} resulted in '{l_parsed_hex}'", arg_debug)
    return l_bytes

bytes_read = get_bytes = read_bytes

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def write_bytes(arg_ea: EvaluateType, arg_buf: Union[BufferType, int], arg_debug: bool = False) -> bool:
    ''' Write bytes (or hex string) to the IDB. OBS! The IDB might not match the file on disk or in active memory.
    Use ida_bytes.get_original_byte() to get back the bytes
    Replacement for ida_bytes.patch_bytes()
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return False

    if isinstance(arg_buf, int):
        if arg_buf <= 0xFF: # allow ints that is <= 1 Byte to be handled as the user probably wanted
            l_buf: bytes = bytes.fromhex(f"{arg_buf:02x}")
        else:
            log_print(f'arg_buf is an int: {_hex_str_if_int(arg_buf)} but I need a buffer to write. (I actually am OK with a byte <= 0xFF also)', arg_type="ERROR")
            return False
    elif isinstance(arg_buf, bytes):
        l_buf = arg_buf
    else:
        l_temp = hex_parse(arg_buf, arg_debug=arg_debug)
        if l_temp is None:
            log_print("hex_parse() failed.", arg_type="ERROR")
            return False
        parsed_hex: str = " ".join(l_temp)
        log_print(f"addr: {l_addr:x}, bytes: {parsed_hex}", arg_debug)
        l_buf = bytes.fromhex(parsed_hex)
    _ida_bytes.patch_bytes(l_addr, l_buf)
    l_written_bytes = read_bytes(l_addr, len(l_buf), arg_debug=arg_debug)
    res = l_written_bytes == l_buf
    _idaapi_request_refresh() # Update the GUI if we actually managed to write something
    return res

bytes_write = set_bytes = patch_bytes = write_bytes

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def bytes_restore_to_original(arg_ea: EvaluateType, arg_len: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Restore the bytes to the original state
    @param arg_ea The address to restore the bytes to
    @param arg_len The length of the bytes to restore
    @return True if the bytes were restored successfully, False otherwise
    '''
    l_start_addr = address(arg_ea, arg_debug=arg_debug)
    if l_start_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return False

    l_len = eval_expression(arg_len, arg_debug=arg_debug)
    if l_len is None:
        log_print("eval_expression(arg_len) failed", arg_type="ERROR")
        return False

    if l_len <= 0:
        return True

    # Collect all original bytes first and write them in ONE call. (write_bytes() per byte means a read back + GUI refresh per byte)
    l_original_bytes = bytearray()
    for i in range(l_len):
        l_original_byte = _ida_bytes.get_original_byte(l_start_addr + i)
        if l_original_byte is None:
            log_print(f"get_original_byte(0x{l_start_addr + i:x}) failed", arg_type="ERROR")
            return False
        l_original_bytes.append(l_original_byte & 0xFF)
        log_print(f"Original byte at 0x{l_start_addr + i:x}: 0x{l_original_byte & 0xFF:02x}", arg_debug) # Also the clipboard abort check for big ranges

    res = write_bytes(l_start_addr, bytes(l_original_bytes), arg_debug=arg_debug)
    if not res:
        log_print(f"write_bytes(0x{l_start_addr:x}, <0x{l_len:x} original bytes>) failed", arg_type="ERROR")
        return False

    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def bytes_smart_delete(arg_ea: EvaluateType, arg_len: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Smart delete of bytes. If the bytes are code then replace with NOP (0x90) and if you press delete again, then write 0x00
    OBS! Only working smart on Intel. On other architectures, it just writes 0x00.

    If one wants to make this function smarter, see <https://en.wikipedia.org/wiki/NOP_(code)>
      '''
    l_start_addr = address(arg_ea, arg_debug=arg_debug)
    if l_start_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_len = eval_expression(arg_len, arg_debug=arg_debug)
    if l_len is None:
        log_print("eval_expression(arg_len) failed", arg_type="ERROR")
        return None

    l_is_code = is_code(arg_ea, arg_debug=arg_debug)
    l_bytes = read_bytes(arg_ea, arg_len=1, arg_debug=arg_debug)
    if l_bytes is None:
        log_print("read_bytes() failed", arg_type="ERROR")
        return None

    l_is_already_nop = l_bytes[0] == 0x90 # Intel NOP == 0x90

    if l_is_already_nop or not l_is_code or _ida_idp.ph_get_id() != _ida_idp.PLFM_386: # Only do the smart delete on Intel, thanks to [milankovo](https://github.com/milankovo) <https://github.com/Harding-Stardust/community_base/issues/4>
        res = write_bytes(arg_ea, arg_buf = "00 " * l_len, arg_debug=arg_debug)
    else:
        res = write_bytes(arg_ea, arg_buf = "90 " * l_len, arg_debug=arg_debug)

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def write_string(arg_ea: EvaluateType, arg_string: str, arg_append_NULL_byte: bool = True, arg_debug: bool = False) -> bool:
    ''' Write a null-terminated C string (utf-8) to IDB
    @param arg_ea The address to write the string to
    @param arg_string The string to write
    @param arg_append_NULL_byte If True, then append a NULL byte to the end of the string
    @return True if the string was written successfully, False otherwise

    Replacement for ida_bytes.patch_strlit()
    '''
    return write_bytes(arg_ea=arg_ea, arg_buf=bytes(arg_string + ('\x00' if arg_append_NULL_byte else ''), encoding='utf-8'), arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _local_type_names(arg_debug: bool = False) -> List[str]:
    ''' Internal function. Get the names of all types in the local type library (the Local Types window)

    @return A list with the names of all local types
    '''
    l_til = _ida_typeinf.get_idati()
    # ida_typeinf.get_ordinal_limit() is IDA 9.0+, in IDA 8.4 the same function is named get_ordinal_qty()
    l_ordinal_limit: int = _ida_typeinf.get_ordinal_limit(l_til) if hasattr(_ida_typeinf, "get_ordinal_limit") else _ida_typeinf.get_ordinal_qty(l_til)
    if l_ordinal_limit in (0, 0xFFFFFFFF): # 0xFFFFFFFF == uint32(-1) --> failed
        log_print(f"Could not get the number of local types, got 0x{l_ordinal_limit:x}", arg_debug)
        return []

    res: List[str] = []
    for l_ordinal in range(1, l_ordinal_limit):
        l_name = _ida_typeinf.get_numbered_type_name(l_til, l_ordinal)
        log_print(f"ordinal {l_ordinal} --> '{l_name}'", arg_debug)
        if l_name:
            res.append(l_name)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _h_file_type_names(arg_h_file: str, arg_debug: bool = False) -> List[str]:
    ''' Internal function. Get the names of all types that a header file (.h file) declares, also the types that already exist in the IDB.
    This does NOT change the IDB: the header file is parsed into a temporary copy of the local type library where all the types are deleted first,
    so every type that is in the copy after the parsing comes from the header file. The copy has the same base type libraries (ex: mssdk64_win7) and compiler settings as the IDB.

    OBS! Types in the header file that need a type that only exists in Local Types (not in the header file and not in a base type library) are missed

    @param arg_h_file The path to the header file
    @param arg_debug Print debug messages
    @return A list with the names of the types in the header file. Empty list on failure
    '''
    import tempfile
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_til_file: str = _os.path.join(l_temp_dir, "community_base_temp.til")
        if not _ida_typeinf.store_til(_ida_typeinf.get_idati(), None, l_til_file):
            log_print(f"ida_typeinf.store_til() failed to write '{l_til_file}'", arg_type="WARNING")
            return []
        l_temp_til = _ida_typeinf.load_til(l_til_file)
    if l_temp_til is None:
        log_print(f"ida_typeinf.load_til('{l_til_file}') failed", arg_type="WARNING")
        return []

    try:
        l_name = _ida_typeinf.first_named_type(l_temp_til, _ida_typeinf.NTF_TYPE)
        while l_name: # Deleting the first type every time is OK, we want all of them gone
            log_print(f"Deleting '{l_name}' from the temporary type library", arg_debug)
            if not _ida_typeinf.del_named_type(l_temp_til, l_name, _ida_typeinf.NTF_TYPE):
                log_print(f"Could not delete '{l_name}' from the temporary type library", arg_type="WARNING")
                return []
            l_name = _ida_typeinf.first_named_type(l_temp_til, _ida_typeinf.NTF_TYPE)

        # OBS! ida_typeinf.parse_decls() wants HTI_FIL for a file, with PT_FILE it fails
        l_errors: int = _ida_typeinf.parse_decls(l_temp_til, arg_h_file, None, _ida_typeinf.HTI_FIL | _ida_typeinf.PT_SIL)
        log_print(f"Parsing '{arg_h_file}' into the temporary type library gave {l_errors} errors", arg_debug)

        res: List[str] = []
        l_name = _ida_typeinf.first_named_type(l_temp_til, _ida_typeinf.NTF_TYPE)
        while l_name:
            log_print(f"'{l_name}' is a type in the header file", arg_debug)
            res.append(l_name)
            l_name = _ida_typeinf.next_named_type(l_temp_til, l_name, _ida_typeinf.NTF_TYPE)
        return res
    finally:
        _ida_typeinf.free_til(l_temp_til)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def import_h_file(arg_h_file: str, arg_flags: int = _ida_typeinf.PT_FILE, arg_folder: Optional[str] = None, arg_debug: bool = False) -> bool:
    ''' Import a header file (.h file) with types into IDA. Same as using the menu File -> Load file -> Parse C header file. Default keybinding for the menu is Ctrl + F9
    @param arg_h_file The path to the header file to import
    @param arg_flags The flags to pass to ida_typeinf.idc_parse_types()
    @param arg_folder The folder in the Local Types window to put ALL the types from the header file in, the folder is created if needed.
                      None (default) means use the name of the header file, ex: "C:/temp/default_types.h" --> "default_types.h". "" means don't move the types.
                      Types that existed before the import are moved too (also from other folders), so the folder tells you which header file was the last one to write the type.
                      The folder is only for display, the type names are still global
    @param arg_debug Print debug messages
    @return True if the header file was imported successfully, False otherwise. Problems with the folder only give a WARNING, they don't change the return value

    Replacement for ida_typeinf.idc_parse_types() and ida_typeinf.parse_decls() '''
    if not _os.path.exists(arg_h_file):
        log_print(f"File does not exists: '{arg_h_file}'", arg_type="ERROR")
        return False

    if arg_folder is None:
        arg_folder = _os.path.basename(arg_h_file) # The folder gets the same name as the header file
    arg_folder = arg_folder.strip("/")

    # OBS! Must be done BEFORE the import, _h_file_type_names() works on a copy of the local types as they are now
    l_type_names_in_h_file: List[str] = _h_file_type_names(arg_h_file, arg_debug=arg_debug) if arg_folder else []
    l_type_names_before: List[str] = _local_type_names(arg_debug=arg_debug) if arg_folder else []
    l_idc_parse_types_res = _ida_typeinf.idc_parse_types(arg_h_file, arg_flags)
    log_print(f"_ida_typeinf.idc_parse_types() result: {l_idc_parse_types_res}", arg_debug)

    res = 0 == l_idc_parse_types_res
    if not res:
        log_print(f"There where errors when trying to import the header file '{arg_h_file}'. Please make sure it's correct by manual load with Ctrl + F9", arg_type="ERROR")
    if not arg_folder:
        return res

    # Also done if there were errors, the types before the error are imported.
    # The new types are added in case _h_file_type_names() missed some, see the OBS! in that function
    l_new_type_names: Set[str] = set(_local_type_names(arg_debug=arg_debug)) - set(l_type_names_before)
    l_type_names_to_move: List[str] = sorted(set(l_type_names_in_h_file) | l_new_type_names)
    log_print(f"{len(l_type_names_to_move)} types ({len(l_new_type_names)} new) to move into the folder '{arg_folder}'", arg_debug)
    if not l_type_names_to_move:
        return res

    l_dirtree = _ida_dirtree.get_std_dirtree(_ida_dirtree.DIRTREE_LOCAL_TYPES)
    if l_dirtree is None:
        log_print(f"Could not get the dirtree for Local Types, the types are not moved into the folder '{arg_folder}'", arg_type="WARNING")
        return res

    if not l_dirtree.isdir(arg_folder):
        l_mkdir_res: int = l_dirtree.mkdir(arg_folder)
        if l_mkdir_res != _ida_dirtree.DTE_OK:
            log_print(f"Could not create the folder '{arg_folder}' in Local Types: {_ida_dirtree.dirtree_t.errstr(l_mkdir_res)}", arg_type="WARNING")
            return res

    l_til = _ida_typeinf.get_idati()
    for l_type_name in l_type_names_to_move:
        log_print(f"Moving '{l_type_name}' into the folder '{arg_folder}'", arg_debug)
        l_ordinal: int = _ida_typeinf.get_type_ordinal(l_til, l_type_name)
        if not l_ordinal: # The type is in the header file but it did not end up in Local Types, ex: the import failed on that type
            log_print(f"'{l_type_name}' is not in Local Types, skipping it", arg_debug)
            continue

        l_cursor = l_dirtree.find_entry(_ida_dirtree.direntry_t(l_ordinal, False)) # In the Local Types dirtree the inode is the ordinal. The type can be in any folder, ex: "/pdb/_GUID"
        if not l_cursor.valid():
            log_print(f"Could not find the type '{l_type_name}' (ordinal {l_ordinal}) in the Local Types dirtree", arg_type="WARNING")
            continue

        l_old_path: str = l_dirtree.get_abspath(l_cursor)
        l_new_path: str = f"/{arg_folder}/{l_type_name}"
        if l_old_path == l_new_path: continue # Already in the right folder

        l_rename_res: int = l_dirtree.rename(l_old_path, l_new_path)
        if l_rename_res != _ida_dirtree.DTE_OK:
            log_print(f"Could not move the type '{l_old_path}' to '{l_new_path}': {_ida_dirtree.dirtree_t.errstr(l_rename_res)}", arg_type="WARNING")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _ida_default_type_info_library() -> _ida_typeinf.til_t:
    ''' Get the local type library - this TIL (Type Information Library) is private for each IDB file '''
    return _ida_typeinf.get_idati()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _local_types_as_c_types(arg_debug: bool = False) -> Optional[List[str]]:
    ''' Internal function. Get all local types as a list of strings that can be exported to a header file.
    Read more [at Github](https://github.com/idapython/src/blob/ae62cd4df534f18c8c3dc47bd159d50c9822d82d/python/idc.py#L5142)
    '''
    class CustomPrinter(_ida_typeinf.text_sink_t):
        ''' Handle the _print calls by putting them into a list '''
        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def __init__(self):
            ''' Empty list of lines '''
            _ida_typeinf.text_sink_t.__init__(self)
            self.lines: List[str] = [] # type: ignore[annotation-unchecked]

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def _print(self, arg_str: str): # IDA BUG: community_base.py:2008:8: W0237: Parameter 'str' has been renamed to 'arg_str' in overriding 'CustomPrinter._print' method (arguments-renamed)
            ''' Called by ida_typeinf.print_decls() for every piece of text, we save it. Returns 0 to continue '''
            self.lines.append(arg_str)
            return 0

    l_printer = CustomPrinter()
    l_flags: int = 0
    l_flags |= _ida_typeinf.PDF_INCL_DEPS
    l_flags |= _ida_typeinf.PDF_DEF_FWD
    res_of_print_decls: int = _ida_typeinf.print_decls(l_printer, _ida_default_type_info_library(), [], l_flags )
    if res_of_print_decls < 0: # print_decls() returns the number of types printed (0 is OK: an IDB without local types) or a negative error code
        log_print(f'ida_typeinf.print_decls() failed with error code {res_of_print_decls}', arg_type="ERROR")
        return None
    log_print(f'Exported {res_of_print_decls} types', arg_debug)

    return l_printer.lines

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def export_h_file(arg_h_file: str = "", arg_add_comment_at_top: bool = True, arg_debug: bool = False) -> str:
    ''' Export all local types into a header file

        @param arg_h_file The destination file, if empty, then generate input_file.idb_path + ".h"
        @param arg_add_comment_at_top Add a comment field with some info about the file the header file was exported from

        Replacement for ida_typeinf.print_decls()
    '''
    l_save_to_file: str = arg_h_file or f"{input_file.idb_path}.h"
    l_local_types: Optional[List[str]] = _local_types_as_c_types(arg_debug=arg_debug)
    if l_local_types is None:
        log_print('_local_types_as_c_types() failed.', arg_type="ERROR")
        return "<<< Export header file failed >>>"

    with open(l_save_to_file, "w", encoding="utf-8", newline="\n") as f:
        if arg_add_comment_at_top:
            l_header_dict: Dict[str, str] = {}
            l_header_dict["generated_by"] = f"{__name__}.py"
            l_header_dict["plugin_version"] = __version__
            l_header_dict["generated_at"] = _timestamped_line('').strip()
            l_header_dict["input_file_filename"] = _os.path.basename(input_file.filename)
            l_header_dict["input_file_MD5"] = input_file.md5
            l_header_dict["input_file_SHA256"] = input_file.sha256
            f.write("/*\n")
            f.write(_json.dumps(l_header_dict, ensure_ascii=False, indent=4, default=str))
            f.write("\n*/")
        f.write("\n".join(l_local_types))

    return l_save_to_file

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def string_encoding(arg_ea: EvaluateType, arg_detect: bool = False, arg_debug: bool = False) -> Optional[str]:
    '''
    Gets the encoding of a string, can also be used to check if IDA thinks there is a string on that address
    If it's not a string at the given address and you want to make a string at that place, you can use string(<address>, arg_encoding="<encoding>", arg_create_string=True)

    @param arg_ea The address to check for string encoding
    @param arg_detect True --> attempts to detect the encoding even if IDA doesn't recognize it as a string, requires the third party package chardet (pip install chardet)

    @return: The encoding name, if there is no string on that address, then we return "" (empty str)

    Replacement for ida_bytes.is_strlit()
    '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_is_str_lit = _ida_bytes.is_strlit(_idaapi_get_flags(l_addr, arg_debug=arg_debug))
    log_print(f"{arg_ea} is string literal: {l_is_str_lit}", arg_debug)
    if l_is_str_lit:
        res = _idaapi_encoding_from_strtype(_ida_nalt.get_str_type(l_addr))
    elif arg_detect:
        l_max_len = 0x100
        l_raw = read_bytes(l_addr, l_max_len, arg_debug=arg_debug) # One read instead of one per byte
        if l_raw is None:
            return None
        # Cut at the terminator. A single 0x00 can be half of a UTF-16 char so for UTF-16 like data (every other byte is 0x00) look for 00 00 on an even offset
        l_looks_like_utf16 = len(l_raw) >= 4 and l_raw[1] == 0 and l_raw[3] == 0
        if l_looks_like_utf16:
            l_end = next((i for i in range(0, len(l_raw) - 1, 2) if l_raw[i] == 0 and l_raw[i + 1] == 0), len(l_raw))
        else:
            l_end = l_raw.find(b'\x00')
            l_end = len(l_raw) if l_end == -1 else l_end
        l_bytes = l_raw[:l_end]

        log_print(f"_chardet.detect({str(l_bytes)}) len: {len(l_bytes)}", arg_debug)
        l_detected = _chardet.detect(l_bytes)
        log_print(f"_chardet gave the following: {str(l_detected)}", arg_debug)
        res = l_detected["encoding"] if l_detected["encoding"] is not None else ""
    else:
        log_print(f"IDA does _NOT_ think there is a string at {_hex_str_if_int(arg_ea)} but you can try to detect what encoding is used by calling string_encoding(<address>, arg_detect=True)", arg_type="ERROR")
        res = ""
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _is_invalid_strtype(arg_strtype: int) -> bool:
    ''' It's not clear what is ida_nalt.get_str_type() should return that is a valid strtype.
    I used to think that 0xFFFFFFFF was the constant but I have gotten cases where 0xFFFFFF00 is also returned
    @param arg_strtype The strtype to check
    @return True if the strtype is invalid, False otherwise
    '''
    arg_strtype = arg_strtype & 0xFFFFFFFF
    return (arg_strtype >> 8) == 0xFFFFFF

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _normalize_encoding_name(arg_encoding: str, arg_debug: bool = False) -> str:
    ''' Try to normalize some encoding names
    @param arg_encoding The encoding name to validate
    @return The normalized encoding name
    '''
    # Encoding already exists in the IDB
    for i in range(1, _ida_nalt.get_encoding_qty()):
        l_encoding_name = _ida_nalt.get_encoding_name(i)
        log_print(f"Encoding already in the IDB: {l_encoding_name}", arg_debug)
        if arg_encoding.lower() == l_encoding_name.lower():
            return l_encoding_name

    # The user gave us an encoding name that is not in the IDB
    import codecs
    try:
        res = codecs.lookup(arg_encoding).name
    except LookupError as e:
        log_print(f"Could not understand the encoding: {arg_encoding}, got exception: {e}. Returning default encoding: {_G_DEFAULT_ENCODING}", arg_type="ERROR")
        return _G_DEFAULT_ENCODING

    log_print(f"codecs converted: {arg_encoding} --> {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _encoding_to_strtype(arg_encoding: str, arg_debug: bool = False) -> int:
    ''' Internal function. Do not use directly.
    @param arg_encoding The encoding name to convert to a strtype
    @return returns the str_type: int, returns -1 on error
    '''
    l_encoding: str = _normalize_encoding_name(arg_encoding, arg_debug=arg_debug)
    log_print(f"l_encoding: {l_encoding}", arg_debug)
    l_encoding_index: int = _ida_nalt.add_encoding(l_encoding) # If the encoding exists, then return the index, else create it and return index.
    if l_encoding_index == -1:
        log_print(f'ida_nalt.add_encoding("{arg_encoding}") failed.', arg_type="ERROR")
        return -1
    log_print(f"Encoding index: {l_encoding_index}", arg_debug)
    res: int = _ida_nalt.make_str_type(0, l_encoding_index)
    log_print(f"l_strtype: 0x{res:x}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_encoding_from_strtype(arg_strtype: int) -> str:
    ''' Wrapper around ida_nalt.encoding_from_strtype() that honors the type hints
    It does NOT return None (NULLPTR) if we send in an invalid index as the docstring say
    @param arg_strtype The strtype to convert to an encoding name
    @return The encoding name
    '''
    if _is_invalid_strtype(arg_strtype):
        log_print(f"Invalid encoding. Got 0x{arg_strtype:x}. Returning the default encoding: {_G_DEFAULT_ENCODING}")
        return _G_DEFAULT_ENCODING

    res = _ida_nalt.encoding_from_strtype(arg_strtype)
    if res is None:
        log_print(f"Invalid encoding. Got 0x{arg_strtype:x} which ida_nalt.encoding_from_strtype() returned None for. Returning the default encoding: {_G_DEFAULT_ENCODING} ")
        return _G_DEFAULT_ENCODING
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def string(arg_ea: EvaluateType,
           arg_encoding: Optional[Union[int, str]] = None,
           arg_len: EvaluateType = 0,
           arg_create_string: bool = False,
           arg_flags: int = _ida_bytes.ALOPT_IGNHEADS | _ida_bytes.ALOPT_IGNPRINT | _ida_bytes.ALOPT_IGNCLT,
           arg_debug: bool = False) -> Optional[str]:
    ''' Reads a string (excluding the NULL terminator) from the IDB that can handle C strings, wide strings (utf-16).
    If you want to force read a string use the functions c_string() or wide_string().

    @param arg_encoding: See ida_nalt.STRTYPE_* for valid values. If you give it a string, I use this as encoding name.
    If None: use the string type IDA has at the address. If the bytes are unknown (not defined), guess C string or UTF-16 from the first bytes WITHOUT changing the IDB
    @param arg_len: Length in BYTES (not characters) to read, 0 --> find the length with ida_bytes.get_max_strlit_length()
    @param arg_flags: See  ida_bytes.ALOPT_* for valid values. Default: ida_bytes.ALOPT_IGNHEADS | ida_bytes.ALOPT_IGNPRINT | ida_bytes.ALOPT_IGNCLT
    ALOPT_IGNHEADS: Don't stop if another data item is encountered. Only the byte values will be used to determine the string length. If not set, a defined data item or instruction will truncate the string.
    ALOPT_IGNPRINT: Don't stop at non-printable codepoints, but only at the terminating character (or not unicode-mapped character (e.g., 0x8f in CP1252))
    ALOPT_IGNCLT:   Don't stop at codepoints that are not part of the current 'culture'; accept all those that are graphical (this is typically used used by user-initiated actions creating string literals.)

    @param arg_create_string If True, then create a string literal at the given address (this is the only case where the IDB is changed)
    @return The string read from the IDB

    Replacement for ida_bytes.get_strlit_contents() and idc.get_strlit_contents()
    '''
    if isinstance(arg_ea, _idautils.Strings.StringItem):
        log_print("arg_ea is of type idautils.Strings.StringItem, I will use that info instead of rest of arguments", arg_debug)
        l_type: int = arg_ea.strtype
        arg_len = arg_ea.length
        arg_ea = arg_ea.ea

    l_t_len = eval_expression(arg_len, arg_debug=arg_debug)
    if l_t_len is None:
        log_print(f'eval_expression({arg_len}) failed', arg_type="ERROR")
        return None
    l_len: int = l_t_len
    del l_t_len

    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if isinstance(arg_encoding, str):
        l_type = _encoding_to_strtype(arg_encoding) # TODO: This will overwrite l_type if it was set from StringItem, is this correct?
        if l_type == -1:
            log_print(f'_encoding_to_strtype("{arg_encoding}") failed')
            return None
    elif isinstance(arg_encoding, int):
        l_type = arg_encoding

    if arg_create_string and is_unknown(l_addr, arg_debug=arg_debug): # Only change the IDB when asked to
        log_print(f"address: {_hex_str_if_int(l_addr)} is tagged as unknown, trying to convert it to string", arg_debug)
        if arg_encoding is None:
            is_unicode: bool = _ida_bytes.create_strlit(l_addr, l_len, _ida_nalt.STRTYPE_C_16)
            if is_unicode:
                log_print(f"ida_bytes.create_strlit(0x{l_addr:x}, 0x{l_len:x}, ida_nalt.STRTYPE_C_16) OK", arg_debug)
            else:
                log_print(f"ida_bytes.create_strlit(0x{l_addr:x}, 0x{l_len:x}, ida_nalt.STRTYPE_C_16) failed. Trying with normal C string", arg_debug)
                _ida_bytes.create_strlit(l_addr, l_len, _ida_nalt.STRTYPE_C)
        else:
            _ida_bytes.create_strlit(l_addr, l_len, l_type)
        _ida_auto.auto_wait()

    if arg_encoding is None:
        l_type = _ida_nalt.get_str_type(l_addr)
        if _is_invalid_strtype(l_type) and is_unknown(l_addr, arg_debug=arg_debug):
            # Unknown bytes (e.g. memory we just allocated) and no encoding given: guess the string type WITHOUT changing the IDB.
            # "A\0B\0" looks like UTF-16, everything else is read as a C string.
            l_first_bytes: bytes = _ida_bytes.get_bytes(l_addr, 4) or b''
            l_looks_like_utf16: bool = len(l_first_bytes) == 4 and l_first_bytes[0] != 0 and l_first_bytes[1] == 0 and l_first_bytes[2] != 0 and l_first_bytes[3] == 0
            l_type = _ida_nalt.STRTYPE_C_16 if l_looks_like_utf16 else _ida_nalt.STRTYPE_C
            log_print(f"0x{l_addr:x} is unknown bytes, guessing the string type: {'STRTYPE_C_16' if l_looks_like_utf16 else 'STRTYPE_C'}", arg_debug)
    if _is_invalid_strtype(l_type):
        log_print(f"IDA doesn't think there is a string at {_hex_str_if_int(arg_ea)}. (0x{l_type:x} is not a valid string type).", arg_type="ERROR")
        l_item_head: int = _ida_bytes.get_item_head(l_addr)
        if l_addr != l_item_head:
            log_print(f"IDA thinks that the item starts at 0x{l_item_head:x} instead of 0x{l_addr:x} which you entered. Maybe that's a clue?", arg_type="ERROR")

        log_print("If you want to try and force read it, use the function c_string() or wide_string()", arg_type="ERROR")
        log_print(f'If you want to create a string at this place (same as pressing <a> in IDA), use string(0x{l_addr:x}, arg_encoding="<encoding>", arg_create_string=True)', arg_type="ERROR")
        return None

    if not l_len:
        log_print(f"Calling _ida_bytes.get_max_strlit_length(0x{l_addr:x}, '{_idaapi_encoding_from_strtype(l_type)}', {arg_flags})", arg_debug)
        l_len = _ida_bytes.get_max_strlit_length(l_addr, l_type, arg_flags)
        log_print(f"That resulted in a len: {l_len}", arg_debug)

    log_print(f"type: 0x{l_type:x} = '{_idaapi_encoding_from_strtype(l_type)}'. See _ida_nalt.STRTYPE_* for valid types", arg_debug)
    log_print(f"l_len: {l_len}", arg_debug)

    l_t_bytes_read = read_bytes(l_addr, l_len, arg_debug=arg_debug)
    if l_t_bytes_read is None:
        log_print(f"read_bytes({_hex_str_if_int(l_addr)}, 0x{l_len:x}) returned None", arg_type="ERROR")
        return None
    l_bytes_read: bytes = l_t_bytes_read
    try:
        res = l_bytes_read.decode(_idaapi_encoding_from_strtype(l_type))
        log_print(f'l_bytes_read.decode({_idaapi_encoding_from_strtype(l_type)}) OK!', arg_debug)
    except:
        l_bytes_read = _ida_bytes.get_strlit_contents(l_addr, l_len, l_type)
        res = l_bytes_read.decode(_idaapi_encoding_from_strtype(l_type))
        if not res:
            log_print(f'l_bytes_read.decode() failed. arg_ea: {_hex_str_if_int(arg_ea)}, l_type: 0x{l_type:x}, _idaapi_encoding_from_strtype(l_type): {_idaapi_encoding_from_strtype(l_type)}', arg_type="ERROR")
            return None

    if not res:
        log_print("Everything failed :-(", arg_type="ERROR")
        return None

    if arg_create_string:
        l_temp = _ida_bytes.create_strlit(l_addr, l_len, l_type)
        log_print(f"_ida_bytes.create_strlit(0x{l_addr:x}, {l_len}, {l_type}) --> {l_temp}", arg_debug)

    res = res.rstrip('\x00') # Remove the NULL terminator
    log_print(f"res: '{res}'", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def c_string(arg_ea: EvaluateType, arg_len: int = 0, arg_flags: int = _ida_bytes.ALOPT_IGNHEADS | _ida_bytes.ALOPT_IGNPRINT | _ida_bytes.ALOPT_IGNCLT, arg_debug: bool = False) -> Optional[str]:
    ''' Forcefully read the data as a NULL terminated C string (ida_nalt.STRTYPE_C, decoded with the default 1 byte encoding of the IDB) For more info about the flags, see the docstring for string()
    @param arg_ea The address to read the string from
    @param arg_len The length of the string to read, set to 0 to use the length of the string at the given address
    @param arg_flags The flags to pass to string()
    @return The string read from the IDB

    Replacement for idc.get_cstr() and ida_bytes.get_cstr()
    '''
    return string(arg_ea=arg_ea, arg_encoding=_ida_nalt.STRTYPE_C, arg_len=arg_len, arg_flags=arg_flags, arg_debug=arg_debug)

utf8_string = string_utf8 = c_string

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def wide_string(arg_ea: EvaluateType, arg_len: int = 0, arg_flags: int = _ida_bytes.ALOPT_IGNHEADS | _ida_bytes.ALOPT_IGNPRINT | _ida_bytes.ALOPT_IGNCLT, arg_debug: bool = False) -> Optional[str]:
    ''' Forcefully read the data as a NULL terminated wide/unicode/utf-16 string. For more info about the flags, see the docstring for string()
    @param arg_ea The address to read the string from
    @param arg_len The length of the string to read, set to 0 to use the length of the string at the given address
    @param arg_flags The flags to pass to string()
    @return The string read from the IDB

    Replacement for idc.get_wstr() and ida_bytes.get_wstr()
    '''
    return string(arg_ea=arg_ea, arg_encoding=_ida_nalt.STRTYPE_C_16, arg_len=arg_len, arg_flags=arg_flags, arg_debug=arg_debug)

utf16_string = string_utf16 = wide_string

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def strings(arg_only_first: int = 100_000, arg_debug: bool = False) -> List[_idautils.Strings.StringItem]:
    ''' Returns strings that IDA has found.

    @param arg_only_first: Only get the first X entries, default: 100_000 (should be enough for most programs)
    '''
    # TODO: Add config to the arguments? Like arg_min_len = 10 ?
    res: List[_idautils.Strings.StringItem] = []
    l_strings = _idautils.Strings() # This is where IDA scans the database (ida_strlist.build_strlist()). TODO: Investigate if ida_domain should be used
    for string_item in l_strings:
        if string_item is None: # idautils.Strings yields None if ida_strlist.get_strlist_item_ex() fails, that would fail the validate_return on the whole list
            continue
        res.append(string_item)
        log_print(f'Found string at: 0x{string_item.ea:x}', arg_debug) # Also checks the clipboard for the abort string, so a long loop can be stopped
        if len(res) >= arg_only_first:
            break

    if l_strings.size > arg_only_first:
        log_print(f"Showing only first {arg_only_first} of {l_strings.size} strings.", arg_type="WARNING")
    log_print(f"len(res) = {len(res)}", arg_debug)
    return res

def _strings_profiled():
    r''' Internal function. Do not use.
    Profile code to see what is taking most time
    From the command console: snakeviz C:\temp\strings.prof
    '''
    import cProfile
    import pstats

    profiler = cProfile.Profile()
    profiler.enable()

    # Start of code to profile
    a = strings(arg_debug=True)
    log_print(str(a))
    # End of code to profile

    profiler.disable()
    stats = pstats.Stats(profiler).sort_stats('cumtime')
    stats.print_stats()
    stats.dump_stats(r'C:\temp\strings.prof')
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pointer_type(arg_type_or_function_name: Union[str, _ida_typeinf.tinfo_t], arg_debug: bool = False) -> Optional[_ida_typeinf.tinfo_t]:
    ''' Send in a name or a type and get a pointer type back.
    The reverse function is ida_typeinf.tinfo_t.remove_ptr_or_array()
    Usually one use str(res) to get it as a string

    @param arg_type_or_function_name The name or type to get a pointer type for
    @return A pointer type or None if it failed

    Replacement for ida_typeinf.tinfo_t().create_ptr()
    '''
    l_type: Optional[_ida_typeinf.tinfo_t] = get_type(arg_type_or_function_name, arg_debug=arg_debug)
    if l_type is None:
        log_print(f"get_type({arg_type_or_function_name}) failed", arg_type="ERROR")
        return None
    res = _ida_typeinf.tinfo_t()
    res.create_ptr(l_type)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _fix_assembly(arg_assembly_string: str, arg_debug: bool = False) -> str:
    ''' Internal function. If you read assembly from IDA and try to reassemble it, it won't work.
    OBS! This is NOT a complete fix!

    @param arg_assembly_string The assembly string to fix
    @return The fixed assembly string
    '''
    res = arg_assembly_string
    res = res.replace(" loc_", " 0x")
    res = res.replace(" near ptr ", " ") # Must be before " near " otherwise " near ptr " never matches
    res = res.replace(" near ", " ")
    res = res.replace(" short ", " ")
    res = res.replace(" offset ", " ")
    res = res.replace(" large ", " ")
    res = res.replace(" ds:", " ")
    res = _re.sub(r"([cdfg])s:(\d+)", r"\1s:[\2]", res, flags=_re.IGNORECASE)
    # Convert C style hex to asm style: 0x12 -> 12h. A number that starts with a letter needs a leading 0, otherwise it's a label: 0xdeadbeef -> 0deadbeefh
    res = _re.sub(r"0x([0-9a-f]+)", lambda m: ("0" if m.group(1)[0].isalpha() else "") + m.group(1) + "h", res, flags=_re.IGNORECASE)
    res = res.replace("  ", " ")
    res = res.replace("  ", " ")
    res = res.replace("  ", " ")
    res = res.replace("  ", " ")
    log_print(f"in: {arg_assembly_string} --> out: {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def assemble(arg_ea: EvaluateType,
             arg_line: str,
             arg_cs: Optional[int] = None,
             arg_ip: Optional[int] = None,
             arg_code_is_32_bit: bool = True,
             arg_keep_size: bool = False,
             arg_debug: bool = False) -> Optional[int]:
    ''' Replacement for ida_idp.assemble() and idautils.Assemble() that has the "not interesting arguments" set to default + add the argument to keep the size of the instruction
        WARNING! IDA does NOT support 64-bit code! Only 32-bit and 16-bit!

        This function is not tested properly and is left "as is" since IDA does _NOT_ support 64-bit code

        @return The address after the one we assembled, this is so we can use to it in a loop
    '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_ip is None:
        _t_segment = segment(l_addr, arg_debug=arg_debug)
        if _t_segment is None:
            log_print("segment() failed", arg_type="ERROR")
            return None
        arg_ip = l_addr - (_ida_segment.sel2para(_t_segment.sel) << 4) # This is how idautils.Assemble() does it. I have no idea what is happening here.

    NOP = "90" # x64/x86 only
    if arg_keep_size:
        l_ins = instruction(l_addr)
        if l_ins is None:
            log_print(f"instruction({_hex_str_if_int(l_addr)}) failed", arg_type="ERROR")
            return None
        instr_size_before = l_ins.size
        original_bytes = _ida_bytes.get_bytes(l_addr, 15)

    fixed_asm = _fix_assembly(arg_line, arg_debug=arg_debug) # IDA can't run assemble() on it's own code from it's own disassembly
    log_print(f"addr: {l_addr:x}, arg_line: '{arg_line}', fixed: '{fixed_asm}', arg_keep_size: {arg_keep_size}", arg_debug)

    if arg_cs is None:
        l_seg = segment(l_addr, arg_debug=arg_debug)
        if l_seg is None:
            log_print(f"segment({_hex_str_if_int(l_addr)}) failed", arg_type="ERROR")
            return None
        arg_cs = l_seg.sel

    log_print(f"_ida_idp.assemble(0x{l_addr:x}, arg_cs={arg_cs}, arg_ip=0x{arg_ip:x}, arg_code_is_32_bit={arg_code_is_32_bit}, line={fixed_asm})", arg_debug)
    if not _ida_idp.assemble(l_addr, arg_cs, arg_ip, arg_code_is_32_bit, fixed_asm): # _ida_idp.assemble can NOT assemble 64-bit code!
        log_print(f"_ida_idp.assemble(0x{l_addr:x}, arg_cs = {arg_cs}, arg_ip = 0x{arg_ip:x}, arg_code_is_32_bit = {arg_code_is_32_bit}, line = '{fixed_asm}') failed!", arg_type="ERROR")
        return None

    l_ins = instruction(l_addr)
    if l_ins is None:
        log_print(f"instruction({_hex_str_if_int(l_addr)}) failed", arg_type="ERROR")
        return None
    instr_size_after = l_ins.size

    log_print(f"_ida_idp.assemble() OK! instr_size_after: {instr_size_after}", arg_debug)
    if arg_keep_size:
        log_print(f"Before: {instr_size_before} -> after: {instr_size_after}", arg_debug)
        if instr_size_after == instr_size_before:
            log_print("Same size", arg_debug)
        elif instr_size_after < instr_size_before:
            log_print("Patching with NOPs", arg_debug)
            _ida_bytes.patch_bytes(l_addr + instr_size_after, bytes(bytearray.fromhex(NOP * (instr_size_before - instr_size_after))))
        else:
            # ERROR! The new code is too big, restore the original code and return an error
            log_print("Code too large", arg_type="ERROR")
            _ida_bytes.patch_bytes(l_addr, original_bytes)
            return None
    return l_addr + instr_size_after

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def disassemble(arg_ea: EvaluateType,
                arg_flags: int = _ida_lines.GENDSM_FORCE_CODE,
                arg_show_size: bool = True,
                arg_show_bytes: bool = True,
                arg_debug: bool = False) -> Optional[str]:
    ''' Disassemble bytes at the given address into assembly string. If you want an object, use ```instruction()``` instead
        Replacement for idc.generate_disasm_line() and ida_lines.generate_disasm_line() Read more at [the official docs](https://python.docs.hex-rays.com/idc/index.html#idc.generate_disasm_line)

        @param arg_ea The address to disassemble
        @param arg_flags Default to ida_lines.GENDSM_FORCE_CODE. Read more at [the official docs](https://python.docs.hex-rays.com/ida_lines/index.html#ida_lines.GENDSM_FORCE_CODE)
        @param arg_show_size If True, then show the size of the instruction
        @param arg_show_bytes If True, then show the bytes of the instruction
        @return The disassembled assembly string or None if it failed
    '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_text = _ida_lines.generate_disasm_line(l_addr, arg_flags)
    if not l_text:
        log_print(f"ida_lines.generate_disasm_line(0x{l_addr:x}, {arg_flags}) failed!", arg_type="ERROR")
        return None

    res = _ida_lines.tag_remove(l_text)
    # Only lower case the mnemonic. Names, strings and comments in the operands are case sensitive (IDA names are case sensitive)
    l_mnemonic, l_separator, l_rest = res.partition(" ")
    res = l_mnemonic.lower() + l_separator + l_rest
    l_ins = instruction(l_addr, arg_debug=arg_debug)
    if l_ins is None:
        log_print(f"instruction({_hex_str_if_int(l_addr)}) failed", arg_type="ERROR")
        return None
    if arg_show_size:
        res += f' ; size: 0x{l_ins.size:x}'
    if arg_show_bytes:
        res += ' ; bytes: ' + " ".join(f"{b:02x}" for b in bytes(l_ins)) # type: ignore[union-attr]
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def instruction(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[_ida_ua.insn_t]:
    '''
    Instruction object at given ea (Effective Address).
    Replacement for ida_ua.decode_insn()
    @param arg_ea The address to get the instruction object for
    @return The instruction object or None if it failed
    '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None
    insn = _ida_ua.insn_t()
    _ida_ua.decode_insn(insn, l_addr)
    if insn.size == 0:
        log_print(f"Instruction is NOT valid at {_hex_str_if_int(l_addr)}", arg_type="ERROR")
        return None
    return insn

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def instruction_before(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[_ida_ua.insn_t]:
    ''' Returns the instruction before the given instruction
    @param arg_ea The address to get the instruction before
    @return The instruction object or None if it failed
    '''
    return instruction(arg_ea=_ida_bytes.get_item_head(address(arg_ea, arg_debug=arg_debug) - 1), arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def instruction_after(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[_ida_ua.insn_t]:
    ''' Returns the instruction after the given instruction
    @param arg_ea The address to get the instruction after
    @return The instruction object or None if it failed
    '''
    return instruction(arg_ea=_ida_bytes.get_item_end(address(arg_ea, arg_debug=arg_debug) + 1), arg_debug=arg_debug)

def xrefs_to(arg_ea: EvaluateType, arg_debug: bool = False) -> Dict[int, _ida_xref.xrefblk_t]:
    ''' Replacement for idautils.XrefsTo()

    OBS! I add the member "type_name" to the objects returned in the dict
    @param arg_ea The address to get the xrefs to
    @return Dict[address: int] --> _ida_xref.xrefblk_t
    '''
    res = {}
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    for l_xref_to in _idautils.XrefsTo(l_addr):
        l_xref_to.type_name = _idautils.XrefTypeName(l_xref_to.type) # Add the type as a human readable string also. There is some black magic going on in _ida_xref.xrefblk_t.refs_from()
        res[l_xref_to.frm] = l_xref_to

    log_print(f"len of dict: {len(res)}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pointer_size(arg_debug: bool = False) -> int:
    ''' Returns the native pointer size on the system in bytes '''

    l_type: Optional[_ida_typeinf.tinfo_t] = _parse_decl('void*', arg_debug=arg_debug)
    if l_type is None:
        log_print("_parse_decl('void*') returned None, fallback to input_file.bits // 8", arg_type="WARNING")
        return input_file.bits // 8
    res = l_type.get_size()
    log_print(f"Pointer size is {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def pointer(arg_ea: EvaluateType, arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Reads a pointer from memory. If no memory is active, then read from the IDB.
    If arg_set_value is set, then write that pointer to the memory. The value does not have to be an address (e.g. 0 --> NULL). Works like WinDBG poi() '''

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if arg_set_value is not None:
        # eval_expression() and NOT address(): the value does not have to be a mapped address (e.g. NULL or a value outside the IDB)
        l_temp_value: Optional[int] = eval_expression(arg_set_value, arg_debug=arg_debug)
        if l_temp_value is None:
            log_print(f"arg_set_value: '{_hex_str_if_int(arg_set_value)}' could not be evaluated", arg_type="ERROR")
            return None
        l_value: int = l_temp_value & ((1 << input_file.bits) - 1) if input_file.bits else l_temp_value # Negative values --> two's complement in the pointer size
        res = qword(l_addr, l_value, arg_debug=arg_debug) if input_file.bits == 64 else dword(l_addr, l_value, arg_debug=arg_debug) if input_file.bits == 32 else word(l_addr, l_value, arg_debug=arg_debug)
    else:
        res = qword(l_addr, arg_debug=arg_debug) if input_file.bits == 64 else dword(l_addr, arg_debug=arg_debug) if input_file.bits == 32 else word(l_addr, arg_debug=arg_debug)
    return res
p = poi = ptr = pointer # WinDBG, I love you and I hate you

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def clipboard_copy(arg_text: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Helper function to put text into the clipboard

    @return Returns True if we could put the text into the clipboard, False otherwise
    '''

    if not isinstance(arg_text, str):
        l_evaled: Optional[int] = eval_expression(arg_text, arg_debug=arg_debug)
        if l_evaled is None:
            log_print(f'eval_expression({arg_text}) returned None', arg_type="ERROR")
            return False
        l_text = f"0x{l_evaled:x}"
    else:
        l_text = arg_text
    log_print(f"We got length 0x{len(l_text):x} --> l_text: '{l_text}'", arg_debug)

    _pyperclip.copy(l_text)
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_get_flags(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[int]:
    ''' Wrapper around ida_bytes.get_flags() '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    return _ida_bytes.get_flags(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_generate_disassembly(arg_ea: int, arg_max_lines: int, arg_as_stack: bool, arg_notag: bool) -> Tuple[int, List[str]]:
    ''' Wrapper around ida_lines.generate_disassembly()
    IDA < 9.2 uses notags, IDA >= 9.2 uses notag as argument name, 8.4 have no keyword args so I use no keyword args to make it work on all of them
    '''
    return _ida_lines.generate_disassembly(arg_ea, arg_max_lines, arg_as_stack, arg_notag)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_code(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Is the given EA (Effective Address) code? '''
    l_flags = _idaapi_get_flags(arg_ea, arg_debug=arg_debug)
    if l_flags is None:
        log_print(f"_flags({_hex_str_if_int(arg_ea)}) returned None", arg_type="ERROR")
        return False
    return _ida_bytes.is_code(l_flags)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_data(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Is the given EA (Effective Address) data? '''
    l_flags = _idaapi_get_flags(arg_ea, arg_debug=arg_debug)
    if l_flags is None:
        log_print(f"_flags({_hex_str_if_int(arg_ea)}) returned None", arg_type="ERROR")
        return False
    return _ida_bytes.is_data(l_flags)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_unknown(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Is the given EA (Effective Address) unknown bytes? '''
    l_flags = _idaapi_get_flags(arg_ea, arg_debug=arg_debug)
    if l_flags is None:
        log_print(f"_flags({_hex_str_if_int(arg_ea)}) returned None", arg_type="ERROR")
        return False
    return _ida_bytes.is_unknown(l_flags)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def is_head(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Is the given EA (Effective Address) the start (head) of an instruction OR a data item? (same as ida_bytes.is_head() says) '''
    l_flags = _idaapi_get_flags(arg_ea, arg_debug=arg_debug)
    if l_flags is None:
        log_print(f"_flags({_hex_str_if_int(arg_ea)}) returned None", arg_type="ERROR")
        return False
    return _ida_bytes.is_head(l_flags)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def make_unknown(arg_ea: EvaluateType, arg_len: int = 1, arg_debug: bool = False) -> Optional[bool]:
    ''' Mark the bytes as unknown '''

    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    res = _ida_bytes.del_items(l_addr, _ida_bytes.DELIT_SIMPLE, arg_len)
    res &= _ida_auto.auto_wait() # waits for the auto analysis to be done. It returns True if everything went smooth and False if the user clicked cancel
    res &= is_unknown(l_addr, arg_debug=arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def make_code(arg_ea: EvaluateType, arg_len: int = 1, arg_force: bool = False, arg_debug: bool = False) -> Optional[bool]:
    ''' Tell IDA to parse the bytes at address as code.
    Replacement for ida_auto.auto_mark_range(a, b, ida_auto.AU_CODE), idc.auto_mark_range(a, b, ida_auto.AU_CODE) and idc.auto_make_code()
    '''

    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if not arg_force:
        l_bytes = read_bytes(l_addr, 8)
        if l_bytes in (bytes.fromhex("0000000000000000"), bytes.fromhex("FFFFFFFFFFFFFFFF")):
            log_print(f"The address 0x{l_addr:x} does not seem to contain code. Use the argument arg_force=True to force the conversion", arg_type="WARNING")
            return False

    _ = make_unknown(l_addr, arg_len=arg_len, arg_debug=arg_debug) # _ida_ua.create_insn() needs to have clear bytes so we mark them as unknown before we make it code
    _ = _ida_ua.create_insn(l_addr)
    return _ida_auto.auto_wait() and is_code(l_addr, arg_debug=arg_debug) # _ida_auto.auto_wait() waits for the auto analysis to be done. It returns true if everything went smooth and false if the user clicked cancel

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def make_data(arg_ea: EvaluateType, arg_item_type: str = "BYTE", arg_number_of_items: int = 1, arg_debug: bool = False) -> Optional[bool]:
    ''' Make address into data, can be used to create arrays also. OBS! If you want create an array or other type, consider using set_type() instead.

    Replacement for ida_bytes.create_data()
    '''
    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_dataflag: int = _ida_bytes.stru_flag() # Default is a structure
    l_flags = {'BYTE': _ida_bytes.byte_flag(), 'WORD': _ida_bytes.word_flag(), 'DWORD': _ida_bytes.dword_flag(), 'QWORD': _ida_bytes.qword_flag()}
    if isinstance(arg_item_type, str):
        l_dataflag = l_flags.get(arg_item_type.upper(), _ida_bytes.stru_flag())

    l_type: Optional[_ida_typeinf.tinfo_t] = get_type(arg_item_type, arg_debug=arg_debug) # TODO: This is not working as expected on MIPS or other things that do not have a type named DWORD and such
    if l_type is None:
        log_print(f"Invalid arg_item_type, you wrote '{arg_item_type}'", arg_type="ERROR")
        return None

    if arg_item_type.upper() not in l_flags and not l_type.is_struct():
        # Not one of the types in the data carousel and not a struct (e.g. "int", "float", "char", "GUID *"), create_data() can't do those with stru_flag().
        # Apply the type (as an array if more than 1 item) with the type system instead
        l_type_to_apply = _ida_typeinf.tinfo_t()
        if arg_number_of_items > 1:
            if not l_type_to_apply.create_array(l_type, arg_number_of_items):
                log_print(f"Could not create an array of {arg_number_of_items} * '{l_type}'", arg_type="ERROR")
                return False
        else:
            l_type_to_apply = l_type
        make_unknown(l_addr, arg_len=max(1, l_type_to_apply.get_size()), arg_debug=arg_debug)
        if not _ida_typeinf.apply_tinfo(l_addr, l_type_to_apply, _ida_typeinf.TINFO_DEFINITE):
            log_print(f"ida_typeinf.apply_tinfo(0x{l_addr:x}, '{l_type_to_apply}') failed", arg_type="ERROR")
            return False
        return _ida_auto.auto_wait() and is_data(l_addr, arg_debug=arg_debug)

    l_type_id = _ida_netnode.BADNODE # If the dataflag is one of the data types in the data carousel, then we set this to ida_netnode.BADNODE
    if l_type.is_struct():
        l_type_id = _idc.get_struc_id(str(l_type))
        if l_type_id == _ida_idaapi.BADADDR:
            log_print(f"Cannot find any struct ID for '{arg_item_type}', make sure it's in the Local Types window", arg_type="ERROR")
            return None

    make_unknown(l_addr, arg_len=arg_number_of_items * l_type.get_size(), arg_debug=arg_debug) # _ida_bytes.create_data() needs to have unknown bytes so we mark them as unknown before we make it data
    log_print(f"Calling _ida_bytes.create_data(0x{l_addr:x}, 0x{l_dataflag:x}, {arg_number_of_items} * {l_type.get_size()}, 0x{l_type_id:x})", arg_debug)
    cd_res = _ida_bytes.create_data(l_addr, l_dataflag, arg_number_of_items * l_type.get_size(), l_type_id)
    if not cd_res:
        log_print(f"ida_bytes.create_data(0x{l_addr:x}, dataflag={l_dataflag}, size=0x{arg_number_of_items:x} * 0x{l_type.get_size():x}, tid=0x{l_type_id:x}) failed", arg_type="ERROR")
        return False
    return _ida_auto.auto_wait() and is_data(l_addr, arg_debug=arg_debug) # _ida_auto.auto_wait() waits for the auto analysis to be done. It returns true if everything went smooth and false if the user clicked cancel

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def make_array(arg_ea: EvaluateType, arg_item_type: str, arg_number_of_items: int, arg_debug: bool = False) -> Optional[bool]:
    ''' Make an array of item type with given length in number of items '''
    return make_data(arg_ea=arg_ea, arg_item_type=arg_item_type, arg_number_of_items=arg_number_of_items, arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_parse_binpat_str(arg_out: _ida_bytes.compiled_binpat_vec_t,
                             arg_ea: int,
                             arg_in: str,
                             arg_radix: int,
                             arg_strlits_encoding: int = 0) -> bool:
    ''' Wrapper around ida_bytes.parse_binpat_str() which have a bad history of return type problems '''
    # TODO: IDA 9.2 say that parse_binpat_str() is deprecated: "Please use compiled_binpat_vec_t.from_pattern() instead" investigate
    l_temp = _ida_bytes.parse_binpat_str(arg_out, arg_ea, arg_in, arg_radix, arg_strlits_encoding) # IDA 9.0 documentation say this is a bool but it STILL returns None on fail and '' (empty string) on success! WTF
    # log_print(f"ida_bytes.parse_binpat_str() have a bad history of type problems... type: {type(_t)}  value: '{_t}'", arg_debug)
    return "" == l_temp

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_bin_search(arg_start_ea: int, arg_end_ea: int, arg_data: _ida_bytes.compiled_binpat_vec_t, arg_flags: int) -> int:
    ''' Wrapper around bin_search() that actually honors the type hints
    @param arg_start_ea: linear address, start of range to search
    @param arg_end_ea: linear address, end of range to search (exclusive)
    @param arg_data: the prepared data to search for (see parse_binpat_str())
    @param arg_flags: combination of ida_bytes.BIN_SEARCH_* flags

    @return: the address of a match, or ida_idaapi.BADADDR if not found
    '''
    res = _ida_bytes.bin_search(arg_start_ea, arg_end_ea, arg_data, arg_flags)
    if ida_version() >= 900: # IDA 9.0 returns a tuple, IDA < 9.0 returns int
        res = res[0]
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_get_encoding_bpu_by_name(arg_encoding_name: str) -> int:
    ''' Wrapper around ida_nalt.get_encoding_bpu_by_name().
    Take a human readable string and get the width of each element. e.g. "utf-8" -> 1, "utf-16" -> 2, "utf-32" -> 4
    However, ida_nalt.get_encoding_bpu_by_name() actually returns 1 even for encodings IDA does NOT recognize which is unexpected
    Some encodings seems to be wrong, like Big5 <https://en.wikipedia.org/wiki/Big5> which should return 2 (I think?)

    [Read more at Hex-Rays blog](https://hex-rays.com/blog/igor-tip-of-the-week-13-string-literals-and-custom-encodings)
    OBS! There is a part where they write "On Linux or macOS, run iconv -l to see the available encodings. Note: some encodings are not supported on all systems so your IDB may become system-specific."
    '''
    l_debug = False
    l_encoding: str =_normalize_encoding_name(arg_encoding_name, arg_debug=l_debug)
    return _ida_nalt.get_encoding_bpu_by_name(l_encoding)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def search_binary(arg_pattern: BufferType,
                  arg_min_ea: Optional[EvaluateType] = None,
                  arg_max_ea: Optional[EvaluateType] = None,
                  arg_use_idas_parser: bool = False,
                  arg_radix: int = 0x10,
                  arg_flags: int = _ida_bytes.BIN_SEARCH_FORWARD,
                  arg_strlits_encoding: Union[int, str] = _ida_bytes.PBSENC_DEF1BPU,
                  arg_max_hits: EvaluateType = 1,
                  arg_debug: bool = False) -> Optional[List[int]]:
    ''' Search for a binary pattern in the file and returns the first hit.
    To get all hits, set the argument arg_max_hits = 0

    @param arg_pattern can be hex string, string, bytes, or list of bytes
    @param arg_min_ea start the search from this address, if None then we start from the first byte we can reach
    @param arg_max_ea end search if we pass this address, if None then we end from the last byte we can reach
    @param arg_use_idas_parser IDA has a special format that is used in the GUI and in their internal API. If you want to use that search type, set this to True
    If this flag is set, then I won't parse the input and just pass it to ida_bytes.parse_binpat_str(). See help(ida_bytes.parse_binpat_str)
    Use this flag if you like to search for byte sequences like "FF ?? ?? 13" (using wildcards)

    @param arg_flags Default: ida_bytes.BIN_SEARCH_FORWARD See ida_bytes.BIN_SEARCH_* for different flags
    @param arg_radix The radix the numerical values in the search pattern is parsed as. Default: 0x10 (hex)
    @param arg_strlits_encoding Default: ida_bytes.PBSENC_DEF1BPU. This is used to parse the literals in the string. e.g. '"CreateFileA"'
    Other values that can be used: ida_bytes.PBSENC_ALL (all encodings IDA know of) or if you send in a string like 'utf-16', then I translate that with ida_nalt.get_encoding_bpu_by_name('utf-16')
    @param arg_max_hits After we found this many hits, we return. Set to 0 for all hits

    @return List[address: int]: List of ints where the search matched or [] if not found, returns None if something failed
    '''
    # TODO: This function needs more testing
    # TODO: split into smaller parts
    l_strlits_encoding: int = _idaapi_get_encoding_bpu_by_name(arg_strlits_encoding) if isinstance(arg_strlits_encoding, str) else arg_strlits_encoding

    l_max_hits: Optional[int] = eval_expression(arg_max_hits, arg_debug=arg_debug)
    if l_max_hits is None:
        log_print('eval_expression(arg_max_hits) failed', arg_type="ERROR")
        return None

    if isinstance(arg_pattern, str) and '?' in arg_pattern:
        log_print("arg_pattern contains '?' (wildcards), then this function only works with IDAs parser -> arg_use_idas_parser = True", arg_debug)
        arg_use_idas_parser = True

    if isinstance(arg_pattern, str) and ((arg_pattern.startswith("'") and arg_pattern.endswith("'")) or (arg_pattern.startswith('"') and arg_pattern.endswith('"'))):
        arg_pattern = '"' + arg_pattern[1:-1] + '"' # IDA only understands " and not '
        log_print("String search only works in IDAs parser -> arg_use_idas_parser = True", arg_debug)
        arg_use_idas_parser = True

    if arg_use_idas_parser:
        if not isinstance(arg_pattern, str):
            log_print(f'arg_use_idas_parser == True --> arg_pattern must be of type str. It is of type: {type(arg_pattern)}', arg_type="ERROR")
            return None
        search_pattern: str = arg_pattern
    else:
        l_parsed_hex = hex_parse(arg_pattern, arg_debug=arg_debug)
        if not l_parsed_hex:
            log_print(f'arg_pattern: "{str(arg_pattern)}" could not be parsed as bytes in any meaningful way. If you want to search for a string, make sure to put " around the string', arg_type="ERROR")
            return None

        search_pattern = " ".join(l_parsed_hex)
    log_print(f"search_pattern: '{str(search_pattern)}'", arg_debug)
    l_binpat = _ida_bytes.compiled_binpat_vec_t()
    if not _idaapi_parse_binpat_str(l_binpat, 0, search_pattern, arg_radix, l_strlits_encoding):
        log_print(f"ida_bytes.parse_binpat_str() failed to parse your input. You gave me {' '.join(hex_parse(arg_pattern))} which I converted to {search_pattern}", arg_type="ERROR")
        return None

    l_min_ea = input_file.min_ea if arg_min_ea is None else address(arg_min_ea, arg_debug=arg_debug)
    if l_min_ea == _ida_idaapi.BADADDR:
        l_min_ea = input_file.min_ea

    if isinstance(arg_max_ea, _ida_segment.segment_t):
        l_max_ea = arg_max_ea.end_ea # bin_search() end is already exclusive
    else:
        l_max_ea = input_file.max_ea if arg_max_ea is None else address(arg_max_ea, arg_debug=arg_debug)
    if l_max_ea == _ida_idaapi.BADADDR:
        l_max_ea = input_file.max_ea

    res = []
    l_search_backward: bool = _bool(arg_flags & _ida_bytes.BIN_SEARCH_BACKWARD)
    l_range_start = l_min_ea
    l_range_end = l_max_ea
    while l_range_start < l_range_end:
        l_hit = _idaapi_bin_search(l_range_start, l_range_end, l_binpat, arg_flags)
        log_print(f"result from _idaapi_bin_search(): {_hex_str_if_int(l_hit)}", arg_debug)
        if l_hit == _ida_idaapi.BADADDR:
            break
        res.append(l_hit)
        if l_search_backward: # Backward search goes from the end of the range towards the start --> shrink the end
            l_range_end = l_hit
        else:
            l_range_start = l_hit + 1
        l_max_hits -= 1
        if l_max_hits == 0:
            break

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def search_text(arg_search_for: str,
                arg_search_direction_down: bool = True,
                arg_search_is_regex: bool = False,
                arg_start_ea: Optional[EvaluateType] = None,
                arg_max_hits: EvaluateType = 1,
                arg_debug: bool = False) -> Optional[List[int]]:
    ''' Search for text in the disassembly view and returns the first hit.
    To get all hits, set the argument arg_max_hits = 0

    @param arg_search_for The string that you see on the screen (that you can mark and copy)
    @param arg_search_direction_down True --> search from the given ```arg_start_ea````and to higher adresses, False --> search from the given ```arg_start_ea````and to lower adresses
    @param arg_search_is_regex True --> Handle the string as a regex, False --> The input string is a literal
    @param arg_start_ea start the search from this address, if None then we start from the first byte we can reach in the IDB
    @param arg_max_hits After we found this many hits, we return. Set to 0 for all hits

    @return List[address: int]: List of ints where the search matched or [] if not found, returns None if something failed
    '''
    res = []
    l_max_hits: Optional[int] = eval_expression(arg_max_hits, arg_debug=arg_debug)
    if l_max_hits is None:
        log_print('eval_expression(arg_max_hits) failed', arg_type="ERROR")
        return None

    l_min_ea = _ida_ida.inf_get_min_ea() if arg_start_ea is None else address(arg_start_ea, arg_debug=arg_debug)
    if l_min_ea == _ida_idaapi.BADADDR:
        l_min_ea = _ida_ida.inf_get_min_ea()

    l_search_flags = _ida_search.SEARCH_DOWN if arg_search_direction_down else _ida_search.SEARCH_UP
    l_search_flags |= _ida_search.SEARCH_NEXT
    l_search_flags |= _ida_search.SEARCH_BRK # return BADADDR if the search was cancelled
    if arg_search_is_regex:
        l_search_flags |= _ida_search.SEARCH_REGEX
    l_start_next_search_at = l_min_ea
    while True:
        l_useless_y: int = 0
        l_useless_x: int = 0
        log_print(f"Calling _ida_search.find_text(0x{l_start_next_search_at:x}, {l_useless_y}, {l_useless_x}, '{arg_search_for}', {l_search_flags})", arg_debug)
        l_start_next_search_at = _ida_search.find_text(l_start_next_search_at, l_useless_y, l_useless_x, arg_search_for, l_search_flags)
        log_print(f"result from ida_search.find_text(): {_hex_str_if_int(l_start_next_search_at)}", arg_debug)
        if l_start_next_search_at == _ida_idaapi.BADADDR:
            break
        res.append(l_start_next_search_at)
        l_start_next_search_at = _ida_bytes.get_item_end(l_start_next_search_at) if arg_search_direction_down else (_ida_bytes.get_item_head(l_start_next_search_at) - 1)
        l_max_hits -= 1
        if l_max_hits == 0:
            break
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def plugin_load_and_run(arg_plugin_name: str, arg_optional_argument_to_plugin: int = 0, arg_debug: bool = False) -> Optional[bool]:
    ''' Load a plugin and run it with optional argument.

    @param arg_plugin_name: The name of the plugin on disk in the IDA plugin directory or a full path to a .py file or full path to a .dll file
    @param arg_optional_argument_to_plugin: Each plugin has it's own way to handle arguments but often it's just 0.

    @return: Returns True or False depending on what the plugin returns. Returns None if the plugin cannot be found.
    '''

    if _os.path.sep not in arg_plugin_name:
        arg_plugin_name = _os.path.splitext(arg_plugin_name)[0]

    log_print(f'Loading plugin: {arg_plugin_name}', arg_debug)
    _plugin = _ida_loader.load_plugin(arg_plugin_name)
    if not _plugin:
        log_print(f"Failed to load plugin '{arg_plugin_name}'", arg_type="ERROR")
        return None

    return _ida_loader.run_plugin(_plugin, arg_optional_argument_to_plugin)

load_and_run_plugin = plugin_load_and_run

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def segments() -> List[_ida_segment.segment_t]:
    ''' Get all segments in the program
    @return Returns List[segment_obj: ida_segment.segment_t]
    '''
    res = []
    for segment_index in range(_ida_segment.get_segm_qty()):
        res.append(_ida_segment.getnseg(segment_index))
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def segment(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[_ida_segment.segment_t]:
    ''' Gets the segment the given EA (Effective Address) '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None
    res: Optional[_ida_segment.segment_t] = _ida_segment.getseg(l_addr)
    if not res:
        log_print(f"_ida_segment.getseg({_hex_str_if_int(l_addr)}) failed", arg_type="ERROR")
        return None

    log_print(f"Segment found: {str(res)}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _segment_permissions(arg_segment: EvaluateType,
                         arg_readable: Optional[bool] = None,
                         arg_writable: Optional[bool] = None,
                         arg_executable: Optional[bool] = None,
                         arg_debug: bool = False) -> int:
    ''' Internal function. To change a sections permissions, use:
    s = segment(<address>)
    s.writable = True

    Gets or sets the permission flags according to the arguments.
    If an argument is set to None, then it won't be changed.

    OBS! During an active debugger session, even if you set the executable flag,
    the memory will not be executable. This is only IDAs view and not what the OS thinks
    This is something I'm thinking of adding but atm I am just so tired of this function...

    '''
    l_temp_segment: Optional[_ida_segment.segment_t] = segment(arg_segment, arg_debug=arg_debug)
    if l_temp_segment is None:
        log_print(f"segment({_hex_str_if_int(arg_segment)}) failed", arg_type="ERROR")
        return -1
    l_segment: _ida_segment.segment_t = l_temp_segment
    l_perm_before: int = l_segment.perm

    MAX_MASK = 0xFFFFFFFFFFFFFFFF
    if arg_readable is not None:
        l_segment.perm = (~_ida_segment.SEGPERM_READ & MAX_MASK) & l_segment.perm            # Always clear the bit first
        l_segment.perm = l_segment.perm | (_ida_segment.SEGPERM_READ if arg_readable else 0) # Then set it if that what is we wanted

    if arg_writable is not None:
        l_segment.perm = (~_ida_segment.SEGPERM_WRITE & MAX_MASK) & l_segment.perm
        l_segment.perm = l_segment.perm | (_ida_segment.SEGPERM_WRITE if arg_writable else 0)

    if arg_executable is not None:
        l_segment.perm = (~_ida_segment.SEGPERM_EXEC & MAX_MASK) & l_segment.perm
        l_segment.perm = l_segment.perm | (_ida_segment.SEGPERM_EXEC if arg_executable else 0)

    if l_segment.perm != l_perm_before:
        # Changing the fields of a segment_t only changes the object in memory, update() is what saves it to the database
        if not l_segment.update():
            log_print(f"segment_t.update() failed for the segment at 0x{l_segment.start_ea:x}", arg_type="ERROR")
            return -1
        _idaapi_request_refresh()

    return l_segment.perm

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def xref_add_code_ref(arg_from: EvaluateType, arg_to: EvaluateType, arg_flags: int = _ida_xref.XREF_USER | _ida_xref.fl_CN, arg_add_comment: bool = True, arg_debug: bool = False) -> Optional[bool]:
    ''' Creates a code xref arg_from --> arg_to.
    IDA does not show anything in the arg_from position so we add a comment at that address
    so we can follow the code xref both ways.

    arg_flags: int = ida_xref.XREF_USER | ida_xref.fl_CN. ida_xref.XREF_USER --> xref created by the user (and not IDA). ida_xref.fl_CN --> Flow: Call Near
    '''

    l_from_addr: int = address(arg_from, arg_debug=arg_debug)
    if l_from_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_from: '{_hex_str_if_int(arg_from)}' could not be located in the IDB", arg_type="ERROR")
        return None
    l_to_addr: int = address(arg_to, arg_debug=arg_debug)
    if l_to_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_to: '{_hex_str_if_int(arg_to)}' could not be located in the IDB", arg_type="ERROR")
        return None

    l_xref_res: bool = _ida_xref.add_cref(l_from_addr, l_to_addr, arg_flags) # Flags are _ida_xref.XREF_*
    if not l_xref_res:
        log_print(f"_ida_xref.add_cref(0x{l_from_addr:x}, 0x{l_to_addr:x}, {arg_flags}) failed", arg_type="ERROR")
        return False
    res = True
    if arg_add_comment:
        res = res and _comment_append(arg_ea=l_from_addr, arg_comment=f"code xref to: 0x{l_to_addr:x}", arg_debug=arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def decompiler_calls(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[List[_ida_hexrays.cexpr_t]]:
    ''' Returns a list of all _ida_hexrays.cexpr_t that is of type "call" '''
    res = []
    l_cfunc = decompile(arg_ea, arg_debug=arg_debug)
    if l_cfunc is None:
        log_print(f"Could not decompile '{_hex_str_if_int(arg_ea)}'", arg_type="ERROR")
        return None
    for item in l_cfunc.treeitems:
        if item.to_specific_type.opname == 'call':
            res.append(item.to_specific_type.cexpr)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def assembler_calls(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[List[_ida_ua.insn_t]]:
    ''' Returns a list of all _ida_ua.insn_t that is of type "call" '''
    res = []
    l_func = function(arg_ea, arg_debug=arg_debug)
    if l_func is None:
        log_print(f"Could not get a function object for '{_hex_str_if_int(arg_ea)}'", arg_type="ERROR")
        return None
    for l_address in l_func.code_items():
        l_ins = instruction(l_address, arg_debug=arg_debug)
        if l_ins is not None and _ida_idp.is_call_insn(l_ins): # Since IDA 7, is_call_insn() takes an insn_t and not an address
            res.append(l_ins)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def file_write_patches_to_file(arg_validate_input_file: bool = True, arg_make_backup: bool = True, arg_debug: bool = False) -> bool:
    ''' Write the bytes that are patched in the IDB into the input file on disk (same as Edit -> Patch program -> Apply patches to input file).
    Patched bytes that have no position in the file (e.g. in .bss or in memory from the debugger) are skipped with a warning.
    @param arg_validate_input_file If True, validate the input file before patching it (by comparing the SHA-256 hash)
    @param arg_make_backup If True, make a backup of the input file (original file name + timestamp + '.bak') in the same directory as the input file
    @return True if the patch was applied successfully, False otherwise
    '''
    import shutil as _shutil
    if arg_validate_input_file:
        if not _os.path.exists(input_file.filename):
            log_print(f"File '{input_file.filename}' does not exist", arg_type="ERROR")
            return False

        import hashlib
        with open(input_file.filename, 'rb') as l_file_validator:
            l_file_contents: bytes = l_file_validator.read()
        l_input_file_hash: str = hashlib.sha256(l_file_contents).hexdigest()
        if l_input_file_hash != input_file.sha256:
            log_print(f"Input file has changed, not going to patch it. Original file hash: {input_file.sha256} != SHA256: {l_input_file_hash}", arg_type="ERROR")
            return False

    if arg_make_backup:
        l_backup_file_path: str = input_file.filename + '.' + _time.strftime(_G_DEFAULT_TIME_FORMAT.replace('-','_').replace(' ','_').replace(':','_').replace('/','_'), _datetime.timetuple(_datetime.now())) + '.bak'
        log_print(f"Backing up to: {l_backup_file_path}", arg_type="INFO")
        _shutil.copyfile(input_file.filename, l_backup_file_path, follow_symlinks=True)

    # Make sure we can write to the file, if we have a file open or a process running, we might need to save to another filename
    l_write_path: str = input_file.filename
    try:
        with open(l_write_path, 'rb+'):
            pass # We only want to test if the file can we written to
    except PermissionError:
        l_write_path = input_file.filename + '.patched'
        log_print(f"Cannot open '{input_file.filename}' for writing. Falling back to: '{l_write_path}'", arg_type="WARNING")
        _shutil.copyfile(input_file.filename, l_write_path, follow_symlinks=True)

    l_num_bytes_patched = 0
    l_skipped_without_file_position: List[int] = []

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _visit_patched_bytes_callback(arg_ea: int, arg_file_pos: int, arg_org_val: int, arg_patch_val: int) -> int:
        ''' Internal function. Please use file_write_patches_to_file() instead.
        @param arg_ea The address of the byte
        @param arg_file_pos The position of the byte in the file, -1 if the byte is not in the file (e.g. .bss or memory from the debugger)
        @param arg_org_val The original value of the byte
        @param arg_patch_val The patch value of the byte
        @return 0 to continue the enumeration, anything else to stop the enumeration
        '''
        nonlocal l_num_bytes_patched
        log_print(f"Patching byte at 0x{arg_ea:x} from 0x{arg_org_val:x} to 0x{arg_patch_val:x} (fpos: {arg_file_pos})", arg_debug)

        if arg_file_pos == -1:
            # The byte is not backed by the file (e.g. .bss or memory from a debugging session), it cannot be written to the file.
            # Skip it and keep going, stopping here would leave the file half patched.
            l_skipped_without_file_position.append(arg_ea)
            return 0

        l_file_patcher.seek(arg_file_pos)
        # OBS! I do NOT need to verify the original value, because the SHA-256 is either correct or the user passed arg_validate_input_file == False and then I don't care about the original value
        l_file_patcher.write(arg_patch_val.to_bytes(1, 'little'))
        l_num_bytes_patched += 1
        return 0 # Return 0 to continue the enumeration

    with open(l_write_path, 'rb+') as l_file_patcher:
        l_visitor_res = _ida_bytes.visit_patched_bytes(input_file.min_ea, input_file.max_ea, _visit_patched_bytes_callback)

    if l_skipped_without_file_position:
        l_examples = ", ".join(f"0x{l_ea:x}" for l_ea in l_skipped_without_file_position[:10])
        log_print(f"Skipped {len(l_skipped_without_file_position)} patched byte(s) that have no position in the file, e.g. {l_examples}", arg_type="WARNING")

    if l_visitor_res != 0:
        log_print(f"Patching failed, visitor returned: {l_visitor_res}", arg_type="ERROR")
        return False

    log_print(f"Patching done, wrote 0x{l_num_bytes_patched:x} ({l_num_bytes_patched}) bytes to: {l_write_path}", arg_type="INFO")
    return True



# DATA TYPES ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- DATA TYPES


_G_DUMMY_FUNCTION_NAME: str = "community_base_dummy_function_name" # Used by _fix_c_type() to give nameless function prototypes a name. OBS! The clang parser does NOT accept "_" as a name

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _fix_c_type(arg_c_type: str, arg_debug: bool = False) -> Optional[str]:
    '''
    Internal function. Please use get_type() instead.
    ida_typeinf.parse_decl() is very strict on the format of the C type.

    Ex: mangled name "._ZdaPvm" --> demangled name "operator delete[](void *, unsigned long)" This will ida_typeinf.parse_decl() not take

    The clang parser (default from IDA 9.5) is stricter than the legacy parser: it needs the ending ';' and it can NOT parse a function prototype without a function name
    if the first argument is a typedef, ex: "PVOID __stdcall(PVOID lpAddress)". When it can parse a nameless prototype it drops the argument names.
    So nameless prototypes get a dummy function name, that string is OK for both parsers: "PVOID __stdcall community_base_dummy_function_name(PVOID lpAddress);"

    @param arg_c_type The C type as a string. Ex: "int", "void *", "PVOID __stdcall(PVOID lpAddress, SIZE_T dwSize)"
    @return A string that ida_typeinf.parse_decl() can parse with both the legacy and the clang parser, None if we failed to fix the string
    '''
    if arg_c_type in ['byte', 'word', 'dword', 'qword']: # Some simple words that I use in lower case should be OK  # TODO: This is not true for things like MIPS
        return arg_c_type.upper() + ';'

    arg_c_type += ";"
    arg_c_type = arg_c_type.replace(";;", ";")
    _til = None

    # A calling convention directly followed by '(' or '@<' means that the function name is missing. "(__stdcall *)" (function pointer) and "__stdcall f(" (has a name) do not match
    l_named_c_type: str = _re.sub(r"\b(__stdcall|__cdecl|__thiscall|__fastcall|__vectorcall|__usercall|__userpurge|__golang|__pascalcall|__pascal)\s*(?=\(|@<)", r"\1 " + _G_DUMMY_FUNCTION_NAME, arg_c_type, count=1)
    if l_named_c_type != arg_c_type:
        log_print(f"Named parse test is of: '{l_named_c_type}'", arg_debug)
        _t = _ida_typeinf.tinfo_t()
        _ida_typeinf.parse_decl(_t, _til, l_named_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
        if _t.is_well_defined():
            log_print(f"Named parse test OK! Returning '{l_named_c_type}'", arg_debug)
            return l_named_c_type

    log_print(f"1st parse test is of: '{arg_c_type}'", arg_debug)
    _t = _ida_typeinf.tinfo_t()
    _ida_typeinf.parse_decl(_t, _til, arg_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
    if _t.is_well_defined():
        log_print(f"1st parse test OK! Returning '{arg_c_type}'", arg_debug)
        return arg_c_type

    # Nameless prototype without calling convention, ex: "PVOID(PVOID lpAddress)". The legacy parser took it in the 1st test, the clang parser needs the name
    l_named_c_type = _re.sub(r"^([^(]*?)\s*\((?!\s*\*)", r"\1 " + _G_DUMMY_FUNCTION_NAME + "(", arg_c_type, count=1) # (?!\s*\*) --> do not touch function pointers like "int (*)(int)"
    if l_named_c_type != arg_c_type and _G_DUMMY_FUNCTION_NAME not in arg_c_type:
        log_print(f"Named parse test without calling convention is of: '{l_named_c_type}'", arg_debug)
        _t = _ida_typeinf.tinfo_t()
        _ida_typeinf.parse_decl(_t, _til, l_named_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
        if _t.is_well_defined() and _t.is_func(): # is_func() so we don't accept something that is not a function after we added a function name
            log_print(f"Named parse test without calling convention OK! Returning '{l_named_c_type}'", arg_debug)
            return l_named_c_type

    # Ex: mangled name "._ZdaPvm" --> demangled name "operator delete[](void *, unsigned long)" --> IDA decompiler: "void __fastcall operator delete[](void *a1, unsigned __int64 a2);" This will _ida_typeinf.parse_decl() not take
    # However, it WILL parse the string "void __fastcall operator_delete__(void *a1, unsigned __int64 a2)"
    arg_c_type = arg_c_type.replace("operator ", "operator_")
    arg_c_type = arg_c_type.replace("[]", "__")

    # Mangled name:  "__int64 std__getline_char_std__char_traits_char__std__allocator_char__()" --> demangled: "std::istream & std::getline<char, std::char_traits<char>, std::allocator<char>>(std::istream &, std::string &, char)" -->
    # IDA prototype: "__int64 std::getline<char,std::char_traits<char>,std::allocator<char>>();" -- > IDA type: "__int64 std__getline_char_std__char_traits_char__std__allocator_char__()"
    arg_c_type = arg_c_type.replace(":", "_")
    arg_c_type = arg_c_type.replace("<", "_")
    arg_c_type = arg_c_type.replace(">", "_")

    # void __fastcall std__runtime_error___runtime_error(std::runtime_error *a1)


    # OBS! Do NOT do replace(" *)", ")") here, that silently changes "void f(char *)" into "void f(char)" which parses fine but is the wrong type
    arg_c_type += ';'
    arg_c_type = arg_c_type.replace(";;", ";")
    arg_c_type = arg_c_type.replace(";;", ";")

    log_print(f"2nd parse test is of: '{arg_c_type}'", arg_debug)
    _t = _ida_typeinf.tinfo_t()
    _ida_typeinf.parse_decl(_t, _til, arg_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
    if _t.is_well_defined():
        log_print(f"2nd parse test OK! Returning '{arg_c_type}'", arg_debug)
        return arg_c_type


    # This is ugly, I know...
    arg_c_type = arg_c_type.replace('__stdcall', '(__stdcall)').replace('((__stdcall))', '(__stdcall)')
    arg_c_type = arg_c_type.replace('__cdecl', '(__cdecl)').replace('((__cdecl))', '(__cdecl)')
    arg_c_type = arg_c_type.replace('__thiscall', '(__thiscall)').replace('((__thiscall))', '(__thiscall)')
    arg_c_type = arg_c_type.replace('__fastcall', '(__fastcall)').replace('((__fastcall))', '(__fastcall)')
    arg_c_type = arg_c_type.replace('__usercall', '(__usercall)').replace('((__usercall))', '(__usercall)')
    arg_c_type = arg_c_type.replace('__userpurge', '(__userpurge)').replace('((__userpurge))', '(__userpurge)')
    arg_c_type = arg_c_type.replace('__golang', '(__golang)').replace('((__golang))', '(__golang)')
    arg_c_type = arg_c_type.replace('__pascalcall', '(__pascalcall)').replace('((__pascalcall))', '(__pascalcall)')

    log_print(f"3rd parse test is of: '{arg_c_type}'", arg_debug)
    _t = _ida_typeinf.tinfo_t()
    _ida_typeinf.parse_decl(_t, _til, arg_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
    if _t.is_well_defined():
        return arg_c_type

    log_print("Failed to make the c type string into something IDA wants to swallow :-(", arg_debug, arg_type="ERROR")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _parse_decl(arg_c_type: str, arg_debug: bool = False) -> Optional[_ida_typeinf.tinfo_t]:
    ''' Internal function. Please use get_type() instead.
    Can convert a C string such as "int* a" to a ida_typeinf.tinfo_t (type information).
    To convert from tinfo_t --> str, use str(my_type).

    OBS! There is a ida_srclang that can handle more advanced C types

    Replacement for ida_typeinf.parse_decl()
    '''

    # TODO: in linux the word 'dword' works but returns wrong type (size 0)
    log_print(f"arg_c_type before _fix_c_type(): '{arg_c_type}'", arg_debug)
    l_c_type: Optional[str] = _fix_c_type(arg_c_type, arg_debug=arg_debug)
    log_print(f"l_c_type after _fix_c_type(): {l_c_type}", arg_debug)
    if not l_c_type:
        log_print(f"_fix_c_type() failed. arg_c_type = '{l_c_type}'", arg_debug, arg_type="ERROR")
        return None

    res = _ida_typeinf.tinfo_t()
    _ida_typeinf.parse_decl(res, None, l_c_type, _ida_typeinf.PT_SIL) # PT_SIL == SILENT, meaning no popup that there were any problems
    if res.is_well_defined():
        log_print(f"Everything is OK, returning a ida_typeinf.tinfo_t with str: '{res}'", arg_debug)
        return res

    log_print(f"ida_typeinf.parse_decl(res, None, '{l_c_type}', ida_typeinf.PT_SIL) failed", arg_type="ERROR")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def get_type(arg_name_or_ea: Union[EvaluateType, _ida_hexrays.lvar_t, _ida_typeinf.tinfo_t],
             arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
             arg_debug: bool = False
             ) -> Optional[_ida_typeinf.tinfo_t]:
    ''' Get the type info from different inputs e.g.
    "_STARTUPINFOW" or
    "CreateFileA" or
    "0x00400000" or
    "char __stdcall(int a1, int a2, int a3)" or
    a register (if the debugger is active) that points to a an address where there is a type
    '''
    if isinstance(arg_name_or_ea, _ida_typeinf.tinfo_t):
        log_print("arg_name_or_ea is already a ida_typeinf.tinfo_t", arg_debug)
        return arg_name_or_ea.copy()

    if isinstance(arg_name_or_ea, _ida_hexrays.lvar_t):
        log_print(f"arg_name_or_ea is {type(arg_name_or_ea)} which have a function named 'type' that returns ida_typeinf.tinfo_t", arg_debug)
        return arg_name_or_ea.type().copy()

    if hasattr(arg_name_or_ea, 'type') and isinstance(arg_name_or_ea.type, _ida_typeinf.tinfo_t):
        log_print(f"arg_name_or_ea is of type: {type(arg_name_or_ea)} which have a member called 'type' which is of type ida_typeinf.tinfo_t", arg_debug)
        return arg_name_or_ea.type.copy()

    if isinstance(arg_name_or_ea, str): # Are we sending in a parsable C type?
        log_print("arg_name_or_ea is a str, trying to convert it directly to a type", arg_debug)
        parsed_c_type = _parse_decl(arg_name_or_ea, arg_debug=arg_debug)
        if parsed_c_type is not None:
            return parsed_c_type
        log_print("Failed to parse it as a str", arg_debug)

    # Is the name we are looking for a function/label/name/register we can reach in our IDB?
    l_addr: int = address(arg_name_or_ea, arg_supress_error=True, arg_debug=arg_debug)
    if l_addr != _ida_idaapi.BADADDR:
        if not arg_cached_cfunc and _ida_funcs.get_func(l_addr) is not None and _ida_funcs.get_func(l_addr).start_ea == l_addr: # Only decompile if it is the start of a function. Data should never be turned into code by asking for its type
            arg_cached_cfunc = decompile(l_addr, arg_debug=arg_debug)

        if arg_cached_cfunc and arg_cached_cfunc.entry_ea == l_addr:
            l_function_prototype: str = function_prototype(arg_cached_cfunc, arg_cached_cfunc=arg_cached_cfunc)
            res = _parse_decl(l_function_prototype, arg_debug=arg_debug)
            log_print(f"address('{arg_name_or_ea}') --> 0x{l_addr:x}, function_prototype --> '{l_function_prototype}', 0x{l_addr:x} can be decompiled, so using the decompiled function prototype", arg_debug)
            if res:
                return res

        res = _ida_typeinf.tinfo_t()
        _ = _ida_nalt.get_tinfo(res, l_addr)
        if res.empty():
            log_print(f"Resolved to address: 0x{l_addr:x} but ida_nalt.get_tinfo() found no type there.", arg_type="ERROR")
            return None
        return res

    # Is the name a standard type in the IDA Type Information Library (TIL)?
    if not isinstance(arg_name_or_ea, str):
        log_print(f"arg_name_or_ea is not of any type I can parse. You sent me {type(arg_name_or_ea)}: {arg_name_or_ea}", arg_type="ERROR")
        return None

    o = _ida_typeinf.get_named_type(None, arg_name_or_ea, _ida_typeinf.NTF_TYPE) # Normal type such as structs and such in the standard Type Information Library (TIL)
    if not o:
        o = _ida_typeinf.get_named_type(None, arg_name_or_ea, _ida_typeinf.NTF_SYMU) # function (unmangled) use NTF_SYMM if you need a mangled name
    if not o:
        log_print(f"ida_typeinf.get_named_type('{arg_name_or_ea}') failed with both NTF_TYPE and NTF_SYMU", arg_type="ERROR")
        return None
    res = _ida_typeinf.tinfo_t()
    l_code, l_type_str, l_fields_str, l_cmt, l_field_cmts, l_sclass, l_value = o
    del l_code # never used but I want to keep the local names for the future
    del l_cmt
    del l_sclass
    del l_value
    if res.deserialize(None, l_type_str, l_fields_str, l_field_cmts):
        log_print("t.deserialize() OK from a TIL", arg_debug)
        return res

    log_print("t.deserialize() failed", arg_type="ERROR")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def set_type(arg_original_type_name_or_ea: EvaluateType, arg_new_type: Union[str, _ida_typeinf.tinfo_t], arg_debug: bool = False) -> bool:
    ''' Set type by name or address.

    @param arg_original_type_name_or_ea:
    1. Known TIL name, e.g. SetFilePointer
    2. Address (or label) where the type should be set

    @param arg_new_type:
    1. cdecl string
    2. _ida_typeinf.tinfo_t
    3. address with a type at it
    4. label with a type at it
    5. Register pointing to an address type

    Replacement for ida_typeinf.apply_tinfo() and ida_typeinf.apply_cdecl() and ida_typeinf.set_symbol_type()
    '''

    l_new_type: Optional[_ida_typeinf.tinfo_t] = get_type(arg_new_type, arg_debug=arg_debug) if isinstance(arg_new_type, str) else arg_new_type
    if l_new_type is None:
        log_print("Failed to convert arg_new_type to ida_typeinf.tinfo_t'", arg_type="ERROR")
        return False

    l_addr = address(arg_original_type_name_or_ea, arg_supress_error=True, arg_debug=arg_debug)
    if l_addr != _ida_idaapi.BADADDR:
        log_print(f"{arg_original_type_name_or_ea} resolved to 0x{l_addr:x} which means I have to use ida_typeinf.apply_tinfo()", arg_debug)
        log_print(f"Calling _ida_typeinf.apply_tinfo(0x{l_addr:x}, '{l_new_type}', ida_typeinf.TINFO_DEFINITE)", arg_debug)

        if not l_new_type.is_func() and not l_new_type.is_funcptr():
            log_print("The type system and the disassembly view can get out of sync. This make_unknown() hack makes sure that whatever was on that address before is now gone", arg_debug)
            make_unknown(l_addr, arg_debug=arg_debug)
        l_applied_ok: bool = _bool(_ida_typeinf.apply_tinfo(l_addr, l_new_type, _ida_typeinf.TINFO_DEFINITE))
        if not l_applied_ok:
            log_print("apply_tinfo() failed, this can happen but it still works...? IDA BUG?", arg_debug)
            l_type_now_temp = get_type(l_addr, arg_debug=arg_debug)
            if l_type_now_temp is None or l_type_now_temp != l_new_type:
                log_print("The type was NOT set correct :-(", arg_type="ERROR")
            else:
                log_print("The type was set correct even if apply_tinfo() returned False.", arg_debug)
                l_applied_ok = True

        # Only touch the symbol type in the TIL if the caller gave us a NAME, e.g. "GetProcAddress" which is both an imported function and a known (function) type name (TIL)
        # If we got an address (or an object), then we would add junk like "dword_403000" or "sub_401000" to the type library.
        if not isinstance(arg_original_type_name_or_ea, str) or _ida_typeinf.get_named_type(None, arg_original_type_name_or_ea.replace("kernel32_", ""), _ida_typeinf.NTF_SYMU) is None:
            _idaapi_request_refresh()
            return l_applied_ok

    if arg_original_type_name_or_ea and isinstance(arg_original_type_name_or_ea, str):
        arg_original_type_name_or_ea = arg_original_type_name_or_ea.replace("kernel32_", "")
        res = l_new_type.set_symbol_type(None, arg_original_type_name_or_ea, _ida_typeinf.NTF_REPLACE)       # If you call set_named_type() instead, then the local types will be created. The set_symbol_type() will set the TIL (for this IDB)
        log_print(f"Calling set_symbol_type() with arg_original_type_name_or_ea: '{arg_original_type_name_or_ea}' returned {'OK' if res == _ida_typeinf.TERR_OK else res}", arg_debug)
    else:
        log_print(f"'if arg_original_type_name_or_ea and isinstance(arg_original_type_name_or_ea, str)' failed. {type(arg_original_type_name_or_ea)} = '{arg_original_type_name_or_ea}'", arg_type="ERROR")
        return False

    res = _ida_typeinf.TERR_OK == res
    _idaapi_request_refresh()
    if l_addr != _ida_idaapi.BADADDR: # The type at the address is what the caller asked for, the TIL symbol is a bonus
        if not res:
            log_print(f"The type was applied at 0x{l_addr:x} but set_symbol_type('{arg_original_type_name_or_ea}') failed", arg_type="WARNING")
        return l_applied_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _display_type_at_as_dict(arg_ea: EvaluateType,
                             arg_type: Union[EvaluateType,_ida_hexrays.lvar_t, _ida_typeinf.tinfo_t],
                             arg_member_name: str = "",
                             arg_max_num_recursive: int = 10,
                             arg_debug: bool = False) -> Optional[Dict[int, Tuple]]:
    ''' Like Windbgs command dt, this can show you an object pasted at a given address '''
    # TODO: This function is very brittle, test hard and maybe rewrite?
    # TODO: Am I reinventing the wheel here? Look at:
    # dos_tp = idaapi.Appcall.typedobj('IMAGE_DOS_HEADER;') # from https://github.com/allthingsida/allthingsida/blob/0bf54e148a212a59e64b72c19f6ae181cc633bcd/file-formats/pe-file/common.py#L12
    # parsed = dos_tp.retrieve(addr)[1] # retrieve returns a tuple (<read ok: int>, <parsed data object>:object)
    # print([x for x in dir(parsed) if not x.startswith("__")])

    if arg_max_num_recursive < 1:
        log_print(f"Max recursive depth reached ({arg_max_num_recursive}), not going deeper.", arg_type="WARNING")
        return {}

    res: Dict[int, Tuple] = {}
    l_type = get_type(arg_type, arg_debug=arg_debug)
    if l_type is None:
        log_print("failed to parse arg_type", arg_type="ERROR")
        return None

    l_addr = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the IDB", arg_type="ERROR")
        return None

    if l_type.is_struct():
        log_print("l_type is a struct, we are going to enumerate all members (udm)", arg_debug)

        l_udt_details = _ida_typeinf.udt_type_data_t()
        l_type.get_udt_details(l_udt_details)
        for l_udm in l_udt_details:
            if l_udm.is_gap():
                log_print("l_udm is_gap(), skipping", arg_debug)
                continue
            log_print(f"l_udm: name: {l_udm.name}, tinfo: {l_udm.type}, offset in bytes: 0x{l_udm.offset//8:x}, size: 0x{l_udm.size//8}", arg_debug) # OBS! Offset is in bits

            l_temp = _display_type_at_as_dict(l_addr + l_udm.offset//8, arg_type=l_udm.type, arg_member_name=f"{arg_member_name}<{l_type}>.{l_udm.name}", arg_max_num_recursive=arg_max_num_recursive-1, arg_debug=arg_debug)
            if l_temp is None:
                return res
            for k, v in l_temp.items():
                res[k] = v

    elif l_type.is_array():
        l_array_details = _ida_typeinf.array_type_data_t()
        l_type.get_array_details(l_array_details)
        log_print(f"The array has {l_array_details.nelems} elements", arg_debug)

        if str(l_array_details.elem_type) in ("char", "const char"):
            log_print("char[] should be printed as 1 string", arg_debug)
            return {l_addr: ("", str(l_type), string(l_addr, arg_encoding="utf-8", arg_len=l_array_details.nelems, arg_debug=arg_debug))}

        if str(l_array_details.elem_type) in ("wchar_t", "const wchar_t"):
            log_print("wchar_t[] should be printed as 1 string", arg_debug)
            return {l_addr: ("", str(l_type), string(l_addr, arg_encoding="utf-16LE", arg_len=l_array_details.nelems * l_array_details.elem_type.get_size(), arg_debug=arg_debug))} # arg_len is in bytes, not in elements

        for i in range(0, l_array_details.nelems):
            l_member_name = arg_member_name
            if l_member_name:
                l_member_name += f"[{i}]"

            l_temp = _display_type_at_as_dict(l_addr + i * l_array_details.elem_type.size, arg_type=l_array_details.elem_type, arg_member_name=l_member_name, arg_max_num_recursive=arg_max_num_recursive-1, arg_debug=arg_debug)
            if l_temp is None:
                return res
            for k, v in l_temp.items():
                res[k] = v
    else:
        log_print("l_type is not a struct nor an array, using typeobj to read the data", arg_debug)

        if str(l_type) in ("PWSTR", "wchar_t *"):
            log_print("l_type is PWSTR, using my special code to read the string", arg_debug)
            l_points_to = pointer(l_addr, arg_debug=arg_debug)
            if l_points_to is None:
                log_print("pointer() failed", arg_type="ERROR")
                return {l_addr: (arg_member_name, str(l_type), _ida_idaapi.BADADDR)}
            l_string = string(l_points_to, arg_debug=arg_debug)
            log_print(f'{string_encoding(l_points_to, arg_debug=arg_debug)} string: "{l_string}"', arg_debug)
            return {l_addr: (arg_member_name, str(l_type), _hex_str_if_int(l_points_to)), l_points_to: (f"{arg_member_name}<data>", "str" , l_string)}

        # Normal simple types can be read here
        l_typed_obj = _ida_idd.Appcall.typedobj(l_type)
        l_ok, l_parsed_data = l_typed_obj.retrieve(l_addr)
        if l_ok:
            return {l_addr: (arg_member_name, str(l_type), _hex_str_if_int(l_parsed_data))}
        else:
            log_print(f"Failed to parse type: {l_type} at {_hex_str_if_int(l_addr)}", arg_type="ERROR")
            return {}
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def display_type_at(arg_ea: EvaluateType,
                    arg_type: Union[EvaluateType, _ida_hexrays.lvar_t, _ida_typeinf.tinfo_t],
                    arg_max_num_recursive: int = 10,
                    arg_debug: bool = False) -> str:
    ''' Display the data as nice to look at. If you want to parse it, use _display_type_at_as_dict() '''
    return _json.dumps(_display_type_at_as_dict(arg_ea=arg_ea, arg_type=arg_type, arg_member_name="", arg_max_num_recursive=arg_max_num_recursive, arg_debug=arg_debug), ensure_ascii=False,  indent=4, default=str)

dt = display_type_at # Windbg <3


# DEBUGGER ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- DEBUGGER


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_refresh_memory_WARNING_VERY_EXPENSIVE() -> None:
    ''' Force a refresh of IDAs view on the targets memory.
    WARNING! This is a VERY expensive function if the debugger is active, if not --> fast
    Read more on [refresh_debugger_memory](https://python.docs.hex-rays.com/ida_dbg/index.html#ida_dbg.refresh_debugger_memory)
    '''
    _ida_dbg.refresh_debugger_memory()
    return

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_is_active() -> bool:
    ''' Check if the debugger is active.
      @return Returns True if the debugger is active and False otherwise
    '''
    return _ida_dbg.is_debugger_on()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def process_is_suspended() -> Optional[bool]:
    ''' Returns True if the debugger is active and the process is suspended.
        Returns False if the debugger is active but the process is not suspended.
        Returns None if debugger is not active
       '''
    if not debugger_is_active():
        log_print("You must have an active debugging session to use this function", arg_type="ERROR")
        return None

    return _ida_dbg.get_process_state() == _ida_dbg.DSTATE_SUSP

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _step_synchronous(arg_num_step_to_take: int = 1, arg_step_into: bool = True, arg_seconds_max_wait: int = 60, arg_debug: bool = False) -> Optional[int]:
    ''' The normal ida_dbg.step_into() / ida_dbg.step_over() is asynchronous which can make it a little tricky to use.
    @param arg_seconds_max_wait: number of seconds to wait, -1 --> infinity

    @return: event_id_t (if > 0) or dbg_event_code_t (if <= 0) of the LAST step
    See ida_dbg.wait_for_next_event() for the return value help.

    read more: [ida_dbg.wait_for_next_event()](https://python.docs.hex-rays.com/ida_dbg/index.html#ida_dbg.wait_for_next_event)
    [AllThingsIDA on YouTube](https://www.youtube.com/watch?v=vS_xjnKW21I)
    '''
    if not process_is_suspended():
        log_print("The process must be suspended. Use debugger_suspend() and to resume the process: use debugger_resume()", arg_type="ERROR")
        return None

    if arg_num_step_to_take < 1:
        log_print(f"arg_num_step_to_take must be >= 1, got {arg_num_step_to_take}", arg_type="ERROR")
        return None

    res: Optional[int] = None
    for _ in range(0, arg_num_step_to_take):
        if arg_step_into:
            _ida_dbg.step_into()
        else:
            _ida_dbg.step_over()
        res = _ida_dbg.wait_for_next_event(_ida_dbg.WFNE_SUSP, arg_seconds_max_wait)
        log_print(f"ida_dbg.wait_for_next_event() returned {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_step_into_synchronous(arg_num_step_to_take: int = 1, arg_seconds_max_wait: int = 60, arg_debug: bool = False) -> Optional[int]:
    ''' The normal ida_dbg.step_into() is asynchronous which can make it a little tricky to use
    @param arg_seconds_max_wait: number of seconds to wait, -1 --> infinity

    @return: event_id_t (if > 0) or dbg_event_code_t (if <= 0) of the LAST step
    See ida_dbg.wait_for_next_event() for the return value help.

    read more: [ida_dbg.wait_for_next_event()](https://python.docs.hex-rays.com/ida_dbg/index.html#ida_dbg.wait_for_next_event)
    [AllThingsIDA on Youtube](https://www.youtube.com/watch?v=vS_xjnKW21I)
    '''

    return _step_synchronous(arg_num_step_to_take=arg_num_step_to_take, arg_step_into=True, arg_seconds_max_wait=arg_seconds_max_wait, arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_step_over_synchronous(arg_num_step_to_take: int = 1, arg_seconds_max_wait: int = 60, arg_debug: bool = False) -> Optional[int]:
    ''' The normal ida_dbg.step_over() is asynchronous which can make it a little tricky to use
    @param arg_seconds_max_wait: number of seconds to wait, -1 --> infinity

    @return: event_id_t (if > 0) or dbg_event_code_t (if <= 0) of the LAST step
    See ida_dbg.wait_for_next_event() for the return value help.

    read more: [ida_dbg.wait_for_next_event()](https://python.docs.hex-rays.com/ida_dbg/index.html#ida_dbg.wait_for_next_event)
    [AllThingsIDA on Youtube](https://www.youtube.com/watch?v=vS_xjnKW21I)
    '''
    return _step_synchronous(arg_num_step_to_take=arg_num_step_to_take, arg_step_into=False, arg_seconds_max_wait=arg_seconds_max_wait, arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint_add(arg_ea: EvaluateType,
                   arg_size: int = 0,
                   arg_breakpoint_type: int = _ida_idd.BPT_DEFAULT,
                   arg_condition: str = '',
                   arg_debug: bool = False) -> Optional[_ida_dbg.bpt_t]:
    ''' Add (set) a breakpoint (Software or Hardware)

    @param arg_ea Where to set the breakpoint. Anything that address() can resolve: an address (int), a name/label, a register name and so on
    @param arg_size The number of bytes the breakpoint covers. Only used by hardware breakpoints, on x86/x64 the valid sizes are 1, 2, 4 and 8 (8 only on x64).
                    Use 0 for software breakpoints. If it is 0 and arg_breakpoint_type is BPT_READ, BPT_WRITE or BPT_EXEC then it is set to 1
    @param arg_breakpoint_type The type of the breakpoint, one of the ida_idd.BPT_* constants:
                    ida_idd.BPT_DEFAULT (BPT_SOFT | BPT_EXEC) lets IDA choose the type automatically. This is the default
                    ida_idd.BPT_SOFT    software breakpoint
                    ida_idd.BPT_EXEC    hardware breakpoint on execute
                    ida_idd.BPT_WRITE   hardware breakpoint on write
                    ida_idd.BPT_READ    hardware breakpoint on read. OBS! x86/x64 CPUs can not break on read only, use BPT_RDWR there
                    ida_idd.BPT_RDWR    hardware breakpoint on read or write. OBS! arg_size is NOT set to 1 for this type, you must give the size yourself
    @param arg_condition A Python expression that is evaluated every time the breakpoint is hit, the debugger only stops if it is True. '' (default) means always stop
    @param arg_debug Print debug messages

    @return The new breakpoint as ida_dbg.bpt_t. None if arg_ea could not be resolved, if the breakpoint could not be added (ex: there is already a breakpoint at that address)
            or if the breakpoint could not be read back or updated
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return None

    if arg_breakpoint_type in [_ida_idd.BPT_READ, _ida_idd.BPT_WRITE, _ida_idd.BPT_EXEC] and arg_size == 0:
        log_print("Your arg_type is a hardware breakpoint but no size is given so I set arg_size to 1", arg_type="WARNING")
        arg_size = 1

    l_success: bool = _ida_dbg.add_bpt(l_addr, arg_size, arg_breakpoint_type)
    if not l_success:
        log_print(f"ida_dbg.add_bpt(0x{l_addr:x}, 0x{arg_size:x}, 0x{arg_breakpoint_type:x}) returned False. Maybe there is already a breakpoint there?", arg_type="ERROR")
        return None

    l_bpt = _ida_dbg.bpt_t()
    l_success = _ida_dbg.get_bpt(l_addr, l_bpt)
    if not l_success:
        log_print(f"ida_dbg.get_bpt(0x{l_addr:x}, l_bpt) returned False", arg_type="ERROR")
        return None

    if arg_condition:
        l_bpt.condition = arg_condition
        l_bpt.elang = 'Python'
    l_update_bpt = debugger_breakpoint_update(l_bpt)
    if not l_update_bpt:
        log_print("ida_dbg.update_bpt(l_bpt) returned False", arg_type="ERROR")
        return None
    return l_bpt

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint_disable(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Disable a breakpoint '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return None

    return _ida_dbg.disable_bpt(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint_enable(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Enable a breakpoint '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return None

    return _ida_dbg.enable_bpt(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint_delete(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Delete a breakpoint '''

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return None

    return _ida_dbg.del_bpt(l_addr)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint(arg_ea: EvaluateType, arg_create_if_needed: bool = False, arg_debug: bool = False) -> Optional[_ida_dbg.bpt_t]:
    ''' Get the breakpoint at the given address. If there is no breakpoint there, returns None
    @param arg_create_if_needed if there is no breakpoint, then create one at that address if this argument is set
    '''

    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return None

    res = _ida_dbg.bpt_t()
    l_success: bool = _ida_dbg.get_bpt(l_addr, res)
    if not l_success and arg_create_if_needed:
        debugger_breakpoint_add(arg_ea=l_addr, arg_debug=arg_debug)
        l_success = _ida_dbg.get_bpt(l_addr, res)

    if not l_success:
        log_print(f"Could not get breakpoint at 0x{l_addr:x} (ida_dbg.get_bpt() returned False)", arg_type="ERROR")
        return None

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoint_update(arg_breakpoint: _ida_dbg.bpt_t) -> bool:
    ''' Update (change) a breakpoint that already exists.
    OBS! You can NOT change the address (ea) of the breakpoint with this function!
    ida_dbg.update_bpt have a long docstring with potential problems, please read that.
    '''
    return _ida_dbg.update_bpt(arg_breakpoint)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_breakpoints() -> List[_ida_dbg.bpt_t]:
    ''' Get all breakpoints '''
    res = []
    for i in range(_ida_dbg.get_bpt_qty()):
        l_t_breakpoint = _ida_dbg.bpt_t()
        if _ida_dbg.getn_bpt(i, l_t_breakpoint):
            res.append(l_t_breakpoint)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_select(arg_debugger: str = "win32", arg_use_remote: bool = False, arg_options: int = _ida_dbg.DOPT_TEMP_HWBPT | _ida_dbg.DOPT_FAST_STEP) -> bool:
    ''' Select what debugger you want to use and what options
    @param arg_debugger What debugger, very strange way IDA picks debugger. Check <https://youtu.be/vS_xjnKW21I?t=80> for an explanation
    @param arg_options flags from ida_dbg.DOPT_*. Default is: ida_dbg.DOPT_TEMP_HWBPT --> Use hardware breakpoints for stepping and ida_dbg.DOPT_FAST_STEP --> Do NOT refresh memory on each step

    See also: ida_dbg.set_remote_debugger()
    [AllThingsIDA on YouTube](https://www.youtube.com/watch?v=vS_xjnKW21I)
    '''
    # arg_debugger can be: ("bochs", remote=False), ("win32", remote=True|False), "GDB", ("windbg", remote=True)

    l_old_options: int = _ida_dbg.set_debugger_options(arg_options)
    del l_old_options
    res = _ida_dbg.load_debugger(arg_debugger, arg_use_remote)
    if not res:
        log_print(f'ida_dbg.load_debugger("{arg_debugger}", arg_use_remote={arg_use_remote}) failed', arg_type="ERROR")
        if arg_debugger == "win32":
            log_print('I suggest: debugger_select("windbg", arg_use_remote=True)')
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_process_start(arg_path: str = "", arg_args: str = "", arg_start_dir: str = "") -> int:
    ''' Passthru ida_dbg.start_process()
    Read more: [ida_dbg.start_process()](https://python.docs.hex-rays.com/ida_dbg/index.html#ida_dbg.start_process)
    '''
    return _ida_dbg.start_process(arg_path, arg_args, arg_start_dir)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_process_id() -> int:
    ''' Get the PID of the running process.

    @return pid on OK, -1 --> error
    '''
    l_debug_event: _ida_idd.debug_event_t = _ida_dbg.get_debug_event()
    # l_debug_event.info() or l_debug_event.modinfo() # Causes IDA bug: Internal error 1502 occurred when running a script. Either
    #   - the script misused the IDA API, or
    #   - there is a logic error in IDA
    # Please check the script first.
    # If it appears correct, send a bug report to <support@hex-rays.com>.
    # In any case we strongly recommend you to restart IDA as soon as possible.
    return l_debug_event.pid

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_run_to_synchronous(arg_ea: EvaluateType, arg_seconds_max_wait: int = -1, arg_debug: bool = False) -> bool:
    ''' Replacement for ida_dbg.run_to()

    @param arg_seconds_max_wait how many seconds to wait until timeout, -1 --> infinity
    @return True if everything went OK, False if something failed
    '''
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"arg_ea: '{_hex_str_if_int(arg_ea)}' could not be located in the process", arg_type="ERROR")
        return False

    if not process_is_suspended():
        log_print("The process must be suspended. Use debugger_suspend() and to resume the process, use debugger_resume()", arg_type="ERROR")
        return False

    if not _ida_dbg.run_to(l_addr):
        log_print(f"ida_dbg.run_to(0x{l_addr:x}) failed", arg_type="ERROR")
        return False
    l_event = _ida_dbg.wait_for_next_event(_ida_dbg.WFNE_SUSP, arg_seconds_max_wait)
    if l_event <= 0: # 0 --> timeout, < 0 --> error (see ida_dbg.wait_for_next_event())
        log_print(f"ida_dbg.wait_for_next_event() returned {l_event} (timeout or error)", arg_type="ERROR")
        return False
    if _ida_dbg.get_ip_val() != l_addr:
        log_print(f"The process stopped at 0x{_ida_dbg.get_ip_val():x} and not at 0x{l_addr:x} (breakpoint or exception on the way?)", arg_type="WARNING")
        return False
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_process_list(arg_name_filter_regex: str = ".*", arg_debug: bool = False) -> List[_ida_idd.process_info_t]:
    ''' List all process that are running
    @param arg_name_filter_regex Only processes which name fully match this regex
    '''
    res = []
    l_processes = _ida_idd.procinfo_vec_t()
    l_num_processes = _ida_dbg.get_processes(l_processes)
    if l_num_processes == -1:
        log_print("ida_dbg.get_processes() failed, maybe you haven't selected any debugger? See debugger_select()", arg_type="ERROR")
        return []
    log_print(f"Number of processes: {l_num_processes}", arg_debug)
    for l_process in l_processes:
        if not _re.fullmatch(arg_name_filter_regex, l_process.name):
            continue
        l_t_process_info = _ida_idd.process_info_t()
        l_t_process_info.name = l_process.name
        l_t_process_info.pid = l_process.pid
        log_print(f"Process name: {l_t_process_info.pid}, PID: 0x{l_t_process_info.pid:x} ({l_t_process_info.pid})", arg_debug)
        res.append(l_t_process_info)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_suspend() -> bool:
    ''' Passthru for ida_dbg.suspend_process() '''
    return _ida_dbg.suspend_process()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_resume() -> bool:
    ''' Passthru for ida_dbg.continue_process() '''
    return _ida_dbg.continue_process()

debugger_process_continue = debugger_resume

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_command(arg_command: str) -> Tuple[bool, str]:
    ''' Passthru for ida_dbg.send_dbg_command()
    Used to send raw commands to the debugger backend. Works best with WinDbg, GDB and Bochs
    '''
    return _ida_dbg.send_dbg_command(arg_command)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_detach() -> bool:
    ''' Passthru for ida_dbg.detach_process() '''
    return _ida_dbg.detach_process()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_exit() -> bool:
    ''' Passthru for ida_dbg.exit_process() '''
    return _ida_dbg.exit_process()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def debugger_process_options(arg_debug: bool = False) -> Dict[str, str]:
    ''' Get the options which the process is started '''
    (file_on_disk, program_arguments, directory, remote_server_ip, remote_server_password, remote_server_port) = _ida_dbg.get_process_options()
    res = {'file_on_disk': file_on_disk,
           'program_arguments' : program_arguments,
           'directory': directory,
           'remote_server_ip': remote_server_ip,
           'remote_server_password': remote_server_password,
           'remote_server_port': str(remote_server_port)}
    log_print(f"res: {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _add_property_to_registers_object(arg_reg_name: str, arg_debug: bool = False):
    ''' Internal function. This has to be its own function because of how Python closures work ("late binding"):
    a lambda created directly in the loop in _populate_register_dict() looks up the loop variable when it is CALLED, not when it is created,
    so every register property would use the LAST register name of the loop. Calling this function gives each lambda its own arg_reg_name.
    (The same can be done inline with a default argument: lambda self, arg_reg_name=arg_reg_name: ...)
    '''
    arg_reg_name = arg_reg_name.replace('$', '').lower() # MIPS
    setattr(_registers_object, arg_reg_name, property(fget=lambda self: registers._as_dict[arg_reg_name], fset=lambda self, value: _register(arg_reg_name, arg_set_value=value, arg_debug=arg_debug))) # type: ignore[arg-type] # To be honest, I don't understand what mypy is complaining about

class _registers_object():
    ''' Interface to interact with the registers. It works like idautils.cpu but my version supports tab completion.

        In general, you should not create objects of this class but instead use the community_base.registers object
    '''
    _as_dict: Dict[str, _ida_idp.reg_info_t] = {}

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __init__(self, arg_reg_sizes: Optional[List[int]] = None, arg_debug: bool = False):
        ''' Find all registers in the current processor module. See _populate_register_dict() for arg_reg_sizes '''
        self._populate_register_dict(arg_reg_sizes=arg_reg_sizes, arg_debug=arg_debug)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _populate_register_dict(self, arg_reg_sizes: Optional[List[int]] = None, arg_debug: bool = False) -> Dict[str, _ida_idp.reg_info_t]:
        ''' Returns a dict that contains all registers in this processor module.
        The dict looks like: Dict[register_name: str] = register_info: _ida_idp.reg_info_t

        OBS! This function is relatively slow and if you just want a list of strings to check register names against then use
        'rax' in community_base.registers._as_dict

        Replacement for idautils.GetRegisterList() and _ida_idp.ph_get_regnames() which do NOT return a complete list. RAX is missing among many.
        '''
        self._as_dict = {}
        if arg_reg_sizes is None:
            arg_reg_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256] # This is bytes

        if isinstance(arg_reg_sizes, int):
            arg_reg_sizes = [arg_reg_sizes]

        for l_reg_index in range(0, 500):
            for l_reg_size_in_bytes in arg_reg_sizes:
                l_reg_name: str = _ida_idp.get_reg_name(l_reg_index, l_reg_size_in_bytes) or "<no register name>"
                if l_reg_name in ['k0', 'k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'mxcsr', 'bnd0', 'bnd1', 'bnd2', 'bnd3', 'fpctrl', 'fpstat', 'fptags']: # Ignore these special registers
                    continue
                # log_print(f"_ida_idp.get_reg_name({reg_index}, {reg_size_in_bytes}): {reg_name}", arg_debug)
                l_reg_info = _ida_idp.reg_info_t()
                if _ida_idp.parse_reg_name(l_reg_info, l_reg_name) and l_reg_info.size == l_reg_size_in_bytes:
                    l_reg_name = l_reg_name.replace('$', '').lower() # MIPS
                    self._as_dict[l_reg_name] = l_reg_info
                    _add_property_to_registers_object(l_reg_name, arg_debug=arg_debug)
        return self._as_dict

    def __str__(self) -> str:
        ''' All register names, sorted and comma separated '''
        l_regs = [reg for reg in self._as_dict]
        l_regs.sort()
        return ", ".join(l_regs)

    def __repr__(self) -> str:
        ''' The type and all register names '''
        return f"{type(self)} with the following registers:\n{str(self)}"

registers = _registers_object() # Recreated in the "_new_file_opened_notification_callback" function

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _register(arg_register: Union[str, _ida_idp.reg_info_t], arg_set_value: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[int]:
    ''' Internal function. The public interface is the community_base.registers.<register_name>
    Get or set the value in a register in a running process '''

    if not process_is_suspended():
        log_print("The process must be suspended to be able to read/write the register. Use debugger_suspend() and to resume the process: use debugger_resume()", arg_type="ERROR")
        return None

    if isinstance(arg_register, _ida_idp.reg_info_t):
        arg_register = _ida_idp.get_reg_name(arg_register.reg, arg_register.size)
        log_print(f"arg_register is of type ida_idp.reg_info_t, using that info to get the register name: '{arg_register}'", arg_debug)
    else:
        if arg_register not in registers._as_dict:
            log_print(f"arg_register: '{arg_register}' is not a valid register. These registers are support in this architecture:\n{str(registers)}", arg_type="ERROR")
            return None

    if arg_set_value is not None:
        log_print(f"Set value: {arg_set_value} will be checked by eval_expression()", arg_debug)
        l_expr_res: Optional[int] = eval_expression(arg_set_value, arg_debug=arg_debug)     # OBS! eval_expression() understands register names so _register('rax', 'rbx') has the effect: rax = rbx
        if isinstance(l_expr_res, int):
            _ida_dbg.set_reg_val(arg_register, l_expr_res)
        else:
            log_print(f"eval_expression('{arg_set_value}') returned None", arg_type="ERROR")
            return None
    res = None
    try:
        res = _ida_dbg.get_reg_val(arg_register)
        if isinstance(res, bytes):
            log_print("Registers such at xmm1 (and more) have return value that is of type bytes and not int)", arg_debug)
            res = int.from_bytes(res, 'little')

    except Exception as exc:
        log_print(f"res = ida_dbg.get_reg_val('{arg_register}') threw an exception:'", arg_type="ERROR")
        log_print(str(exc), arg_type="ERROR")
        return None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def appcall(arg_function_name: EvaluateType,
            arg_prototype: Union[EvaluateType, _ida_typeinf.tinfo_t, None] = None,
            arg_set_type_in_IDB: bool = True,
            arg_debug: bool = False
            ) -> Optional[_ida_idd.Appcall_callable__]:
    ''' To easy call functions (Appcall) from the python code, this function can help you make it callable.
    Hexrays example code: <https://hex-rays.com/blog/practical-appcall-examples/>
    <https://docs.hex-rays.com/user-guide/debugger/debugger-tutorials/appcall_primer>
    AllThingsIDA: <https://www.youtube.com/watch?v=GZUHXkV0vdM>

    @param arg_prototype can be either: c type string, ida_typeinf.tinfo_t, address/name/label/register which can be resolved to an address and then the type is read from that location
    @param arg_set_type_in_IDB: Set the type at the function start in the IDB also

    If you are debugging and have a function you want to call:
    decrypt_function = appcall('this_is_the_decrypt_function')
    res = decrypt_function(0x00401000, 0x12) # The arguments here are whatever that function you are calling have
    print(res)

    Replacement for ida_idd.Appcall.proto()
    '''
    if not process_is_suspended():
        log_print("The process must be active and suspended to be able to use appcall. Use debugger_suspend() and to resume the process: debugger_resume()", arg_type="ERROR")
        return None

    l_addr = address(arg_function_name, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"Could not find {arg_function_name}", arg_type="ERROR")
        return None

    l_function_prototype: Optional[_ida_typeinf.tinfo_t] = get_type(l_addr if arg_prototype is None else arg_prototype, arg_debug=arg_debug)
    if l_function_prototype is None:
        log_print(f"Failed to get a good type on'{_hex_str_if_int(l_addr)}'. Either set it with set_type() or pass the argument arg_prototype to this function.", arg_type="ERROR")
        return None

    if arg_set_type_in_IDB:
        set_type(l_addr, l_function_prototype, arg_debug=arg_debug)

    log_print(f"Calling ida_idd.Appcall.proto('{name(l_addr,arg_debug=arg_debug)}', '{l_function_prototype}')", arg_debug)
    res = _ida_idd.Appcall.proto(l_addr, l_function_prototype)
    res.__doc__ = l_function_prototype
    res.prototype = l_function_prototype
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def allocate_memory_in_target(arg_size: EvaluateType, arg_executable: bool = False, arg_debug: bool = False) -> Optional[int]:
    ''' If the debugger is active, try to allocate memory in target process.

    This function is using the Appcall magic in IDA, it can only be used in an active debugger session.
    It saves the current state and sets the arguments and then calls the function. After the function call is complete, IDA sets the state back to what it was before.
    To know where to set the arguments, the function must have a proper type. You can se how I use the function here under in my code.

    OBS! There are many moving parts in this function and it needs more testing, please report any problems/bugs if you find any!

    '''
    # TODO: Needs to be tested more
    # TODO: Split into different functions depending on OS?
    l_temp_size = eval_expression(arg_size, arg_debug=arg_debug)
    if l_temp_size is None:
        log_print(f"eval_expression({_hex_str_if_int(arg_size)}) failed", arg_type="ERROR")
        return None
    l_size: int = l_temp_size
    if _ida_name.get_name_ea(_ida_idaapi.BADADDR, '__libc_malloc') != _ida_idaapi.BADADDR:  # Linux
        # TODO: arg_executable is not working. Switch to mmap
        l_malloc = appcall('__libc_malloc', 'void *__fastcall(size_t size)', arg_debug=arg_debug)
        if l_malloc is None:
            log_print('Could not find __libc_malloc', arg_type="ERROR")
            return None

        res = l_malloc(l_size)
    elif _ida_name.get_name_ea(_ida_idaapi.BADADDR, 'kernelbase_VirtualAlloc') != _ida_idaapi.BADADDR:  # Windows
        MEM_COMMIT = 0x1000
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READWRITE = 0x40
        # TODO: The next line fails in IDA 9.5 since they change the default type parser from legacy --> clang. Clang does NOT like: 'PVOID __stdcall(PVOID lpAddress, SIZE_T dwSize, __int32 flAllocationType, __int32 flProtect)'
        l_kernelbase_VirtualAlloc = appcall('kernelbase_VirtualAlloc', 'PVOID __stdcall VirtualAlloc(PVOID lpAddress, SIZE_T dwSize, __int32 flAllocationType, __int32 flProtect)', arg_debug=arg_debug)
        if l_kernelbase_VirtualAlloc is None:
            log_print('Failed to find kernelbase_VirtualAlloc', arg_type="ERROR")
            return None
        res = l_kernelbase_VirtualAlloc(None, l_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE if arg_executable else PAGE_READWRITE)

    elif input_file.format.startswith('ELF64'): # Linux x64 without GLIBC
        # TODO: arg_executable is not working I guess

        # If we can't find __libc_malloc on Linux64, we can simulate this with:
        # mmap(0, size, PROT_WRITE|PROT_READ, MAP_ANON|MAP_PRIVATE, -1, 0) -->
        # mmap(0, size, 3, 0x22, -1, 0)
        l_syscall_as_bytes = bytes.fromhex("0F 05")

        # TODO: This is only working on x64 atm

        # Save the state
        l_rip = registers.rip.value # type: ignore[attr-defined]
        l_rax = registers.rax.value # type: ignore[attr-defined]
        l_rdi = registers.rdi.value # type: ignore[attr-defined]
        l_rsi = registers.rsi.value # type: ignore[attr-defined]
        l_rdx = registers.rdx.value # type: ignore[attr-defined]
        l_r10 = registers.r10.value # type: ignore[attr-defined]
        l_r8 = registers.r8.value # type: ignore[attr-defined]
        l_r9 = registers.r9.value # type: ignore[attr-defined]

        # Setup the new state
        l_syscall_already_in_code: Optional[List[int]] = []
        for l_segment in segments():
            if l_segment.executable:
                l_syscall_already_in_code = search_binary(arg_pattern=l_syscall_as_bytes, arg_min_ea=l_segment.start_ea, arg_max_ea=l_segment.end_ea-2, arg_debug=arg_debug)
                if l_syscall_already_in_code is None:
                    log_print("search_binary(SYSCALL_AS_BYTES) failed", arg_type="ERROR")
                    return None
                if l_syscall_already_in_code:
                    log_print(f"Found SYSCALL at 0x{l_syscall_already_in_code[0]:x}", arg_debug)
                    registers.rip.value = l_syscall_already_in_code[0]  # type: ignore[attr-defined]
                    break

        if l_syscall_already_in_code == []:
            log_print("Could NOT find SYSCALL so I have to create my own", arg_debug)
            l_t_ins = instruction(l_rip, arg_debug=arg_debug)
            if l_t_ins is None:
                return None
            l_len_of_instruction_before = len(l_t_ins)
            l_saved_bytes = read_bytes(l_rip, len(l_syscall_as_bytes), arg_debug=arg_debug)
            if l_saved_bytes is None:
                return None
            write_bytes(l_rip, l_syscall_as_bytes, arg_debug=arg_debug)
            make_code(l_rip, len(l_syscall_as_bytes), arg_debug=arg_debug)

        # syscall mmap == 9
        registers.rax.value = 9 # type: ignore[attr-defined]

        # Addr hint
        registers.rdi.value = 0 # type: ignore[attr-defined]

        # Size to allocate
        registers.rsi.value = l_size # type: ignore[attr-defined]

        # prot = PROT_WRITE | PROT_READ
        registers.rdx.value = 3 # type: ignore[attr-defined]

        # flags = MAP_ANON | MAP_PRIVATE
        registers.r10.value = 0x22 # type: ignore[attr-defined]

        # fd (file descriptor backing this memory mapping)
        registers.r8.value = -1 # type: ignore[attr-defined]

        # off
        registers.r9.value = 0 # type: ignore[attr-defined]

        debugger_step_over_synchronous(arg_seconds_max_wait=60, arg_debug=arg_debug)
        res = registers.rax.value # type: ignore[attr-defined]

        # Restore the old state
        if l_syscall_already_in_code == []:
            l_t_saved_bytes: bytes = l_saved_bytes # type: ignore[assignment] # mypy miss that it is ok, l_saved_bytes: bytes
            _ = write_bytes(l_rip, l_t_saved_bytes, arg_debug=arg_debug)
            _ = make_code(l_rip, max(l_len_of_instruction_before, len(l_t_saved_bytes)))

        registers.rip.value = l_rip # type: ignore[attr-defined]
        registers.rax.value = l_rax # type: ignore[attr-defined]
        registers.rdi.value = l_rdi # type: ignore[attr-defined]
        registers.rsi.value = l_rsi # type: ignore[attr-defined]
        registers.rdx.value = l_rdx # type: ignore[attr-defined]
        registers.r10.value = l_r10 # type: ignore[attr-defined]
        registers.r8.value = l_r8 # type: ignore[attr-defined]
        registers.r9.value = l_r9 # type: ignore[attr-defined]
    else:
        log_print("Could NOT find any function that allocates memory", arg_type="ERROR")
        return None

    debugger_refresh_memory_WARNING_VERY_EXPENSIVE()
    _idaapi_request_refresh()
    return eval_expression(res)

malloc = allocate_memory_in_target

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def modules(arg_name_filter_regex: str = ".*",  arg_debug: bool = False) -> Optional[List[_ida_idd.modinfo_t]]:
    ''' Return all loaded modules. This information is only available with a live running process.
        OBS! Modules here means loaded DLLs in the target process
        Replacement of idautils.Modules()
    '''
    if not debugger_is_active():
        log_print("You must have an active debugging session to use this function", arg_type="ERROR")
        return None

    res = []
    l_temp_mod = _ida_idd.modinfo_t()
    l_temp_result = _ida_dbg.get_first_module(l_temp_mod)
    while l_temp_result:
        if _re.fullmatch(arg_name_filter_regex, l_temp_mod.name, _re.IGNORECASE):
            # This note is from idautils.Modules():
            # Note: can't simply return `mod` here, since callers might
            # collect all modules in a list, and they would all re-use
            # the underlying C++ object.
            l_mod = _ida_idd.modinfo_t()
            l_mod.name = l_temp_mod.name
            l_mod.size = l_temp_mod.size
            l_mod.base = l_temp_mod.base
            l_mod.rebase_to = l_temp_mod.rebase_to
            res.append(l_mod)
            log_print(f"Module OK: {l_temp_mod}", arg_debug)
        else:
            log_print(f"Module SKIPPED: {l_temp_mod.name}, does NOT match '{arg_name_filter_regex}'", arg_debug)

        l_temp_result = _ida_dbg.get_next_module(l_temp_mod)

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def module(arg_module_name_or_address: Optional[EvaluateType] = None, arg_debug: bool = False) -> Optional[_ida_idd.modinfo_t]:
    ''' Find a module based on the name or an address
    OBS! Module in this context refers to a DLL loaded in the target process while it is running '''

    # TODO: https://youtu.be/rgyTaXkPzfM?t=440 maybe look into _ida_name.get_debug_names()?
    if arg_module_name_or_address is None:
        arg_module_name_or_address = current_address() # Default: the module where the cursor is

    l_modules = modules(arg_debug=arg_debug)
    if l_modules is None:
        log_print("modules() returned None", arg_type="ERROR")
        return None

    l_addr = address(arg_module_name_or_address, arg_supress_error=True, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR and isinstance(arg_module_name_or_address, str):
        # If I could not lookup the input but it's a string, try to match against the module name
        for l_module in l_modules:
            if arg_module_name_or_address.lower() in l_module.name.lower():
                return l_module
        log_print(f"No module found for '{arg_module_name_or_address}'", arg_type="ERROR")
        return None

    for l_module in l_modules:
        if l_module.base <= l_addr < l_module.base + l_module.size: # base + size is the first byte AFTER the module
            return l_module

    log_print(f"No module found for '{_hex_str_if_int(arg_module_name_or_address)}'", arg_type="ERROR")
    return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def load_file_into_memory(arg_file_path: str, arg_executable: bool = True, arg_debug: bool = False) -> Optional[int]:
    ''' Take a file on disk (usually shellcode) and allocates that much memory and write the file content to that memory location.
    Requires an active debugging session
    @return Returns the address the data (shellcode) was written to
    '''
    if not _os.path.exists(arg_file_path):
        log_print(f"File '{arg_file_path}' does not exist", arg_type="ERROR")
        return None
    with open(arg_file_path, 'rb') as f:
        l_shellcode = f.read()
    res = allocate_memory_in_target(len(l_shellcode), arg_executable=arg_executable, arg_debug=arg_debug)
    if res is None:
        log_print("Could not allocate memory", arg_type="ERROR")
        return None
    if not write_bytes(res, l_shellcode, arg_debug=arg_debug):
        log_print("Writing the shellcode failed.", arg_type="ERROR")
        return None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_PEB(arg_debug: bool = False) -> Optional[int]:
    ''' Gets the address to the PEB (Process Environment Block). Needs a running debugging session and it needs to be Local Windows Debugger. '''
    if not debugger_is_active():
        log_print("This function can only be called in an active debugging session", arg_type="ERROR")
        return None

    if ida_version() >= 940:
        l_PEB: Optional[_ida_segment.segment_t] = None
        for l_segment in segments():
            if l_segment.name_as_str == "PEB":
                l_PEB = l_segment
                break
        if l_PEB is None:
            log_print("Could NOT find any segment named 'PEB', trying my hack with ntdll_RtlAreLongPathsEnabled", arg_type="ERROR")
            l_ntdll_RtlAreLongPathsEnabled = appcall("ntdll_RtlAreLongPathsEnabled", "size_t ntdll_RtlAreLongPathsEnabled();")
            if l_ntdll_RtlAreLongPathsEnabled is None:
                return None
            res = l_ntdll_RtlAreLongPathsEnabled() & 0xFFFFFFFFFFFFFF00
            return res if input_file.bits == 64 else res - 0x1000
        return l_PEB.start_ea
    else:
        l_thread_id: int = _ida_dbg.get_current_thread()
        teb_segm_name: str = f"TIB[{l_thread_id:08X}]"
        log_print(f"Segment with TEB/TIB information: '{teb_segm_name}'", arg_debug)
        l_TEB: Optional[_ida_segment.segment_t] = _ida_segment.get_segm_by_name(teb_segm_name)

        if not l_TEB:
            log_print(f"Could not find any segment with the name: '{teb_segm_name}'", arg_type="ERROR")
            return None
        return l_TEB.start_ea if input_file.bits == 64 else l_TEB.start_ea + 0x1000

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetCommandLineW(arg_debug: bool = False) -> Optional[str]:
    ''' The command line the program was started with via AppCall '''
    l_GetCommandLineW = appcall('kernel32_GetCommandLineW', "LPWSTR GetCommandLineW();", arg_debug=arg_debug)
    if not l_GetCommandLineW:
        log_print("Failed to find kernel32_GetCommandLineW", arg_type="ERROR")
        return None
    res = l_GetCommandLineW().decode('utf-16')
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetLastError(arg_debug: bool = False) -> Optional[int]:
    ''' Calls GetLastError() via AppCall '''
    l_GetLastError = appcall('kernel32_GetLastError', "DWORD GetLastError();", arg_debug=arg_debug)
    if l_GetLastError is None:
        log_print("appcall('kernel32_GetLastError') failed", arg_type="ERROR")
        return None
    return l_GetLastError()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _win_error_text(arg_last_error: Optional[int]) -> str:
    ''' Internal function. Makes a readable string of an error code from GetLastError() of the DEBUGGED process.
    OBS! Never pass None to ctypes.WinError(), then it reads the last error of IDA's own process.
    '''
    if arg_last_error is None:
        return "error code: <<< unknown, GetLastError() failed >>>"
    l_error_message: Optional[str] = _ctypes.WinError(arg_last_error).strerror if hasattr(_ctypes, "WinError") else None
    return f"error code: {arg_last_error} (0x{arg_last_error:x}), error description: '{l_error_message or '<<< unknown error >>>'}'"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_LoadLibraryA(arg_dll: str, arg_debug: bool = False) -> Optional[int]:
    ''' Load a DLL into the running process via AppCall '''
    l_load_library = appcall('kernel32_LoadLibraryA', "HMODULE LoadLibraryA(LPCSTR lpLibFileName);", arg_debug=arg_debug)
    if not l_load_library:
        log_print("Failed to find kernel32_LoadLibraryA", arg_type="ERROR")
        return None
    res = l_load_library(arg_dll)
    res = eval_expression(res, arg_debug=arg_debug) # res can be ida_idaapi.PyIdc_cvt_int64__ on win64 but not on win32
    if res == 0:
        l_last_error: Optional[int] = win_GetLastError()
        if l_last_error == 0xC1: # ERROR_BAD_EXE_FORMAT
            log_print("The DLL you tried to load was in a bad format and could not be loaded. Did you try to load a 32 bit DLL into a 64 bit process?", arg_type="ERROR")
        else:
            log_print(f"LoadLibraryA('{arg_dll}') failed with {_win_error_text(l_last_error)}", arg_type="ERROR")

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetProcAddress(arg_hmodule: EvaluateType, arg_function_name: str, arg_debug: bool = False) -> Optional[int]:
    ''' Gets the address of a function in a DLL via AppCall

    @param arg_hmodule: Handle to DLL module (from LoadLibrary)
    @param arg_function_name: Name of function to look up
    @return: Function address or None on error
    '''
    l_GetProcAddress = appcall('kernel32_GetProcAddress', "FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);", arg_debug=arg_debug)
    if not l_GetProcAddress:
        log_print("Failed to find kernel32_GetProcAddress", arg_type="ERROR")
        return None

    l_module: Optional[_ida_idd.modinfo_t] = module(arg_hmodule, arg_debug=arg_debug)
    if l_module is None:
        log_print(f"address({_hex_str_if_int(arg_hmodule)}) failed", arg_type="ERROR")
        return None

    res = l_GetProcAddress(l_module.base, arg_function_name)
    res = eval_expression(res, arg_debug=arg_debug) # Handle PyIdc_cvt_int64__ on win64

    if not res:
        log_print(f"GetProcAddress('{arg_hmodule}', '{arg_function_name}') failed with {_win_error_text(win_GetLastError())}", arg_type="ERROR")
        return None

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_FreeLibrary(arg_hmodule: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Free a DLL in the running process via AppCall '''
    l_free_library = appcall('kernel32_FreeLibrary', "BOOL FreeLibraryA(HMODULE hLibModule)", arg_debug=arg_debug)
    if not l_free_library:
        log_print("Failed to find kernel32_FreeLibrary", arg_type="ERROR")
        return False

    l_module: Optional[_ida_idd.modinfo_t] = module(arg_hmodule, arg_debug=arg_debug)
    if l_module is None:
        log_print(f"address({_hex_str_if_int(arg_hmodule)}) failed", arg_type="ERROR")
        return False

    log_print(f"Freeing {l_module.name}", arg_debug)
    res = _bool(l_free_library(l_module.base))
    if not res:
        log_print(f"FreeLibrary('{arg_hmodule}') failed with {_win_error_text(win_GetLastError())}", arg_type="ERROR")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetProcessHeap(arg_debug: bool = False) -> Optional[int]:
    ''' Gets the default heap for this process via AppCall '''
    l_GetProcessHeap = appcall('kernel32_GetProcessHeap', "HANDLE GetProcessHeap()", arg_debug=arg_debug)
    if not l_GetProcessHeap:
        log_print("Failed to find kernel32_GetProcessHeap", arg_type="ERROR")
        return None
    res = l_GetProcessHeap()
    log_print(f"res: {res}", arg_debug)
    return eval_expression(res, arg_debug=arg_debug) # res can be ida_idaapi.PyIdc_cvt_int64__ on win64 but not on win32

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetProcessHeap_emulated(arg_debug: bool = False) -> Optional[int]:
    ''' Gets the default heap for this process by reading from the PEB

    Emulates kernelbase_GetProcessHeap()
    '''
    l_default_heap_offset = 0x30 if input_file.bits == 64 else 0x18
    l_PEB: Optional[int] = win_PEB(arg_debug=arg_debug)
    if not l_PEB:
        return None
    return pointer(l_PEB + l_default_heap_offset, arg_debug=arg_debug)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def win_GetCurrentProcessId(arg_debug: bool = False) -> Optional[int]:
    ''' Gets the process ID of the currently debugged process via AppCall '''
    l_GetCurrentProcessId = appcall('kernel32_GetCurrentProcessId', "DWORD GetCurrentProcessId()", arg_debug=arg_debug)
    if not l_GetCurrentProcessId:
        log_print("Failed to find kernel32_GetCurrentProcessId", arg_type="ERROR")
        return None
    res = l_GetCurrentProcessId()
    log_print(f"res: {res}", arg_debug)
    return res


# UI ---------------------------------------------------------------------------------------------------------------------
if _G_QT_IS_AVAILABLE:
    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _is_TWidget_TWidget_ptr_or_QtWidget(arg_widget: Any) -> str:
        ''' Detects what kind of Widget you send in and returns that as a str '''
        # TODO: Test this with PySide and add a real test case for future
        if isinstance(arg_widget, TWidget):
            return "TWidget"
        if str(type(arg_widget)) == "<class 'SwigPyObject'>":
            return "IDA_TWidget_ptr"
        if ".QtWidgets." in str(type(arg_widget)):
            return "QtWidget"

        log_print("arg_widget should be either window title (type: str) or the twidget* object (type: SwigPyObject) or a QtWidget (type: .QtWidgets.)", arg_type="ERROR")
        log_print(f"I got type(arg_widget): {type(arg_widget)}", arg_type="ERROR")
        return "<<< unknown Widget Type >>>"

    class TWidget():
        ''' TWidget is really IDAs type but there doesn't seem to be any Python type for it so we create this wrapper to get real type hints '''
        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def __init__(self, arg_TWidget: Any) -> None:
            ''' Create a wrapper object around what IDA calls TWidget*

            @param arg_TWidget can be either the window name (type str), the SwigPyObject that is returned from the IDA APIs, a QtWidget or a community_base TWidget

            E.g. l_functions_TWidget = TWidget("Functions")
            l_functions_TWidget = TWidget(ida_kernwin.find_widget("Functions"))
            l_last_used_TWidget = TWidget(ida_kernwin.get_last_widget())
            '''
            # Always set the members first so every method can check them, even if we return early below
            self._m_IDAs_TWidget_ptr: Optional[Any] = None
            self._m_original_window_title: str = "<<< invalid TWidget >>>"
            if arg_TWidget is None:
                log_print("arg_TWidget is None", arg_type="ERROR")
                return

            if isinstance(arg_TWidget, str):
                self._m_IDAs_TWidget_ptr = _ida_kernwin.find_widget(arg_TWidget)  # m_TWidget is Optional[PySwigObj]
                if self._m_IDAs_TWidget_ptr is None:
                    log_print(f"No widget named '{arg_TWidget}' found. OBS! The window titles are case sensitive", arg_type="ERROR")
            elif _is_TWidget_TWidget_ptr_or_QtWidget(arg_TWidget) == "IDA_TWidget_ptr":
                self._m_IDAs_TWidget_ptr = arg_TWidget
            elif _is_TWidget_TWidget_ptr_or_QtWidget(arg_TWidget) == "QtWidget":
                self._m_IDAs_TWidget_ptr = _ida_kernwin.PluginForm.QtWidgetToTWidget(arg_TWidget)
            elif _is_TWidget_TWidget_ptr_or_QtWidget(arg_TWidget) == "TWidget":
                self._m_IDAs_TWidget_ptr = arg_TWidget._m_IDAs_TWidget_ptr
            else:
                log_print("arg_TWidget should be either window title (type: str) or the twidget* object (type: SwigPyObject) or a QtWidget (type: .QtWidgets.*)", arg_type="ERROR")
                self._m_IDAs_TWidget_ptr = None

            if not self._m_IDAs_TWidget_ptr is None:
                l_PyQTWidget = self.as_PyQtWidget()
                if l_PyQTWidget is None:
                    self._m_original_window_title = "<<< invalid TWidget >>>"
                    return
                self._m_original_window_title = l_PyQTWidget.windowTitle()

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def as_PyQtWidget(self) -> Optional[QWidget]:
            ''' TWidget is IDAs own type, if you want to use Qt functions, then you need to convert to a PyQtWidget
            [Official example](https://github.com/HexRaysSA/IDAPython/blob/d12e31eae9d678f647013527596a715dd378f989/examples/ui/pyqt/inject_command.py#L76)

            Convert from QtWidget --> TWidget* use: TWidget(my_QtWidget).as_TWidget_ptr()
            '''
            if self._m_IDAs_TWidget_ptr is None:
                log_print("_m_TWidget is not a valid TWidget", arg_type="ERROR")
                return None
            return _ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._m_IDAs_TWidget_ptr)

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def as_TWidget_ptr(self) -> Optional[Any]:
            ''' For the IDA APIs that takes a TWidget* (e.g. ida_kernwin.attach_action_to_popup()) you can use this to get the correct type '''
            if self._m_IDAs_TWidget_ptr is None:
                log_print("_m_TWidget is not a valid TWidget", arg_type="ERROR")
                return None
            return self._m_IDAs_TWidget_ptr

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def activate(self, arg_take_focus: bool = True) -> None:
            ''' Activate this TWdidget. Same as focus() '''
            _idaapi_activate_widget(self, arg_take_focus=arg_take_focus)

        focus = activate

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def close(self, arg_close_normally: bool = True) -> None:
            ''' Close this TWidget '''
            _idaapi_close_widget(self, arg_close_normally)

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def display(self, arg_options: int = _ida_kernwin.WOPN_NOT_CLOSED_BY_ESC, arg_dest_ctrl: Optional[str] = None) -> None:
            ''' Display this TWidget. This function is used to place the windows (TWidget) at different locations such as floating or in a tab next to some given tab and so on
                Read more: [ida_kernwin.display_widget()](https://python.docs.hex-rays.com/ida_kernwin/index.html#ida_kernwin.display_widget)

                @param arg_options: int Flags from ida_kernwin.WOPN_* Read more at [the official docs](https://cpp.docs.hex-rays.com/group___w_i_d_g_e_t___o_p_e_n.html)
                @param arg_dest_ctrl: Optional[str] TODO: I don't know what what this is, something to do with another control that can be used with arg_options? Read more: <https://cpp.docs.hex-rays.com/group___w_i_d_g_e_t___o_p_e_n.html>

                WARNING! Calling this on a window that has been closed crashes IDA. IDA Bug
            '''
            _idaapi_display_widget(self, arg_options=arg_options, arg_dest_ctrl=arg_dest_ctrl)

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def window_title(self, arg_new_window_title: Optional[str] = "") -> str:
            ''' Get / set the window title
            @param arg_new_window_title Optional[str] Set to None to get the original window title, otherwise set to this. If set to empty string then just get the current window title
            '''
            if arg_new_window_title is None:
                l_PyQtWidget = self.as_PyQtWidget()
                if l_PyQtWidget is None:
                    return "<<< Invalid TWidget >>>"
                l_PyQtWidget.setWindowTitle(self._m_original_window_title)
            elif arg_new_window_title:
                l_PyQtWidget = self.as_PyQtWidget()
                if l_PyQtWidget is None:
                    return "<<< Invalid TWidget >>>"
                l_PyQtWidget.setWindowTitle(arg_new_window_title)

            return _idaapi_get_widget_title(self)

        @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
        def __repr__(self) -> str:
            ''' The type and the window title '''
            if self._m_IDAs_TWidget_ptr is None:
                log_print("m_TWidget is not a valid TWidget", arg_type="ERROR")
                return "<<< Invalid TWidget >>>"
            return f"{type(self)} Window title: {_idaapi_get_widget_title(self)}"

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_find_widget(arg_window_title: str) -> TWidget:
        ''' Replacement for ida_kernwin.find_widget() '''
        return TWidget(arg_window_title)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_widget_title(arg_widget: TWidget) -> str:
        ''' Replacement for ida_kernwin.get_widget_title() '''
        if arg_widget._m_IDAs_TWidget_ptr is None:
            log_print("arg_TWidget.m_TWidget is None", arg_type="ERROR")
            return "<<< Invalid TWidget >>>"
        return _ida_kernwin.get_widget_title(arg_widget._m_IDAs_TWidget_ptr)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_activate_widget(arg_widget: Union[TWidget, str], arg_take_focus: bool = True) -> None:
        ''' Replacement for ida_kernwin.activate_widget() '''
        if isinstance(arg_widget, str):
            arg_widget = TWidget(arg_widget)

        if arg_widget.as_TWidget_ptr() is None:
            return
        return _ida_kernwin.activate_widget(arg_widget._m_IDAs_TWidget_ptr, arg_take_focus)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_display_widget(arg_widget: TWidget, arg_options: int = _ida_kernwin.WOPN_NOT_CLOSED_BY_ESC, arg_dest_ctrl: Optional[str] = None) -> None:
        '''Replacement for ida_kernwin.display_widget()

        @param arg_options Flags from ida_kernwin.WOPN_* Read more: <https://cpp.docs.hex-rays.com/group___w_i_d_g_e_t___o_p_e_n.html>

        WARNING! Calling this on a window that has been closed crashes IDA. IDA Bug
        '''
        if arg_widget._m_IDAs_TWidget_ptr is None:
            log_print("Cannot display TWidget, arg_widget.m_TWidget is None", arg_type="ERROR")
            return
        _ida_kernwin.display_widget(arg_widget._m_IDAs_TWidget_ptr, options=arg_options, dest_ctrl=arg_dest_ctrl)
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_close_widget(arg_widget: TWidget, arg_options: bool = False) -> None:
        ''' Replacement for ida_kernwin.close_widget()

        @param arg_options True --> form is closed normally as if the user pressed Enter. False --> form is closed abnormally as if the user pressed Esc.
        [arg_options at official docs](https://python.docs.hex-rays.com/ida_kernwin/index.html#ida_kernwin.Form.Close)
        '''
        if arg_widget._m_IDAs_TWidget_ptr is None:
            log_print("Cannot close TWidget, arg_widget._m_IDAs_TWidget_ptr is None", arg_type="ERROR")
            return
        _ida_kernwin.close_widget(arg_widget._m_IDAs_TWidget_ptr, 1 if arg_options else 0)
        arg_widget._m_IDAs_TWidget_ptr = None
        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_current_widget() -> TWidget:
        ''' Replacement for ida_kernwin.get_current_widget() '''
        return TWidget(_ida_kernwin.get_current_widget())

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_current_viewer() -> Optional[TWidget]:
        ''' Replacement for ida_kernwin.get_current_viewer()
        OBS! Viewer is a widget that is how you see the file. This can be IDA-View, Pseudocode or Hex View '''
        l_current_viewer: Optional[Any] = _ida_kernwin.get_current_viewer()
        if l_current_viewer is None: # This can happen when all the viewer widgets are closed
            log_print("ida_kernwin.get_current_viewer() returned None", arg_type="ERROR")
            return None

        return TWidget(_ida_kernwin.get_current_viewer())

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_last_widget(arg_mask: int = _ida_kernwin.IWID_ALL) -> TWidget:
        ''' Replacement for ida_kernwin.get_last_widget()
        @param arg_mask an OR'ed set of ida_kernwin.IWID_* to limit the search to
        '''
        return TWidget(_ida_kernwin.get_last_widget(arg_mask))

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_widget_type(arg_widget: TWidget) -> int:
        ''' replacement for ida_kernwin.get_widget_type()

        @ return one of ida_kernwin.BWN_* ints on OK, -1 on error

        my_pseudocode_widget = community_base.TWidget("Pseudocode-A")
        widget_type = community_base._idaapi_get_widget_type(my_pseudocode_widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            print("We have a pseudocode window")

        '''
        if arg_widget._m_IDAs_TWidget_ptr is None:
            log_print("Cannot get the type since arg_widget._m_IDAs_TWidget_ptr is None", arg_type="ERROR")
            return -1
        return _ida_kernwin.get_widget_type(arg_widget.as_TWidget_ptr())

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_get_widget_vdui(arg_widget: TWidget) -> Optional[_ida_hexrays.vdui_t]:
        ''' replacement for ida_hexrays.get_widget_vdui()
        vdui is the Visual Decompiler User Interface. i.e. the pseudocode window.

        [Read more at the official docs](https://cpp.docs.hex-rays.com/structvdui__t.html)

        @ return ida_hexrays.vdui_t of the pseudocode window if OK, None otherwise
        '''
        if arg_widget._m_IDAs_TWidget_ptr is None:
            log_print("Cannot get the vdui_t since arg_widget._m_IDAs_TWidget_ptr is None", arg_type="ERROR")
            return None
        return _ida_hexrays.get_widget_vdui(arg_widget.as_TWidget_ptr())

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_read_range_selection(arg_TWidget: Optional[TWidget] = None, arg_allow_one_line: bool = True) -> Tuple[bool, int, int]:
        ''' Reads the selected addresses that you selected with your mouse (or keyboard)

        @param arg_TWidget: TWidget None --> "the last used widget"
        @param arg_allow_one_line: If you mark text on 1 line and run IDAs ida_kernwin.read_range_selection() then you will get an invalid selection, with this argument set then return current_address() instead
        @return (is_valid_selection: bool, selection_start: int, selection_end: int)

        Replacement for ida_kernwin.read_range_selection()
        '''
        l_widget = arg_TWidget.as_TWidget_ptr() if isinstance(arg_TWidget, TWidget) else None
        l_valid_selection, l_start_address, l_end_address = _ida_kernwin.read_range_selection(l_widget)
        if not l_valid_selection:

            if arg_allow_one_line:
                return (True, current_address(), _ida_bytes.get_item_end(current_address()))

            log_print("You haven't selected any addresses", arg_type="ERROR")
            return (False, 0, 0)

        return (l_valid_selection, l_start_address, l_end_address)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __widget_lines(arg_TWidget: TWidget, arg_from: _ida_kernwin.twinpos_t, arg_to: _ida_kernwin.twinpos_t, arg_debug: bool = False) -> List[str]:
        """
        get lines between places arg_from and arg_to in widget

        Code taken from examples: dump_selection.py but changed to fix the bug where the user select some bytes on on the same line
        """

        # TODO: This is working better than the old code but it still isn't correct. Interier comment will mess everything up

        l_user_data = _ida_kernwin.get_viewer_user_data(arg_TWidget.as_TWidget_ptr())
        l_line_array = _ida_kernwin.linearray_t(l_user_data)
        l_line_array.set_place(arg_from.at)
        res = []
        while True:
            cur_place = l_line_array.get_place()
            first_line_ref = _ida_kernwin.l_compare2(cur_place, arg_from.at, l_user_data)
            last_line_ref = _ida_kernwin.l_compare2(cur_place, arg_to.at, l_user_data)

            log_print(f"\n\nfirst_line_ref: {first_line_ref}, last_line_ref: {last_line_ref}", arg_debug)
            if (first_line_ref == 0 and last_line_ref == 1) or (first_line_ref == 0 and last_line_ref == 0): # Special case where only 1 line is selected
                log_print(f"first_line_ref: {first_line_ref}, last_line_ref: {last_line_ref}, special case with only 1 line. Changing to get_custom_viewer_curline()", arg_debug)
                l_t_line =_ida_lines.tag_remove(_ida_kernwin.get_custom_viewer_curline(arg_TWidget.as_TWidget_ptr(), mouse=False))
                res.append(l_t_line[arg_from.x : arg_to.x])
                return res

            if last_line_ref > 0: # beyond last line
                log_print(f"first_line_ref: {first_line_ref}, last_line_ref: {last_line_ref}, breaking the loop", arg_debug)
                break

            l_line = _ida_lines.tag_remove(l_line_array.down())
            log_print(f"l_line: {l_line}", arg_debug)
            if last_line_ref == 0: # at last line
                log_print(f"first_line_ref: {first_line_ref}, last_line_ref: {last_line_ref}, l_line: {l_line}, last line?", arg_debug)
                l_line = l_line[0:arg_to.x]
            elif first_line_ref == 0: # at first line
                log_print(f"first_line_ref: {first_line_ref}, last_line_ref: {last_line_ref}, l_line: {l_line}, first line?", arg_debug)
                l_line = l_line[arg_from.x:]
            res.append(l_line)

        log_print(f"res after loop but before any mods: {res}", arg_debug)

        if len(res) == 1:
            log_print("sometimes we get the loop even if we only have selected part of 1 line, this hack fix that special case. Changing to get_custom_viewer_curline()", arg_debug)
            res = []
            l_t_line =_ida_lines.tag_remove(_ida_kernwin.get_custom_viewer_curline(arg_TWidget.as_TWidget_ptr(), mouse=False))
            res.append(l_t_line[arg_from.x : arg_to.x])
            return res

        log_print("Since we cannot get any signal that we are at the last line in the loop, we have to adjust the last line afterwards", arg_debug)


        l_last_line = res[-1]
        l_last_line = l_last_line[0:arg_to.x]
        res[-1] = l_last_line
        return res

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def ui_selected_text(arg_TWidget: Optional[TWidget] = None, arg_debug: bool = False) -> str:
        ''' Returns the selected text, if no text is selected, then return empty string

        @param arg_TWidget The widget to get the selected text from, if set to None, then get the selected text from the last used widget

        Code taken from examples: dump_selection.py

        OBS! This version is working better than dump_selection.py but it still is buggy...
        '''
        l_from = _ida_kernwin.twinpos_t()
        l_to = _ida_kernwin.twinpos_t()
        # l_view = TWidget(_ida_kernwin.get_current_viewer())
        l_view = arg_TWidget if arg_TWidget else _idaapi_get_last_widget()
        if l_view.as_TWidget_ptr() is None:
            log_print("No widget to read the selected text from", arg_type="ERROR")
            return ""
        l_read_selection = _ida_kernwin.read_selection(l_view.as_TWidget_ptr(), l_from, l_to)
        if not l_read_selection:
            log_print(f"No text is selected in {l_view.window_title()}", arg_type="ERROR")
            return ""

        lines = __widget_lines(l_view, l_from, l_to, arg_debug=arg_debug)
        return "\n".join(lines)

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def ui_highlighted_identifier(arg_viewer: Optional[TWidget] = None, arg_allow_selected_text: bool = True) -> Optional[str]:
        ''' If you have clicked in a window on an identifier so that the window highlights the identifier, this can read that identifier. '''
        # reg_read_bool() with the default True: IDA only writes the value to the registry when the user has changed it, so a missing value means "on" (the default)
        if not _ida_registry.reg_read_bool("AutoHighlight", True):
            log_print("You have turned off highlighting in Options -> General -> Browser -> Auto highlight the current identifier which means this function will not work", arg_type="ERROR")
            return None

        if arg_viewer:
            l_viewer = arg_viewer.as_TWidget_ptr()
        else:
            l_current_viewer: Optional[TWidget] = _idaapi_get_current_viewer()
            if l_current_viewer is None:
                log_print("No viewer to use", arg_type="ERROR")
                return None

            l_viewer = l_current_viewer.as_TWidget_ptr()

        l_ret = _ida_kernwin.get_highlight(l_viewer) # TODO: Break out to own function with the check in it
        if l_ret is None:
            log_print("No highlighted identifier", arg_type="ERROR")
            return None
        l_highlighted = l_ret[0]
        l_is_valid = l_ret[1]
        if l_is_valid:
            return l_highlighted

        # If we get there, then the user might have selected text with the mouse and not just clicked an identifier in the UI
        if arg_allow_selected_text:
            return ui_selected_text(arg_viewer)

        log_print("l_is_valid is not valid", arg_type="ERROR")
        return ""

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def _idaapi_ask_file() -> Optional[TWidget]:
        ''' TODO: Documentation. Replacement for ida_kernwin.ask_file() '''
        # Crashing IDA: ida_kernwin.ask_file(True, "*.txt", "Select file with symbols info")
        return _ida_kernwin.ask_file() # TODO: https://github.com/therealdreg/symseghelper/blob/0cce5d62890e044626f364fe2e60de4108e6f58d/ida_load_names.py#L35

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def ida_main_window() -> Optional[TWidget]:
        ''' Get the top window. If you set the window title on this, then the IDA Process window title will be set
        The idea is that you can set the window title to give some info to the user
        '''
        for l_widget in QApplication.topLevelWidgets():
            if isinstance(l_widget, QMainWindow):
                return TWidget(l_widget)
        return None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def jumpto(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Moves the current (last used) view to show the address/name/label/register.
    Replacement for ida_kernwin.jumpto()
    '''
    # TODO: Test how this plays with ida_domain
    l_addr: int = address(arg_ea, arg_debug=arg_debug)
    if l_addr == _ida_idaapi.BADADDR:
        log_print(f"address({_hex_str_if_int(arg_ea)}) failed", arg_type="ERROR")
        return False
    log_print(f"Jumping to {_hex_str_if_int(l_addr)}", arg_debug)
    return _ida_kernwin.jumpto(l_addr)

j = jumpto # Make it short, make it fast!

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ui_quick_view() -> None:
    ''' Opens the quick view where the user can pick what view they want. Default shortcut is Ctrl + 1
    This is an example on how to use the ida_kernwin.process_ui_action() function
    The input to process_ui_action() can be found in the GUI. "Options" -> "Shortcuts". The column named "Action" is the action name that goes in to the function.
    You can also list them with ida_kernwin.get_registered_actions()

    e.g.
    ida_kernwin.process_ui_action("community_base:copy_current_address")
    ida_kernwin.process_ui_action("HelpPythonAPI") --> Will open a browser window at [Hex-Rays Python Doc](https://python.docs.hex-rays.com/)

    There is also execute_ui_requests(). [Read more at Github](https://github.com/HexRaysSA/IDAPython/blob/9.0sp1/examples/ui/trigger_actions_programmatically.py)
    '''
    # TODO: Does this work with ida_domain?
    _ida_kernwin.process_ui_action('QuickView')

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_output_text(arg_last_num_lines: int = -1, arg_clear_it_after: bool = False) -> List[str]:
    ''' Returns the text in the Output window (widget)
    @param arg_last_num_lines: int Get only the last X lines. -1 --> all lines
    @param arg_clear_it_after: After we have read the lines, clear the output
    This a way to get some information that are usually hard to find (like output from other plugins)
    '''
    res = _ida_kernwin.msg_get_lines(arg_last_num_lines)
    res = res[::-1] # For some strange reason, the list is reversed so we turn it around

    if arg_clear_it_after:
        l_output_TWidget = TWidget("Output")
        l_output_TWidget.focus()
        _ida_kernwin.process_ui_action("OutputClearContents") # TODO: Does not work when working from a external Jupyter console
    return res

# TODO: Remove?
# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def _hype_find_connection_file(arg_copy_to_clipboard: bool = True) -> str:
#     ''' I have a Jupyter Kernel plugin that I strongly recommend.
#         You can find it here: https://github.com/Harding-Stardust/hype
#         It is a replacement for IPyIDA
#     '''
#     l_hype = _sys.modules.get("__plugins__hype", None)
#     if l_hype is None:
#         l_download_command: str = f"wget -O \"{_os.path.join(ida_plugin_dirs()[0], 'hype.py')}\" https://raw.githubusercontent.com/Harding-Stardust/hype/refs/heads/main/hype.py"
#         log_print(f"Plugin HYPE not found, you can install it with: {l_download_command}", arg_type="ERROR")
#         if arg_copy_to_clipboard:
#             clipboard_copy(l_download_command)
#         return ""

#     res = l_hype.g_connection_file # Parsed dict: l_hype.g_app.get_connection_info()
#     if arg_copy_to_clipboard:
#         clipboard_copy(res)
#     return res

# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def _hype_jupyter_console_from_shell(arg_copy_to_clipboard: bool = True) -> str:
#     ''' The command you can run in your shell to connect to [HYPE](https://github.com/Harding-Stardust/hype) and have it outside of IDA (But IDA and HYPE must both be up and running)
#         @param arg_copy_to_clipboard Copy the command to the clipboard
#     '''
#     log_print("OBS! When leaving the external Jupyter console press Ctrl+D or exit(keep_kernel=True)", arg_type="INFO")
#     l_connection_file: str = _hype_find_connection_file()
#     if l_connection_file:
#         res = f"jupyter-console --existing {l_connection_file}"
#         if arg_copy_to_clipboard:
#             clipboard_copy(res)
#         return res
#     return ""

# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def _hype_exit(arg_copy_to_clipboard: bool = True) -> str:
#     ''' If you have connected to the Jupyter kernel from the shell using _hype_jupyter_console_from_shell() use this command to exit the shell window without killing the kernel
#         @param arg_copy_to_clipboard Copy the command to the clipboard
#     '''
#     l_connection_file: str = _hype_find_connection_file()
#     if l_connection_file:
#         res = "exit(keep_kernel=True)"
#         if arg_copy_to_clipboard:
#             clipboard_copy(res)
#         log_print(f"This function does not do the exit, you need to paste in the following line in yout Jupyter console: {res}", arg_type="INFO")
#         return res
#     return ""

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def lumina_pull_all(arg_primary_server: bool) -> bool:
    ''' Pull all function info from a Lumina server '''
    # TODO: Is there any better way to control Lumina? Investigate ida_lumina.py
    if arg_primary_server:
        return _ida_kernwin.process_ui_action('LuminaPullAllMds') # Same as the Menu: Lumina -> Pull all (F12)

    return _ida_kernwin.process_ui_action('LuminaSecondaryPullAllMds')


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def lumina_push_all(arg_primary_server: bool) -> bool:
    ''' Push all function info to a Lumina server '''
    # TODO: Is there any better way to control Lumina? Investigate ida_lumina.py
    if arg_primary_server:
        return _ida_kernwin.process_ui_action('LuminaPushAllMds') # Same as the Menu: Lumina -> Push all (Ctrl + F12)

    return _ida_kernwin.process_ui_action('LuminaSecondaryPushAllMds')

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _idaapi_reg_data_type(arg_key: str, arg_subkey: Optional[str] = None) -> int:
    ''' Wrapper around ida_registry.reg_data_type() that honors the type hints
    regval_type_t is one of ida_registry.reg_sz, ida_registry.reg_binary or ida_registry.reg_dword

    @return -1 on fail (the arg_key does NOT exist) and the regval_type_t (int) otherwise
    '''
    # TODO: The subkey doesn't seem to work at all? I need to investigate...

    l_temp = _ida_registry.reg_data_type(arg_key, arg_subkey)
    return l_temp if l_temp else -1

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def ida_registry_read(arg_key: str, arg_subkey: Optional[str] = None) -> Tuple[str, str]:
    r''' Read from IDAs registy, on Windows this is the Windows registry: Computer\HKEY_CURRENT_USER\SOFTWARE\Hex-Rays\IDA and on Linux/MAC IDA emulates a registry
    e.g. print(ida_registry_read("AutoHighlight"))

    @ returns Tuple[reg_type: str, value: str]
    Read more <https://python.docs.hex-rays.com/namespaceida__registry.html>
    '''

    l_reg_type: int = _idaapi_reg_data_type(arg_key, arg_subkey)
    if l_reg_type == -1: # ERROR
        l_error = f'<<< idaapi_reg_data_type("{arg_key}", "{arg_subkey}") failed >>>'
        log_print(l_error, arg_type="ERROR")
        return ("ERROR", l_error)

    l_reg_type_as_str: str = _int_to_str_dict_from_module(_ida_registry, "reg_.*").get(l_reg_type, f"<<< Unknown reg type: 0x{l_reg_type:x} >>>")
    if l_reg_type == _ida_registry.reg_sz:
        res = _ida_registry.reg_read_string(arg_key, arg_subkey, "<<< default >>>")
        if res == "<<< default >>>":
            log_print(f'ida_registry.reg_read_string("{arg_key}", "{arg_subkey}") failed', arg_type="ERROR")
            return ("ERROR", "")
        return (l_reg_type_as_str, res)

    if l_reg_type == _ida_registry.reg_binary:
        res = " ".join(hex_parse(_ida_registry.reg_read_binary(arg_key, arg_subkey)))
        return (l_reg_type_as_str, res)

    if l_reg_type == _ida_registry.reg_dword:
        res = str(_ida_registry.reg_read_int(arg_key, -12345, arg_subkey))
        if res == "-12345":
            log_print(f'ida_registry.reg_read_int("{arg_key}", "{arg_subkey}") failed', arg_type="ERROR")
            return ("ERROR", "")
        return (l_reg_type_as_str, res)

    return ("ERROR", f"<<< Not implemented read for type: 0x{l_reg_type:x} >>>")

# @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
# def ida_registy_write(arg_key: str, arg_subkey: Optional[str] = None) -> Tuple[str, str]:
#     ''' # TODO: Implement '''
#     return ("# TODO: Implement", "# TODO: Implement")

_G_CALLING_CONVENTION_INT_TO_STR: Dict[int, str] = _dict_sort(_int_to_str_dict_from_module(_ida_typeinf, "CM_CC.*"))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_calling_convention(arg_ea: EvaluateType,
                                arg_new_calling_convertion: Union[str, int] = -1,
                                arg_cached_cfunc: Optional[_ida_hexrays.cfuncptr_t] = None,
                                arg_debug: bool = False) -> int:
    ''' Gets or sets the calling convention of a function
    @arg_new_calling_convertion ida_typeinf.CM_CC_* or the name of the calling convention, -1 means don't set any new calling convention
    @return -1 on fail otherwise ida_typeinf.CM_CC_*
    '''

    l_function = function(arg_ea, arg_debug=arg_debug)
    if l_function is None:
        log_print(f"No function at {_hex_str_if_int(arg_ea)}", arg_type="ERROR")
        return -1
    l_function_tinfo = get_type(arg_name_or_ea=l_function.start_ea, arg_cached_cfunc=arg_cached_cfunc, arg_debug=arg_debug)
    if l_function_tinfo is None:
        log_print(f"get_type(0x{l_function.start_ea:x}) failed", arg_type="ERROR")
        return -1
    l_function_details = _ida_typeinf.func_type_data_t()
    l_function_tinfo.get_func_details(l_function_details)
    l_calling_convention: int = _ida_typeinf.CM_CC_MASK
    if ida_version() >= 920:
        l_calling_convention &= l_function_details.get_explicit_cc() # https://python.docs.hex-rays.com/ida_typeinf/index.html#ida_typeinf.func_type_data_t.get_explicit_cc
    else:
        l_calling_convention &= l_function_details.cc

    if arg_new_calling_convertion == -1:
        return l_calling_convention

    # If we get here, then we are setting a new calling convention
    # Smart convert the user input to a ida_typinf.CM_CC_*
    if isinstance(arg_new_calling_convertion, str):
        arg_new_calling_convertion = arg_new_calling_convertion.upper()
        if arg_new_calling_convertion.startswith("__"):
            arg_new_calling_convertion = arg_new_calling_convertion[2:]

        if arg_new_calling_convertion == "USERCALL":
            arg_new_calling_convertion = "SPECIAL"
        elif arg_new_calling_convertion == "USERPURGE":
            arg_new_calling_convertion = "SPECIALP"

        if not arg_new_calling_convertion.startswith("CM_CC_"):
            arg_new_calling_convertion = "CM_CC_" + arg_new_calling_convertion
        log_print(f"Trying to look up: {arg_new_calling_convertion}", arg_debug)
        res = _dict_swap_key_and_value(_G_CALLING_CONVENTION_INT_TO_STR).get(arg_new_calling_convertion, -1)
        if res == -1:
            log_print(f"Failed to find: {arg_new_calling_convertion}", arg_type="ERROR")
            return -1
    else:
        res = arg_new_calling_convertion

    if res not in _G_CALLING_CONVENTION_INT_TO_STR:
        log_print(f"Invalid calling convention: {res}", arg_type="ERROR")
        return -1

    if ida_version() >= 920:
        l_function_details.set_cc(res)
    else:
        l_function_details.cc = res

    l_function_tinfo.create_func(l_function_details)
    _ = _ida_typeinf.apply_tinfo(l_function.start_ea, l_function_tinfo, _ida_typeinf.TINFO_DEFINITE)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_convert_to_usercall(arg_ea: EvaluateType, arg_debug: bool = False) -> bool:
    ''' Convert a function to __usercall (or __userpurge)
    Code was almost a pure copy from [HexraysPyTools](https://github.com/oopsmishap/HexRaysPyTools/blob/4742ce4ac7db72ad0cfb862d34cb15065b1b136e/HexRaysPyTools/callbacks/function_signature_modifiers.py#L15)
    Read more: <https://hex-rays.com/blog/igors-tip-of-the-week-51-custom-calling-conventions>
    '''
    l_cfunc = decompile(arg_ea, arg_force_fresh_decompilation=True, arg_debug=arg_debug)
    l_calling_convention: int = function_calling_convention(arg_ea=arg_ea, arg_new_calling_convertion=-1, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
    if l_calling_convention == -1:
        log_print("Got invalid calling convention, aborting", arg_type="ERROR")
        return False

    if l_calling_convention == _ida_typeinf.CM_CC_CDECL:
        function_calling_convention(arg_ea=arg_ea, arg_new_calling_convertion=_ida_typeinf.CM_CC_SPECIAL, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug) # __usercall
    elif l_calling_convention in (_ida_typeinf.CM_CC_STDCALL, _ida_typeinf.CM_CC_FASTCALL, _ida_typeinf.CM_CC_PASCAL, _ida_typeinf.CM_CC_THISCALL):
        function_calling_convention(arg_ea=arg_ea, arg_new_calling_convertion=_ida_typeinf.CM_CC_SPECIALP, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug) # __userpurge
    elif l_calling_convention == _ida_typeinf.CM_CC_ELLIPSIS:
        function_calling_convention(arg_ea=arg_ea, arg_new_calling_convertion=_ida_typeinf.CM_CC_SPECIALE, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
    elif l_calling_convention == _ida_typeinf.CM_CC_SPECIALP: # __userpurge
        log_print(f"Function {_hex_str_if_int(arg_ea)} is already __userpurge", arg_type="WARNING")
    elif l_calling_convention == _ida_typeinf.CM_CC_SPECIAL: # __usercall
        log_print(f"Function {_hex_str_if_int(arg_ea)} is already __usercall", arg_type="WARNING")
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def function_set_return_type(arg_ea: EvaluateType, arg_new_ret_type: Union[str, _ida_typeinf.tinfo_t], arg_debug: bool = False) -> bool:
    ''' Set the return type of a function '''
    # TODO: Rewrite this as a get and set in the same?
    l_cfunc = decompile(arg_ea, arg_debug=arg_debug)
    if l_cfunc is None:
        log_print(f"decompile({arg_ea}) failed", arg_type="ERROR")
        return False
    l_function_tinfo = _ida_typeinf.tinfo_t()
    if not l_cfunc.get_func_type(l_function_tinfo):
        log_print("l_cfunc.get_func_type() failed", arg_type="ERROR")
        return False
    l_function_details = _ida_typeinf.func_type_data_t()
    l_function_tinfo.get_func_details(l_function_details)

    l_temp_type = get_type(arg_new_ret_type, arg_debug=arg_debug)
    if l_temp_type is None:
        log_print(f"get_type({arg_new_ret_type}) failed", arg_type="ERROR")
        return False
    l_function_details.rettype = l_temp_type

    l_function_tinfo.create_func(l_function_details)
    return _bool(_ida_typeinf.apply_tinfo(l_cfunc.entry_ea, l_function_tinfo, _ida_typeinf.TINFO_DEFINITE))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def file_generate(arg_outfile_type: Union[str, int],
                           arg_out_file_path: str = "",
                           arg_start_ea: EvaluateType = 0,
                           arg_end_ea: EvaluateType = 0,
                           arg_flags: int = 0,
                           arg_debug: bool = False) -> str:
    ''' Generate a new file from the input file. This function is very weird since there is an option to generate EXE file but when you pick it in the menu, IDA say that this is not supported?!

    @param arg_outfile_type is either a string with the "ASM", "DIF", "EXE", "IDC", "LST" or "MAP". If it is an int, then it should be one of ida_loader.OFILE_*
    @param arg_out_file_path Filename to save to, it not set then use input_file.idb_path + "extension generated from the arg_outfile_type"
    @param arg_start_ea start from this EA (Effective Address)
    @param arg_end_ea end at this EA (Effective Address)
    @param arg_flags see ida_loader.GENFLG_*

    @return The file path I wrote the result to, empty str if something failed
    '''
    l_ofile_int_to_str = _int_to_str_dict_from_module(_ida_loader, "OFILE_.*")
    l_ofile_str_to_int = _dict_swap_key_and_value(l_ofile_int_to_str)
    if isinstance(arg_outfile_type, str):
        if not arg_outfile_type.startswith("OFILE_"):
            arg_outfile_type = "OFILE_" + arg_outfile_type.upper()

        if arg_outfile_type not in l_ofile_str_to_int:
            log_print(f"Invalid arg_outfile_type, valid: {l_ofile_str_to_int.keys()}")
            return ""

        l_outfile_type: int = l_ofile_str_to_int[arg_outfile_type]
    else:
        l_outfile_type = arg_outfile_type

    if l_outfile_type not in l_ofile_int_to_str:
        log_print(f"Invalid arg_outfile_type, valid: {l_ofile_str_to_int.keys()}")
        return ""

    l_expected_extension = l_ofile_int_to_str[l_outfile_type][6:].lower()

    l_outfile_path = arg_out_file_path if arg_out_file_path else input_file.idb_path + "." + l_expected_extension
    l_start_ea = address(arg_start_ea, arg_debug=arg_debug) if arg_start_ea else input_file.min_ea
    l_end_ea = address(arg_end_ea, arg_debug=arg_debug) if arg_end_ea else input_file.max_ea

    # Code taken from https://github.com/HexRaysSA/IDAPython/blob/d12e31eae9d678f647013527596a715dd378f989/examples/disassembler/produce_lst_file.py#L32
    l_file_wrapper = _ida_fpro.qfile_t() # FILE * wrapper
    l_file_mode = "wb" if l_outfile_type == l_ofile_str_to_int["OFILE_EXE"] else "wt"
    if l_file_wrapper.open(l_outfile_path, l_file_mode):
        l_ren_file_res = _ida_loader.gen_file(l_outfile_type, l_file_wrapper.get_fp(), l_start_ea, l_end_ea, arg_flags)
        if not l_ren_file_res:
            log_print("ida_loader.gen_file() failed", arg_type="ERROR")
        l_file_wrapper.close()
    else:
        log_print(f'Could not open "{l_outfile_path}"', arg_type="ERROR")
        return ""

    # gen_file_flags = {}
    # gen_file_flags["GENFLG_MAPSEG"] = 0x0001 # map: generate map of segments
    # gen_file_flags["GENFLG_MAPNAME"] = 0x0002 # map: include dummy names
    # gen_file_flags["GENFLG_MAPDMNG"] = 0x0004 # map: demangle names
    # gen_file_flags["GENFLG_MAPLOC"] = 0x0008 # map: include local names
    # gen_file_flags["GENFLG_IDCTYPE"] = 0x0008 # idc: gen only information about types
    # gen_file_flags["GENFLG_ASMTYPE"] = 0x0010 # asm&lst: gen information about types too
    # gen_file_flags["GENFLG_GENHTML"] = 0x0020 # asm&lst: generate html (ui_genfile_callback will be used)
    # gen_file_flags["GENFLG_ASMINC"] = 0x0040 # asm&lst: gen information only about types

    # gen_file_flags = _dict_swap_key_and_value(_int_to_str_dict_from_module("_ida_loader", "GENFLG_.*"))

    return l_outfile_path


# New members/functions of IDA pythons objects -------------------------------------------------------------------------------------------------------------------------- New members/functions of IDA pythons objects


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def __repr__type_address_str(arg_self: EvaluateType) -> str:
    ''' repr with type, address and content '''
    return f"{type(arg_self)} @ 0x{address(arg_self):x} which has str():\n{str(arg_self)}"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def __repr__type_str(arg_self: Any) -> str:
    ''' repr with type and content '''
    return f"{type(arg_self)} which has str():\n{str(arg_self)}"

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _instruction_is_same_as_nop(arg_instruction: EvaluateType, arg_debug: bool = False) -> Optional[bool]:
    ''' Given an instruction, check if the operation done by the instruction is not changing any state, e.g. mov rax, rax

    OBS! This list is _NOT_ all the NOPs there are. This list will get populated as the script evolves
    '''
    l_ins = instruction(arg_instruction, arg_debug=arg_debug)
    if l_ins is None:
        return None
    if l_ins.itype == _ida_allins.NN_nop: # e.g. nop
        return True
    if _ida_idp.ph_get_id() != _ida_idp.PLFM_386: # The NN_* itypes below are only valid for x86/x64
        return False
    if l_ins.itype == _ida_allins.NN_nop: # e.g. nop
        return True

    # OBS! In 64-bit code, writing a 32-bit register zero extends it: "mov eax, eax" and "xchg eax, eax" (87 C0) clear the upper half of rax so they are NOT NOPs
    l_writes_32_bit_register_in_64_bit_code: bool = input_file.bits == 64 and l_ins.ops[0].type == _ida_ua.o_reg and l_ins.ops[0].dtype == _ida_ua.dt_dword
    if l_writes_32_bit_register_in_64_bit_code:
        return False
    if l_ins.itype == _ida_allins.NN_mov and l_ins.ops[0].type == _ida_ua.o_reg and l_ins.ops[0] == l_ins.ops[1]: # e.g. mov rax, rax
        return True
    if l_ins.itype == _ida_allins.NN_xchg and l_ins.ops[0].type == _ida_ua.o_reg and l_ins.ops[0] == l_ins.ops[1]: # e.g. xchg rax, rax
        return True

    return False

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _instruction_jumps(arg_instruction: _ida_ua.insn_t) -> bool:
    ''' Internal function. Processor independent: does the instruction have a jump xref (not a call) to another address? '''
    l_xref = _ida_xref.xrefblk_t()
    l_ok = l_xref.first_from(arg_instruction.ea, _ida_xref.XREF_FAR) # XREF_FAR (no ordinary flow) exists in IDA 8.4 and 9.x, XREF_CODE is new in IDA 9. We only look at fl_JN/fl_JF below anyway
    while l_ok:
        if l_xref.type in (_ida_xref.fl_JN, _ida_xref.fl_JF):
            return True
        l_ok = l_xref.next_from()
    return False

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _instruction_is_jmp(arg_instruction: _ida_ua.insn_t) -> bool:
    ''' Internal function. Is the instruction an unconditional jump? The NN_* itypes are only valid on x86/x64, other processors use a generic check '''
    if _ida_idp.ph_get_id() == _ida_idp.PLFM_386:
        return arg_instruction.itype in [_ida_allins.NN_jmp, _ida_allins.NN_jmpshort, _ida_allins.NN_jmpfi, _ida_allins.NN_jmpni]
    return _instruction_jumps(arg_instruction) and _bool(_ida_idp.has_insn_feature(arg_instruction.itype, _ida_idp.CF_STOP)) # Jumps and does not continue to the next instruction

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _instruction_is_jcc(arg_instruction: _ida_ua.insn_t) -> bool:
    ''' Internal function. Is the instruction a conditional jump? The NN_* itypes are only valid on x86/x64, other processors use a generic check '''
    if _ida_idp.ph_get_id() == _ida_idp.PLFM_386:
        return arg_instruction.itype in _conditional_jmps_x64
    return _instruction_jumps(arg_instruction) and not _bool(_ida_idp.has_insn_feature(arg_instruction.itype, _ida_idp.CF_STOP)) and not _ida_idp.is_call_insn(arg_instruction) # Jumps but can also continue to the next instruction

setattr(_ida_ua.insn_t, '__str__', disassemble)
setattr(_ida_ua.insn_t, '__repr__', __repr__type_address_str)
setattr(_ida_ua.insn_t, '__len__', lambda self: self.size)
setattr(_ida_ua.insn_t, '__bytes__',  lambda self: self.bytes)
setattr(_ida_ua.insn_t, 'instruction_before', property(fget=instruction_before))
setattr(_ida_ua.insn_t, 'previous_instruction', property(fget=instruction_before))
setattr(_ida_ua.insn_t, 'instruction_after', property(fget=instruction_after))
setattr(_ida_ua.insn_t, 'next_instruction', property(fget=instruction_after))
setattr(_ida_ua.insn_t, 'operands', property(fget=lambda self: [op for op in self.ops if op.type != _ida_ua.o_void])) # Replacement for ida_ua.insn_t.ops. _ida_ua.insn_t.ops is always 8 elements long even if there are not that many operands
setattr(_ida_ua.insn_t, 'operands_as_dict', property(fget=lambda self: [_operand_parser(op, self) for op in self.operands], doc='Same as op_t.as_dict for every operand, but also correct for r8-r15 in [base + index * scale] on x64 (the REX prefix is in the instruction)'))
setattr(_ida_ua.insn_t, 'function', property(fget=function))
setattr(_ida_ua.insn_t, 'mnemonic', property(fget=lambda self: _ida_ua.print_insn_mnem(address(self)).lower(), doc='Get the mnemonic. e.g. "MOV EAX, EBX" --> "mov"'))
setattr(_ida_ua.insn_t, 'bytes', property(fget=lambda self: read_bytes(self.ea, _ida_bytes.get_item_size(self.ea)), doc='Get the byte values that makes up this instruction'))
setattr(_ida_ua.insn_t, 'is_jmp', property(fget=_instruction_is_jmp, doc='Is the instruction an unconditional JMP?'))
setattr(_ida_ua.insn_t, 'comment', property(fget=_comment_get, fset=_comment_set)) # type: ignore[arg-type]
_conditional_jmps_x64 = [_ida_allins.NN_ja, _ida_allins.NN_jae, _ida_allins.NN_jb, _ida_allins.NN_jbe, _ida_allins.NN_jc, _ida_allins.NN_jcxz, _ida_allins.NN_je, _ida_allins.NN_jecxz, _ida_allins.NN_jg, _ida_allins.NN_jge, _ida_allins.NN_jl, _ida_allins.NN_jle, _ida_allins.NN_jna, _ida_allins.NN_jnae, _ida_allins.NN_jnb, _ida_allins.NN_jnbe, _ida_allins.NN_jnc, _ida_allins.NN_jne, _ida_allins.NN_jng, _ida_allins.NN_jnge, _ida_allins.NN_jnl, _ida_allins.NN_jnle, _ida_allins.NN_jno, _ida_allins.NN_jnp, _ida_allins.NN_jns, _ida_allins.NN_jnz, _ida_allins.NN_jo, _ida_allins.NN_jp, _ida_allins.NN_jpe, _ida_allins.NN_jpo, _ida_allins.NN_jrcxz, _ida_allins.NN_js, _ida_allins.NN_jz]
setattr(_ida_ua.insn_t, 'is_jcc', property(fget=_instruction_is_jcc, doc='Is the instruction a conditional JMP?'))
setattr(_ida_ua.insn_t, 'is_call', property(fget=_ida_idp.is_call_insn, doc='Is the instruction a call?'))
setattr(_ida_ua.insn_t, 'is_ret', property(fget=_ida_idp.is_ret_insn, doc='Is the instruction a return?'))
setattr(_ida_ua.insn_t, 'is_same_as_nop', property(fget=_instruction_is_same_as_nop, doc='Is the instruction a NOP? (or code that does nothing e.g. mov rax, rax)'))
setattr(_ida_funcs.func_t, '__str__', lambda self: f"name: {_ida_funcs.get_func_name(self.start_ea)},  start_ea: 0x{self.start_ea:x}, end_ea: 0x{self.end_ea:x}")
setattr(_ida_funcs.func_t, '__repr__', __repr__type_address_str)
setattr(_ida_funcs.func_t, '__len__', lambda self: self.end_ea - self.start_ea)
setattr(_ida_funcs.func_t, 'decompiled', property(fget=decompile, doc="Returns a ida_hexrays.cfuncptr_t, same as the decompile() function returns"))
setattr(_ida_funcs.func_t, 'prototype', property(fget=function_prototype, fset=set_type)) # type: ignore[arg-type]
setattr(_ida_funcs.func_t, 'name', property(fget=name, fset=name, doc="Get or set the name of the function")) # type: ignore[arg-type]
setattr(_ida_funcs.func_t, 'address', property(fget=address))
setattr(_ida_funcs.func_t, 'return_type', property(fget=lambda self: decompile(self).type.get_rettype())) # type: ignore[union-attr]
setattr(_ida_funcs.func_t, 'is_library_function', property(fget=function_is_library_function))
setattr(_ida_funcs.func_t, 'is_lumina_name', property(fget=function_is_lumina_name))

__GLOBAL_KEEP_REFERENCE_TO_AVOID_MEMORY_CORRUPTION__ = 0
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _function_arguments(arg_ea: EvaluateType, arg_debug: bool = False) -> Optional[_ida_typeinf.func_type_data_t]:
    ''' Internal function. Gets the arguments to a function '''

    global __GLOBAL_KEEP_REFERENCE_TO_AVOID_MEMORY_CORRUPTION__
    l_function = function(arg_ea, arg_debug=arg_debug)
    if l_function is None:
        log_print(f"function({_hex_str_if_int(arg_ea)}) failed", arg_type="ERROR")
        return None
    l_tif = _ida_typeinf.tinfo_t()
    if not _ida_nalt.get_tinfo(l_tif, l_function.address):
        log_print(f"ida_nalt.get_tinfo(_tif, 0x{l_function.address:x}) failed", arg_type="ERROR")
        return None
    l_funcdata = _ida_typeinf.func_type_data_t()
    if not l_tif.get_func_details(l_funcdata):
        log_print("tif.get_func_details() failed", arg_type="ERROR")
        return None

    # TODO: You get memory corruption if you do: community_base.function(<address>).arguments[0], IDA bug
    __GLOBAL_KEEP_REFERENCE_TO_AVOID_MEMORY_CORRUPTION__ = l_funcdata
    return l_funcdata

setattr(_ida_funcs.func_t, 'arguments', property(fget=_function_arguments))
setattr(_ida_funcs.func_t, 'calls', property(fget=assembler_calls))
setattr(_ida_funcs.func_t, '__call__', lambda *args: appcall(args[0])(*args[1:])) # type: ignore[misc] # py_lstrcmpA = cb.function("lstrcmpA"); py_lstrcmpA("input_text", "input_text") # TODO: This is dangerous, maybe remove?
setattr(_ida_funcs.func_t.__call__, '__doc__', f"Calls the function via AppCall. Read more: {links()['links']['appcall_guide']}")
setattr(_ida_funcs.func_t, '__bytes__', lambda f: read_bytes(f.start_ea, f.end_ea - f.start_ea)) # end_ea is exclusive, OBS! Function tails (chunks) are not included
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _argloc_t_type_to_str(arg_argloc: Union[_ida_typeinf.argloc_t, _ida_typeinf.funcarg_t]) -> Optional[str]:
    ''' Internal function. Convert the int from argloc.atype() to a human readable string '''

    l_argloc: _ida_typeinf.argloc_t = arg_argloc.argloc if isinstance(arg_argloc, _ida_typeinf.funcarg_t) else arg_argloc
    l_argloc_dict: Dict[int, str] = _int_to_str_dict_from_module(_ida_typeinf, "ALOC_.*") # l_argloc_dict[_ida_typeinf.ALOC_STACK: int] -> "ALOC_STACK": str
    res = l_argloc_dict.get(l_argloc.atype(), None)
    if res is None:
        log_print(f"Could not find any ALOC_* type for arg_argloc.atype(): {l_argloc.atype()}", arg_type="ERROR")
        log_print(f"Since atype() is so large, it hints about memory corruption.\nThe possible values are:\n{l_argloc_dict}", l_argloc.atype() > 1000)
        return None

    return res
setattr(_ida_typeinf.argloc_t, '__str__', _argloc_t_type_to_str)
setattr(_ida_typeinf.argloc_t, '__repr__', __repr__type_str)
setattr(_ida_typeinf.argloc_t, 'atype_as_str', property(fget=_argloc_t_type_to_str))
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _funcarg_t_str(arg_funcarg_t: _ida_typeinf.funcarg_t) -> str:
    ''' Internal function. Makes a nice string from a ida_typeinf.funcarg_t object '''

    res = f"argument: '{str(arg_funcarg_t.type)} {arg_funcarg_t.name if arg_funcarg_t.name else '<no name>' }' with argument location: {str(arg_funcarg_t.argloc)}"
    if arg_funcarg_t.argloc.is_reg1():
        res += f'\nRegister: {str(arg_funcarg_t.register.name)}: {(f"0x{_register(arg_funcarg_t.register):x}" if debugger_is_active() else "<value only available when debugger is active>")}'
    # TODO: elif on stack: print stack var
    return res
setattr(_ida_typeinf.funcarg_t, '__str__', _funcarg_t_str)
setattr(_ida_typeinf.funcarg_t, '__repr__', __repr__type_str)
setattr(_ida_typeinf.funcarg_t, 'size', property(fget=lambda self: len(self.type)))
setattr(_ida_typeinf.funcarg_t, 'register', property(fget=lambda self: registers._as_dict[_ida_idp.get_reg_name(self.argloc.reg1(), self.size)] if self.argloc.is_reg1() else None))
setattr(_ida_typeinf.func_type_data_t, '__str__', lambda self: '[ ' + "\n\n".join([repr(funcarg_t) for funcarg_t in self]) + '\n]')
setattr(_ida_typeinf.func_type_data_t, '__repr__', __repr__type_str)
setattr(_ida_typeinf.tinfo_t, '__repr__', __repr__type_str)
setattr(_ida_typeinf.tinfo_t, '__len__', lambda self: self.get_size() if self.get_size() != _ida_typeinf.BADSIZE else 0)
setattr(_ida_typeinf.tinfo_t, '__bool__', lambda self: self.is_well_defined())
setattr(_ida_typeinf.tinfo_t, 'size', property(fget=len))
setattr(_ida_typeinf.tinfo_t, 'return_type', property(fget=lambda self: self.get_rettype() if self.is_func() or self.is_funcptr() else None))

# TODO: add details for ida_typeinf.udt_type_data_t

setattr(_ida_kernwin.simpleline_t, '__str__', lambda self: _ida_lines.tag_remove(self.line))
setattr(_ida_kernwin.simpleline_t, '__repr__', __repr__type_str)
setattr(_ida_pro.strvec_t, '__str__', lambda self: "\n".join([str(simpleline) for simpleline in self]))
setattr(_ida_segment.segment_t, '__repr__', __repr__type_str)
setattr(_ida_segment.segment_t, '__str__', lambda self: f".name_as_str: {self.name_as_str}, .class_as_str: {self.class_as_str}, .start_ea: 0x{self.start_ea:x}, .end_ea: 0x{self.end_ea:x}, .readable: {self.readable}, .writable: {self.writable}, .executable: {self.executable}")
setattr(_ida_segment.segment_t, '__len__', lambda self: self.size())
setattr(_ida_segment.segment_t, 'readable', property(fget=lambda self: _bool(self.perm & _ida_segment.SEGPERM_READ), fset=lambda self, value: _segment_permissions(self, arg_readable=value))) # type: ignore[arg-type]
setattr(_ida_segment.segment_t, 'writable', property(fget=lambda self: _bool(self.perm & _ida_segment.SEGPERM_WRITE), fset=lambda self, value: _segment_permissions(self, arg_writable=value))) # type: ignore[arg-type]
setattr(_ida_segment.segment_t, 'executable', property(fget=lambda self: _bool(self.perm & _ida_segment.SEGPERM_EXEC), fset=lambda self, value: _segment_permissions(self, arg_executable=value))) # type: ignore[arg-type]
setattr(_ida_segment.segment_t, 'name_as_str', property(fget=_ida_segment.get_segm_name, fset=_ida_segment.set_segm_name)) # '.name' is already taken but it contains an int?
setattr(_ida_segment.segment_t, 'class_as_str', property(fget=_ida_segment.get_segm_class, fset=_ida_segment.set_segm_class))
setattr(_ida_segment.segment_t, 'bits', property(fget=lambda self: 0x10 << self.bitness))
_G_DATA_TYPE_SIZES_IN_BYTES: Dict[int, int] = {_ida_ua.dt_byte: 1, _ida_ua.dt_word: 2, _ida_ua.dt_dword: 4, _ida_ua.dt_qword: 8, _ida_ua.dt_float: 4, _ida_ua.dt_double: 8, _ida_ua.dt_byte16: 16, _ida_ua.dt_byte32: 32, _ida_ua.dt_byte64: 64, _ida_ua.dt_half: 2}
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _op_t_is_reg(self: _ida_ua.op_t, arg_register_name_or_index: Union[int, str, _ida_idp.reg_info_t]) -> bool:
    ''' Replacement for ida_ua.op_t.is_reg() to allow to also check for register name or ida_idp.reg_info_t '''
    if isinstance(arg_register_name_or_index, int):
        return self.reg == arg_register_name_or_index
    if isinstance(arg_register_name_or_index, str):
        l_reg_info = _ida_idp.reg_info_t()
        if not _ida_idp.parse_reg_name(l_reg_info, arg_register_name_or_index):
            log_print("Invalid register name", arg_type="ERROR")
            return False

        return l_reg_info.reg == self.reg and _G_DATA_TYPE_SIZES_IN_BYTES[self.dtype] == l_reg_info.size
    # isinstance(arg_register_name_or_index, _ida_idp.reg_info_t):
    return arg_register_name_or_index.reg == self.reg and _G_DATA_TYPE_SIZES_IN_BYTES[self.dtype] == arg_register_name_or_index.size

setattr(_ida_ua.op_t, 'is_reg', _op_t_is_reg)
_operand_type = _int_to_str_dict_from_module(_ida_ua, "o_.*")
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _op_t__str__(self: _ida_ua.op_t, arg_debug: bool = False) -> str:
    ''' Internal function. More verbose output in the __str__() of ida_ua.op_t '''
    if self.type == _ida_ua.o_void:
        return "<<< invalid operand >>> IDA use an ida_ua.op_t with .type == ida_ua.o_void to signal that it's invalid. I don't like this."

    l_parsed = _operand_parser(self, arg_debug=arg_debug)
    if l_parsed is None:
        log_print(f"Unknown operand type, we got 0x{self.type:x} which I cannot handle.", arg_type="ERROR")
        return "<<< Can _NOT_ parse this operand >>>"

    log_print(f"l_parsed: {l_parsed}", arg_debug)

    l_temp = l_parsed.get('register', None)
    if l_temp is not None:
        return str(l_temp)

    l_temp = l_parsed.get('address', None)
    if l_temp is not None:
        return _hex_str_if_int(l_temp, arg_debug=arg_debug)

    l_temp = l_parsed.get('value', None)
    if l_temp is not None:
        return _hex_str_if_int(l_temp, arg_debug=arg_debug)

    l_base_reg = l_parsed.get('base_register', None)
    if l_base_reg is not None:
        l_displacement = l_parsed['displacement']
        l_displacement_string = _signed_hex_text(l_displacement) if l_displacement else ""
        l_scale_string = ""
        if l_parsed.get('index_register', None):
            l_scale = l_parsed['scale']
            l_scale_const = f"*{l_parsed['scale']}" if l_parsed['scale'] > 1 else ""
            l_index_reg = l_parsed['index_register']
            l_scale_string = f"+{l_index_reg.name}{l_scale_const}" if l_scale else ""
        return f"[{l_base_reg.name}{l_scale_string}{l_displacement_string}]"

    log_print("Could not parse the given ida_ua.op_t.", arg_type='ERROR')
    return "<<< invalid operand, could _NOT_ parse it >>>"
setattr(_ida_ua.op_t, '__str__', _op_t__str__)
setattr(_ida_ua.op_t, '__repr__', lambda self: f"{type(self)} with operand_type {_operand_type.get(self.type, '<unknown ida_ua.o_???>')} which has str():\n{str(self)}")
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _op_t_to_register(arg_operand: _ida_ua.op_t, arg_debug: bool = False) -> Optional[_ida_idp.reg_info_t]:
    ''' Get the register as ida_idp.reg_info_t '''
    res = None
    if arg_operand.type in [_ida_ua.o_reg, _ida_ua.o_displ, _ida_ua.o_phrase]:
        l_reg_name = _ida_idp.get_reg_name(arg_operand.reg, _G_DATA_TYPE_SIZES_IN_BYTES[arg_operand.dtype])
        res = _ida_idp.reg_info_t()
        _ida_idp.parse_reg_name(res, l_reg_name)
        log_print(f"res: {repr(res)}", arg_debug)
        return res

    # log_print(f"arg_operand is {str(arg_operand)} which is something I cannot handle right now", arg_type="ERROR")
    return None

setattr(_ida_ua.op_t, 'register', property(fget=_op_t_to_register))
setattr(_ida_ua.op_t, 'name', property(fget=name))
setattr(_ida_ua.op_t, '__len__', lambda self: _G_DATA_TYPE_SIZES_IN_BYTES[self.dtype])
setattr(_ida_ua.op_t, 'as_dict', property(fget=_operand_parser))
setattr(_ida_ua.op_t, '__eq__', lambda self, other: isinstance(other, _ida_ua.op_t) and self.type == other.type and self.dtype == other.dtype and self.value == other.value and self.value64 == other.value64 and self.specflag1 == other.specflag1 and self.specflag2 == other.specflag2 and self.reg == other.reg and self.addr == other.addr)
setattr(_ida_idp.reg_info_t, '__str__', lambda self: f".name: {_ida_idp.get_reg_name(self.reg, self.size)}, .size: 0x{self.size:x}, .register_index: {self.reg}, .value: " + (_hex_str_if_int(_register(self)) if debugger_is_active() else "<value only available when debugger is active>") + "\n")
setattr(_ida_idp.reg_info_t, '__repr__', __repr__type_str)
setattr(_ida_idp.reg_info_t, '__len__', lambda self: self.size)
setattr(_ida_idp.reg_info_t, 'name', property(fget=lambda self: _ida_idp.get_reg_name(self.reg, self.size)))
setattr(_ida_idp.reg_info_t, 'register_index', _ida_idp.reg_info_t.reg)
setattr(_ida_idp.reg_info_t, 'value', property(fget=_register, fset=_register)) # type: ignore[arg-type]
setattr(_ida_idp.reg_info_t, '__add__', lambda self, other: eval_expression(self) + eval_expression(other)) # type: ignore[operator]
setattr(_ida_idp.reg_info_t, '__radd__', _ida_idp.reg_info_t.__add__)
setattr(_ida_idp.reg_info_t, '__iadd__', lambda self, other: self if _register(arg_register=self, arg_set_value=eval_expression(self) + eval_expression(other)) else self) # type: ignore[operator]
setattr(_ida_idp.reg_info_t, '__sub__', lambda self, other: eval_expression(self) - eval_expression(other)) # type: ignore[operator]
setattr(_ida_idp.reg_info_t, '__rsub__', lambda other, self: _ida_idp.reg_info_t.__sub__(self, other))
setattr(_ida_idp.reg_info_t, '__isub__', lambda self, other: self if _register(arg_register=self, arg_set_value=eval_expression(self) - eval_expression(other)) else self) # type: ignore[operator]
setattr(_ida_idp.reg_info_t, '__eq__', lambda self, other: self is other or self.name == other)
setattr(_ida_hexrays.carg_t, '__repr__', lambda self: f"{type(self)} which looks like:\n{self.type} {str(self)}")
setattr(_ida_hexrays.carg_t, 'name', property(fget=str)) # TODO: Bad idea?
setattr(_ida_hexrays.carglist_t, '__repr__', lambda self: f"{type(self)} which looks like:\n{' '.join([chr(0x0D)+repr(arg)+chr(0x0D) for arg in self])}")
setattr(_ida_hexrays.cfuncptr_t, '__str__', lambda self: str(self.get_pseudocode())) # Print THIS object, don't decompile again (the strvec_t.__str__ is set below)
setattr(_ida_hexrays.cfuncptr_t, '__repr__', lambda self: __repr__type_address_str(self)[0:200])
setattr(_ida_hexrays.cfuncptr_t, 'address', property(fget=address))
setattr(_ida_hexrays.cfuncptr_t, 'prototype', property(fget=function_prototype))
setattr(_ida_hexrays.cfuncptr_t, 'return_type', property(fget=lambda self: self.type.get_rettype(), doc='The tinfo_t of the return value'))
setattr(_ida_hexrays.cfuncptr_t, 'name', property(fget=name, fset=lambda self, new_name: name(self, arg_set_name=new_name, arg_force=True))) # type: ignore[union-attr, arg-type]
setattr(_ida_hexrays.cfuncptr_t, 'local_variables', property(fget=lambda self: {var.name: var for var in self.lvars}))
setattr(_ida_hexrays.cfuncptr_t, 'calls', property(fget=decompiler_calls))
setattr(_ida_hexrays.cfuncptr_t, 'is_lumina_name', property(fget=function_is_lumina_name))
setattr(_ida_hexrays.citem_t, '__str__', lambda self: f"{_ida_lines.tag_remove(self.print1(None))}")
setattr(_ida_hexrays.citem_t, '__repr__', __repr__type_address_str)
setattr(_ida_hexrays.cexpr_t, '__repr__', lambda self: f"{type(self)} with opname: '{self.opname}' and to_specific_type.opname: '{self.to_specific_type.opname}' @ 0x{address(self):x} which looks like:\n{str(self)}"  ) # TODO: address of cexpr_t is not OK according to the type hints
setattr(_ida_hexrays.cexpr_t, 'arguments', property(fget=lambda self: self._get_a() if self.opname == 'call' else None)) # Used for cot_call
setattr(_ida_hexrays.cexpr_t, 'first_operand', _ida_hexrays.cexpr_t.x) # Better name
setattr(_ida_hexrays.cexpr_t, 'second_operand', _ida_hexrays.cexpr_t.y) # Better name
setattr(_ida_hexrays.cexpr_t, 'third_operand', _ida_hexrays.cexpr_t.z) # Better name
setattr(_ida_hexrays.cexpr_t, 'variable', _ida_hexrays.cexpr_t.v) # Better name. used for cot_var
setattr(_ida_hexrays.cexpr_t.v, '__doc__', 'Short name for variable. Only used for cot_var')
setattr(_ida_hexrays.cexpr_t, 'value', property(fget=lambda self: self.numval() if self.opname == 'num' else None)) # Used for cot_num
setattr(_ida_hexrays.cexpr_t, 'float', _ida_hexrays.cexpr_t.fpc) # Used for cot_fnum
setattr(_ida_hexrays.cexpr_t, 'target_ea', property(fget=lambda self: self.x.obj_ea if self.opname == 'call' else None)) # Used for cot_obj. Use this to get the address that the call is calling to
setattr(_ida_hexrays.cexpr_t, 'member_offset', _ida_hexrays.cexpr_t.m) # Used for cot_memptr and cot_memref
setattr(_ida_hexrays.cinsn_t, '__repr__', lambda self: f"{type(self)} with opname: '{self.opname}' and to_specific_type.opname: '{self.to_specific_type.opname}' @ 0x{address(self):x} which looks like:\n{str(self)}"  ) # "cinsn_t represents statements supported by Hex-Rays (cit_for, cit_if, cit_return etc...)" source: https://hex-rays.com/blog/hex-rays-decompiler-primer
setattr(_ida_hexrays.casm_t, '__repr__', lambda self: "__asm { \n" + "\n".join(["\t" + disassemble(x, arg_show_size=False, arg_show_bytes=False) for x in self]) + "\n}") # type: ignore[operator]
setattr(_ida_hexrays.lvar_t, '__str__', lambda self: f"{str(self.type()).replace(' *','*')} {str(self.name)}")
setattr(_ida_hexrays.lvar_t, '__repr__', lambda self: f"{type(self)} which looks like:\n{str(self)}")
setattr(_ida_hexrays.lvar_t, '__len__', lambda self: self.type().size)
setattr(_ida_hexrays.lvar_t, 'register', property(fget=lambda self: registers._as_dict[_ida_idp.get_reg_name(_ida_hexrays.mreg2reg(self.get_reg1(), len(self)), len(self))] if self.is_reg1() else None))
setattr(_ida_hexrays.lvars_t, "__repr__", lambda self: "[" +  "\n".join([repr(var) for var in self]) + "]")
setattr(_ida_hexrays.var_ref_t, '__str__', lambda self: str(self.getv())) # self.getv() returns a _ida_hexrays.lvar_t
setattr(_ida_hexrays.var_ref_t, '__repr__', __repr__type_str)
setattr(_ida_hexrays.vdui_t, '__str__', lambda self: f"Window title: {TWidget(self.ct).window_title()}, function name: {name(self.cfunc)}")
setattr(_ida_hexrays.vdui_t, '__repr__', __repr__type_str)
setattr(_ida_hexrays.ctree_items_t, '__repr__', lambda self: f"{type(self)} which looks like:\n[{', '.join([str(citem) for citem in self])}]")
setattr(_ida_idd.Appcall_callable__, '__str__', lambda self: str(function(self)))
setattr(_ida_idd.Appcall_callable__, '__repr__', __repr__type_address_str)
setattr(_ida_typeinf.enum_member_t, '__str__', lambda self: f"{self.name} = 0x{self.value:x}, // {self.value}")
setattr(_ida_typeinf.enum_member_t, '__repr__', __repr__type_str)
setattr(_ida_typeinf.enum_type_data_t, '__repr__', lambda self: "\n".join([str(member) for member in self]))
setattr(_ida_dbg.bpt_t, '__str__', lambda self: f"ea: 0x{self.ea:x}, is hardware breakpoint (is_hwbpt): {self.is_hwbpt()}, enabled: {self.enabled()}, eval_lang: {self.elang}, condition: {self.condition}")
setattr(_ida_dbg.bpt_t, '__repr__', __repr__type_address_str)
setattr(_ida_dbg.bpt_t.elang, "__doc__", "The language used to evaluate what to do when we hit this breakpoint. Allowed values are IDC or Python")
setattr(_ida_idd.modinfo_t, '__str__', lambda self: f"name: {self.name}, base: 0x{self.base:x}, size: 0x{self.size:x}, rebase_to: 0x{self.rebase_to:x}")
setattr(_ida_idd.modinfo_t, '__repr__', __repr__type_address_str)
setattr(_ida_idd.modinfo_t, '__add__', lambda self, other: eval_expression(self) + eval_expression(other)) # type: ignore[operator]
setattr(_ida_range.range_t, '__str__', lambda self: f"start_ea: {_hex_str_if_int(self.start_ea)} --> end_ea: {_hex_str_if_int(self.end_ea)}")
setattr(_ida_range.range_t, '__repr__', __repr__type_address_str)
setattr(_ida_idd.process_info_t, '__repr__', lambda self: f"process name: {self.name}, PID: 0x{self.pid:x} ({self.pid})")
setattr(_idautils.Strings.StringItem, "__repr__", __repr__type_address_str)
setattr(_idautils.Strings.StringItem, "encoding", property(fget=lambda self: _idaapi_encoding_from_strtype(self.strtype)))


# TESTS ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ TESTS


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_appcall_on_Windows(arg_debug: bool = False) -> bool:
    ''' Test appcall on Windows. Needs a running process. '''
    res = True
    l_GetProcessHeap_res = win_GetProcessHeap(arg_debug=arg_debug)
    if l_GetProcessHeap_res is None:
        log_print('win_GetProcessHeap returned None', arg_type="ERROR")
        return False
    res &= (l_GetProcessHeap_res == win_GetProcessHeap_emulated(arg_debug=arg_debug)) # win_GetProcessHeap --> appcall,

    if res:
        log_print('Appcall tests OK!', arg_debug, arg_type="INFO")
    else:
        log_print('Appcall tests failed!', arg_debug, arg_type="ERROR")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_mem_alloc_write_read(arg_debug: bool = False) -> bool:
    ''' Tests: allocate_memory_in_target(), write_string(), write_bytes(), read_bytes(), string()
        Needs a running process.
    '''
    res = True
    l_memory = allocate_memory_in_target(0x1000, arg_debug=arg_debug)
    if l_memory is None:
        log_print('Failed to allocate memory', arg_type="ERROR")
        return False
    log_print(f"Allocated 0x1000 bytes at 0x{l_memory:x}", arg_type="INFO")
    l_input_test_string: str = "This string is for the tests!"
    write_string(l_memory, l_input_test_string, arg_debug=arg_debug) # write_string --> write_bytes --> read_bytes
    l_test_string = string(l_memory, arg_debug=arg_debug)
    l_ok = (l_input_test_string == l_test_string) # l_ok is the result of THIS check, res is the result of all checks so far
    res &= l_ok
    log_print(f"cstring test: {l_ok}", arg_debug)
    log_print(f"<<< FAILED >>> cstring test: got '{l_test_string}'", arg_actually_print=not l_ok, arg_type="ERROR")

    l_input_test_string_wide: bytes = b"T\x00e\x00s\x00t\x00\x00\x00"
    write_bytes(l_memory, l_input_test_string_wide, arg_debug=arg_debug)
    l_wide_string_res = string(l_memory, arg_encoding="utf-16LE", arg_debug=arg_debug)
    l_ok = ("Test" == l_wide_string_res)
    res &= l_ok
    log_print(f"simple wide string test: {l_ok}", arg_debug)
    log_print(f"<<< FAILED >>> simple wide string test: got '{l_wide_string_res}'", arg_actually_print=not l_ok, arg_type="ERROR")

    l_non_english_char_test_string: str = "åäö"
    l_encoding = "utf-8"
    write_bytes(l_memory, "00" * 32, arg_debug=arg_debug)
    write_bytes(l_memory, l_non_english_char_test_string.encode(l_encoding), arg_debug=arg_debug)
    l_nonenglish_res = string(l_memory, arg_encoding=l_encoding, arg_debug=arg_debug)
    if l_nonenglish_res is None:
        log_print("string() failed", arg_type="ERROR")
        return False
    l_ok = (l_nonenglish_res == l_non_english_char_test_string)
    res &= l_ok
    log_print(f"l_non_english_char_test_string: {' '.join(hex_parse(l_non_english_char_test_string.encode(l_encoding)))}", arg_debug)
    log_print(f"l_nonenglish_res: {' '.join(hex_parse(l_nonenglish_res.encode(l_encoding)))}", arg_debug)
    log_print(f"non english string test: {l_ok}", arg_debug)
    log_print(f"<<< FAILED >>> {l_encoding} test: got '{l_nonenglish_res}'", arg_actually_print=not l_ok, arg_type="ERROR")

    l_encoding = "utf-16LE"
    write_bytes(l_memory, "00" * 32, arg_debug=arg_debug)
    write_bytes(l_memory, l_non_english_char_test_string.encode(l_encoding), arg_debug=arg_debug)
    l_nonenglish_res = string(l_memory, arg_encoding=l_encoding, arg_debug=arg_debug)
    if l_nonenglish_res is None:
        log_print("string() failed", arg_type="ERROR")
        return False
    l_ok = (l_nonenglish_res == l_non_english_char_test_string)
    res &= l_ok
    log_print(f"l_non_english_char_test_string: {' '.join(hex_parse(l_non_english_char_test_string.encode(l_encoding)))}", arg_debug)
    log_print(f"l_nonenglish_res: {' '.join(hex_parse(l_nonenglish_res.encode(l_encoding)))}", arg_debug)
    log_print(f"non english string test: {l_ok}", arg_debug)
    log_print(f"<<< FAILED >>> {l_encoding} test: got '{l_nonenglish_res}'", arg_actually_print=not l_ok, arg_type="ERROR")

    l_encoding = "Latin-1"
    write_bytes(l_memory, "00" * 32, arg_debug=arg_debug)
    write_bytes(l_memory, l_non_english_char_test_string.encode(l_encoding), arg_debug=arg_debug)
    l_nonenglish_res = string(l_memory, arg_encoding=l_encoding, arg_debug=arg_debug)
    if l_nonenglish_res is None:
        log_print("string() failed", arg_type="ERROR")
        return False
    l_ok = (l_nonenglish_res == l_non_english_char_test_string)
    res &= l_ok
    log_print(f"l_non_english_char_test_string: {' '.join(hex_parse(l_non_english_char_test_string.encode(l_encoding)))}", arg_debug)
    log_print(f"l_nonenglish_res: {' '.join(hex_parse(l_nonenglish_res.encode(l_encoding)))}", arg_debug)
    log_print(f"non english string test: {l_ok}", arg_debug)
    log_print(f"<<< FAILED >>> {l_encoding} test: got '{l_nonenglish_res}'", arg_actually_print=not l_ok, arg_type="ERROR")

    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_modules_on_Windows(arg_debug: bool = False) -> bool:
    ''' Tests: modules(), read_bytes()
        Needs a running process.
    '''
    l_modules = modules(arg_debug=arg_debug)
    if l_modules is None:
        log_print('modules() returned None', arg_type="ERROR")
        return False
    l_MZ_header = read_bytes(l_modules[0].base, 0x2)
    if l_MZ_header is None:
        log_print('read_bytes() returned None', arg_type="ERROR")
        return False
    res = True
    res &= (l_MZ_header == b'MZ')
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_eval_expression(arg_debug: bool = False) -> bool:
    ''' Tests: eval_expression() '''
    res = True
    res &= (eval_expression("11") == 0x0B)
    log_print(f'Test 1: {res}', arg_debug)
    res &= (eval_expression("11+0") == 11)
    log_print(f'Test 2: {res}', arg_debug)
    res &= (_idaapi_str2ea("This is an invalid address!") == _ida_idaapi.BADADDR)
    log_print(f'Test 3: {res}', arg_debug)
    res &= (_ida_kernwin.str2ea("11") == 0x11)
    log_print(f'Test 4: {res}', arg_debug)
    res &= (_ida_kernwin.str2ea("11+0") == 0x0B)
    log_print(f'Test 5: {res}', arg_debug)
    res &= (eval_expression("This is an invalid address", arg_supress_error=True) is None)
    log_print(f'Test 6: {res}', arg_debug)
    # This test is disabled because it is not working as expected in IDA 9.4, I need to investigate why.
    # res &= ((input_file.imagebase + 0x12) == address(virtual_address_to_module_and_offset(input_file.imagebase) + ' + 0x12'))
    # log_print(f'Test 7: {res}', arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_TWidget(arg_debug: bool = False) -> bool:
    ''' Tests: TWidget(), needs Qt
    OBS! I have gotten cases where this crash IDA but I can't reliable reproduce it :-(
    '''
    if not _G_QT_IS_AVAILABLE:
        log_print("Qt is not available, failing test", arg_type="ERROR")
        return False

    l_current_viewer: Optional[TWidget] = _idaapi_get_current_viewer()
    if l_current_viewer is None:
        l_current_viewer = _idaapi_get_current_widget()
    log_print(f"l_current_viewer.window_title(): \"{l_current_viewer.window_title()}\"", arg_debug)
    res = len(l_current_viewer.window_title()) > 3
    if not res:
        log_print("Failed: len(l_current_viewer.window_title()) > 3", arg_type="ERROR")
        return False
    log_print(f"l_current_viewer: {l_current_viewer}", arg_debug)

    l_funcs_TWidget_ptr = _ida_kernwin.open_disasm_window("test_window") # open_disasm_window() has the side effect that it sets get_current_viewer() and when we close it later, get_current_viewer() will then return None
    test_1 = TWidget(l_funcs_TWidget_ptr)
    log_print(str(test_1), arg_debug)
    test_2 = TWidget(test_1)
    log_print(str(test_2), arg_debug)
    test_3 = TWidget(test_2.as_PyQtWidget())
    log_print(str(test_3), arg_debug)
    test_4 = TWidget(test_3.window_title())
    log_print(str(test_4), arg_debug)

    _idaapi_request_refresh()

    res &= test_1.window_title() == test_2.window_title()
    log_print(f"test_1.window_title() == test_2.window_title() -> {test_1.window_title()} == {test_2.window_title()}", arg_debug)
    res &= test_2.window_title() == test_3.window_title()
    log_print(f"test_2.window_title() == test_3.window_title() -> {test_2.window_title()} == {test_3.window_title()}", arg_debug)
    res &= test_3.window_title() == test_4.window_title()
    log_print(f"test_3.window_title() == test_4.window_title() -> {test_3.window_title()} == {test_4.window_title()}", arg_debug)
    test_1.close()
    test_2.close()
    test_3.close()
    test_4.close()
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_Qt_stuff(arg_debug: bool = False) -> bool:
    ''' Tests: Qt stuff. This will make sure that PySide6/PyQt5 works as expected '''
    if not _G_QT_IS_AVAILABLE:
        log_print("Qt is not available, failing test", arg_type="ERROR")
        return False

    l_ida_started_with = ida_arguments()
    log_print(f"ida_started_with: {l_ida_started_with}", arg_debug)

    import secrets
    l_test_string = ''.join([secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10)])
    log_print(f"l_test_string: {l_test_string}", arg_debug)
    return clipboard_copy(l_test_string) and l_test_string == _pyperclip.paste()

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_decompiler(arg_debug: bool = False) -> bool:
    ''' Tests: decompiler '''
    l_pseudocode = decompiler_pseudocode(registers.rip, arg_debug=arg_debug) # type: ignore [attr-defined]
    log_print(f"pseudocode of entrypoint: {l_pseudocode}", arg_debug)
    res = len(l_pseudocode) > 10 and not l_pseudocode.startswith("<<<")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_licence(arg_debug: bool = False) -> bool:
    ''' Tests: licence '''
    l_licence = ida_license_info(arg_delete_user_info_from_IDB=False)
    log_print(f"licence: {l_licence}", arg_debug)
    return l_licence is not None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_decompiler_comments(arg_debug: bool = False) -> bool:
    ''' Tests: decompiler comments '''
    l_comments = decompiler_comments(arg_debug=arg_debug)
    log_print(f"decompiler comments: {l_comments}", arg_debug)
    return l_comments is not None

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_relative_virtual_address(arg_debug: bool = False) -> bool:
    ''' Tests: relative_virtual_address. Requires a running process in a Windows system. '''
    l_rva_of_ep = relative_virtual_address(input_file.entry_point, arg_from_DLL_base=False, arg_debug=arg_debug)
    log_print(f"relative_virtual_address of entry point: {l_rva_of_ep}", arg_debug)

    l_API_to_test = "kernel32_GetProcAddress"
    l_rva_of_GetProcAddress = relative_virtual_address(l_API_to_test, arg_from_DLL_base=True, arg_debug=arg_debug)
    if l_rva_of_GetProcAddress is None:
        log_print(f"Could not find any relative virtual address for {l_API_to_test}", arg_type="ERROR")
        return False

    l_module = module(l_API_to_test, arg_debug=arg_debug)
    if l_module is None:
        log_print(f"Could not find any module at {_hex_str_if_int(l_API_to_test)}", arg_type="ERROR")
        return False

    return name(l_module.base + l_rva_of_GetProcAddress, arg_debug=arg_debug) == l_API_to_test

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_convert_to_usercall(arg_debug: bool = False) -> bool:
    ''' Convert the entry point to usercall and verify that it has __userpurge or __usercall in the prototype.
        Requires an active debugging session.
    '''
    l_function_to_convert = "kernelbase_LoadLibraryA"
    # The DLL is only loaded in the debugger and not analyzed, function() only creates code + function when explicitly asked to
    if function(l_function_to_convert, arg_create_function=True, arg_debug=arg_debug) is None:
        log_print(f"Could not create a function at {l_function_to_convert}", arg_type="ERROR")
        return False
    l_prototype_before = function_prototype(l_function_to_convert, arg_debug=arg_debug)
    res = function_convert_to_usercall(l_function_to_convert, arg_debug=arg_debug)
    if not res:
        log_print(f"function_convert_to_usercall({_hex_str_if_int(l_function_to_convert)}) failed", arg_type="ERROR")
        return False
    l_prototype_after = function_prototype(l_function_to_convert, arg_debug=arg_debug)
    res &= "__user" in l_prototype_after
    if not res:
        log_print("__user in l_prototype_after failed", arg_type="ERROR")
        return False
    res &= set_type(l_function_to_convert, l_prototype_before, arg_debug=arg_debug)
    log_print(f"resetting the prototype back to '{l_prototype_before}' failed", not res, arg_type="ERROR")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_input_file(arg_debug: bool = False) -> bool:
    ''' Test the input file object '''
    l_info = str(input_file) # Some properties will make call chain to ctypes also
    log_print(f"l_info:\n{l_info}", arg_debug)
    res = l_info != ""
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_GetProcAddress_on_Windows(arg_debug: bool = False) -> bool:
    ''' Test GetProcAddress(), needs an active debugging session '''
    l_module: str = "kernel32"
    l_function_to_test = "LoadLibraryA"
    l_LoadLibraryA_addr = win_GetProcAddress(l_module, l_function_to_test)
    if l_LoadLibraryA_addr is None:
        log_print(f"win_GetProcAddress('kernel32', '{l_function_to_test}') failed! Test failed", arg_type="ERROR")
        return False
    res = name(l_LoadLibraryA_addr, arg_debug=arg_debug) == f"{l_module}_{l_function_to_test}"
    l_should_be_None = win_GetProcAddress(l_module, "Nonexistantfunction")
    res &= l_should_be_None is None
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_virtual_address_to_file_offset_and_back_again(arg_debug: bool = False) -> bool:
    ''' Test to convert an VA -> FO -> VA again '''
    l_virtual_address_to_test = input_file.entry_point
    l_file_offset = virtual_address_to_fileoffset(l_virtual_address_to_test)
    if l_file_offset == -1:
        log_print(f"virtual_address_to_fileoffset(0x{l_virtual_address_to_test:x}) returned -1 (fail)")
        return False
    l_virtual_address_again = fileoffset_to_virtual_address(l_file_offset)
    res = l_virtual_address_to_test == l_virtual_address_again
    log_print(f"res: {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_save_database(arg_debug: bool = False) -> bool:
    ''' Test ida_save_database() '''
    import tempfile
    res = False
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_extension = _os.path.splitext(input_file.idb_path)[1] # IDA 8.4 can have IDB, otherwise its always I64
        l_new_filename = _os.path.join(l_temp_dir, "test_ida_save_database" + l_extension)
        res = ida_save_database(l_new_filename)
        log_print(f"ida_save_database('{l_new_filename}') returned {res}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_python_load_module(arg_debug: bool = False) -> bool:
    ''' Test _python_load_module() '''
    import tempfile
    res = False
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_temp_file = _os.path.join(l_temp_dir, "test_python_load_module.py")
        with open(l_temp_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("def print_test_text() -> str:\n    return 'This text is from the test_python_load_module.py file'\n")
        l_module = _python_load_module(l_temp_file)
        if l_module is None:
            log_print(f"_python_load_module({l_temp_file}) returned None", arg_type="ERROR")
            return False
        res = l_module.print_test_text() == "This text is from the test_python_load_module.py file"
        log_print("l_module.print_test_text() failed", not res, arg_type="ERROR")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_pe_header_linker_version(arg_debug: bool = False) -> bool:
    ''' Test pe_header_linker_version() '''
    res = False
    (l_major, l_minor) = pe_header_linker_version()
    res = l_major > 0 or l_minor > 0
    log_print(f"pe_header_linker_version() returned {l_major}.{l_minor}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_imports_and_exports(arg_debug: bool = False) -> bool:
    ''' Test getting all imports and exports '''
    l_imports = imports(arg_debug=arg_debug)
    l_exports = exports(arg_debug=arg_debug)
    return len(l_imports) >= 1 and len(l_exports) >= 1

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_instruction(arg_debug: bool = False) -> bool:
    ''' Test to decode bytes into an instruction '''

    l_ins = instruction(address("rip"))
    if l_ins is None:
        log_print("RIP is not at any instruction", arg_type="ERROR")
        return False
    log_print(str(l_ins), arg_debug)
    l_next_ins = l_ins.next_instruction
    if l_next_ins is None:
        log_print("RIP is not at any instruction", arg_type="ERROR")
        return False

    log_print(str(l_next_ins), arg_debug)
    l_first_instruction_again = l_next_ins.previous_instruction
    if l_first_instruction_again is None:
        log_print("RIP is not at any instruction", arg_type="ERROR")
        return False

    log_print(str(l_first_instruction_again), arg_debug)
    return str(l_ins) == str(l_first_instruction_again)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_bug_report(arg_debug: bool = False) -> bool:
    ''' Test to create a bug report '''
    log_print("There will be 2 lines printed in the console that are part of the testing. Ignore them.", arg_type="INFO")
    l_bug_report = bug_report("TEST of bug report")
    log_print(f"Removing file {l_bug_report}", arg_type="INFO")
    _os.remove(l_bug_report)
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_ida_is_running_in_batch_mode(arg_debug: bool = False) -> bool:
    ''' Test if reading from the cvar works '''
    res = not ida_is_running_in_batch_mode()
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_notepad_text(arg_debug: bool = False) -> bool:
    ''' Test if writing and reading from the internal notepad works '''
    l_text_to_write = "This text is just a test!"
    l_read = notepad_text(arg_text=l_text_to_write)
    return l_text_to_write == l_read

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_hex_dump(arg_debug: bool = False) -> bool:
    ''' Test if hexdump works '''
    log_print("There will be a line printed in the console that is part of the testing. Ignore it.", arg_type="INFO")
    hex_dump(arg_ea=here(), arg_len=0x10, arg_width=0x20, arg_unprintable_char="-", arg_debug=arg_debug)
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_licence_ex(arg_debug: bool = False) -> bool:
    ''' Test if we can read the license info '''
    l_license_info = ida_license_info_ex()
    if l_license_info is None:
        log_print("l_license_info is None", arg_debug)
    else:
        log_print(l_license_info, arg_debug)
    return True

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_ida_domain(arg_debug: bool = False) -> bool:
    ''' Test how we compare to ida_domain '''
    try:
        import ida_domain as _ida_domain
    except ImportError:
        log_print("ida_domain is not installed. It is optional but quite nice. pip install ida_domain", arg_type="WARNING")
        return True
    l_db = _ida_domain.Database.open()
    res = l_db.architecture == input_file.processor
    res &= l_db.bytes.get_bytes_at(l_db.base_address, 0x10) == read_bytes(input_file.imagebase, 0x10)
    res &= l_db.md5 == input_file.md5
    # l_db.microcode.get_text()
    l_db.close()
    log_print(f"test_ida_domain: {res}", arg_debug)
    return res

_g_test_scratch_memory: Optional[int] = None
@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_scratch_memory(arg_debug: bool = False) -> Optional[int]:
    ''' Internal function for the tests. 0x1000 bytes in the debugged process that the tests can write whatever they want to.
        Allocated once and reused by all tests. Needs a running process.
    '''
    global _g_test_scratch_memory
    if _g_test_scratch_memory is None:
        _g_test_scratch_memory = allocate_memory_in_target(0x1000, arg_debug=arg_debug)
    if _g_test_scratch_memory is None:
        log_print("Could not allocate scratch memory for the tests", arg_type="ERROR")
    return _g_test_scratch_memory

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_operand_parser_x64(arg_debug: bool = False) -> bool:
    ''' Tests: _operand_parser() / insn_t.operands_as_dict with REX extended SIB (r8-r15), index r12 (low bits == "no index") and scale 1.
        Needs a running 64-bit process.
    '''
    if input_file.bits != 64:
        log_print("_test_operand_parser_x64 only works on 64-bit files, skipping", arg_type="WARNING")
        return True
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False

    # (bytes, expected base, expected index, expected scale, expected displacement)
    l_test_cases = [("4B 8B 44 AC 10", "r12", "r13", 4, 0x10), # mov rax, [r12+r13*4+10h]
                    ("4B 8B 44 E5 20", "r13", "r12", 8, 0x20), # mov rax, [r13+r12*8+20h]
                    ("48 8B 04 0B",    "rbx", "rcx", 1, 0x00)] # mov rax, [rbx+rcx]
    res = True
    for l_bytes, l_base, l_index, l_scale, l_displacement in l_test_cases:
        write_bytes(l_memory, l_bytes, arg_debug=arg_debug)
        l_ins = instruction(l_memory, arg_debug=arg_debug)
        if l_ins is None:
            log_print(f"instruction() failed on '{l_bytes}'", arg_type="ERROR")
            return False
        l_parsed = l_ins.operands_as_dict[1]
        l_ok = (l_parsed is not None
                and l_parsed['base_register'].name == l_base
                and l_parsed['index_register'] is not None and l_parsed['index_register'].name == l_index
                and l_parsed['scale'] == l_scale
                and l_parsed['displacement'] == l_displacement)
        log_print(f"'{l_bytes}' --> {disassemble(l_memory, arg_show_size=False, arg_show_bytes=False)} --> OK: {l_ok}", arg_debug)
        log_print(f"<<< FAILED >>> _operand_parser on '{l_bytes}' gave {l_parsed}", arg_actually_print=not l_ok, arg_type="ERROR")
        res &= l_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_instruction_is_same_as_nop(arg_debug: bool = False) -> bool:
    ''' Tests: insn_t.is_same_as_nop. In 64-bit code "mov eax, eax" zero extends rax so it is NOT a NOP.
        Needs a running 64-bit process.
    '''
    if input_file.bits != 64:
        log_print("_test_instruction_is_same_as_nop only works on 64-bit files, skipping", arg_type="WARNING")
        return True
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False

    l_test_cases = {"90":       True,  # nop
                    "48 89 C0": True,  # mov rax, rax
                    "48 87 C0": True,  # xchg rax, rax
                    "89 C0":    False, # mov eax, eax --> clears the upper 32 bits of rax
                    "87 C0":    False} # xchg eax, eax --> clears the upper 32 bits of rax
    res = True
    for l_bytes, l_expected in l_test_cases.items():
        write_bytes(l_memory, l_bytes + " 90 90 90", arg_debug=arg_debug) # Padding so the next instruction is well defined
        l_ins = instruction(l_memory, arg_debug=arg_debug)
        if l_ins is None:
            log_print(f"instruction() failed on '{l_bytes}'", arg_type="ERROR")
            return False
        l_ok = l_ins.is_same_as_nop == l_expected
        log_print(f"'{l_bytes}' --> {disassemble(l_memory, arg_show_size=False, arg_show_bytes=False)} is_same_as_nop: {l_ins.is_same_as_nop} (expected {l_expected})", arg_debug)
        log_print(f"<<< FAILED >>> is_same_as_nop on '{l_bytes}'", arg_actually_print=not l_ok, arg_type="ERROR")
        res &= l_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_fix_assembly(arg_debug: bool = False) -> bool:
    ''' Tests: _fix_assembly(). " near ptr " must be removed and hex numbers that start with a letter need a leading 0 '''
    l_test_cases = {"call near ptr sub_1":  "call sub_1",
                    "mov eax, 0xdeadbeef":  "mov eax, 0deadbeefh",
                    "mov eax, 0x12":        "mov eax, 12h",
                    "jmp short loc_401000": "jmp 401000h"}
    res = True
    for l_input, l_expected in l_test_cases.items():
        l_output = _fix_assembly(l_input, arg_debug=arg_debug)
        l_ok = l_output == l_expected
        log_print(f"<<< FAILED >>> _fix_assembly('{l_input}') --> '{l_output}' expected '{l_expected}'", arg_actually_print=not l_ok, arg_type="ERROR")
        res &= l_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_pointer_write(arg_debug: bool = False) -> bool:
    ''' Tests: pointer() with values that are not addresses (NULL, a random value and -1). Needs a running process. '''
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False

    l_all_ones: int = (1 << input_file.bits) - 1
    l_test_cases = {0: 0,                                   # NULL used to become BADADDR (0xFFFFFFFFFFFFFFFF)
                    0x11223344 & l_all_ones: 0x11223344 & l_all_ones,
                    -1: l_all_ones}                         # Negative --> two's complement
    res = True
    for l_value, l_expected in l_test_cases.items():
        pointer(l_memory, l_value, arg_debug=arg_debug)
        l_read = pointer(l_memory, arg_debug=arg_debug)
        l_ok = l_read == l_expected
        log_print(f"<<< FAILED >>> pointer(0x{l_memory:x}, {l_value}) then read back {_hex_str_if_int(l_read)}, expected 0x{l_expected:x}", arg_actually_print=not l_ok, arg_type="ERROR")
        res &= l_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_eval_expression_words_are_not_numbers(arg_debug: bool = False) -> bool:
    ''' Tests: the regexp fallback in eval_expression() and that address("+<unknown>") does not crash.
        OBS! eval_expression("decade") == 0xdecade is CORRECT: ida_kernwin.str2ea() itself reads a bare hex word as a number (if there is no name like that)
    '''
    res = True
    l_value = eval_expression("x401000", arg_supress_error=True) # Regexp fallback: "x" + hex with digits
    l_ok = l_value == 0x401000
    log_print(f'Test "x401000": {l_ok} (got {_hex_str_if_int(l_value)})', arg_debug)
    log_print(f'<<< FAILED >>> eval_expression("x401000") gave {_hex_str_if_int(l_value)}, expected 0x401000', arg_actually_print=not l_ok, arg_type="ERROR")
    res &= l_ok

    l_label = "this_label_does_not_exist"
    l_value = eval_expression(l_label, arg_supress_error=True)
    l_ok = l_value is None
    log_print(f'Test "{l_label}": {l_ok} (got {_hex_str_if_int(l_value)})', arg_debug)
    log_print(f'<<< FAILED >>> eval_expression("{l_label}") gave {_hex_str_if_int(l_value)}, expected None', arg_actually_print=not l_ok, arg_type="ERROR")
    res &= l_ok

    l_address = address("+" + l_label, arg_supress_error=True) # Used to be a TypeError (int + None)
    l_ok = l_address == _ida_idaapi.BADADDR
    log_print(f'Test "+{l_label}": {l_ok} (got {_hex_str_if_int(l_address)})', arg_debug)
    log_print(f'<<< FAILED >>> address("+{l_label}") gave {_hex_str_if_int(l_address)}, expected BADADDR', arg_actually_print=not l_ok, arg_type="ERROR")
    res &= l_ok
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_name_demangle(arg_debug: bool = False) -> bool:
    ''' Tests: name(arg_demangle_name=True) on a name that is NOT mangled must return the name and not "" '''
    l_function = function(input_file.entry_point, arg_debug=arg_debug)
    if l_function is None:
        log_print("No function at the entry point", arg_type="ERROR")
        return False
    l_plain = name(l_function.start_ea, arg_debug=arg_debug)
    l_demangled = name(l_function.start_ea, arg_demangle_name=True, arg_debug=arg_debug)
    l_expected = _idaapi_demangle_name(l_plain or "", 0) or l_plain
    log_print(f"name: '{l_plain}', demangled: '{l_demangled}', expected: '{l_expected}'", arg_debug)
    return bool(l_demangled) and l_demangled == l_expected

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_virtual_address_to_module_and_offset(arg_debug: bool = False) -> bool:
    ''' Tests: virtual_address_to_module_and_offset() returns "<module> + 0x<offset>" (it used to crash without a debugger) '''
    l_res = virtual_address_to_module_and_offset(input_file.entry_point, arg_debug=arg_debug)
    log_print(f"virtual_address_to_module_and_offset(entry_point) --> '{l_res}'", arg_debug)
    return not l_res.startswith("<<<") and " + 0x" in l_res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_comment_append_no_duplicates(arg_debug: bool = False) -> bool:
    ''' Tests: _comment_append() appends to the disassembly comment only once and does not copy other comment levels into it.
        Uses the first data item in the input file and restores the comment afterwards.
    '''
    l_data_ea: int = _ida_idaapi.BADADDR
    for l_segment in segments():
        if l_segment.executable or (l_segment.flags & _ida_segment.SFL_DEBUG): # Only the input file's own data segments, not memory that the debugger added
            continue
        for l_head in _idautils.Heads(l_segment.start_ea, l_segment.end_ea):
            if is_data(l_head):
                l_data_ea = l_head
                break
        if l_data_ea != _ida_idaapi.BADADDR:
            break
    if l_data_ea == _ida_idaapi.BADADDR:
        log_print("Could not find any data item to test on", arg_type="ERROR")
        return False

    l_original_comment: str = _ida_bytes.get_cmt(l_data_ea, False) or ""
    l_original_repeatable_comment: str = _ida_bytes.get_cmt(l_data_ea, True) or ""
    l_test_text = "community_base test comment"
    try:
        _ida_bytes.set_cmt(l_data_ea, "old comment", False)
        _ida_bytes.set_cmt(l_data_ea, "repeatable comment", True)
        _comment_append(l_data_ea, l_test_text, arg_debug=arg_debug)
        _comment_append(l_data_ea, l_test_text, arg_debug=arg_debug) # 2nd time must not add it again
        l_comment_now: str = _ida_bytes.get_cmt(l_data_ea, False) or ""
        log_print(f"Comment at 0x{l_data_ea:x} is now: '{l_comment_now}'", arg_debug)
        res = l_comment_now == f"old comment; {l_test_text}" # Exactly once and the repeatable comment is NOT copied into it
    finally:
        _ida_bytes.set_cmt(l_data_ea, l_original_comment, False)
        _ida_bytes.set_cmt(l_data_ea, l_original_repeatable_comment, True)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_function_bytes(arg_debug: bool = False) -> bool:
    ''' Tests: bytes(func_t) includes the last byte of the function '''
    l_function = function(input_file.entry_point, arg_debug=arg_debug)
    if l_function is None:
        log_print("No function at the entry point", arg_type="ERROR")
        return False
    l_bytes = bytes(l_function)
    log_print(f"len(bytes(function)): 0x{len(l_bytes):x}, len(function): 0x{len(l_function):x}", arg_debug)
    return len(l_bytes) == len(l_function) and l_bytes == read_bytes(l_function.start_ea, len(l_function))

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_search_binary_backward(arg_debug: bool = False) -> bool:
    ''' Tests: search_binary() with BIN_SEARCH_BACKWARD finds the same hits as a forward search (it used to find the same hit forever) '''
    l_segment = segment(input_file.entry_point, arg_debug=arg_debug)
    l_pattern_bytes = read_bytes(input_file.entry_point, 4, arg_debug=arg_debug)
    if l_segment is None or l_pattern_bytes is None:
        log_print("segment() or read_bytes() failed on the entry point", arg_type="ERROR")
        return False
    l_pattern = " ".join(hex_parse(l_pattern_bytes))
    l_forward = search_binary(l_pattern, arg_min_ea=l_segment.start_ea, arg_max_ea=l_segment, arg_max_hits=0, arg_debug=arg_debug)
    l_backward = search_binary(l_pattern, arg_min_ea=l_segment.start_ea, arg_max_ea=l_segment, arg_flags=_ida_bytes.BIN_SEARCH_BACKWARD, arg_max_hits=0, arg_debug=arg_debug)
    log_print(f"forward: {[hex(x) for x in l_forward or []]}, backward: {[hex(x) for x in l_backward or []]}", arg_debug)
    if not l_forward or l_backward is None:
        return False
    return input_file.entry_point in l_forward and sorted(l_backward) == l_forward and len(set(l_backward)) == len(l_backward)

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_segment_permissions(arg_debug: bool = False) -> bool:
    ''' Tests: segment_t.writable setter changes the segment (it used to never call segment_t.update()). Uses the scratch memory segment and restores it. '''
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False
    l_segment = segment(l_memory, arg_debug=arg_debug)
    if l_segment is None:
        log_print(f"No segment at the scratch memory 0x{l_memory:x}", arg_type="ERROR")
        return False
    l_before: bool = l_segment.writable
    try:
        l_segment.writable = not l_before
        l_segment_again = segment(l_memory, arg_debug=arg_debug) # Read it again from IDA
        res = l_segment_again is not None and l_segment_again.writable == (not l_before)
    finally:
        l_segment.writable = l_before
    l_segment_restored = segment(l_memory, arg_debug=arg_debug)
    res &= l_segment_restored is not None and l_segment_restored.writable == l_before
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_dump_to_disk_uses_arguments(arg_debug: bool = False) -> bool:
    ''' Tests: dump_to_disk(address, length) dumps what we ask for and not what is selected / under the cursor in the GUI '''
    import tempfile
    l_length = 0x10
    l_expected = read_bytes(input_file.entry_point, l_length, arg_debug=arg_debug)
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_file = _os.path.join(l_temp_dir, "test_dump_to_disk.bin")
        l_res = dump_to_disk(arg_ea_start=input_file.entry_point, arg_len=l_length, arg_filename=l_file, arg_debug=arg_debug)
        if l_res != l_file or not _os.path.exists(l_file):
            log_print(f"dump_to_disk() returned {l_res}", arg_type="ERROR")
            return False
        with open(l_file, "rb") as f:
            l_dumped = f.read()
    log_print(f"dumped: {l_dumped.hex(' ')}, expected: {l_expected.hex(' ') if l_expected else None}", arg_debug)
    return l_dumped == l_expected

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_decompile_many(arg_debug: bool = False) -> bool:
    ''' Tests: decompile_many() on 2 functions (it used to pass the raw argument list to IDA instead of the resolved addresses) '''
    if not _ida_hexrays.init_hexrays_plugin():
        log_print("No decompiler, skipping _test_decompile_many", arg_type="WARNING")
        return True
    import tempfile
    l_functions: List[EvaluateType] = [l_function for l_function in functions(arg_allow_library_functions=False, arg_debug=arg_debug)[:2]] # List is invariant, so List[int] is not a List[EvaluateType] for mypy
    if not l_functions:
        log_print("No functions to decompile", arg_type="ERROR")
        return False
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_c_file = _os.path.join(l_temp_dir, "test_decompile_many.c")
        l_res = decompile_many(arg_outfile=l_c_file, arg_functions=l_functions, arg_allow_user_to_stop=False, arg_debug=arg_debug)
        l_size = _os.path.getsize(l_c_file) if _os.path.exists(l_c_file) else 0
    log_print(f"decompile_many() returned {l_res}, size of the C file: {l_size}", arg_debug)
    return l_res and l_size > 0

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_check(arg_name: str, arg_ok: bool, arg_got: Any, arg_debug: bool = False) -> bool:
    ''' Internal function for the tests. Logs the result of ONE check (and what we got if it failed) and returns arg_ok so it can be used as: res &= _test_check(...) '''
    log_print(f"{arg_name}: {arg_ok} (got {_hex_str_if_int(arg_got)})", arg_debug)
    log_print(f"<<< FAILED >>> {arg_name}: got {_hex_str_if_int(arg_got)}", arg_actually_print=not arg_ok, arg_type="ERROR")
    return arg_ok

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_hex_parse(arg_debug: bool = False) -> bool:
    ''' Tests: hex_parse() on the different kinds of input it understands. The regexps are easy to break. '''
    l_test_cases: List[Tuple[BufferType, List[str]]] = [("aa bb cc", ['aa', 'bb', 'cc']), # Plain hex with spaces
                    ("aa-bb-cc",                  ['aa', 'bb', 'cc']), # Dashes
                    ("00401000 aa bb cc",         ['aa', 'bb', 'cc']), # Address prefix from a hex dump
                    (b"\x01\xab",                 ['01', 'ab']),       # bytes
                    ([b"\x01", b"\x02"],          ['01', '02'])]       # List of bytes
    res = True
    for l_input, l_expected in l_test_cases:
        l_output = hex_parse(l_input, arg_debug=arg_debug)
        res &= _test_check(f"hex_parse({l_input!r})", l_output == l_expected, l_output, arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_int_to_str_dict_from_module(arg_debug: bool = False) -> bool:
    ''' Tests: _int_to_str_dict_from_module() which a lot of the code use to make IDA constants readable. Breaks if IDA renames/renumbers constants. '''
    l_operand_types = _int_to_str_dict_from_module(_ida_ua, "o_.*")
    res = True
    res &= _test_check("o_void", l_operand_types.get(_ida_ua.o_void) == "o_void", l_operand_types.get(_ida_ua.o_void), arg_debug)
    res &= _test_check("o_reg", l_operand_types.get(_ida_ua.o_reg) == "o_reg", l_operand_types.get(_ida_ua.o_reg), arg_debug)
    res &= _test_check("o_imm", l_operand_types.get(_ida_ua.o_imm) == "o_imm", l_operand_types.get(_ida_ua.o_imm), arg_debug)
    res &= _test_check("CM_CC_FASTCALL in _G_CALLING_CONVENTION_INT_TO_STR", _G_CALLING_CONVENTION_INT_TO_STR.get(_ida_typeinf.CM_CC_FASTCALL) == "CM_CC_FASTCALL", _G_CALLING_CONVENTION_INT_TO_STR.get(_ida_typeinf.CM_CC_FASTCALL), arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_demangle_string(arg_debug: bool = False) -> bool:
    ''' Tests: demangle_string() via ida_name.demangle_name() on a MSVC mangled name and on a name that is not mangled '''
    l_demangled = demangle_string("?foo@@YAXXZ", arg_debug=arg_debug) # void __cdecl foo(void)
    res = True
    res &= _test_check("demangle_string('?foo@@YAXXZ')", "foo(" in l_demangled and "void" in l_demangled, l_demangled, arg_debug)
    l_not_mangled = _idaapi_demangle_name("main", 0)
    res &= _test_check("_idaapi_demangle_name('main')", l_not_mangled == "", l_not_mangled, arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_encoding_round_trip(arg_debug: bool = False) -> bool:
    ''' Tests: _encoding_to_strtype() --> _idaapi_encoding_from_strtype() gives back the same encoding. Uses the encoding list in the IDB. '''
    res = True
    for l_encoding in ("utf-8", "utf-16LE"):
        l_strtype = _encoding_to_strtype(l_encoding, arg_debug=arg_debug)
        l_back = _idaapi_encoding_from_strtype(l_strtype) if l_strtype != -1 else "<<< _encoding_to_strtype() failed >>>"
        l_ok = l_back.lower().replace("-", "").replace("_", "") == l_encoding.lower().replace("-", "")
        res &= _test_check(f"{l_encoding} --> strtype 0x{l_strtype & 0xFFFFFFFF:x} --> encoding", l_ok, l_back, arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_get_type_and_parse_decl(arg_debug: bool = False) -> bool:
    ''' Tests: get_type() from C declarations, from the type library (TIL) and pointer_size() '''
    res = True
    l_int = get_type("int", arg_debug=arg_debug)
    res &= _test_check("get_type('int').get_size() == 4", l_int is not None and l_int.get_size() == 4, l_int, arg_debug)
    l_pointer = get_type("void *", arg_debug=arg_debug)
    res &= _test_check("get_type('void *').get_size() == pointer_size()", l_pointer is not None and l_pointer.get_size() == pointer_size(arg_debug=arg_debug), l_pointer, arg_debug)
    res &= _test_check("pointer_size() == bits // 8", pointer_size(arg_debug=arg_debug) == input_file.bits // 8, pointer_size(arg_debug=arg_debug), arg_debug)
    # In notepad.exe the name CreateFileW is the import table slot, so the type there is a function POINTER. Both are OK.
    l_from_til = get_type("CreateFileW", arg_debug=arg_debug)
    res &= _test_check("get_type('CreateFileW') is a function or function pointer", l_from_til is not None and (l_from_til.is_func() or l_from_til.is_funcptr()), l_from_til, arg_debug)
    # Function prototypes without a function name, the clang parser (default from IDA 9.5) can not parse these as they are, see _fix_c_type()
    l_nameless = get_type("PVOID __stdcall(PVOID lpAddress, SIZE_T dwSize, __int32 flAllocationType, __int32 flProtect)", arg_debug=arg_debug)
    res &= _test_check("get_type() on nameless __stdcall prototype is a function with 4 arguments", l_nameless is not None and l_nameless.is_func() and l_nameless.get_nargs() == 4, l_nameless, arg_debug)
    res &= _test_check("get_type() on nameless __stdcall prototype keeps the argument names", l_nameless is not None and "lpAddress" in str(l_nameless), l_nameless, arg_debug)
    l_nameless_no_cc = get_type("PVOID(PVOID lpAddress)", arg_debug=arg_debug)
    res &= _test_check("get_type() on nameless prototype without calling convention is a function with 1 argument", l_nameless_no_cc is not None and l_nameless_no_cc.is_func() and l_nameless_no_cc.get_nargs() == 1, l_nameless_no_cc, arg_debug)
    l_named = get_type("PVOID __stdcall VirtualAlloc(PVOID lpAddress, SIZE_T dwSize, __int32 flAllocationType, __int32 flProtect)", arg_debug=arg_debug)
    res &= _test_check("get_type() on named __stdcall prototype is a function with 4 arguments", l_named is not None and l_named.is_func() and l_named.get_nargs() == 4, l_named, arg_debug)
    l_function_pointer = get_type("PVOID (__stdcall *)(PVOID lpAddress, SIZE_T dwSize)", arg_debug=arg_debug)
    res &= _test_check("get_type() on function pointer is still a function pointer", l_function_pointer is not None and l_function_pointer.is_funcptr(), l_function_pointer, arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_import_h_file(arg_debug: bool = False) -> bool:
    ''' Tests: import_h_file() (ida_typeinf.idc_parse_types()) and get_type() on the new struct. The struct is deleted afterwards. '''
    import tempfile
    l_struct_name = "community_base_test_struct"
    l_folder = "community_base_test.h" # import_h_file() names the folder after the header file
    l_folder_2 = "community_base_test_2.h"
    res = True
    l_dirtree = _ida_dirtree.get_std_dirtree(_ida_dirtree.DIRTREE_LOCAL_TYPES)
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_h_file = _os.path.join(l_temp_dir, "community_base_test.h")
        with open(l_h_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"struct {l_struct_name} {{ int a; int b; }};\n")
        try:
            res &= _test_check("import_h_file()", import_h_file(l_h_file, arg_debug=arg_debug), l_h_file, arg_debug)
            l_type = get_type(l_struct_name, arg_debug=arg_debug)
            res &= _test_check(f"get_type('{l_struct_name}') is a struct of size 8", l_type is not None and l_type.is_struct() and l_type.get_size() == 8, l_type, arg_debug)
            l_is_in_folder: bool = l_dirtree.isfile(f"{l_folder}/{l_struct_name}")
            res &= _test_check(f"import_h_file() moved '{l_struct_name}' into the folder '{l_folder}'", l_is_in_folder, l_is_in_folder, arg_debug)

            # A second header file with the same struct (unchanged, so we can't see it on the type itself), the struct must move to the folder of the last header file
            l_h_file_2 = _os.path.join(l_temp_dir, l_folder_2)
            with open(l_h_file_2, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"struct {l_struct_name} {{ int a; int b; }};\n")
            res &= _test_check("import_h_file() of the second header file", import_h_file(l_h_file_2, arg_debug=arg_debug), l_h_file_2, arg_debug)
            l_is_in_folder = l_dirtree.isfile(f"{l_folder_2}/{l_struct_name}") and not l_dirtree.isfile(f"{l_folder}/{l_struct_name}")
            res &= _test_check(f"import_h_file() moved the existing '{l_struct_name}' from the folder '{l_folder}' to '{l_folder_2}'", l_is_in_folder, l_is_in_folder, arg_debug)
        finally:
            # OBS! Move the struct out of the folder BEFORE it is deleted. If the struct is deleted inside the folder then rmdir() fails with "directory is not empty"
            l_dirtree.rename(f"{l_folder}/{l_struct_name}", f"/{l_struct_name}")
            l_dirtree.rename(f"{l_folder_2}/{l_struct_name}", f"/{l_struct_name}")
            for l_folder_to_remove in (l_folder, l_folder_2):
                l_rmdir_res: int = l_dirtree.rmdir(l_folder_to_remove)
                res &= _test_check(f"The folder '{l_folder_to_remove}' is removed again", l_rmdir_res == _ida_dirtree.DTE_OK and not l_dirtree.isdir(l_folder_to_remove), _ida_dirtree.dirtree_t.errstr(l_rmdir_res), arg_debug)
            _ida_typeinf.del_named_type(None, l_struct_name, _ida_typeinf.NTF_TYPE)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_export_h_file_and_file_generate(arg_debug: bool = False) -> bool:
    ''' Tests: export_h_file() (ida_typeinf.print_decls()) and file_generate() (ida_fpro.qfile_t + ida_loader.gen_file()) '''
    import tempfile
    res = True
    with tempfile.TemporaryDirectory() as l_temp_dir:
        l_h_file = _os.path.join(l_temp_dir, "community_base_test_export.h")
        l_res = export_h_file(l_h_file, arg_debug=arg_debug)
        res &= _test_check("export_h_file()", l_res == l_h_file and _os.path.exists(l_h_file), l_res, arg_debug)

        l_segment = segment(input_file.entry_point, arg_debug=arg_debug)
        if l_segment is None:
            log_print("segment() failed on the entry point", arg_type="ERROR")
            return False
        l_map_file = _os.path.join(l_temp_dir, "community_base_test.map")
        l_res = file_generate("MAP", l_map_file, arg_start_ea=l_segment.start_ea, arg_end_ea=l_segment.end_ea - 1, arg_debug=arg_debug)
        l_size = _os.path.getsize(l_map_file) if _os.path.exists(l_map_file) else 0
        res &= _test_check("file_generate('MAP')", l_res == l_map_file and l_size > 0, f"{l_res} with size {l_size}", arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_misc_wrappers(arg_debug: bool = False) -> bool:
    ''' Tests: wrappers around IDA APIs (and ctypes calls into ida.dll) that have changed between IDA versions '''
    res = True
    l_size_str = _pretty_print_size(1231231332) # ctypes --> ida.dll pretty_print_size()
    res &= _test_check("_pretty_print_size(1231231332)", l_size_str is not None and len(l_size_str) > 0 and l_size_str[0].isdigit(), l_size_str, arg_debug)
    l_loader = input_file.loader # ctypes --> ida.dll get_loader_name()
    res &= _test_check("input_file.loader", bool(l_loader) and not l_loader.startswith("<<<"), l_loader, arg_debug)
    l_compiler = _compiler_str()
    res &= _test_check("_compiler_str()", l_compiler.endswith(("(sure)", "(unsure)")), l_compiler, arg_debug)
    # IDA only writes a setting to the registry when the user has changed it, so the value might not exist (e.g. a fresh IDA 8.4). Both cases must work.
    l_registry = ida_registry_read("AutoHighlight")
    if _ida_registry.reg_exists("AutoHighlight"):
        res &= _test_check("ida_registry_read('AutoHighlight') (exists)", l_registry == ("reg_dword", str(_ida_registry.reg_read_int("AutoHighlight", -12345))), l_registry, arg_debug)
    else:
        res &= _test_check("ida_registry_read('AutoHighlight') (does not exist) --> 'ERROR'", l_registry[0] == "ERROR", l_registry, arg_debug)
    res &= _test_check("ida_registry_read('community_base_this_value_does_not_exist') --> 'ERROR'", ida_registry_read("community_base_this_value_does_not_exist")[0] == "ERROR", None, arg_debug)
    l_os_version = pe_header_os_version()
    res &= _test_check("pe_header_os_version() >= (4, 0)", l_os_version >= (4, 0), l_os_version, arg_debug)
    l_compiled_time = pe_header_compiled_time() # Can be "" if it's a reproducible build, then we only test that it doesn't crash
    res &= _test_check("pe_header_compiled_time() is '' or starts with a year", l_compiled_time == "" or l_compiled_time[0:2] in ("19", "20"), l_compiled_time, arg_debug)
    l_earliest = _pe_linker_earliest_timestamp(14, 29) # Visual Studio 2019 --> 2018-01-01 (1 year before the release year)
    res &= _test_check("_pe_linker_earliest_timestamp(14, 29) == 2018-01-01", l_earliest == 1514764800, l_earliest, arg_debug)
    l_earliest = _pe_linker_earliest_timestamp(14, 0) # Visual Studio 2015 and lld-link --> 2014-01-01
    res &= _test_check("_pe_linker_earliest_timestamp(14, 0) == 2014-01-01", l_earliest == 1388534400, l_earliest, arg_debug)
    l_earliest = _pe_linker_earliest_timestamp(2, 25) # Delphi and GNU ld use 2.x, we don't know when those were released
    res &= _test_check("_pe_linker_earliest_timestamp(2, 25) is None", l_earliest is None, l_earliest, arg_debug)
    # plugins() can be empty (e.g. no Python plugins loaded in this IDA), so only test that it finds exactly the "__plugins__*" modules
    l_plugins = plugins()
    l_expected_plugins = [l_name.replace("__plugins__", "") for l_name in list(_sys.modules) if "__plugins__" in l_name]
    res &= _test_check("plugins() == the __plugins__* modules in sys.modules", sorted(l_plugins.keys()) == sorted(l_expected_plugins) and all(isinstance(l_module, ModuleType) for l_module in l_plugins.values()), list(l_plugins.keys()), arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_strings_and_xrefs(arg_debug: bool = False) -> bool:
    ''' Tests: strings() (idautils.Strings), string() with a StringItem and xrefs_to() on an imported function '''
    res = True
    l_strings = strings(arg_only_first=10, arg_debug=arg_debug)
    res &= _test_check("strings() is not empty", len(l_strings) > 0, len(l_strings), arg_debug)
    if l_strings:
        l_string_item = l_strings[0]
        l_encoding = l_string_item.encoding # Property added by community_base
        res &= _test_check("StringItem.encoding", bool(l_encoding), l_encoding, arg_debug)
        l_text = string(l_string_item, arg_debug=arg_debug)
        res &= _test_check("string(StringItem) == str(StringItem)", l_text is not None and l_text == str(l_string_item).rstrip('\x00'), l_text, arg_debug)

    l_import_with_xrefs: int = _ida_idaapi.BADADDR
    for l_functions_in_module in imports(arg_debug=arg_debug).values():
        for l_import_ea, _ in l_functions_in_module.values():
            if any(True for _ in _idautils.XrefsTo(l_import_ea)):
                l_import_with_xrefs = l_import_ea
                break
        if l_import_with_xrefs != _ida_idaapi.BADADDR:
            break
    res &= _test_check("Found an imported function with xrefs", l_import_with_xrefs != _ida_idaapi.BADADDR, l_import_with_xrefs, arg_debug)
    if l_import_with_xrefs != _ida_idaapi.BADADDR:
        l_xrefs = xrefs_to(l_import_with_xrefs, arg_debug=arg_debug)
        l_ok = len(l_xrefs) > 0 and all(isinstance(l_xref.type_name, str) and l_xref.type_name for l_xref in l_xrefs.values())
        res &= _test_check(f"xrefs_to({name(l_import_with_xrefs)}) has xrefs with type_name", l_ok, len(l_xrefs), arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_decompiler_helpers(arg_debug: bool = False) -> bool:
    ''' Tests: function_prototype(), decompiler_line(), decompiler_variable(), function_calling_convention() on the entry point '''
    if not _ida_hexrays.init_hexrays_plugin():
        log_print("No decompiler, skipping _test_decompiler_helpers", arg_type="WARNING")
        return True
    res = True
    l_cfunc = decompile(input_file.entry_point, arg_debug=arg_debug)
    if l_cfunc is None:
        log_print("Could not decompile the entry point", arg_type="ERROR")
        return False
    l_prototype = function_prototype(input_file.entry_point, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
    res &= _test_check("function_prototype(entry_point)", "(" in l_prototype and not l_prototype.startswith("<<<"), l_prototype, arg_debug)

    l_first_statement_ea: int = l_cfunc.body.cblock[0].ea if l_cfunc.body.cblock.size() > 0 else input_file.entry_point
    l_line = decompiler_line(l_first_statement_ea, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
    res &= _test_check("decompiler_line(first statement)", bool(l_line) and not l_line.startswith("<<<"), l_line, arg_debug)

    if l_cfunc.lvars.size() > 0:
        l_variable_name: str = l_cfunc.lvars[0].name
        l_variable = decompiler_variable(input_file.entry_point, l_variable_name, arg_debug=arg_debug)
        res &= _test_check(f"decompiler_variable('{l_variable_name}')", l_variable is not None and l_variable.name == l_variable_name, l_variable, arg_debug)

    l_calling_convention = function_calling_convention(input_file.entry_point, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
    res &= _test_check("function_calling_convention(entry_point) != -1", l_calling_convention != -1, _G_CALLING_CONVENTION_INT_TO_STR.get(l_calling_convention, l_calling_convention), arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_instruction_properties_x64(arg_debug: bool = False) -> bool:
    ''' Tests: insn_t.is_call / is_ret / is_jmp / is_jcc / operands_as_dict on xmm registers. Needs a running 64-bit process. '''
    if input_file.bits != 64:
        log_print("_test_instruction_properties_x64 only works on 64-bit files, skipping", arg_type="WARNING")
        return True
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False
    make_unknown(l_memory, arg_len=0x20, arg_debug=arg_debug)

    # (bytes, is_call, is_ret, is_jmp, is_jcc)
    l_test_cases = [("E8 00 00 00 00", True,  False, False, False), # call $+5
                    ("C3",             False, True,  False, False), # ret
                    ("EB 00",          False, False, True,  False), # jmp short $+2
                    ("74 00",          False, False, False, True),  # jz short $+2
                    ("48 89 C0",       False, False, False, False)] # mov rax, rax
    res = True
    for l_bytes, l_is_call, l_is_ret, l_is_jmp, l_is_jcc in l_test_cases:
        write_bytes(l_memory, l_bytes + " 90 90 90 90 90", arg_debug=arg_debug)
        l_ins = instruction(l_memory, arg_debug=arg_debug)
        if l_ins is None:
            log_print(f"instruction() failed on '{l_bytes}'", arg_type="ERROR")
            return False
        l_got = (l_ins.is_call, l_ins.is_ret, l_ins.is_jmp, l_ins.is_jcc)
        res &= _test_check(f"'{l_bytes}' ({disassemble(l_memory, arg_show_size=False, arg_show_bytes=False)}) (is_call, is_ret, is_jmp, is_jcc)", l_got == (l_is_call, l_is_ret, l_is_jmp, l_is_jcc), l_got, arg_debug)

    write_bytes(l_memory, "66 0F 6F C1 90 90", arg_debug=arg_debug) # movdqa xmm0, xmm1
    l_ins = instruction(l_memory, arg_debug=arg_debug)
    l_parsed = l_ins.operands_as_dict if l_ins is not None else None
    l_names = [getattr(l_operand.get('register') if l_operand else None, 'name', None) for l_operand in (l_parsed or [])]
    res &= _test_check("movdqa xmm0, xmm1 operands", l_names == ["xmm0", "xmm1"], l_names, arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_make_data_and_set_type(arg_debug: bool = False) -> bool:
    ''' Tests: make_data() with a type from the data carousel and with a C type, set_type() + get_type() on an address. Uses the scratch memory. '''
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False
    res = True
    make_unknown(l_memory, arg_len=0x100, arg_debug=arg_debug)
    write_bytes(l_memory, "00" * 0x40, arg_debug=arg_debug)

    l_ok = make_data(l_memory, "DWORD", 4, arg_debug=arg_debug)
    res &= _test_check("make_data(DWORD, 4) --> 16 bytes of data", bool(l_ok) and is_data(l_memory) and _ida_bytes.get_item_size(l_memory) == 16, _ida_bytes.get_item_size(l_memory), arg_debug)

    l_ok = make_data(l_memory + 0x20, "int", 3, arg_debug=arg_debug) # Not in the data carousel --> the type system path
    res &= _test_check("make_data(int, 3) --> 12 bytes of data", bool(l_ok) and is_data(l_memory + 0x20) and _ida_bytes.get_item_size(l_memory + 0x20) == 12, _ida_bytes.get_item_size(l_memory + 0x20), arg_debug)

    l_ok = set_type(l_memory + 0x30, "int", arg_debug=arg_debug)
    l_type = get_type(l_memory + 0x30, arg_debug=arg_debug)
    res &= _test_check("set_type(int) + get_type() == 'int'", l_ok and l_type is not None and str(l_type) == "int", l_type, arg_debug)
    make_unknown(l_memory, arg_len=0x100, arg_debug=arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_bytes_smart_delete(arg_debug: bool = False) -> bool:
    ''' Tests: bytes_smart_delete() (the Del hotkey): code --> NOP, NOP --> 0x00. Uses the scratch memory. '''
    if _ida_idp.ph_get_id() != _ida_idp.PLFM_386:
        log_print("_test_bytes_smart_delete only works on x86/x64, skipping", arg_type="WARNING")
        return True
    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False
    res = True
    write_bytes(l_memory, "C3 C3 C3 C3", arg_debug=arg_debug)
    make_code(l_memory, 1, arg_force=True, arg_debug=arg_debug)
    bytes_smart_delete(l_memory, 1, arg_debug=arg_debug)
    res &= _test_check("smart delete on code --> 0x90", byte(l_memory) == 0x90, byte(l_memory), arg_debug)
    bytes_smart_delete(l_memory, 1, arg_debug=arg_debug)
    res &= _test_check("smart delete on NOP --> 0x00", byte(l_memory) == 0x00, byte(l_memory), arg_debug)
    make_unknown(l_memory, arg_len=4, arg_debug=arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_debugger_registers_modules_breakpoints(arg_debug: bool = False) -> bool:
    ''' Tests: registers.<name>, eval_expression("<register>"), module(), modules() and adding/removing a breakpoint. Needs a suspended process. '''
    if not process_is_suspended():
        log_print("The process must be suspended for _test_debugger_registers_modules_breakpoints", arg_type="ERROR")
        return False
    res = True
    l_ip_name = "rip" if input_file.bits == 64 else "eip"
    res &= _test_check(f"'{l_ip_name}' in registers._as_dict", l_ip_name in registers._as_dict, sorted(registers._as_dict.keys())[:10], arg_debug)
    l_ip_value = _ida_dbg.get_ip_val()
    l_ip_from_registers = getattr(registers, l_ip_name).value
    res &= _test_check(f"registers.{l_ip_name}.value == ida_dbg.get_ip_val()", l_ip_from_registers == l_ip_value, l_ip_from_registers, arg_debug)
    l_ip_from_eval = eval_expression(l_ip_name, arg_debug=arg_debug)
    res &= _test_check(f"eval_expression('{l_ip_name}') == ida_dbg.get_ip_val()", l_ip_from_eval == l_ip_value, l_ip_from_eval, arg_debug)

    l_ntdll = module("ntdll", arg_debug=arg_debug)
    res &= _test_check("module('ntdll')", l_ntdll is not None and "ntdll" in l_ntdll.name.lower(), l_ntdll, arg_debug)
    if l_ntdll is not None:
        l_same = module(l_ntdll.base + 0x10, arg_debug=arg_debug)
        res &= _test_check("module(<address inside ntdll>) is ntdll", l_same is not None and l_same.base == l_ntdll.base, l_same, arg_debug)

    l_memory = _test_scratch_memory(arg_debug=arg_debug)
    if l_memory is None:
        return False
    l_breakpoint_ea = l_memory + 0x100
    try:
        l_breakpoint = debugger_breakpoint_add(l_breakpoint_ea, arg_debug=arg_debug)
        res &= _test_check("debugger_breakpoint_add()", l_breakpoint is not None and _ida_dbg.exist_bpt(l_breakpoint_ea), l_breakpoint, arg_debug)
    finally:
        debugger_breakpoint_delete(l_breakpoint_ea, arg_debug=arg_debug)
    res &= _test_check("debugger_breakpoint_delete()", not _ida_dbg.exist_bpt(l_breakpoint_ea), _ida_dbg.exist_bpt(l_breakpoint_ea), arg_debug)
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _test_all(arg_slow_mode: bool = False, arg_coverage: bool = False, arg_debug: bool = False) -> bool:
    ''' Tests all tests we have so far. This is NOT complete and needs to be extended.
    Every time I have to fix something in an update, I add a test for that.

    To make the tests work:
    1. You need to be on Windows
    2. Open notepad.exe
    3. Set at breakpoint at the WinMain
    4. Start the debugger and when RIP is on WinMain
    5. Run these tests
    '''
    if arg_coverage:
        import coverage
    import tempfile
    import time

    log_print("To make the tests work, you need to be on Windows, open notepad.exe and set at breakpoint at the start, start the debugger and when RIP is on WinMain. Then run these tests.", arg_type="INFO")

    if arg_coverage:
        l_this_file = _os.path.abspath(__file__)
        l_report_dir = _os.path.join(tempfile.gettempdir(), "coverage_community_base")
        _os.makedirs(l_report_dir, exist_ok=True)
        cov = coverage.Coverage(include=[l_this_file], data_file=l_report_dir + "/coverage.dat")
        cov.start()

    l_test_functions = {'_test_appcall_on_Windows': _test_appcall_on_Windows,
                        '_test_mem_alloc_write_read': _test_mem_alloc_write_read,
                        '_test_modules_on_Windows': _test_modules_on_Windows,
                        '_test_eval_expression': _test_eval_expression,
                        # '_test_TWidget': _test_TWidget, # Crash IDA, need to investigate
                        '_test_Qt_stuff': _test_Qt_stuff,
                        '_test_decompiler': _test_decompiler,
                        '_test_licence': _test_licence,
                        '_test_decompiler_comments': _test_decompiler_comments,
                        '_test_relative_virtual_address': _test_relative_virtual_address,
                        '_test_convert_to_usercall': _test_convert_to_usercall,
                        '_test_input_file' : _test_input_file,
                        '_test_GetProcAddress_on_Windows' : _test_GetProcAddress_on_Windows,
                        '_test_virtual_address_to_file_offset_and_back_again': _test_virtual_address_to_file_offset_and_back_again,
                        '_test_save_database': _test_save_database,
                        '_test_python_load_module': _test_python_load_module,
                        '_test_pe_header_linker_version': _test_pe_header_linker_version,
                        '_test_imports_and_exports': _test_imports_and_exports,
                        '_test_instruction': _test_instruction,
                        '_test_bug_report' : _test_bug_report,
                        '_test_ida_is_running_in_batch_mode': _test_ida_is_running_in_batch_mode,
                        '_test_notepad_text': _test_notepad_text,
                        '_test_hex_dump': _test_hex_dump,
                        '_test_licence_ex': _test_licence_ex,
                        '_test_ida_domain': _test_ida_domain,
                        '_test_operand_parser_x64': _test_operand_parser_x64,
                        '_test_instruction_is_same_as_nop': _test_instruction_is_same_as_nop,
                        '_test_fix_assembly': _test_fix_assembly,
                        '_test_pointer_write': _test_pointer_write,
                        '_test_eval_expression_words_are_not_numbers': _test_eval_expression_words_are_not_numbers,
                        '_test_name_demangle': _test_name_demangle,
                        '_test_virtual_address_to_module_and_offset': _test_virtual_address_to_module_and_offset,
                        '_test_comment_append_no_duplicates': _test_comment_append_no_duplicates,
                        '_test_function_bytes': _test_function_bytes,
                        '_test_search_binary_backward': _test_search_binary_backward,
                        '_test_segment_permissions': _test_segment_permissions,
                        '_test_dump_to_disk_uses_arguments': _test_dump_to_disk_uses_arguments,
                        '_test_decompile_many': _test_decompile_many,
                        '_test_hex_parse': _test_hex_parse,
                        '_test_int_to_str_dict_from_module': _test_int_to_str_dict_from_module,
                        '_test_demangle_string': _test_demangle_string,
                        '_test_encoding_round_trip': _test_encoding_round_trip,
                        '_test_get_type_and_parse_decl': _test_get_type_and_parse_decl,
                        '_test_import_h_file': _test_import_h_file,
                        '_test_export_h_file_and_file_generate': _test_export_h_file_and_file_generate,
                        '_test_misc_wrappers': _test_misc_wrappers,
                        '_test_strings_and_xrefs': _test_strings_and_xrefs,
                        '_test_decompiler_helpers': _test_decompiler_helpers,
                        '_test_instruction_properties_x64': _test_instruction_properties_x64,
                        '_test_make_data_and_set_type': _test_make_data_and_set_type,
                        '_test_bytes_smart_delete': _test_bytes_smart_delete,
                        '_test_debugger_registers_modules_breakpoints': _test_debugger_registers_modules_breakpoints
                        }

    l_test_result = {}

    for l_test_name, l_test_func in l_test_functions.items():
        if arg_slow_mode:
            log_print(f"Running test: {l_test_name}", arg_type="INFO") # Print before running so we know which test is currently executing if it crashes
            for l_handler in _g_logger.handlers:
                l_handler.flush()

        l_test_result[l_test_name] = l_test_func(arg_debug=arg_debug)

        if arg_slow_mode:
            if l_test_result[l_test_name]:
                log_print(f"{l_test_name}: {l_test_result[l_test_name]}", arg_type="INFO")
            else:
                log_print(f"{l_test_name}: {l_test_result[l_test_name]}", arg_type="ERROR")

            for l_handler in _g_logger.handlers:
                l_handler.flush()

            time.sleep(1) # Give time to read which test just ran before moving on

    log_print("\n-----------------------------------\n"
                "----------  Test results ----------\n"
                "-----------------------------------"
                , arg_type="INFO")
    log_print(f"IDA version: {str(ida_version())}", arg_type="INFO")
    log_print(f"Decompiler version: {_ida_hexrays.get_hexrays_version()}", arg_type="INFO")
    log_print(f"Community_base version: {__version__}", arg_type="INFO")
    log_print(f"Python version: {_sys.version}", arg_type="INFO")
    log_print(f"OS: {_platform.uname().system} {_platform.uname().version} {_platform.uname().machine}", arg_type="INFO")
    log_print(f"Timestamp: {_timestamped_line('').strip()}", arg_type="INFO")
    
    for l_test_name, l_result in l_test_result.items():
        if l_result:
            log_print(f"{l_test_name}: {l_result}", arg_type="INFO")
        else:
            log_print(f"{l_test_name}: {l_result}", arg_type="ERROR")

    res = all(l_test_result.values())
    if res:
        log_print("All tests passed OK!", arg_type="INFO")
    else:
        log_print("Some tests failed!", arg_type="ERROR")

    if arg_coverage:
        cov.stop()
        cov.save()
        cov.html_report(directory=l_report_dir)
        _os.system(f"start {l_report_dir}/index.html") # TODO: During debugging, I dont want a new window popping up

    return res

# EXPERIMENTAL ---------------------------------------------------------------------------------------------------------------------------------------------------------- EXPERIMENTAL


@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _export_names_and_types(arg_save_to_file: str = "",
                            arg_allow_library_functions: bool = True,
                            arg_list_of_functions: Union[List[_ida_funcs.func_t], List[int], None] = None,
                            arg_full_export: bool = False,
                            arg_debug: bool = False) -> Dict[str, Dict[str,str]]:
    ''' Exports functions name and function type so we can import that file in another project that use the same name and function prototype
    TODO: Export: types in .h file, notepad in .txt, the assembly code in .asm and the pseudo code in .c

    TODO: WARNING! This function is "working" but is very slow and I am not happy with how it works right now, consider it experimental
    EXPERIMENTAL
    '''
    res = {}
    if not arg_save_to_file:
        arg_save_to_file = input_file.idb_path + ".export_names_and_functions.json"
    log_print(f"Saving exported data to {arg_save_to_file}", arg_debug)

    if not arg_list_of_functions:
        arg_list_of_functions = functions(arg_allow_library_functions=arg_allow_library_functions, arg_debug=arg_debug)

    l_counter = 0
    for func_start_address in arg_list_of_functions:
        func: Optional[_ida_funcs.func_t] = function(func_start_address)
        if func is None:
            log_print("function(func) failed", arg_type="ERROR")
            continue
        l_counter += 1
        l_data_to_export: Dict[str, str] = {}
        l_data_to_export["name"] = name(func, arg_demangle_name=False) or f"sub_{func.start_ea:X}"
        if arg_full_export: # OBS! This is VERY SLOW
            l_data_to_export["demangled_name"] = name(func, arg_demangle_name=True) or f"sub_{func.start_ea:X}"
            l_data_to_export["prototype"] = function_prototype(func.start_ea, arg_allow_comments=False, arg_debug=arg_debug)
            _t = _ida_typeinf.tinfo_t()
            _ida_hexrays.get_type(func.start_ea, _t, 0)
            l_data_to_export["type"] = str(_t)
            l_data_to_export["comment"] = comment(func.start_ea) or ""
            l_data_to_export["rva"] = f"0x{rva(func.start_ea):x}"

        res[f"0x{func.start_ea:x}"] = l_data_to_export

        if l_counter % 100 == 0: # TODO: During debugging, its nice to see the progress and get an idea on how long time it will take
            log_print(f"l_counter = {l_counter}")
            with open(arg_save_to_file + f".{l_counter}.json", "w", encoding="utf-8", newline="\n") as f:
                _json.dump(res, f, ensure_ascii=False, indent=4, default=str)

    with open(arg_save_to_file, "w", encoding="utf-8", newline="\n") as f:
        _json.dump(res, f, ensure_ascii=False, indent=4, default=str)
    log_print(f"Wrote JSON to:\n'{arg_save_to_file}'", arg_type="INFO")
    return res

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _ignore_cast(arg_expr: _ida_hexrays.cexpr_t) -> _ida_hexrays.cexpr_t:
    ''' Helper function for (<type>)variable_name in the decompiler '''
    return arg_expr.first_operand if arg_expr.opname == 'cast' else arg_expr

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _errors_find_type_errors(arg_ea: EvaluateType,
                            arg_force_fresh_decompilation: bool = True,
                            arg_debug: bool = False) -> Optional[bool]:
    ''' Find type errors such as <int> - <ptr> and in the future: <ptr> + <ptr>
    EXPERIMENTAL
    '''

    l_cfunc = decompile(arg_ea, arg_force_fresh_decompilation=arg_force_fresh_decompilation, arg_debug=arg_debug)
    if not l_cfunc:
        return None

    for _t in l_cfunc.treeitems:
        _t = _ida_hexrays.citem_to_specific_type(_t)

        if _t.opname == 'sub': # checking for <int> - <ptr>
            left = _ignore_cast(_t.first_operand)
            right = _ignore_cast(_t.second_operand)

            if left.opname == 'var':
                left_type = left.variable.getv().type()
                if left_type.is_int():
                    if right.opname == 'var':
                        right_type = right.variable.getv().type()
                        if right_type.is_ptr():
                            log_print(f'Found invalid types at "{_t}" where {left} is int and {right} is ptr', arg_type="WARNING")
                            return True
        elif _t.opname == 'eq': # Checking for a <ptr> == <integer value> which is very rare
            left = _ignore_cast(_t.first_operand)
            right = _ignore_cast(_t.second_operand)
            if left.opname == 'var':
                left_type = left.variable.getv().type()
                if left_type.is_ptr():
                    if right.opname == 'num':
                        log_print(f'WARNING! Found possible invalid types at "{_t}" where {left} is ptr and {right} is num')
                        return True
    return False

@validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
def _comment_copy_from_disassembly_to_decompiler(arg_function: EvaluateType,  arg_debug: bool = False) -> bool:
    ''' Read comments from the disassembly view and set them in the decompiler view.
    EXPERIMENTAL
    WARNING! If there are multiple comments on different addresses in the assembly that turns into the same line in the decompiler, then only the last comment will be set.

    This code is ThisIsMyAltAccount's contribution (AI generated code) from https://github.com/Harding-Stardust/community_base/issues/5
    '''
    l_func = function(arg_function, arg_debug=arg_debug)
    if l_func is None:
        log_print(f"No function at {_hex_str_if_int(arg_function)}", arg_type="ERROR")
        return False

    l_cfunc = decompile(l_func.start_ea)
    if l_cfunc is None:
        log_print(f"Could not decompile function at 0x{l_func.start_ea:x}", arg_type="ERROR")
        return False

    l_pending: Dict[int, str] = {}
    l_function_items_iterator = _ida_funcs.func_item_iterator_t(l_func)
    for l_ea in l_function_items_iterator:
        if is_code(l_ea, arg_debug=arg_debug):
            l_repeatable_comment = False
            l_disassembly_comment = _ida_bytes.get_cmt(l_ea, l_repeatable_comment)
            # TODO: Verify if it is a auto comment from IDA?
            if l_disassembly_comment:
                l_pending[l_ea] = l_disassembly_comment

    if not l_pending:
        return True

    for l_ea, l_comment in l_pending.items():
        l_insn = _ea_to_hexrays_insn(l_ea, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug)
        if l_insn is None or l_insn.is_epilog():
            continue
        l_tree_location = _ida_hexrays.treeloc_t()
        l_tree_location.ea = l_insn.ea
        l_tree_location.itp = _ida_hexrays.ITP_SEMI
        l_cfunc.set_user_cmt(l_tree_location, l_comment) # type: ignore[union-attr]
    l_cfunc.save_user_cmts() # type: ignore[union-attr]

    l_cfunc = decompile(l_func.start_ea, arg_force_fresh_decompilation=True)
    if l_cfunc is None:
        log_print(f"Decompilation failed for function at 0x{l_func.start_ea:x}", arg_type="ERROR")
        return False

    if not l_cfunc.has_orphan_cmts(): # type: ignore[union-attr]
        log_print(f"All {len(l_pending)} comment(s) were set correctly with ITP_SEMI in a single pass", arg_type="INFO")
        return True

    # Some comments got orphaned (ITP_SEMI was not the right tree location for them).
    # Drop the orphans and figure out which addresses from l_pending are still missing
    # their comment, then fall back to the slow, exhaustive per-comment method ONLY for
    # those, instead of redoing the whole function.
    l_cfunc.del_orphan_cmts() # type: ignore[union-attr]
    l_cfunc.save_user_cmts() # type: ignore[union-attr]

    l_eas_with_comment_now: Set[int] = set()
    l_comments_now: _ida_hexrays.user_cmts_t = _ida_hexrays.restore_user_cmts(l_cfunc.entry_ea) # type: ignore[union-attr]
    if l_comments_now is not None:
        for l_tree_location in l_comments_now.keys():
            l_eas_with_comment_now.add(l_tree_location.ea)
        _ida_hexrays.user_cmts_free(l_comments_now)

    l_all_ok = True
    l_nr_of_fallbacks = 0
    for l_ea, l_comment in l_pending.items():
        if l_ea in l_eas_with_comment_now:
            continue # Already set correctly with ITP_SEMI, no need for the slow path
        l_nr_of_fallbacks += 1
        if not _comment_set_decompiler(l_ea, l_comment, arg_cached_cfunc=l_cfunc, arg_debug=arg_debug):
            l_all_ok = False
    log_print(f"{l_nr_of_fallbacks} out of {len(l_pending)} comment(s) needed the slow, per-comment fallback", arg_type="INFO")

    return l_all_ok


#
# void* __spoils<esi, edi> memcpy(void*, void*, int); # https://hex-rays.com/blog/igors-tip-of-the-week-51-custom-calling-conventions

# Plugin mode  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- Plugin mode


_G_PLUGIN_NAME = "community_base_nice_hotkeys"
_G_HOTKEY_DUMP_TO_DISK = _hotkey_str_fixer('W') # Select bytes and press w to dump it to disk in the same directory as the IDB. One can also call dump_to_disk(address, length) to dump from the console
_G_HOTKEY_COPY_SELECTED_BYTES_AS_HEX_TEXT = _hotkey_str_fixer('Shift + C') # Select bytes and press Shift-C to copy the marked bytes as hex text. Same shortcut as in x64dbg.
_G_HOTKEY_COPY_CURRENT_ADDRESS = _hotkey_str_fixer('Alt + Ins') # Copy the current address as hex text into the clipboard. Same shortcut as x64dbg.
_G_HOTKEY_SMART_DELETE_BYTES = _hotkey_str_fixer('Del') # Pressing delete on code turns it into NOP (0x90) if it's already NOP (or data) then write 0x00

class community_base_plugmod_t(_ida_idaapi.plugmod_t):
    ''' This is the code that is actually run '''

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __init__(self) -> None:
        ''' Registers the 4 hotkeys (actions). Existing actions with the same names are unregistered first so a reload works. Needs Qt (the GUI) '''
        if not _G_QT_IS_AVAILABLE:
            log_print(f"{_G_PLUGIN_NAME} found no QT and will not add any hotkeys", arg_type="WARNING")
            return
        log_print(f"{_G_PLUGIN_NAME} loaded as plugin", arg_type="INFO")

        # ---- Hotkey: w --> Dump selected bytes to a file on disk ----------------------------------------------------------------------------------------
        _ACTION_NAME_DUMP_SELECTED_BYTES = f"{__name__}:dump_selected_bytes_to_disk"
        if _ACTION_NAME_DUMP_SELECTED_BYTES in _ida_kernwin.get_registered_actions():
            if _ida_kernwin.unregister_action(_ACTION_NAME_DUMP_SELECTED_BYTES):
                log_print(f"unregister_action(): '{_ACTION_NAME_DUMP_SELECTED_BYTES}' OK", arg_type="INFO")
            else:
                log_print(f"unregister_action(): '{_ACTION_NAME_DUMP_SELECTED_BYTES}' failed", arg_type="ERROR")

        class ActionHandlerDumpToDisk(_ida_kernwin.action_handler_t):
            ''' Handler for dump to disk '''
            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def activate(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This code is run when the hotkey is pressed '''
                del ctx # Not used but needed in prototype
                l_debug: bool = False
                log_print("ActionHandlerDumpToDisk activate", l_debug)
                _ = dump_to_disk(arg_debug=l_debug) # Without arguments --> selected bytes
                return 1

            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def update(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This function is called whenever something has changed, and you can tell IDA in here when you want your update() function to be called. '''
                del ctx # Not used but needed in prototype
                return _ida_kernwin.AST_ENABLE_ALWAYS # This hotkey should be available everywhere

        if _ida_kernwin.register_action(_ida_kernwin.action_desc_t(_ACTION_NAME_DUMP_SELECTED_BYTES, f"{__name__}: Dump selected bytes to disk", ActionHandlerDumpToDisk(), _G_HOTKEY_DUMP_TO_DISK)):
            log_print(f"register_action('{_ACTION_NAME_DUMP_SELECTED_BYTES}') OK, shortcut: {_G_HOTKEY_DUMP_TO_DISK}", arg_type="INFO")
        else:
            log_print(f"register_action('{_ACTION_NAME_DUMP_SELECTED_BYTES}') failed", arg_type="ERROR")

        # ---- Hotkey: Shift + C --> Copy selected bytes as hex text to clipboard ----------------------------------------------------------------------------------------
        _ACTION_NAME_COPY_HEX_TEXT = f"{__name__}:copy_hex_text"
        if _ACTION_NAME_COPY_HEX_TEXT in _ida_kernwin.get_registered_actions():
            if _ida_kernwin.unregister_action(_ACTION_NAME_COPY_HEX_TEXT):
                log_print(f"unregister_action(): '{_ACTION_NAME_COPY_HEX_TEXT}' OK", arg_type="INFO")
            else:
                log_print(f"unregister_action(): '{_ACTION_NAME_COPY_HEX_TEXT}' failed", arg_type="ERROR")

        class ActionHandlerCopyHexText(_ida_kernwin.action_handler_t):
            ''' Handler for copy hex text '''
            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def activate(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This code is run when the hotkey is pressed '''
                del ctx # Not used but needed in prototype
                l_debug: bool = False
                log_print("ActionHandlerCopyHexText activate", l_debug)
                clipboard_copy_hex_text_to_clipboard() # Without arguments --> Copy selected bytes as hex text
                return 1

            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def update(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This function is called whenever something has changed, and you can tell IDA in here when you want your update() function to be called. '''
                del ctx # Not used but needed in prototype
                return _ida_kernwin.AST_ENABLE_ALWAYS # This hotkey should be available everywhere

        if _ida_kernwin.register_action(_ida_kernwin.action_desc_t(_ACTION_NAME_COPY_HEX_TEXT, f"{__name__}: Copy selected bytes as hex text", ActionHandlerCopyHexText(), _G_HOTKEY_COPY_SELECTED_BYTES_AS_HEX_TEXT)):
            log_print(f"register_action('{_ACTION_NAME_COPY_HEX_TEXT}') OK, shortcut: {_G_HOTKEY_COPY_SELECTED_BYTES_AS_HEX_TEXT}", arg_type="INFO")
        else:
            log_print(f"register_action('{_ACTION_NAME_COPY_HEX_TEXT}') failed", arg_type="ERROR")

        # ---- Hotkey: Alt + Ins --> Copy current address ----------------------------------------------------------------------------------------
        _ACTION_NAME_COPY_CURRENT_ADDRESS = f"{__name__}:copy_current_address"
        if _ACTION_NAME_COPY_CURRENT_ADDRESS in _ida_kernwin.get_registered_actions():
            if _ida_kernwin.unregister_action(_ACTION_NAME_COPY_CURRENT_ADDRESS):
                log_print(f"unregister_action(): '{_ACTION_NAME_COPY_CURRENT_ADDRESS}' OK", arg_type="INFO")
            else:
                log_print(f"unregister_action(): '{_ACTION_NAME_COPY_CURRENT_ADDRESS}' failed", arg_type="ERROR")

        class ActionHandlerCopyCurrentAddress(_ida_kernwin.action_handler_t):
            ''' Handler for copy current address '''
            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def activate(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This code is run when the hotkey is pressed '''
                del ctx # Not used but needed in prototype
                l_debug: bool = False
                log_print("ActionHandlerCopyCurrentAddress activate", l_debug)
                _ = clipboard_copy(f'0x{current_address():x}')
                return 1

            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def update(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This function is called whenever something has changed, and you can tell IDA in here when you want your update() function to be called. '''
                del ctx # Not used but needed in prototype
                return _ida_kernwin.AST_ENABLE_ALWAYS # This hotkey should be available everywhere

        if _ida_kernwin.register_action(_ida_kernwin.action_desc_t(_ACTION_NAME_COPY_CURRENT_ADDRESS, f"{__name__}: Copy the current address as hex text", ActionHandlerCopyCurrentAddress(), _G_HOTKEY_COPY_CURRENT_ADDRESS)):
            log_print(f"register_action('{_ACTION_NAME_COPY_CURRENT_ADDRESS}') OK, shortcut: {_G_HOTKEY_COPY_CURRENT_ADDRESS}", arg_type="INFO")
        else:
            log_print(f"register_action('{_ACTION_NAME_COPY_CURRENT_ADDRESS}') failed", arg_type="ERROR")

        # ---- Hotkey: Delete --> Smart delete bytes ----------------------------------------------------------------------------------------
        _ACTION_NAME_SMART_DELETE_BYTES = f"{__name__}:smart_delete_bytes"
        if _ACTION_NAME_SMART_DELETE_BYTES in _ida_kernwin.get_registered_actions():
            if _ida_kernwin.unregister_action(_ACTION_NAME_SMART_DELETE_BYTES):
                log_print(f"unregister_action(): '{_ACTION_NAME_SMART_DELETE_BYTES}' OK", arg_type="INFO")
            else:
                log_print(f"unregister_action(): '{_ACTION_NAME_SMART_DELETE_BYTES}' failed", arg_type="ERROR")

        class ActionHandlerSmartDeleteBytes(_ida_kernwin.action_handler_t):
            ''' Handler for smart delete bytes'''
            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def activate(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This code is run when the hotkey is pressed '''
                del ctx # Not used but needed in prototype
                l_debug: bool = False
                log_print("ActionHandlerSmartDeleteBytes activate", l_debug)
                l_is_valid, l_start_address, l_end_address = _idaapi_read_range_selection(arg_allow_one_line=True)
                if not l_is_valid:
                    log_print("Invalid selection", arg_type="ERROR")
                    return 1
                _ = bytes_smart_delete(arg_ea=l_start_address, arg_len=l_end_address - l_start_address, arg_debug=l_debug)
                return 1

            @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
            def update(self, ctx: _ida_kernwin.action_ctx_base_t):
                ''' This function is called whenever something has changed, and you can tell IDA in here when you want your update() function to be called. '''

                if ctx.widget_type in (_ida_kernwin.BWN_PSEUDOCODE, _ida_kernwin.BWN_DISASM):
                    return _ida_kernwin.AST_ENABLE_FOR_WIDGET
                return _ida_kernwin.AST_DISABLE_FOR_WIDGET

        if _ida_kernwin.register_action(_ida_kernwin.action_desc_t(_ACTION_NAME_SMART_DELETE_BYTES, f"{__name__}: Smart delete bytes", ActionHandlerSmartDeleteBytes(), _G_HOTKEY_SMART_DELETE_BYTES)):
            log_print(f"register_action('{_ACTION_NAME_SMART_DELETE_BYTES}') OK, shortcut: {_G_HOTKEY_SMART_DELETE_BYTES}", arg_type="INFO")
        else:
            log_print(f"register_action('{_ACTION_NAME_SMART_DELETE_BYTES}') failed", arg_type="ERROR")

        return

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def run(self, arg_user_argument: int) -> int:
        ''' Called when the user runs the plugin from the menu. Does nothing, the hotkeys are registered in __init__() '''
        del arg_user_argument # Not used but needed in prototype
        log_print(f"{_G_PLUGIN_NAME} called the run() method. This does nothing as the constructor sets up the 4 hotkeys", arg_type="INFO")
        return 0

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def __del__(self) -> None:
        ''' This code is run when the user closes the IDB '''
        log_print(f"{_G_PLUGIN_NAME} is running the destructor", arg_type="INFO")
        return

class community_base_plugin_t(_ida_idaapi.plugin_t):
    ''' This is the config for the plugin, the actual code is in community_base_plugmod_t() '''
    flags: int = _ida_idaapi.PLUGIN_MULTI # if this flag is set, then init have to return a ida_idaapi.plugmod_t()
    comment: str = f"{_G_PLUGIN_NAME}:Added 4 new hotkeys"
    help: str = f"{_G_PLUGIN_NAME}:Added 4 new hotkeys"
    wanted_name: str = _G_PLUGIN_NAME
    wanted_hotkey: str = "" # The hotkeys are registered in the community_base_plugmod_t() constructor

    @validate_call(config={"arbitrary_types_allowed": True, "strict": True, "validate_return": True})
    def init(self) -> Optional[_ida_idaapi.plugmod_t]:
        ''' We can do checking and if we don't want to be loaded, we can return None.
        If we want to be loaded, then we return a ida_idaapi.plugmod_t
        '''
        return community_base_plugmod_t()

def PLUGIN_ENTRY() -> _ida_idaapi.plugin_t:
    ''' IDA calls this function to get the plugin object when it loads the plugin '''
    return community_base_plugin_t()

# "from community_base import *" exports everything public EXCEPT help(), which would shadow Python's builtin help(). Use community_base.help() for that one.
__all__ = [_t_name for _t_name, _t_value in list(globals().items()) if not _t_name.startswith('_') and _t_name != 'help' and not isinstance(_t_value, ModuleType)]

if not _is_running_as_plugin():
    log_print(f"Loaded {__name__} version: {__version__} by {__author__}. This version was released {_time_since(__version__)}", arg_type="INFO")


