"""Import reconstruction for Aletheia's dynamic layer -- turn a dumped IAT full of
raw resolved addresses back into a ``DLL!function`` map.

When a packer unpacks, it rebuilds the Import Address Table *in memory* as an
array of **resolved absolute function pointers** (each slot holds e.g.
``kernel32_base + rva_of_LoadLibraryA``). A raw memory dump (see
:mod:`aletheia.dump`) therefore has an IAT of nameless addresses -- useless to a
static decompiler and not loadable. This is the follow-on the ``dump.py`` docstring
promised: resolve each slot's address back to ``DLL!function`` by walking the
**export table** of whichever loaded module contains that address -- exactly what
Scylla / ImpRec do.

Two pieces:

* :func:`parse_exports` -- read a module's EXPORT directory out of its *mapped*
  image (data-directory index 0) into an ``rva -> name`` map. Handles named
  exports, ordinal-only (name-less) exports (recorded as ``"#<ordinal>"``), and
  forwarder exports (an EAT rva that points back *inside* the export directory is
  a forwarder string, not code -- recorded separately, kept out of the code map).
* :func:`resolve_imports` -- read the dumped IAT slot-by-slot, and for each slot
  whose value lands inside a known module, look the address up in that module's
  exports to name it.

House style mirrors ``aletheia.dump`` / ``aletheia.unpack``: a pure function over a
``read_mem(addr, size) -> bytes`` callable (from ``procdump.make_reader`` live, or
a synthetic closure in tests), so it runs with no live process. It imports cleanly
everywhere -- there is nothing Windows-specific in here; ``ctypes`` stays in
``procdump``.

**The mapped-vs-disk RVA distinction (get this right):** ``pe.py`` parses an
*on-disk* file, where an RVA must be translated to a file offset through the
section table (``_rva_to_off``). Here the image is *mapped* (the loader has already
placed each section at its VirtualAddress), so ``RVA == offset-from-base`` and every
lookup is simply ``read_mem(base + rva, n)``. No section walk.
"""
from __future__ import annotations

import enum
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

ReadMem = Callable[[int, int], bytes]

# One loaded module for the resolver: (mapped_base, size_of_image, name).
Module = Tuple[int, int, str]

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_EXPORT_DIR_SIZE = 40          # sizeof(IMAGE_EXPORT_DIRECTORY)
_MAX_EXPORTS = 1 << 20         # sanity clamp on NumberOf(Functions|Names)
_CSTR_LIMIT = 512             # max bytes we read for one exported symbol name
_PTR = 8                       # x64 IAT slot width


# ===========================================================================
# export table
# ===========================================================================
@dataclass
class Exports:
    """A module's parsed export table (over its mapped image).

    ``by_rva`` maps each *real* exported function RVA to its name -- the export's
    name for named exports, or ``"#<ordinal>"`` for name-less ordinal exports.
    ``ordinal_by_rva`` carries the export ordinal alongside (the resolver surfaces
    it). ``forwarders`` maps an exported name to its ``"TARGETDLL.func"`` forward
    string -- these are NOT real code in this module, so they are kept out of
    ``by_rva``. ``ok`` is False for a module with no/garbage export directory
    (fail-closed: an empty ``Exports``)."""
    dll_name: str = ""
    by_rva: Dict[int, str] = field(default_factory=dict)
    ordinal_by_rva: Dict[int, int] = field(default_factory=dict)
    forwarders: Dict[str, str] = field(default_factory=dict)
    ok: bool = False


def _read_cstr(read_mem: ReadMem, addr: int, limit: int = _CSTR_LIMIT) -> str:
    """Read a NUL-terminated latin-1 string at absolute ``addr`` (mapped image)."""
    try:
        raw = read_mem(addr, limit)
    except Exception:            # noqa: BLE001 - a bad read is just "no string"
        return ""
    end = raw.find(b"\x00")
    if end < 0:
        end = len(raw)
    return raw[:end].decode("latin-1", "replace")


def _export_dir_dir(read_mem: ReadMem, base: int) -> Optional[Tuple[int, int]]:
    """Return ``(export_rva, export_size)`` from data-directory index 0, or None.

    Reads only the PE headers (first page). Fails closed to None on anything that
    is not a well-formed PE with a non-empty export directory."""
    try:
        hdr = read_mem(base, 0x1000)
    except Exception:            # noqa: BLE001
        return None
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return None
    try:
        (e_lfanew,) = struct.unpack_from("<I", hdr, 0x3C)
        if hdr[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        opt = e_lfanew + 4 + 20                       # PE sig (4) + COFF header (20)
        (opt_magic,) = struct.unpack_from("<H", hdr, opt)
        if opt_magic == _PE32PLUS_MAGIC:
            num_dd_off, dd_off = opt + 108, opt + 112
        elif opt_magic == _PE32_MAGIC:
            num_dd_off, dd_off = opt + 92, opt + 96
        else:
            return None
        (num_dd,) = struct.unpack_from("<I", hdr, num_dd_off)
        if num_dd < 1:                                # need directory index 0
            return None
        export_rva, export_size = struct.unpack_from("<II", hdr, dd_off)  # index 0
    except struct.error:
        return None
    if not export_rva or not export_size:
        return None
    return export_rva, export_size


def parse_exports(read_mem: ReadMem, base: int) -> Exports:
    """Parse the export table of the module mapped at ``base``.

    ``read_mem(addr, size)`` returns bytes at an absolute address. Because the image
    is MAPPED, ``RVA == offset-from-base`` (``read_mem(base + rva, n)``) -- no
    section-table translation. Returns an empty ``Exports`` (``ok=False``) for a
    module with no export directory or unreadable/garbage data."""
    exp = Exports()
    dd = _export_dir_dir(read_mem, base)
    if dd is None:
        return exp
    export_rva, export_size = dd

    try:
        ed = read_mem(base + export_rva, _EXPORT_DIR_SIZE)
    except Exception:            # noqa: BLE001
        return exp
    if len(ed) < _EXPORT_DIR_SIZE:
        return exp
    (_chars, _ts, _major, _minor, name_rva, ordinal_base,
     num_funcs, num_names, addr_funcs_rva, addr_names_rva,
     addr_ords_rva) = struct.unpack("<IIHHIIIIIII", ed)

    if num_funcs > _MAX_EXPORTS or num_names > _MAX_EXPORTS:
        return exp                                     # implausible -> fail closed

    exp.dll_name = _read_cstr(read_mem, base + name_rva) if name_rva else ""

    # The three parallel arrays: EAT (function RVAs), name-string RVAs, and the
    # WORD ordinals that map a name to its EAT index.
    try:
        eat = read_mem(base + addr_funcs_rva, 4 * num_funcs) if num_funcs else b""
        names = read_mem(base + addr_names_rva, 4 * num_names) if num_names else b""
        ords = read_mem(base + addr_ords_rva, 2 * num_names) if num_names else b""
    except Exception:            # noqa: BLE001
        return exp
    if len(eat) < 4 * num_funcs or len(names) < 4 * num_names \
            or len(ords) < 2 * num_names:
        return exp

    # name-string RVA + ordinal array -> {EAT index: export name}. Multiple names
    # can alias one index; last wins (aliases are rare and harmless here).
    name_of_index: Dict[int, str] = {}
    for i in range(num_names):
        (name_str_rva,) = struct.unpack_from("<I", names, 4 * i)
        (eat_index,) = struct.unpack_from("<H", ords, 2 * i)
        if eat_index >= num_funcs or not name_str_rva:
            continue
        nm = _read_cstr(read_mem, base + name_str_rva)
        if nm:
            name_of_index[eat_index] = nm

    # Walk the EAT. A zero rva is an unused ordinal slot. An rva that points back
    # *inside* the export directory is a forwarder string, not code.
    dir_lo, dir_hi = export_rva, export_rva + export_size
    for idx in range(num_funcs):
        (func_rva,) = struct.unpack_from("<I", eat, 4 * idx)
        if func_rva == 0:
            continue
        ordinal = idx + ordinal_base
        nm = name_of_index.get(idx)
        if dir_lo <= func_rva < dir_hi:                # forwarder ("DLL.func")
            fwd = _read_cstr(read_mem, base + func_rva)
            key = nm if nm else "#%d" % ordinal
            if fwd:
                exp.forwarders[key] = fwd
            continue
        if nm is None:
            nm = "#%d" % ordinal                       # name-less ordinal export
        exp.by_rva[func_rva] = nm
        exp.ordinal_by_rva[func_rva] = ordinal

    exp.ok = True
    return exp


# ===========================================================================
# API purpose classification
# ===========================================================================
class Purpose(str, enum.Enum):
    """The API *family* a resolved import belongs to.

    A ``str``-valued enum so it JSON-serialises as its plain string ("loader",
    "network", ...) and compares equal to that string -- keeping
    :class:`ResolvedImport` round-trips through ``project.py`` (which stores the
    field verbatim) backward-compatible. Read the buckets as a triage lens: "this
    binary loads DLLs (LOADER) + opens sockets (NETWORK) + writes the registry
    (REGISTRY)"."""
    LOADER = "loader"          # LoadLibrary*, GetProcAddress, LdrLoadDll, GetModuleHandle*
    MEMORY = "memory"          # VirtualAlloc*, VirtualProtect*, HeapAlloc, WriteProcessMemory
    PROCESS = "process"        # CreateProcess*, CreateRemoteThread, OpenProcess, QueueUserAPC
    THREAD = "thread"          # CreateThread, ResumeThread, SuspendThread, SetThreadContext
    FILE = "file"              # CreateFile*, ReadFile, WriteFile, DeleteFile*, FindFirstFile*
    REGISTRY = "registry"      # RegOpenKey*, RegCreateKey*, RegSet*, RegGet*, RegDeleteKey*
    NETWORK = "network"        # socket, connect, send/recv, WSA*, Http*, WinHttp*, Internet*
    CRYPTO = "crypto"          # CryptAcquire*, Crypt/BCrypt/NCrypt Encrypt/Decrypt, Cert*
    GUI = "gui"                # CreateWindow*, ShowWindow, MessageBox*, SetWindowsHookEx
    SYSINFO = "sysinfo"        # GetSystemInfo, GetVersion*, IsDebuggerPresent, GetTickCount
    IPC = "ipc"                # CreateNamedPipe*, CreateFileMapping, CreateEvent, CreateMutex
    UNKNOWN = "unknown"        # anything the classifier does not recognise


# Exact function-name (lowercased, A/W-suffix stripped) -> Purpose. The canonical
# ~150-name Windows surface across kernel32, ntdll, advapi32, ws2_32/wininet/winhttp,
# bcrypt/ncrypt/crypt32, user32/gdi32, shell32, psapi, urlmon, dnsapi, iphlpapi.
# Names are stored WITHOUT the trailing A/W (classify_api strips it before lookup),
# except the handful that genuinely end in 'a'/'w' (inet_ntoa, dnsquery_a/_w), which
# are matched raw-first so their real last letter is never mistaken for a suffix.
_EXACT_NAMES: Dict[str, Purpose] = {
    # -- loader ------------------------------------------------------------
    "loadlibrary": Purpose.LOADER, "loadlibraryex": Purpose.LOADER,
    "getprocaddress": Purpose.LOADER, "getmodulehandle": Purpose.LOADER,
    "getmodulehandleex": Purpose.LOADER, "freelibrary": Purpose.LOADER,
    "freelibraryandexitthread": Purpose.LOADER, "getmodulefilename": Purpose.LOADER,
    "disablethreadlibrarycalls": Purpose.LOADER,
    "ldrloaddll": Purpose.LOADER, "ldrgetprocedureaddress": Purpose.LOADER,
    "ldrunloaddll": Purpose.LOADER, "ldrgetdllhandle": Purpose.LOADER,
    # -- memory ------------------------------------------------------------
    "virtualalloc": Purpose.MEMORY, "virtualallocex": Purpose.MEMORY,
    "virtualprotect": Purpose.MEMORY, "virtualprotectex": Purpose.MEMORY,
    "virtualfree": Purpose.MEMORY, "virtualfreeex": Purpose.MEMORY,
    "virtualquery": Purpose.MEMORY, "virtualqueryex": Purpose.MEMORY,
    "heapalloc": Purpose.MEMORY, "heapfree": Purpose.MEMORY,
    "heapcreate": Purpose.MEMORY, "heaprealloc": Purpose.MEMORY,
    "getprocessheap": Purpose.MEMORY,
    "writeprocessmemory": Purpose.MEMORY, "readprocessmemory": Purpose.MEMORY,
    "mapviewoffile": Purpose.MEMORY, "mapviewoffileex": Purpose.MEMORY,
    "unmapviewoffile": Purpose.MEMORY,
    "localalloc": Purpose.MEMORY, "localfree": Purpose.MEMORY,
    "globalalloc": Purpose.MEMORY, "globalfree": Purpose.MEMORY,
    "ntallocatevirtualmemory": Purpose.MEMORY, "ntprotectvirtualmemory": Purpose.MEMORY,
    "ntwritevirtualmemory": Purpose.MEMORY, "ntreadvirtualmemory": Purpose.MEMORY,
    "ntfreevirtualmemory": Purpose.MEMORY, "ntmapviewofsection": Purpose.MEMORY,
    "ntunmapviewofsection": Purpose.MEMORY,
    "rtlmovememory": Purpose.MEMORY, "rtlcopymemory": Purpose.MEMORY,
    "rtlzeromemory": Purpose.MEMORY,
    # -- process -----------------------------------------------------------
    "createprocess": Purpose.PROCESS, "createprocessasuser": Purpose.PROCESS,
    "createprocessinternal": Purpose.PROCESS, "createremotethread": Purpose.PROCESS,
    "createremotethreadex": Purpose.PROCESS, "ntcreatethreadex": Purpose.PROCESS,
    "rtlcreateuserthread": Purpose.PROCESS, "openprocess": Purpose.PROCESS,
    "ntopenprocess": Purpose.PROCESS, "terminateprocess": Purpose.PROCESS,
    "ntterminateprocess": Purpose.PROCESS, "ntcreateprocess": Purpose.PROCESS,
    "ntcreateprocessex": Purpose.PROCESS, "queueuserapc": Purpose.PROCESS,
    "ntqueueapcthread": Purpose.PROCESS, "shellexecute": Purpose.PROCESS,
    "shellexecuteex": Purpose.PROCESS, "winexec": Purpose.PROCESS,
    "exitprocess": Purpose.PROCESS, "getcurrentprocess": Purpose.PROCESS,
    "getcurrentprocessid": Purpose.PROCESS, "createtoolhelp32snapshot": Purpose.PROCESS,
    "process32first": Purpose.PROCESS, "process32next": Purpose.PROCESS,
    "ntqueryinformationprocess": Purpose.PROCESS, "ntsetinformationprocess": Purpose.PROCESS,
    "enumprocesses": Purpose.PROCESS, "enumprocessmodules": Purpose.PROCESS,
    "getmodulefilenameex": Purpose.PROCESS, "getmodulebasename": Purpose.PROCESS,
    "minidumpwritedump": Purpose.PROCESS,
    # -- thread ------------------------------------------------------------
    "createthread": Purpose.THREAD, "resumethread": Purpose.THREAD,
    "suspendthread": Purpose.THREAD, "setthreadcontext": Purpose.THREAD,
    "getthreadcontext": Purpose.THREAD, "ntresumethread": Purpose.THREAD,
    "ntsuspendthread": Purpose.THREAD, "ntsetcontextthread": Purpose.THREAD,
    "ntgetcontextthread": Purpose.THREAD, "openthread": Purpose.THREAD,
    "ntopenthread": Purpose.THREAD, "terminatethread": Purpose.THREAD,
    "getcurrentthread": Purpose.THREAD, "getcurrentthreadid": Purpose.THREAD,
    "switchtothread": Purpose.THREAD, "thread32first": Purpose.THREAD,
    "thread32next": Purpose.THREAD, "wow64setthreadcontext": Purpose.THREAD,
    "wow64getthreadcontext": Purpose.THREAD, "setthreadpriority": Purpose.THREAD,
    # -- file --------------------------------------------------------------
    "createfile": Purpose.FILE, "readfile": Purpose.FILE, "writefile": Purpose.FILE,
    "readfileex": Purpose.FILE, "writefileex": Purpose.FILE,
    "deletefile": Purpose.FILE, "movefile": Purpose.FILE, "movefileex": Purpose.FILE,
    "copyfile": Purpose.FILE, "copyfileex": Purpose.FILE,
    "findfirstfile": Purpose.FILE, "findnextfile": Purpose.FILE, "findclose": Purpose.FILE,
    "setfilepointer": Purpose.FILE, "setfilepointerex": Purpose.FILE,
    "getfilesize": Purpose.FILE, "getfilesizeex": Purpose.FILE,
    "getfileattributes": Purpose.FILE, "setfileattributes": Purpose.FILE,
    "getfileattributesex": Purpose.FILE, "createdirectory": Purpose.FILE,
    "removedirectory": Purpose.FILE, "gettemppath": Purpose.FILE,
    "gettempfilename": Purpose.FILE, "flushfilebuffers": Purpose.FILE,
    "getfiletype": Purpose.FILE, "setendoffile": Purpose.FILE,
    "lockfile": Purpose.FILE, "unlockfile": Purpose.FILE, "openfile": Purpose.FILE,
    "ntcreatefile": Purpose.FILE, "ntopenfile": Purpose.FILE,
    "ntreadfile": Purpose.FILE, "ntwritefile": Purpose.FILE,
    "ntdeletefile": Purpose.FILE, "ntqueryinformationfile": Purpose.FILE,
    "ntsetinformationfile": Purpose.FILE,
    # -- registry ----------------------------------------------------------
    "regopenkey": Purpose.REGISTRY, "regopenkeyex": Purpose.REGISTRY,
    "regcreatekey": Purpose.REGISTRY, "regcreatekeyex": Purpose.REGISTRY,
    "regsetvalue": Purpose.REGISTRY, "regsetvalueex": Purpose.REGISTRY,
    "regqueryvalue": Purpose.REGISTRY, "regqueryvalueex": Purpose.REGISTRY,
    "reggetvalue": Purpose.REGISTRY, "regdeletekey": Purpose.REGISTRY,
    "regdeletekeyex": Purpose.REGISTRY, "regdeletevalue": Purpose.REGISTRY,
    "regclosekey": Purpose.REGISTRY, "regenumkey": Purpose.REGISTRY,
    "regenumkeyex": Purpose.REGISTRY, "regenumvalue": Purpose.REGISTRY,
    "regflushkey": Purpose.REGISTRY, "regconnectregistry": Purpose.REGISTRY,
    "regnotifychangekeyvalue": Purpose.REGISTRY, "regopencurrentuser": Purpose.REGISTRY,
    "regqueryinfokey": Purpose.REGISTRY,
    "ntopenkey": Purpose.REGISTRY, "ntcreatekey": Purpose.REGISTRY,
    "ntsetvaluekey": Purpose.REGISTRY, "ntqueryvaluekey": Purpose.REGISTRY,
    "ntdeletekey": Purpose.REGISTRY, "ntenumeratekey": Purpose.REGISTRY,
    "ntenumeratevaluekey": Purpose.REGISTRY,
    # -- network -----------------------------------------------------------
    "socket": Purpose.NETWORK, "connect": Purpose.NETWORK, "send": Purpose.NETWORK,
    "sendto": Purpose.NETWORK, "recv": Purpose.NETWORK, "recvfrom": Purpose.NETWORK,
    "bind": Purpose.NETWORK, "listen": Purpose.NETWORK, "accept": Purpose.NETWORK,
    "closesocket": Purpose.NETWORK, "shutdown": Purpose.NETWORK,
    "gethostbyname": Purpose.NETWORK, "gethostbyaddr": Purpose.NETWORK,
    "gethostname": Purpose.NETWORK, "getaddrinfo": Purpose.NETWORK,
    "freeaddrinfo": Purpose.NETWORK, "getnameinfo": Purpose.NETWORK,
    "inet_addr": Purpose.NETWORK, "inet_ntoa": Purpose.NETWORK,
    "inet_pton": Purpose.NETWORK, "inet_ntop": Purpose.NETWORK,
    "htons": Purpose.NETWORK, "htonl": Purpose.NETWORK,
    "ntohs": Purpose.NETWORK, "ntohl": Purpose.NETWORK, "select": Purpose.NETWORK,
    "ioctlsocket": Purpose.NETWORK, "setsockopt": Purpose.NETWORK,
    "getsockopt": Purpose.NETWORK, "getpeername": Purpose.NETWORK,
    "getsockname": Purpose.NETWORK,
    "wsastartup": Purpose.NETWORK, "wsacleanup": Purpose.NETWORK,
    "wsasocket": Purpose.NETWORK, "wsaconnect": Purpose.NETWORK,
    "wsasend": Purpose.NETWORK, "wsarecv": Purpose.NETWORK,
    "wsagetlasterror": Purpose.NETWORK, "wsaasyncselect": Purpose.NETWORK,
    "wsaioctl": Purpose.NETWORK,
    "internetopen": Purpose.NETWORK, "internetopenurl": Purpose.NETWORK,
    "internetconnect": Purpose.NETWORK, "internetreadfile": Purpose.NETWORK,
    "internetreadfileex": Purpose.NETWORK, "internetwritefile": Purpose.NETWORK,
    "internetclosehandle": Purpose.NETWORK, "internetsetoption": Purpose.NETWORK,
    "httpopenrequest": Purpose.NETWORK, "httpsendrequest": Purpose.NETWORK,
    "httpqueryinfo": Purpose.NETWORK, "httpaddrequestheaders": Purpose.NETWORK,
    "winhttpopen": Purpose.NETWORK, "winhttpconnect": Purpose.NETWORK,
    "winhttpopenrequest": Purpose.NETWORK, "winhttpsendrequest": Purpose.NETWORK,
    "winhttpreceiveresponse": Purpose.NETWORK, "winhttpreaddata": Purpose.NETWORK,
    "winhttpqueryheaders": Purpose.NETWORK, "winhttpclosehandle": Purpose.NETWORK,
    "winhttpsetoption": Purpose.NETWORK,
    "urldownloadtofile": Purpose.NETWORK, "urldownloadtocachefile": Purpose.NETWORK,
    "dnsquery": Purpose.NETWORK, "dnsquery_a": Purpose.NETWORK,
    "dnsquery_w": Purpose.NETWORK, "dnsquery_utf8": Purpose.NETWORK,
    "getadaptersinfo": Purpose.NETWORK, "getadaptersaddresses": Purpose.NETWORK,
    "icmpsendecho": Purpose.NETWORK, "icmpsendecho2": Purpose.NETWORK,
    # -- crypto ------------------------------------------------------------
    "cryptacquirecontext": Purpose.CRYPTO, "cryptreleasecontext": Purpose.CRYPTO,
    "cryptgenkey": Purpose.CRYPTO, "cryptderivekey": Purpose.CRYPTO,
    "cryptimportkey": Purpose.CRYPTO, "cryptexportkey": Purpose.CRYPTO,
    "cryptencrypt": Purpose.CRYPTO, "cryptdecrypt": Purpose.CRYPTO,
    "cryptcreatehash": Purpose.CRYPTO, "crypthashdata": Purpose.CRYPTO,
    "cryptgethashparam": Purpose.CRYPTO, "cryptsetkeyparam": Purpose.CRYPTO,
    "cryptgetkeyparam": Purpose.CRYPTO, "cryptgenrandom": Purpose.CRYPTO,
    "cryptdestroykey": Purpose.CRYPTO, "cryptdestroyhash": Purpose.CRYPTO,
    "bcryptopenalgorithmprovider": Purpose.CRYPTO,
    "bcryptclosealgorithmprovider": Purpose.CRYPTO, "bcryptgenrandom": Purpose.CRYPTO,
    "bcryptencrypt": Purpose.CRYPTO, "bcryptdecrypt": Purpose.CRYPTO,
    "bcrypthashdata": Purpose.CRYPTO, "bcryptcreatehash": Purpose.CRYPTO,
    "bcryptfinishhash": Purpose.CRYPTO, "bcryptgeneratesymmetrickey": Purpose.CRYPTO,
    "bcryptgeneratekeypair": Purpose.CRYPTO, "bcryptimportkey": Purpose.CRYPTO,
    "bcryptexportkey": Purpose.CRYPTO, "bcryptdestroykey": Purpose.CRYPTO,
    "bcryptderivekey": Purpose.CRYPTO, "bcryptsetproperty": Purpose.CRYPTO,
    "bcryptgetproperty": Purpose.CRYPTO,
    "ncryptopenstorageprovider": Purpose.CRYPTO, "ncryptencrypt": Purpose.CRYPTO,
    "ncryptdecrypt": Purpose.CRYPTO, "ncryptimportkey": Purpose.CRYPTO,
    "ncryptexportkey": Purpose.CRYPTO, "ncryptopenkey": Purpose.CRYPTO,
    "ncryptcreatepersistedkey": Purpose.CRYPTO,
    "certopenstore": Purpose.CRYPTO, "certopensystemstore": Purpose.CRYPTO,
    "certclosestore": Purpose.CRYPTO, "certfindcertificateinstore": Purpose.CRYPTO,
    "cryptstringtobinary": Purpose.CRYPTO, "cryptbinarytostring": Purpose.CRYPTO,
    "cryptprotectdata": Purpose.CRYPTO, "cryptunprotectdata": Purpose.CRYPTO,
    "cryptprotectmemory": Purpose.CRYPTO, "cryptunprotectmemory": Purpose.CRYPTO,
    # -- gui ---------------------------------------------------------------
    "createwindow": Purpose.GUI, "createwindowex": Purpose.GUI,
    "showwindow": Purpose.GUI, "messagebox": Purpose.GUI, "messageboxex": Purpose.GUI,
    "getforegroundwindow": Purpose.GUI, "setforegroundwindow": Purpose.GUI,
    "setwindowshookex": Purpose.GUI, "unhookwindowshookex": Purpose.GUI,
    "callnexthookex": Purpose.GUI, "getwindowtext": Purpose.GUI,
    "setwindowtext": Purpose.GUI, "findwindow": Purpose.GUI, "findwindowex": Purpose.GUI,
    "getasynckeystate": Purpose.GUI, "getkeystate": Purpose.GUI,
    "getkeyboardstate": Purpose.GUI, "registerclass": Purpose.GUI,
    "registerclassex": Purpose.GUI, "defwindowproc": Purpose.GUI,
    "dispatchmessage": Purpose.GUI, "getmessage": Purpose.GUI,
    "peekmessage": Purpose.GUI, "postmessage": Purpose.GUI, "sendmessage": Purpose.GUI,
    "translatemessage": Purpose.GUI, "updatewindow": Purpose.GUI,
    "destroywindow": Purpose.GUI, "getdc": Purpose.GUI, "releasedc": Purpose.GUI,
    "setwindowpos": Purpose.GUI, "getwindowrect": Purpose.GUI,
    "enumwindows": Purpose.GUI, "getwindowthreadprocessid": Purpose.GUI,
    "keybd_event": Purpose.GUI, "mouse_event": Purpose.GUI, "sendinput": Purpose.GUI,
    "registerhotkey": Purpose.GUI, "setclipboarddata": Purpose.GUI,
    "getclipboarddata": Purpose.GUI, "openclipboard": Purpose.GUI,
    "getdesktopwindow": Purpose.GUI,
    "bitblt": Purpose.GUI, "createcompatibledc": Purpose.GUI,
    "createcompatiblebitmap": Purpose.GUI, "getdibits": Purpose.GUI,
    "createdc": Purpose.GUI,
    # -- sysinfo -----------------------------------------------------------
    "getsysteminfo": Purpose.SYSINFO, "getnativesysteminfo": Purpose.SYSINFO,
    "getversion": Purpose.SYSINFO, "getversionex": Purpose.SYSINFO,
    "isdebuggerpresent": Purpose.SYSINFO, "checkremotedebuggerpresent": Purpose.SYSINFO,
    "gettickcount": Purpose.SYSINFO, "gettickcount64": Purpose.SYSINFO,
    "getcomputername": Purpose.SYSINFO, "getcomputernameex": Purpose.SYSINFO,
    "getusername": Purpose.SYSINFO, "getsystemdirectory": Purpose.SYSINFO,
    "getwindowsdirectory": Purpose.SYSINFO, "queryperformancecounter": Purpose.SYSINFO,
    "queryperformancefrequency": Purpose.SYSINFO, "getsystemtime": Purpose.SYSINFO,
    "getlocaltime": Purpose.SYSINFO, "getsystemtimeasfiletime": Purpose.SYSINFO,
    "getenvironmentvariable": Purpose.SYSINFO, "setenvironmentvariable": Purpose.SYSINFO,
    "getcurrentdirectory": Purpose.SYSINFO, "setcurrentdirectory": Purpose.SYSINFO,
    "getlogicaldrives": Purpose.SYSINFO, "getdrivetype": Purpose.SYSINFO,
    "getsystemmetrics": Purpose.SYSINFO, "globalmemorystatusex": Purpose.SYSINFO,
    "ntquerysysteminformation": Purpose.SYSINFO, "outputdebugstring": Purpose.SYSINFO,
    "getlasterror": Purpose.SYSINFO, "setlasterror": Purpose.SYSINFO,
    "getcommandline": Purpose.SYSINFO, "getstartupinfo": Purpose.SYSINFO,
    "getcurrenthwprofile": Purpose.SYSINFO,
    # -- ipc / synchronisation --------------------------------------------
    "createnamedpipe": Purpose.IPC, "connectnamedpipe": Purpose.IPC,
    "disconnectnamedpipe": Purpose.IPC, "waitnamedpipe": Purpose.IPC,
    "callnamedpipe": Purpose.IPC, "peeknamedpipe": Purpose.IPC,
    "setnamedpipehandlestate": Purpose.IPC, "createpipe": Purpose.IPC,
    "createfilemapping": Purpose.IPC, "createfilemappingnuma": Purpose.IPC,
    "openfilemapping": Purpose.IPC, "ntcreatesection": Purpose.IPC,
    "ntopensection": Purpose.IPC, "ntcreatenamedpipefile": Purpose.IPC,
    "createevent": Purpose.IPC, "createeventex": Purpose.IPC, "openevent": Purpose.IPC,
    "setevent": Purpose.IPC, "resetevent": Purpose.IPC, "pulseevent": Purpose.IPC,
    "createmutex": Purpose.IPC, "createmutexex": Purpose.IPC, "openmutex": Purpose.IPC,
    "releasemutex": Purpose.IPC, "createsemaphore": Purpose.IPC,
    "createsemaphoreex": Purpose.IPC, "opensemaphore": Purpose.IPC,
    "releasesemaphore": Purpose.IPC, "createmailslot": Purpose.IPC,
    "waitforsingleobject": Purpose.IPC, "waitforsingleobjectex": Purpose.IPC,
    "waitformultipleobjects": Purpose.IPC,
}

# Module-name (lowercased, ".dll" stripped) -> Purpose. A HINT of last resort:
# consulted only when the exact func_name isn't in ``_EXACT_NAMES``, so a novel
# ``advapi32!RegXyz`` still reads as REGISTRY and ``ws2_32!SomeNewCall`` as NETWORK.
# Only DLLs dominated by ONE family are listed -- kernel32/ntdll/kernelbase span too
# many to have a single sensible fallback, so an unrecognised name there stays UNKNOWN.
_MODULE_FALLBACK: Dict[str, Purpose] = {
    "advapi32": Purpose.REGISTRY,       # Reg* dominate (Crypt* caught by _EXACT_NAMES)
    "ws2_32": Purpose.NETWORK, "wsock32": Purpose.NETWORK,
    "wininet": Purpose.NETWORK, "winhttp": Purpose.NETWORK,
    "urlmon": Purpose.NETWORK, "dnsapi": Purpose.NETWORK, "iphlpapi": Purpose.NETWORK,
    "user32": Purpose.GUI, "gdi32": Purpose.GUI,
    "bcrypt": Purpose.CRYPTO, "ncrypt": Purpose.CRYPTO, "crypt32": Purpose.CRYPTO,
    "psapi": Purpose.PROCESS,
}


def _norm_module(module_name: str) -> str:
    """Lowercase and drop a trailing ``.dll`` for ``_MODULE_FALLBACK`` lookup."""
    m = (module_name or "").strip().lower()
    if m.endswith(".dll"):
        m = m[:-4]
    return m


def classify_api(module_name: str, func_name: Optional[str]) -> Purpose:
    """Classify one import into a :class:`Purpose` family.

    Match order (first hit wins):

    1. exact ``func_name`` (case-insensitive) in ``_EXACT_NAMES`` -- the raw name,
       so symbols that genuinely end in 'a'/'w' (``inet_ntoa``, ``DnsQuery_A``) hit
       here before any suffix is touched;
    2. the same with a single trailing ``A``/``W`` charset suffix stripped
       (``LoadLibraryW`` -> ``loadlibrary``), keeping the original name intact;
    3. the module hint in ``_MODULE_FALLBACK`` (``advapi32`` -> REGISTRY), used only
       now that the name itself is unrecognised -- and also the only signal when
       ``func_name`` is ``None`` (an in-module slot that resolved to no export RVA).

    Returns :attr:`Purpose.UNKNOWN` when nothing matches. Pure dict lookups."""
    if func_name:
        key = func_name.lower()
        hit = _EXACT_NAMES.get(key)
        if hit is not None:
            return hit
        if len(key) > 1 and key[-1] in ("a", "w"):
            hit = _EXACT_NAMES.get(key[:-1])
            if hit is not None:
                return hit
    return _MODULE_FALLBACK.get(_norm_module(module_name), Purpose.UNKNOWN)


# ===========================================================================
# IAT resolution
# ===========================================================================
@dataclass
class ResolvedImport:
    """One resolved (or diagnostic) IAT slot.

    ``func_name`` is ``None`` when the slot value lands inside a module but on no
    exact export RVA -- unresolved-but-in-module, kept as diagnostic signal rather
    than dropped. ``purpose`` is the :class:`Purpose` family the API belongs to
    (from :func:`classify_api` -- LOADER / NETWORK / REGISTRY / ...), so a triage
    report can read a binary's behaviour at a glance; it defaults to
    :attr:`Purpose.UNKNOWN` (keeping positional/legacy construction valid)."""
    slot_addr: int                 # absolute address of the IAT slot
    slot_rva: int                  # offset of the slot from iat_addr
    module_name: str               # e.g. "kernel32.dll"
    func_name: Optional[str]       # "LoadLibraryA" / "#123" / None (in-module, no RVA)
    ordinal: Optional[int]         # export ordinal, if the RVA matched an export
    value: int                     # the raw absolute pointer stored in the slot
    purpose: Purpose = Purpose.UNKNOWN   # API family (classify_api); default = UNKNOWN


def _find_module(modules: List[Module], value: int) -> Optional[Module]:
    for base, size, name in modules:
        if base <= value < base + size:
            return (base, size, name)
    return None


def resolve_imports(read_mem: ReadMem, modules: List[Module], iat_addr: int,
                    count: Optional[int] = None, max_slots: int = 4096,
                    ptr_size: int = _PTR) -> List[ResolvedImport]:
    """Resolve a dumped IAT at ``iat_addr`` into ``DLL!func`` entries.

    ``modules`` is ``[(base, size, name), ...]`` (from ``procdump.list_modules``
    live, or hand-built). Reads ``ptr_size``-byte (default 8, x64) slots. For each
    nonzero slot whose value falls inside some module's ``[base, base+size)``, the
    address is resolved against that module's exports (parsed once and cached per
    base): ``by_rva[value - base]`` -> the function name.

    **Termination.** If ``count`` is given, exactly that many slots are read (zero
    and out-of-module slots are skipped, producing no entry, but the walk continues
    to ``count``). Otherwise the walk auto-terminates at the first NULL slot, the
    first slot that points into no known module ("points nowhere"), or ``max_slots``
    -- the standard NULL/garbage-terminated-IAT heuristic. A slot that lands inside
    a module but on no exact export RVA does NOT stop the walk: it is recorded with
    ``func_name=None`` and walking continues."""
    cache: Dict[int, Exports] = {}

    def _exports_for(base: int) -> Exports:
        exp = cache.get(base)
        if exp is None:
            exp = cache[base] = parse_exports(read_mem, base)
        return exp

    out: List[ResolvedImport] = []
    limit = count if count is not None else max_slots
    for i in range(limit):
        slot_addr = iat_addr + i * ptr_size
        try:
            raw = read_mem(slot_addr, ptr_size)
        except Exception:        # noqa: BLE001 - an unreadable slot ends the walk
            break
        if len(raw) < ptr_size:
            break
        value = int.from_bytes(raw, "little")

        if value == 0:
            if count is None:
                break            # NULL terminator ends an auto-walk
            continue             # explicit count: skip padding, keep going

        mod = _find_module(modules, value)
        if mod is None:
            if count is None:
                break            # points nowhere -> ends an auto-walk
            continue             # explicit count: skip, keep going

        base, _size, name = mod
        exp = _exports_for(base)
        rva = value - base
        func_name = exp.by_rva.get(rva)                # None if in-module, no exact RVA
        out.append(ResolvedImport(
            slot_addr=slot_addr,
            slot_rva=i * ptr_size,
            module_name=name,
            func_name=func_name,
            ordinal=exp.ordinal_by_rva.get(rva),
            value=value,
            purpose=classify_api(name, func_name)))    # one dict lookup per slot
    return out


def purpose_summary(resolved: List[ResolvedImport]) -> Dict[Purpose, int]:
    """Count resolved imports per :class:`Purpose` bucket. UNKNOWN tallied
    separately (its own key, never merged into another family). Only buckets that
    actually occur appear in the returned dict."""
    counts = Counter(r.purpose for r in resolved)
    return dict(counts)


# ===========================================================================
# directory rebuild -- documented follow-on (NOT implemented; see report)
# ===========================================================================
def rebuild_import_directory(*args: object, **kwargs: object) -> None:  # noqa: D401
    """FOLLOW-ON, NOT YET IMPLEMENTED -- deliberately raises.

    :func:`resolve_imports` produces the immediately valuable deliverable: an
    ``address -> DLL!func`` resolution report an analyst or decompiler consumes.
    Writing that back into a dumped PE as a *loadable* import directory is a larger,
    separate job and is intentionally NOT half-built here (mirroring how
    ``dump.py`` shipped the raw dump first and left IAT rebuild as a documented
    follow-on). It requires, in brief:

    * grouping the resolved slots into per-DLL blocks (contiguous runs sharing a
      module) and choosing the FirstThunk (IAT) RVA for each,
    * synthesising IMAGE_IMPORT_DESCRIPTORs + Hint/Name tables (and an
      OriginalFirstThunk/ILT) into a fresh ``.idata``-style section appended to the
      dumped image,
    * patching data-directory index 1 (IMPORT) -- and index 12 (IAT) -- and the
      section table / SizeOfImage to point at the rebuilt structures.

    Until then, callers should consume the :class:`ResolvedImport` list directly.
    """
    raise NotImplementedError(
        "rebuild_import_directory is a documented follow-on; use resolve_imports() "
        "for the address->DLL!func report. See the docstring for the full scope.")
