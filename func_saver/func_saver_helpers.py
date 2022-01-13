import os, sys
import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_search
import ida_ua
import idaapi
import idautils
import idc
import tempfile
import json

from string_between import string_between
from superhex import hex

try:
    import __builtin__ as builtins
    integer_types = (int, long)
    string_types = (str, unicode)
    string_type = unicode
    byte_type = str
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str, bytes)
    byte_type = bytes
    string_type = str
    long_type = int
    long = int

if 'debug' not in globals():
    debug = 0

class ChunkFailure(Exception):
    pass

class AdvanceFailure(Exception):
    pass

# An iterable object is an object that implements __iter__, which is expected
# to return an iterator object.
def isIterable(o): return hasattr(o, '__iter__') and not hasattr(o, 'ljust')

def _isAnyJmp_mnem(mnem): return mnem.startswith("j")
def _isCall_mnem(mnem): return mnem.startswith("call")
def _isConditionalJmp_mnem(mnem): return mnem.startswith("j") and not mnem.startswith("jmp")
def _isInterrupt_mnem(mnem): return mnem.startswith("int")
def _isJmpOrCall(mnem): return mnem.startswith(("j", "call"))
def _isJmp_mnem(mnem): return mnem.startswith("jmp")
def _isNop_mnem(mnem): return mnem.startswith("nop") or mnem.startswith("pop")
def _isPushPop_mnem(mnem): return mnem.startswith("push") or mnem.startswith("pop")
def _isRet_mnem(mnem): return mnem.startswith("ret")
def _isUnconditionalJmpOrCall_mnem(mnem): return isUnconditionalJmp(mnem) or isCall(mnem)
def _isUnconditionalJmp_mnem(mnem): return mnem.startswith("jmp")
def isInt(o): return isinstance(o, integer_types)

def _isUnlikely_mnem(mnem): return mnem in ["in", "out", "loop", "cdq",
        "lodsq", "xlat", "clc", "adc", "stc", "iret", "stosd", "bswap",
        "wait", "sbb", "pause", "retf", "retnf", "test", "scasb", "cmc",
        "insb", "hlt", "setnle"]

def _isFlowEnd_mnem(mnem): return mnem in ('ret', 'retn', 'jmp', 'int', 'ud2', 'leave', 'iret')

def perform(fun, *args):
    return fun(*args)


def preprocessIsX(fun, arg):
    if not arg:
        raise Exception("Invalid argument: {}".format(type(arg)))
    if isinstance(arg, str):
        return perform(fun, arg)
    if isinstance(arg, integer_types):
        mnem = GetInsnMnem(arg)
        if not mnem:
            return False
        return perform(fun, mnem)
    raise Exception("Unknown type: {}".format(type(arg)))


def isUnlikely(arg): return preprocessIsX(_isUnlikely_mnem, arg)
def isFlowEnd(arg): return preprocessIsX(_isFlowEnd_mnem, arg)
def isAnyJmp(arg): return preprocessIsX(_isAnyJmp_mnem, arg)
def isJmpOrCall(arg): return preprocessIsX(_isJmpOrCall, arg)
def isCall(arg): return preprocessIsX(_isCall_mnem, arg)

def isJmpOrObfuJmp(ea, patch=0):
    if ea is None:
        return ValueError("ea was None")
    if isJmp(ea):
        return True
    if idc.get_wide_dword(ea) == 0x24648d48:
        searchstr = "55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3"
        found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        if found == ea:
            return True

def isCallOrObfuCall(ea, patch=0):
    if isCall(ea):
        return True
    if idc.get_wide_dword(ea) == 0x24648d48:
        searchstr = '48 8d 64 24 f8 48 89 2c 24 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 55 48 8d 2d ?? ?? ?? ?? 48 87 2c 24 c3'
        found = ida_search.find_binary(ea, ea + div3(len(searchstr)), searchstr, 16, idc.SEARCH_CASE | idc.SEARCH_DOWN | idc.SEARCH_NOSHOW)
        if found == ea:
            if patch:
                l = [0xe8] + list(struct.unpack('4B', struct.pack('I', idc.get_wide_dword(ea + 0x18) + 0x17))) + \
                    [0xe9] + list(struct.unpack('4B', struct.pack('I', idc.get_wide_dword(ea + 0x0c) + 0x06)))
                PatchBytes(ea, l)
                SetFuncEnd(ea, ea + 10)
                if IsFuncHead(ea):
                    LabelAddressPlus(ea, 'StraightCall')
            return True

def isCallOrObfuCallPatch(ea): return isCallOrObfuCall(ea, 1)
def isConditionalJmp(arg): return preprocessIsX(_isConditionalJmp_mnem, arg)
def isJmp(arg): return preprocessIsX(_isJmp_mnem, arg)
def isPushPop(arg): return preprocessIsX(_isPushPop_mnem, arg)

def isNop(ea):
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, get_ea_by_any(ea))
    if inslen == 0:
        return None
    if insn.itype == idaapi.NN_nop:
        return True
    return idc.get_wide_word(ea) == 0x9066

def isUnconditionalJmp(arg): return preprocessIsX(_isUnconditionalJmp_mnem, arg)

def isOpaqueJmp(ea):
    if isUnconditionalJmp(ea):
        opType0 = idc.get_operand_type(ea, 0)
        if opType0 in (idc.o_near, idc.o_mem):
            return False
        if opType0 == idc.o_reg:
            disasm = idc.GetDisasm(ea)
            if get_ea_by_any(string_between('; ', '', disasm)) != idc.BADADDR:
                return False
        return True
    return False


def isUnconditionalJmpOrCall(arg): return preprocessIsX(_isUnconditionalJmpOrCall_mnem, arg)
def isInterrupt(arg): return preprocessIsX(_isInterrupt_mnem, arg)
def isRet(arg):      return preprocessIsX(_isRet_mnem, arg)
def IsChunkHead(ea): return GetFuncStart(get_ea_by_any(ea)) != ea and GetChunkStart(get_ea_by_any(ea)) == ea
def IsFuncHead(ea):  return GetFuncStart(get_ea_by_any(ea)) == ea # idaapi.is_func(idc.get_full_flags(ea))
IsChunkStart = IsChunkHead
IsFuncStart = IsFuncHead
def IsFunc_(ea):     return idaapi.get_func(get_ea_by_any(ea)) is not None
def IsCode_(ea):     return (idc.get_full_flags(get_ea_by_any(ea)) & idc.MS_CLS) == idc.FF_CODE
def IsData(ea):      return (idc.get_full_flags(get_ea_by_any(ea)) & idc.MS_CLS) == idc.FF_DATA
def IsTail(ea):      return (idc.get_full_flags(get_ea_by_any(ea)) & idc.MS_CLS) == idc.FF_TAIL
def IsUnknown(ea):   return (idc.get_full_flags(get_ea_by_any(ea)) & idc.MS_CLS) == idc.FF_UNK
def IsHead(ea):      return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_DATA) != 0
def IsFlow(ea):      return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_FLOW) != 0
def IsExtra(ea):     return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_LINE) != 0
def IsRef(ea):       return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_REF) != 0
def HasName(ea):     return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_NAME) != 0
def HasLabel(ea):    return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_LABL) != 0
def HasUserName(ea): return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_ANYNAME) == idc.FF_NAME
def HasAnyName(ea):  return (idc.get_full_flags(get_ea_by_any(ea)) & idc.FF_ANYNAME) != 0


def isString(o):
    return isinstance(o, string_types)



def div3(n):
    return (n + 1) // 3

def PatchBytes(ea, patch=None, comment=None, code=False):
    """
    @param ea [optional]:           address to patch (or ommit for screen_ea)
    @param patch list|string|bytes: [0x66, 0x90] or "66 90" or b"\x66\x90" (py3)
    @param comment [optional]:      comment to place on first patched line

    @returns int containing nbytes patched

    Can be invoked as PatchBytes(ea, "66 90"), PatchBytes("66 90", ea),
    or just PatchBytes("66 90").
    """

    if 'record_patched_bytes' in globals():
        globals()['record_patched_bytes'].append([ea, patch, comment])

    if isinstance(ea, (list, bytearray) + string_types):
        ea, patch = patch, ea
    if ea is None:
        ea = idc.get_screen_ea()

    was_code = code or idc.is_code(idc.get_full_flags(ea))

    if isinstance(patch, str):
        # unicode for py3, bytes for py2 - but "default" form for
        # passing "06 01 05" type arguments, which is all that counts.
        # -- pass a `bytearray` if you want faster service :)
        def int_as_byte(i, byte_len=0):
            # empty byte container without using
            # py3 `bytes` type
            b = bytearray()
            while byte_len > 0:
                b.append(i & 255)
                i >>= 8
                byte_len -= 1
            for b8bit in b:
                yield b8bit;

        if '?' not in patch:
            #  patch = hex_pattern_as_bytearray(patch.split(' '))
            patch = bytearray().fromhex(patch)
        else:
            patch = [-1 if '?' in x else long_type(x, 16) for x in patch.split(' ')]

    length = len(patch)

    # deal with fixups
    fx = idaapi.get_next_fixup_ea(ea - 1)
    while fx < ea + length:
        idaapi.del_fixup(fx)
        fx = idaapi.get_next_fixup_ea(fx)

    cstart, cend = idc.get_fchunk_attr(ea, idc.FUNCATTR_START), \
                   idc.get_fchunk_attr(ea, idc.FUNCATTR_END)

    if cstart == idc.BADADDR: cstart = ea
    if cend == idc.BADADDR: cend = 0

    # disable automatic tracing and such to prevent function trucation
    #  with InfAttr(idc.INF_AF, lambda v: v & 0xdfe60008):
    #  old_auto = ida_auto.enable_auto(False)

    #  for _ea in range(ea, ea+length):
    #  MyMakeUnknown(_ea, 1)

    #  code_heads = genAsList( NotHeads(ea, ea + length + 16, IsCode) )
    # [0x140a79dfd, 0x140a79e05, 0x140a79e09, 0x140a79e0a]
    if isinstance(patch, bytearray):
        # fast patch
        idaapi.patch_bytes(ea, byte_type(patch))
    else:
        # slower patch to allow for unset values
        [idaapi.patch_byte(ea + i, patch[i]) for i in range(length) if patch[i] != -1]

    #  if was_code:
    #  if debug: print("was_code")
    #  pos = ea + length
    #  while code_heads:
    #  if code_heads[0] < pos:
    #  code_heads = code_heads[1:]
    #  else:
    #  break
    #  if code_heads:
    #  next_code_head = code_heads[0]
    #  else:
    #  next_code_head = idc.next_head(pos)
    #  if next_code_head > pos:
    #  idaapi.patch_bytes(pos, byte_type(bytearray([0x90] * (next_code_head - pos))))
    #
    if debug: print("ida_auto.plan_and_wait({:#x}, {:#x})".format(ea, ea + length))
    if was_code: EaseCode(ea, ea + length, noFlow=1, forceStart=1, noExcept=1)
    ida_auto.plan_and_wait(ea, ea + length)
    # EaseCode(ea, next_code_head)

    #  ida_auto.enable_auto(old_auto)

    # this may seem superfluous, but it stops wierd things from happening
    #  if was_code:
    #  remain = len(patch)
    #  cpos = cstart
    #  length = idc.create_insn(cstart)
    #  while length > 0:
    #  remain -= length
    #  cpos += length
    #  if remain <= 0:
    #  break
    #  length = idc.create_insn(cpos)

    #  if was_code:
    #  idc.auto_wait()
    #  EaseCode(ea, end=ea+length, create=1)

    # ida_auto.plan_and_wait(cstart, cend or (cstart + length))
    # ensures the resultant patch stays in the chunk and as code
    #  if was_code:
    #  ida_auto.plan_and_wait(cstart, cend or (cstart + length))
    #  idc.auto_wait()

    return


def MyGetMnem(ea):
    if idc.get_wide_word(ea) == 0x9066:
        return "nop"
    mnem = idc.print_insn_mnem(ea)
    return mnem

GetMnen = GetInsnMnem = MyGetMnem

def GetChunkStart(ea=None):
    ea = eax(ea)
    return idc.get_fchunk_attr(ea, idc.FUNCATTR_START)


def GetChunkEnd(ea=None):
    ea = eax(ea)
    return idc.get_fchunk_attr(ea, idc.FUNCATTR_END)


def GetChunkNumber(ea=None, funcea=None):
    """
    Get number of chunk in function

    @param ea: linear address

    @return: chunk number
            -1   - ea is not a chunk
            0    - ea is in head chunk
            1..n - tail chunk number
    """
    ea = eax(ea)
    if funcea is None:
        owner = ida_funcs.get_func(ea)
        # if debug: print(f"[idapy] owner = ida_funcs.get_func({ea:#x}):\n{pfh(owner)}")
    elif isinstance(funcea, ida_funcs.func_t):
        pass
    else:
        owner = ida_funcs.get_func(eax(funcea))
        # if debug: print(f"[idapy] owner = ida_funcs.get_func({funcea:#x}):\n" + pfh(owner))
    r = ida_funcs.get_func_chunknum(owner, ea)
    # if debug: print(f"[idapy] ida_funcs.get_func_chunknum(owner, {ea:#x}): {r}")
    return r


def SetFuncEnd(funcea, end):
    # func = clone_items(ida_funcs.get_func(funcea))
    # if func:
    # idc.auto_wait()
    if funcea == idc.BADADDR:
        return False
    if IsTail(end):
        new_end = idc.get_item_head(end)
        print("[warn] SetFuncEnd: end {:#x} is not an itemhead, did you mean {:#x}?".format(end, new_end))
        globals()['warn'] += 1
        # end = new_end
        return False
    ida_auto.plan_range(funcea, end)
    if not ida_funcs.set_func_end(funcea, end):
        print("ida_funcs.set_func_end(0x{:x}, 0x{:x})".format(funcea, end))
    idc.auto_wait()
    func_start = GetFuncStart(funcea)
    func_end = GetFuncEnd(funcea)
    cstart, cend = GetChunkStart(funcea), GetChunkEnd(funcea)
    # dprint("[SetFuncENd] funcea, func_start, end, func_end")
    print(
        "[SetFuncEnd] funcea:{:x}, end:{:x}, func_start:{:x}, func_end:{:x}".format(funcea, end, func_start, func_end))

    #  if cstart != func_start:
    #  print("[warn] Not a head chunk, consider using SetChunkEnd | {:x}\u2013{:x}" \
    #  .format(
    #  #  idc.get_func_name(func_start),
    #  #  func_start, func_end,
    #  #  idc.get_func_name(cstart),
    #  cstart, cend
    #  ))
    #  return SetChunkEnd(funcea, end)

    if debug: print(
        "func {}: {:x}\u2013{:x}  chunk {}: {:x}\u2013{:x}".format(idc.get_name(func_start), func_start, func_end,
                                                                   idc.get_name(cstart), cstart, cend))
    if end == cend:
        return True

    if not ida_funcs.is_same_func(funcea, idc.prev_head(end)):
        # if debug: print("[warn] set_func_end: end {:#x} or {:#x} should be part of function {:#x} or {:#x}".format(end, idc.prev_head(end), func_start, funcea))
        print("[warn] chunk owner '{}' does not match func owner '{}' | {:x}\u2013{:x}" \
            .format(
            idc.get_func_name(funcea),
            idc.get_func_name(idc.prev_head(end)),
            cstart, cend,
        ))
        globals()['warn'] += 1

        #  ptr = idc.prev_head(idc.get_item_head(end))
        #  ptr = idc.get_item_head(end-1)
        ptr = end
        happy = 0
        heads = []
        for r in range(16):
            #  print("[debug] ptr is {:#x}".format(ptr))
            if IsFuncHead(ptr):
                heads.append(ptr)
                #  print("[debug] adding head {:#x}".format(ptr))
            #  else:
            #  print("[debug] not head {:#x}".format(ptr))
            ptr = idc.prev_head(ptr)
            if ida_funcs.is_same_func(funcea, ptr):
                happy = 1
                break
        if happy:
            if heads:
                print("[info] deleting func_heads: {}".format(hex(heads)))
            for head in heads:
                idc.del_func(head)
            ce = GetChunkEnd(ptr)
            idc.del_items(ce, ida_bytes.DELIT_NOTRUNC, end - ce)
            print("idc.append_func_tail(0x{:x}, 0x{:x}, 0x{:x})".format(ptr, ce, end))
            if not idc.append_func_tail(ptr, ce, end):
                print("[warn] idc.append_func_tail({:#x}, {:#x}, {:#x}) failed".format(ptr, ce, end))
                globals()['warn'] += 1
            else:
                print("[info] idc.append_func_tail({:#x}, {:#x}, {:#x}) ok".format(ptr, ce, end))
    else:
        if idc.set_func_end(funcea, end):
            print("[info] set_func_end({:#x}, {:#x})".format(funcea, end))
        else:
            print("[warn] set_func_end({:#x}, {:#x}) failed".format(funcea, end))
            globals()['warn'] += 1
    result = GetChunkEnd(funcea)
    if result != end:
        print("[warn] SetFuncEnd: GetChunkEnd({:#x}) == {:#x}".format(funcea, result))
        globals()['warn'] += 1
        # raise Exception("Terrible")
    return result == end

def IsHeadChunk(ea):
    return GetChunkNumber(ea) == 0

def IsChunk(ea=None, owner=None):
    """
    Is address in a tail chunk

    @param ea: linear address

    @return: 1-yes, 0-no
    """

    #  if not isInt(ea) and not isString(ea):
    #  print("[IsChunk] typeof ea: {}".format(type(ea)))
    if isinstance(ea, ida_funcs.func_t):
        return ea.flags & ida_funcs.FUNC_TAIL
    ea = eax(ea)
    if GetChunkNumber(ea) == 0:
        return False
    if GetChunkOwners(ea, includeOwner=1):
        return True
    return False



def SetFuncOrChunkEnd(ea, value):
    if IsHeadChunk(ea):
        return SetFuncEnd(ea, value)
    elif IsChunk(ea, value):
        return SetChunkEnd(ea, value)
    else:
        print("[SetFuncOrChunkEnd] {:x} Not a chunk/func head)".format(ea))
        return False

def IsChunked(ea):
    #  return idc.get_fchunk_attr(address, FUNCATTR_START) < BADADDR
    return len(list(idautils.Chunks(ea))) > 1

def GetChunk(ea=None):
    """
    GetChunk

    @param ea: linear address
    """
    ea = eax(ea)
    func = ida_funcs.get_fchunk(ea)
    # if debug: print("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
    return func

def IsChunked(ea):
    #  return idc.get_fchunk_attr(address, FUNCATTR_START) < BADADDR
    return len(list(idautils.Chunks(ea))) > 1


def SetChunkEnd(ea, value):
    # idc.set_fchunk_attr(ea, FUNCATTR_END, value)
    if not IsChunked(ea):
        raise TypeError("0x%x is not a chunk" % ea)
    if GetChunkEnd(ea) == value:
        return True

    # get_fchunk(ea) # will return chunk ptr, to any function
    tail = GetChunk(ea)
    if tail.flags & idc.FUNC_TAIL == 0:
        raise ChunkFailure("SetChunkEnd: {:x} was a funchead".format(ea))

    # get_func_chunknum(GetFunc(ea), ea) -> int
    return ida_funcs.set_func_end(tail.start_ea, value)
    # return SetFuncEnd(ea, value)


def GetFuncEnd(ea=None):
    ea = eax(ea)
    """
    Determine a new function boundaries

    @param ea: address inside the new function

    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    # return idc.find_func_end(ea)
    func = ida_funcs.get_func(ea)
    if not func:
        return idc.BADADDR
    return func.end_ea


def MyMakeUnknown(ea, nbytes, flags=ida_bytes.DELIT_NOTRUNC):
    r"""
    @param ea:      any address within the first item to delete (C++: ea_t)
    @param nbytes:  number of bytes in the range to be undefined (C++: asize_t)
    @param flags:   combination of:     DELIT_EXPAND    DELIT_DELNAMES
                                        ida_bytes.DELIT_NOTRUNC   DELIT_NOUNAME
                                        DELIT_NOCMT     DELIT_KEEPFUNC
    @param may_destroy: optional callback invoked before deleting a head item.
                        if callback returns false then deletion and operation
                        fail. (C++: may_destroy_cb_t *)
    @return: true on sucessful operation, otherwise false

    Convert item (instruction/data) to unexplored bytes. The whole item
    (including the head and tail bytes) will be destroyed.
    """
    # check if caller has invoked with (start_ea, end_ea)
    if nbytes > ea:
        nbytes = nbytes - ea
    result = idaapi.del_items(ea, flags, nbytes)
    if not result:
        return result

    # check for fixups that must be removed
    # https://reverseengineering.stackexchange.com/questions/27339/

    fx = idaapi.get_next_fixup_ea(ea - 1)
    while fx < ea + nbytes:
        idaapi.del_fixup(fx)
        fx = idaapi.get_next_fixup_ea(fx)

    return result



def GetFuncStart(ea=None):
    ea = eax(ea)
    """
    @param ea: address inside the new function
    """
    func = ida_funcs.get_func(ea)
    if not func:
        return idc.BADADDR
    return func.start_ea


def json_load(_fn):
    with open(_fn, 'r') as f:
        return json_load_byteified(f)


def _byteify(data, ignore_dicts=False):
    if isinstance(data, str):
        return data

    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()  # changed to .items() for python 2.7/3
        }

    # python 3 compatible duck-typing
    # if this is a unicode string, return its string representation
    if str(type(data)) == "<type 'unicode'>":
        return data.encode('utf-8')

    # if it's anything else, return it in its original form
    return data


# https://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-of-unicode-from-json/33571117#33571117
def json_load_byteified(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )


def json_save_safe(dst, json_object):
    dirname, basename = os.path.split(dst)
    try:
        with tempfile.NamedTemporaryFile(prefix=basename, mode='w', dir=dirname, delete=False) as filename:
            filename.file.write(json.dumps(json_object))
            filename.file.close()
            print("replace({}, {})".format(filename.name, dst))
            print("file_exists", os.path.exists(filename.name))
            os.replace(filename.name, dst)
            if os.path.exists(filename.name):
                os.unlink(filename.name)
    except IOError:
        print("file not writable or some such")
    except Exception as e:
        print("**EXCEPTION** {}".format(e))

def get_ea_by_any(val, d=object):
    """
    returns the address of a val (and if address is
    a number, looks up the val first).

    an easy way to accept either address or val as input.
    """

    if isinstance(val, list):
        return [get_ea_by_any(x) for x in val]
    if isinstance(val, str):
        r = idaapi.str2ea(val)
        if r and r != idc.BADADDR:
            return r

        match = re.match(r'(sub|off|loc|byte|word|dword|qword|nullsub|locret)_([0-9A-F]+)$', val)
        if match:
            return long_type(match.group(2), 16)

        return 0

    if isinstance(val, idaapi.vdui_t):
        val = val.cfunc

    if val is None:
        return idc.get_screen_ea() if d == object else d

    if isinstance(val, (int, long)):
        return val

    try:
        for attr_name in ['start_ea', 'ea', 'entry_ea', 'start', 'min_ea']:
            if hasattr(val, attr_name):
                return getattr(val, attr_name)
    except AttributeError:
        pass

    raise ValueError("Don't know how to convert {} '{}' to address".format(type(val), val))


def eax(*args):
    return get_ea_by_any(*args)


def MakeSigned(number, size = 32):
    number = number & (1<<size) - 1
    return number if number < 1<<size - 1 else - (1<<size) - (~number + 1)


def MyGetInstructionLength(*args):
    if len(args) == 1:
        if not isInt(args[0]):
            print("return_unless: isInt(args[0])")
            return

        ea = args[0]
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        if inslen:
            return inslen
    else:
        return ida_ua.decode_insn(*args)

GetInsnLen = InsnLen = MyGetInstructionLength

def IsValidEA(ea=None):
    """
    IsValidEA

    @param ea: linear address
    """
    ea = eax(ea)
    return ida_ida.cvar.inf.min_ea <= ea < ida_ida.cvar.inf.max_ea


def ValidateEA(ea=None):
    if not IsValidEA(ea):
        raise AdvanceFailure("Invalid Address 0x{:x}".format(ea))


def RemoveChunk(*args):
    """
    @brief RemoveChunk

    Removes a single chunk from a function.

    @param [optional] functionAddress: any address inside the function and chunk
    @param chunkAddress: any address inside the chunk
    """
    from inspect import getframeinfo, currentframe, getdoc

    if len(args) == 2:
        funcStart = args[0]
        chunkAddr = args[1]
    elif len(args) == 1:
        chunkAddr = args[0]
        funcStart = GetFuncStart(chunkAddr)
        if funcStart == idc.BADADDR:
            print("Couldn't find function for chunk at {:x}".format(chunkAddr))
            return
    else:
        # https://stackoverflow.com/questions/8822701/how-to-print-docstring-of-python-function-from-inside-the-function-itself
        print(getdoc(globals()[getframeinfo(currentframe()).function]))

    return idc.remove_fchunk(funcStart, chunkAddr)

def UnpatchUntilChunk(ea, _range=1024):
    if ea is idc.BADADDR:
        return
    nextChunkStart = 0
    ourFunc = idc.BADADDR
    if IsFunc_(ea):
        ourFunc = GetFuncStart(ea)
        #  print("[info] ourFunc is {:x}".format(ourFunc))
    #  print("[info] checking range ... {:#x}".format(ea))
    for r in range(_range):
        fs = GetFuncStart(ea + r)
        if fs != idc.BADADDR and fs != ourFunc:
            nextChunkStart = ea + r
            #  print("[info] stopping at {:x} because GetFuncStart is {:x}".format(nextChunkStart, GetFuncStart(ea+r)))
            #  print("[info] checking for patches {:#x} - {:#x}".format(ea, nextChunkStart))
            break

    if nextChunkStart > ea:
        return UnPatch(ea, nextChunkStart)





def GetTarget(ea, flow=0, calls=1, conditionals=1, operand=0, failnone=False):
    ea = eax(ea)
    if isJmpOrObfuJmp(ea) and not isJmp(ea):
        return MakeSigned(idc.get_wide_dword(ea + 4)) + ea + 7
    mnem = idc.print_insn_mnem(ea)
    disasm = idc.GetDisasm(ea)
    if not mnem:
        print("{:x} couldn't get mnem from '{}'".format(ea, disasm))
        return None if failnone else False # idc.BADADDR

    if mnem == "jmp" or (calls and mnem == "call") or (conditionals and mnem[0] == "j"):
        opType = idc.get_operand_type(ea, operand)
        if opType in (idc.o_near, idc.o_mem):
            return idc.get_operand_value(ea, operand)
        if opType == idc.o_reg:
            # 'call    rax ; j_smth_metric_tamper'
            s = string_between('; ', '', disasm).strip()
            if s:
                result = eax(s)
                if ida_ida.cvar.inf.min_ea <= result < ida_ida.cvar.inf.max_ea:
                    return result

        #  print("[warn] can't follow opType {} from {:x}".format(opType, ea))

    if flow:
        if idc.next_head(ea) == ea + idc.get_item_size(ea) and idc.is_flow(idc.get_full_flags(idc.next_head(ea))):
            return idc.next_head(ea)
        else:
            if debug: print("{:x} no flow".format(ea))

    return None if failnone else idc.BADADDR

def is_sequence(arg):
    """ https://stackoverflow.com/questions/1835018/how-to-check-if-an-object-is-a-list-or-tuple-but-not-string/1835259#1835259
    """
    return (not hasattr(arg, "strip") and
            hasattr(arg, "__getitem__") or
            hasattr(arg, "__iter__"))


patchedBytes = []
def RecordPatchedByte(ea, fpos, org_val, patch_val):
    # print("%x, %x, %x, %x" % (ea, fpos, org_val, patch_val))
    patchedBytes.append([ea - 0x140000000, patch_val])
    #  idaapi.patch_byte(ea, org_value)

def RecordPatches1(ranges):
    global patchedBytes
    del patchedBytes[:]
    #  patchedBytes=[]
    #  for i in ranges: idaapi.visit_patched_bytes(i[0] + 0x140000000, i[1] + i[0] + 0x140000000, RecordPatchedByte)
    if ranges:
        for start, end in ranges:
            idaapi.visit_patched_bytes(start, end, RecordPatchedByte)
    else:
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, RecordPatchedByte)

    n = 0
    c = dict()
    lastEa = 0
    startEa = 0
    for i in patchedBytes:
        a, b = i
        if a == lastEa + 1:
            c[startEa].append(b)
        else:
            startEa = a
            c[a] = [b]
        lastEa = a

    return c



def forceCode(start, end=None, trim=False, delay=None, origin=None):
    log = []
    ea = eax(start)
    ValidateEA(ea)
    log.append("start: {:x}".format(ea))
    if ea == idc.BADADDR or not ea:
        return 0, 0, 0, 0
    insn_len = GetInsnLen(ea) or 15
    end = end or ea + insn_len
    #  print("end, start: {}, {}".format(end, start))
    if end < idaapi.cvar.inf.minEA and end < start:
        end = start + end
    log.append("end: {:x}".format(end))

    #    if ea == forceCode.last:
    #        if _.all(forceCode.last, lambda x, *a: x == ea):
    #            raise RuntimeError("Repeated calls for forceCode for same address")
    #    forceCode.last.append(ea)

    if debug:
        # dprint("[forceCode] start, end, trim, delay")
        print("[forceCode] start:{:x}, end:{:x}, trim:{}, delay:{}".format(start, end, trim, delay))

    last_jmp_or_ret = 0
    last_addr = 0
    trimmed_end = 0
    happy = 0
    # dprint("[forceCode] start")
    #  print("[forceCode] start:{:x}".format(start))

    func_end = GetFuncEnd(start)
    # dprint("[forceCode] func_end")
    #  print("[forceCode] func_end:{:x}".format(func_end))

    func_start = GetFuncStart(start)
    chunk_end = GetChunkEnd(start)
    chunk_start = GetChunkStart(start)
    if debug:
        print("func_start, func_end", hex(func_start), hex(func_end))
        print("chunk_start, chunk_end", hex(func_start), hex(func_end))

    #  idc.del_items(start, idc.DELIT_EXPAND, end - start)
    if GetInsnLen(ea) == 2 and GetInsnMnem(ea) == 'push':
        log.append("{:x} insnlen == 2".format(ea))
        old_type = idc.get_type(ea + 1) if not idc.get_type(ea) else None
        old_name = idc.get_name(ea + 1) if HasUserName(ea + 1) and not HasUserName(ea) else None
        idc.del_items(ea, idc.DELIT_DELNAMES, 2)
        size = idc.create_insn(ea)
        if size == 2:
            if old_name:
                LabelAddressPlus(ea, old_name)
            if old_type:
                idc.SetType(ea, old_type)
            ea += 2
    while ea < end:
        log.append("{:x} {}".format(ea, idc.GetDisasm(ea)))
        happy = 0
        last_addr = ea
        if idc.is_tail(idc.get_full_flags(ea)):
            head = idc.get_item_head(ea)
            if head == ea:
                print("[warn] item_head == ea {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
            #  if not idc.del_items(ea, 0, 1):
            if not idc.MakeUnknown(ea, 1, 0):
                print("[warn] couldn't del item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))
            else:
                if debug: print(
                    "[debug] deleted item at {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(ea, start, start, end))

        if idc.is_code(idc.get_full_flags(ea)):
            # seems to be that deleting the code and remaking it is the only way to ensure everything works ok
            # .. and it seems that deleting and remaking triggered stupid stupid things like the generation of nullsubs out of `retn` statements
            # .. but i think we will cheat and match the instruction against GetFuncEnd, since undefining the end of a chunk is what shrinks it.
            insn_len = idc.get_item_size(ea)
            if debug: print(
                "[info] {:x} code exists for {} bytes | {}".format(ea, insn_len, idc.generate_disasm_line(ea, 0)))
            ea += insn_len
            happy = 1
        if not happy:
            insn_len = idc.create_insn(ea)
            if debug: print(
                "[info] idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))
            if not insn_len:
                # this
                MyMakeUnknown(ea + 1, GetInsnLen(ea) or 1, idc.DELIT_DELNAMES | ida_bytes.DELIT_NOTRUNC)
                # or this (same result)
                for r in range(ea + 1, GetInsnLen(ea) or 1):
                    if HasAnyName(r):
                        LabelAddressPlus(r, '')
                        if debug: print("[info] removing label at {:x}".format(r))
                insn_len = idc.create_insn(ea)
                if debug: print(
                    "[info] idc.create_insn len: {} | fn: {:x} chunk: {:x}\u2013{:x}".format(insn_len, ea, start, end))

            # restore function end if we just removed the last insn in a chunk
            if insn_len and insn_len + ea == chunk_end:
                if debug: print(
                    "[info] restoring chunk_end to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(chunk_end, chunk_start,
                                                                                                 start, end))
                SetFuncEnd(chunk_start, chunk_end)
            if not insn_len:
                # record existing code heads
                existing_code = [x for x in range(ea, ea + 15) if IsCode_(x)]
                idc.del_items(ea, 0, 15)
                insn_len = idc.create_insn(ea)
                if not insn_len and existing_code:
                    [idc.create_insn(x) for x in existing_code]
            if not insn_len:
                trimmed_end = last_jmp_or_ret + idc.get_item_size(
                    last_jmp_or_ret) if last_jmp_or_ret else last_addr or ea
                if not trim:
                    print("[warn] couldn't create instruction at {:x}".format(ea))
                    print("\n".join(log))
                    UnpatchUntilChunk(ea)
                    if idc.create_insn(ea):
                        print("[info] unpatching {:x} seemed to help".format(ea))
                else:
                    print(
                        "[warn] couldn't create instruction at {:x}, shortening chunk to {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(
                            ea, trimmed_end, ea, start, end))
                    if idc.get_func_name(start):
                        if not idc.set_func_end(start, trimmed_end):
                            print(
                                "[warn] couldn't set func end at {:x} or {:x} or {:x} or {:x} | fn: {:x} chunk: {:x}\u2013{:x}".format(
                                    end, last_jmp_or_ret, last_addr, ea, start, start, end))
                    idc.del_items(end, 0, end - trimmed_end)
            else:
                happy = 1
                ea += insn_len

        if not happy:
            return ea - start, start, end, trimmed_end

        mnem = idc.print_insn_mnem(last_addr).split(' ', 2)[0]
        if mnem in ('jmp', 'ret', 'retn', 'int'):
            last_jmp_or_ret = last_addr

    if func_start == start:
        idc.add_func(func_start)
    return ea - start, start, end, trimmed_end


def GetChunkOwner(ea=None):
    """
    GetChunkOwner

    @param ea: linear address
    """
    ea = eax(ea)
    r = idc.get_fchunk_attr(ea, idc.FUNCATTR_OWNER)
    # if debug: print("[idapy] idc.get_fchunk_attr(0x{:x}, FUNCATTR_OWNER): {:x}".format(ea, r))
    return r


def GetChunkOwners(ea=None, includeOwner=False):
    """
    GetChunkOwners

    @param ea: linear address
    """
    ea = eax(ea)

    #  https://www.hex-rays.com/products/ida/support/sdkdoc/classfunc__parent__iterator__t.html
    #  func_parent_iterator_t fpi(fnt);
    #  for ( bool ok=fpi.first(); ok; ok=fpi.next() )
    #      ea_t parent = fpi.parent();

    # func = GetChunk(ea)
    func = ida_funcs.get_fchunk(ea)
    # if debug: print("[idapy] ida_funcs.get_fchunk(0x{:x}):\n{}".format(ea, pfh(func)))
    if not func:
        return []

    #  func = ida_funcs.func_t(ea)
    it = ida_funcs.func_parent_iterator_t(func)
    ok = it.first()
    if not ok:
        return [func.start_ea]

    owners = []
    while ok:
        parent = it.parent()
        owners.append(parent)
        ok = it.next()

    if includeOwner:
        r = idc.get_fchunk_attr(ea, idc.FUNCATTR_OWNER)
        if r != idc.BADADDR:
            if r not in owners:
                #  print("[GetChunkOwners] FUNCATTR_OWNER: {:x} not listed in owners".format(r))
                # owners.append(r)
                pass

    for owner in owners[:]:
        if owner & 0xff00000000000000:
            print("[GetChunkOwners] removing BADADDR: {:x}".format(owner))
            owners.remove(owner)
        if not idaapi.is_func(idc.get_full_flags(owner)):
            if idaapi.get_func(owner) is None:
                print("[GetChunkOwners] stated owner {:x} of chunk {:x} is not a function".format(owner, ea))
            else:
                print("[GetChunkOwners] stated owner {:x} of chunk {:x} is not the function head".format(owner, ea))

    return owners


def EaseCode(ea=None, end=None, forceStart=False, forceStartIfHead=False, noExcept=False, noFlow=False, unpatch=False, ignoreMnem=[], create=None, fixChunks=False, origin=None):
    """
    EaseCode

    @param ea: linear address
    """
    ea = eax(ea)
    if not (ida_ida.cvar.inf.min_ea <= ea < ida_ida.cvar.inf.max_ea):
        raise AdvanceFailure("Invalid Address 0x{:x}".format(ea))
    if debug: 
        print("[EaseCode] {:x}".format(ea))
        stk = []
        for i in range(len(inspect.stack()) - 1, 0, -1):
            stk.append(inspect.stack()[i][3])
        print((" -> ".join(stk)))
    #  d = ["{:x} {}".format(x, idc.generate_disasm_line(x, 0)) for x in range(ea, end or (ea+0x1000)) if not IsTail(x)]
    #  if debug:
        #  print("[EaseCode] pre-disasm\n{}".format("\n".join(d)))
    if not IsCode_(ea):
        if forceStartIfHead and IsHead(ea):
            r = forceCode(ea, GetInsnLen(ea), origin=origin)
            if debug: print("forceStartIfHead: {:x} {}".format(ea, diida(ea)))
        elif forceStart:
            r = forceCode(ea, GetInsnLen(ea), origin=origin)
            if debug: print("forceStart: {:x} {}".format(ea, diida(ea)))
        elif not idc.create_insn(ea):
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))
            else:
                raise AdvanceFailure("0x{:x} EaseCode must start at valid code head".format(ea))

    ida_auto.revert_ida_decisions(ea, GetInsnLen(ea))
    ida_auto.auto_recreate_insn(ea)
    start_ea = ea
    last_ea = ea
    at_end = False
    at_flow_end = False
    unhandled = code = tail = unknown = flow = False
    owners = GetChunkOwners(ea, includeOwner=1)
    _start = True
    _fixChunk = False
    while ea != idc.BADADDR and (end is None or ea < end):
        if _start:
            _start = False
        else:
            last_ea = ea
            ea = ea + insn_len
            if last_ea == start_ea and at_flow_end:
                if debug:
                    print("[EaseCode] ignoring at_flow_end during second loop")
                at_flow_end = False
            if at_end or at_flow_end:
                break

        if unpatch:
            UnPatch(ea, ea + 15)

        idc.GetDisasm(ea)
        insn_len = GetInsnLen(ea)
        if not insn_len:
            if noExcept:
                return AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
            raise AdvanceFailure("0x{:x} EaseCode couldn't advance past 0x{:x} ".format(start_ea, ea))
        _owners = GetChunkOwners(ea, includeOwner=1)
        if _owners:
            if _owners != owners:
                if debug: print("[EaseCode] _owners != owners; break")
                break
        else:
            owners = _owners

        unhandled = code = tail = unknown = flow = False
        next_head = idc.next_head(ea)
        mnem = ''

        if IsCode_(ea):
            # if debug: print("0x{:x} IsCode".format(ea))
            code = True
            mnem = idc.print_insn_mnem(ea)
            if mnem.startswith(('ret', 'jmp', 'int', 'ud2')):
                at_end = True
            if create: # or mnem.startswith(('ret', 'jmp', 'int', 'ud2', 'leave')):
                # raise RuntimeError("don't")
                ida_auto.revert_ida_decisions(ea, GetInsnLen(ea))
                ida_auto.auto_recreate_insn(ea)
                idc.auto_wait()

        else:
            if IsTail(ea):
                # if debug: print("0x{:x} IsTail".format(ea))
                tail = True
            if IsUnknown(ea) or IsData(ea):
                # if debug: print("0x{:x} IsUnknown".format(ea))
                unknown = True
        if not (code or tail or unknown):
            if debug: print("0x{:x} unhandled flags".format(ea))
            if debug: debug_fflags(ea)
        if IsFlow(ea):
            if debug: print("0x{:x} IsFlow ({}) +{}".format(ea, mnem, insn_len))
            flow = True
        elif ea != start_ea:
            prev_ea = last_ea
            prev_mnem = idc.print_insn_mnem(prev_ea)
            if prev_mnem not in ('ret', 'retn', 'jmp', 'int', 'ud2', 'leave', 'iret', 'retf'):
                if prev_mnem != 'call' or ida_funcs.func_does_return(GetTarget(prev_ea)):
                    print("{:x} Flow ended {:x} with '{}' (fixing)".format(ea, prev_ea, prev_mnem))
                    if fixChunks:
                        _fixChunk = True
                    ida_auto.auto_recreate_insn(prev_ea)
                    ida_auto.auto_wait()
                    #  ea1 = prev_ea
                    #  ea2 = idc.next_head(ea)

                    # ida_auto.auto_apply_tail(ea1, ea2)
                    #  print("ida_auto results: {}".format([
                        #  ida_auto.revert_ida_decisions(ea1, ea2), #
                        #  [ida_auto.auto_recreate_insn(x) for x in Heads(ea1, ea2)],
                        #  [ida_auto.plan_ea(x) for x in Heads(ea1, ea2)], #
                        #  ida_auto.auto_wait_range(ea1, ea2),
                        #  ida_auto.plan_and_wait(ea1, ea2),
                        #  ida_auto.plan_and_wait(ea1, ea2, True),
                        #  ida_auto.plan_range(ea1, ea2),  #
                        #  ida_auto.auto_wait()
                    #  ]))

                    #  idaapi.del_items(prev_ea, ida_bytes.DELIT_NOTRUC, ea - prev_ea)
                    #  if not idc.create_insn(prev_ea):
                        #  print("[EaseCode] couldn't recreate insn at {:x}".format(prev_ea))
                    #  ida_auto.auto_recreate_insn(idc.prev_head(prev_ea))
                    #  idc.auto_wait()
                    GetDisasm(prev_ea)
                    flow = True

        # TODO: amalgamate these two, they're basically the same
        if code and isFlowEnd(ea):
                if debug: print("0x{:x} code and isFlowEnd; at_end".format(ea))
                ida_auto.auto_recreate_insn(ea)
                at_flow_end = True
        elif not flow: #  or isFlowEnd(ea):
            if not noFlow and mnem not in ignoreMnem:
                if debug: print("0x{:x} no flow; at_end".format(ea))
                at_flow_end = True

        if tail:
            if debug: print("0x{:x} tail; break".format(ea))
            break

        if unknown:
            # dprint("[debug] next_head, ea, insn_len")
            if debug: print("[debug] next_head:{:x}, ea:{:x}, insn_len:{:x}".format(next_head, ea, insn_len))
            
            if next_head == ea + insn_len:
                pass
                #  print("0x{:x} next_head == ea + insn_len".format(ea))
            elif next_head > ea + insn_len:
                pass
                #  print("0x{:x} next_head > ea + insn_len".format(ea))
            else:
                #  print("0x{:x} next_head < ea + insn_len; forcing space to instruction".format(ea))

                idaapi.del_items(ea, ida_bytes.DELIT_NOTRUNC, insn_len)

            if not idc.create_insn(ea):
                if debug: print("0x{:x} couldn't idc.make_insn(0x{:x}); break".format(ea, ea))
                break

    if unpatch:
        UnPatch(start_ea, ea)

    #  ida_auto.plan_and_wait(start_ea, ea)

    #  ida_auto.plan_range(start_ea, ea)
    #  idc.auto_wait()
    if _fixChunk and GetChunkEnd(start_ea) < ea:
        SetFuncOrChunkEnd(start_ea, ea)
    return ea

def UnPatch(start, end = None):
    if end is None:
        if is_sequence(start):
            try:
                end = start[1]
                if end is not None:
                    return UnPatch(start[0], end)
            except TypeError:
                return 0
            except ValueError:
                return 0
        end = InsnLen(start) + start

    if end < start and end < 16364:
        end = start + end

    count = 0
    if isinstance(start, (int, long)) and isinstance(end, (int, long)):
        while start < end:
            if idc.get_cmt(start, 0):
                idc.set_cmt(start, '', 0)
            if ida_bytes.revert_byte(start):
                count += 1
            start += 1

        return count

    print("Unexpected type: %s" + type(start))

def LabelAddressPlus(ea, name, force=False, append_once=False, unnamed=False, nousername=False, named=False, throw=False):
    """
    Label an address with name (forced) or an alternative_01
    :param ea: address
    :param name: desired name
    :param force: force name (displace existing name)
    :param append_once: append `name` if not already ending with `name`
    :param named: [str, callable(addr, name)] name for things with existing usernames
    :return: success as bool
    """
    def ThrowOnFailure(result):
        if not result and throw:
            raise RuntimeError("Couldn't label address {:x} with \"{}\"".format(ea, name))
        return result

    def MakeUniqueLabel(name, ea=idc.BADADDR):
        fnLoc = idc.get_name_ea_simple(name)
        if fnLoc == idc.BADADDR or fnLoc == ea:
            return name
        fmt = "%s_%%i" % name
        for i in range(100000):
            tmpName = fmt % i
            fnLoc = idc.get_name_ea_simple(tmpName)
            if fnLoc == idc.BADADDR or fnLoc == ea:
                return tmpName
        return ""

    if nousername:
        unnamed = nousername
    if ea < idc.BADADDR:
        if HasUserName(ea):
            if named:
                if callable(named):
                    _name = idc.get_name(ea)
                    _name = named(ea, _name, name)
                else:
                    name = named
            elif unnamed:
                return
        fnName = idc.get_name(ea)
        if append_once:
            if not fnName.endswith(name):
                name += fnName
            else:
                return ThrowOnFailure(False)
        fnLoc = idc.get_name_ea_simple(name)
        if fnLoc == idc.BADADDR:
            return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))
        elif fnLoc == ea:
            return ThrowOnFailure(True)
        else:
            if force:
                idc.set_name(fnLoc, "", idc.SN_AUTO | idc.SN_NOWARN)
                idc.Wait()
                return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))
            else:
                name = MakeUniqueLabel(name, ea)
                return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))

    else:
        print("0x0%0x: Couldn't label %s, BADADDR" % (ea, name))
        return False


def SkipJumps(ea, name=None, until=None, untilInclusive=0, notPatched=False, skipShort=False, skipNops=False,
              iteratee=None, apply=False, *args, **kwargs):
    if isIterable(ea):
        return [SkipJumps(x, name=name, until=until, untilInclusive=untilInclusive, notPatched=notPatched,
                          skipShort=skipShort, skipNops=skipNops, iteratee=iteratee, apply=apply, *args, **kwargs)
                for x in ea]
    if not isInt(ea):
        print("ea was not int: {}".format(type(ea)))
    # apply = 0
    target = ea
    count = 0
    jumps = [ea]
    targets = [ea]
    if callable(iteratee):
        iteratee(ea, *args, **kwargs)
    while target != idc.BADADDR:
        if until:
            endix = max(0, len(targets) - 2 + untilInclusive)
            # dprint("[debug] endix")
            #  print("[debug] endix:{}".format(endix))

            if isInt(until):
                if target == until:
                    return targets[endix]
            elif callable(until):
                r = until(target)
                if r:
                    if r < 0:
                        return r
                    return targets[endix]
        # print(("0x%x: target: 0x%x: %s" % (ea, target, dii(target))))
        insn = idautils.DecodeInstruction(target)
        if not insn:
            print("Couldn't find insn at {:x}".format(target))
            return target
        _tgt = GetTarget(target)
        if _tgt == False:
            print("Invalid _tgt: {:x}, {}".format(_tgt, hex(jumps)))
        if not IsValidEA(_tgt):
            if _tgt != idc.BADADDR:
                print("Invalid _tgt: {:x}".format(_tgt))
                #  UnPatch(target, InsnLen(target))
                ida_auto.auto_recreate_insn(target)
                idc.auto_wait()
            _tgt = GetTarget(target)
        if count == 0 and insn.itype == idaapi.NN_call and SkipJumps(_tgt) != _tgt:
            newTarget = SkipJumps(_tgt)
            return newTarget

        if insn.itype == idaapi.NN_jmp and (not skipShort or GetInsnLen(target) > 2):
            if insn.Op1.type in (idc.o_mem, idc.o_near):
                if notPatched:
                    if ida_bytes.get_original_byte(target) != idc.get_wide_byte(target):
                        break
                newTarget = insn.Op1.addr
                if newTarget and newTarget != idc.BADADDR:
                    count += 1
                    jumps.append(target)
                    if name:
                        LabelAddressPlus(newTarget, name, *args, **kwargs)
                    while skipNops and isNop(newTarget):
                        newTarget = newTarget + GetInsnLen(newTarget)
                        if not IsCode_(newTarget):
                            print("SkipJumps: Skipped NOPs right into a non-instruction: {:x} jumps".format(newTarget))
                            return -1
                    if iteratee:
                        rv = iteratee(newTarget, *args, **kwargs)
                        if rv and isInt(rv) and rv > 1:
                            newTarget = rv
                    targets.append(newTarget)
                    target = newTarget
                    continue
        break
    return target

def GetFuncName(ea, end = None):
    if isinstance(ea, list):
        return [GetFuncName(x) for x in ea]
    if end is None:
        if ea is None:
            ea = idc.get_screen_ea()
        if isInt(ea):
            r = idc.get_func_name(ea)
            # if debug: print("[idapy] idc.get_func_name(0x{:x}): {}".format(ea, r))
            return r
    if isInt(end):
        if end > ea:
            fnNames = set()
            heads = idautils.Heads(ea, end)
            if heads:
                for head in idautils.Heads(ea, end):
                    fnNames.add(GetFuncName(head))
                if '' in fnNames:
                    fnNames.remove('')
                return fnNames
    return ''

def GetAllNames(ea):
    """GetAllNames.

    Args:
        ea:
    """
    fnName = GetFuncName(ea)
    locName = idc.get_name(ea, ida_name.GN_VISIBLE)
    if not fnName:         return locName
    if not locName:        return fnName
    if fnName == locName:  return fnName
    return "%s  %s" % (fnName, locName)


def GetChunkAddressesZeroOffset(ea = 0):
    """GetChunkAddresses.

    Args:
        ea:
    """
    chunks = idautils.Chunks(ea)
    return [[x[0] - 0x140000000, x[1] - x[0]] for x in chunks]

