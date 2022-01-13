import os
import inspect
import json
import re
import struct
import tempfile

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

try:
    from func_saver_helpers import *
except:
    from .func_saver_helpers import *

class FuncSaver(object):
    """Docstring for FuncSaver """

    def __init__(self, funcs):
        """@todo: to be defined

        :funcs: @todo

        """
        # change to make IDA Plan & Wait added chunks (slow, but a good idea)
        self._plan = False
        self._base = ida_ida.cvar.inf.min_ea & ~0xffff
        #  self._chunks = dict()
        #  self._patches = dict()
        #  self._spds = dict()
        self._names = dict()
        self._rnames = dict()
        self._data = dict()
        self._failed = []
        self._old_attr = None
        #  self._item_comments = dict()
        #  self._func_comments = dict()
        if isString(funcs):
            self._funcs = []
            self.load(funcs)
            # self.apply()
        elif type(funcs) == type(self):
            #  self._chunks = funcs._chunks
            #  self._patches = funcs._patches
            #  self._spds = funcs._spds
            self._names = funcs._names
            self._data = funcs._data
            #  self._item_comments = funcs._item_comments
            #  self._func_comments = funcs._func_comments
        else:
            self._funcs = list(funcs)
            self.make()

    def make(self):
        for funcea in [GetFuncStart(eax(x)) for x in self._funcs]:
            if IsValidEA(funcea):
                self._extend(self._names, self.process_names(funcea))
        for name, ea in self._names.items():
            ea = self.rebase(ea)
            if IsValidEA(ea):
                func = dict()
                func['chunks']        = self.process_chunks(ea)
                func['patches']       = self.process_patches(ea)
                func['spds']          = self.process_spdiffs(ea, vimlike=1)
                func['item_comments'] = self.process_item_comments(ea)
                func['func_comments'] = self.process_func_comments(ea)
                self._data[name] = func

    def extend(self, funceas):
        names = dict()
        for funcea in [GetFuncStart(eax(x)) for x in funceas]:
            if IsValidEA(funcea):
                self._extend(names, self.process_names(funcea))
        for name, ea in names.items():
            ea = self.rebase(ea)
            if IsValidEA(ea):
                func = dict()
                func['chunks']        = self.process_chunks(ea)
                func['patches']       = self.process_patches(ea)
                func['spds']          = self.process_spdiffs(ea, vimlike=1)
                func['item_comments'] = self.process_item_comments(ea)
                func['func_comments'] = self.process_func_comments(ea)
                self._data[name] = func

    def append(self, funcea):
        self.extend([funcea])

    def dump(self):
        return {
            # '_funcs': self._funcs,
            '_names': self._names,
            '_data': self._data,
        }

    def lookup(self, name):
        try:
            return long_type(name)
        except ValueError:
            return self.rebase(self._names[name])

    def rlookup(self, ea):
        try:
            ea = long_type(ea)
        except ValueError:
            return ea
        if ea > self._base:
            ea -= self._base
        if ea in self._rnames:
            return self._rnames[ea]
        return "unk_{:X}".format(ea)

    def clear(self):
        for k in ['_names', '_rnames', '_data']:
            getattr(self, k).clear()

    def load(self, filename):
        ori_filename = filename
        if not os.path.isabs(filename):
            base = os.path.splitext(idc.get_idb_path())[0]
            filename = base + ".func_save." + filename
            if not os.path.exists(filename):
                filename = ori_filename

        if not os.path.exists(filename):
            print("File '{}' does not exist".format(filename))
            return

        self.clear()
        self._extend(self, json_load(filename))

    def apply(self):
        self._old_attr = self._old_attr or idc.get_inf_attr(idc.INF_AF)
        idc.set_inf_attr(idc.INF_AF, 0xdfe60008)
        for name in self._names:
            self._rnames[self._names[name]] = name

        for name in self._names:
            #  print("removing functions")
            if not self._data[name]['chunks']: 
                print('*** missing data for {}'.format(name))
                continue
            for x in self._data[name]['chunks']: 
                start, end = self.rebase(x)
                #  for chunk in self._data[name]['chunks']:
                #  for start, end in self.rebase(chunk):
                #  print("[removing] {:x}, {:x}".format(start, end))
                for ea in idautils.Heads(start, end):
                    if IsFunc_(ea):
                        idc.del_func(ea)

        idc.auto_wait()
        for name in self._names:
            if not self._data[name]['chunks']: 
                print('*** missing data for {}'.format(name))
                continue
            for x in self._data[name]['chunks']: 
                start, end = self.rebase(x)
                #  for chunk in self._data[name]['chunks']:
                #  for start, end in self.rebase(chunk):
                #  print("[removing] {:x}, {:x}".format(start, end))
                for ea in idautils.Heads(start, end):
                    if IsFunc_(ea):
                        idc.del_func(ea)

            #  print("applying patches")
            for ea, b in self._data[name]['patches'].items():
                #  print("[pre-patching] {} {:x} {}".format(ea, self.rebase(ea), b))
                ea = self.rebase(ea)
                patch = bytes(bytearray(b))
                #  print("[patching] {:x} {}".format(ea, patch))
                ida_bytes.patch_bytes(ea, patch)

            #  print("applying names")
            ea = self.rebase(self._names[name])
            idc.set_name(ea, name, idc.SN_NOWARN)

            #  print("applying functions and chunks")
            #  p = ProgressBar(len(self._data[name]['chunks']))
                #  p.update(index)
            q = []
            func_started = False
            for index, item in enumerate(self._data[name]['chunks']):
                start, end = self.rebase(item)
                EaseCode(start, end, forceStart=1, noExcept=1, noFlow=1)
                if self._plan:
                    ida_auto.plan_and_wait(start, end)
                if start == self.lookup(name):
                    if IsFunc_(start):
                        idc.remove_fchunk(start, start)
                    if not idc.add_func(start, end):
                        print("{} couldn't create function {:x}-{:x} ".format(self.rlookup(name), start, end))
                        break
                    if not IsFuncHead(start):
                        print("{} couldn't create function (no error) {:x}-{:x} ".format(self.rlookup(name), start, end))
                        break
                    if IsFuncHead(start):
                        #  print("{} created function {:x}-{:x} ".format(self.rlookup(name), start, end))
                        func_started = True
                else:
                    q.append( (start, end) )
            for start, end in q:
                for ea in idautils.Heads(start, end):
                    if GetChunkNumber(ea) > -1:
                        RemoveChunk(ea)
                        if GetChunkNumber(ea) > -1:
                            print("{} func tail already present {:x}-{:x}".format(self.rlookup(name), start, end))
                            break
                if not idc.append_func_tail(self.lookup(name), start, end):
                    print("{} couldn't append func tail {:x}-{:x}".format(self.rlookup(name), start, end))

            #  print("applying stack pointers")
            if isinstance(self._data[name]['spds'], dict):
                for key in self._data[name]['spds']:
                    self.fix_spd_auto(self._data[name]['spds'][key])
            else:
                if self._data[name]['spds']:
                    #  print("spds: {}".format(self._data[name]['spds']))
                    self.fix_spd_auto(self._data[name]['spds'])
                    #  spdlist = []
                    #  for item in self._data[name]['spds']:
                        #  spdlist.extend([[x, y] for x, y in item.items()])
                    #  self.fix_spd_auto(spdlist)

            #  print("applying function comments")
            for key in self._data[name]['func_comments']:
                idc.set_func_cmt(self.rebase(key), self._data[name]['func_comments'][key], 0)

            #  print("applying item comments")
            for key in self._data[name]['item_comments']:
                idc.set_cmt(self.rebase(key), self._data[name]['item_comments'][key], 0)

        idc.set_inf_attr(idc.INF_AF, self._old_attr)

    def fix_spd(self, l):
        l.sort()

        #  print("fix_spd: {}".format(l))
        for x in l:
            #  print("fix_spd_loop: {}".format(x))
            ea = self.rebase(x[0])
            #  fnStart = GetFuncStart(ea)
            #  if fnStart == idc.BADADDR:
                #  continue
            #  chunkStart = GetChunkStart(ea)
            #  if chunkStart == fnStart:
                #  continue
#  
            #  chunkEnd = GetChunkEnd(ea)
#  
            #  if not chunkStart == ea:
                #  continue

            correct_sp = 0 - x[1]  # -0x88
            actual_sp = idc.get_spd(ea)  # -0x8
            actual_delta = idc.get_sp_delta(ea)  # -0x8
            fail = 0
            if actual_sp is None:
                #  print("{:x} idc.get_spd == {}".format(ea, actual_sp))
                fail = 1
            if actual_delta is None:
                #  print("{:x} idc.get_spd_delta == {}".format(ea, actual_sp))
                fail = 1
            if fail:
                return False

            if actual_sp != correct_sp:
                #  print("{:x} correct/actual spd: {:x}/{:x}  current delta: {:x}".format(ea, correct_sp, actual_sp, actual_delta))
                adjust = correct_sp - actual_sp # -0x88 - -0x8 == -0x80
                #  print("{:x} adjusting delta by {:x} to {:x}".format(ea, adjust, actual_delta + adjust))
                idc.add_user_stkpnt(ea, actual_delta + adjust) # -0x8 + -0x80
                idc.auto_wait()
                return True
            #  if actual_sp != correct_sp:
                #  adjust = correct_sp - actual_sp  # -0x88 - -0x8 == -0x80
                #  print("[info] {:x} adjusted sp_delta {:x} => {:x}".format(ea, actual_sp, correct_sp))
                #  idc.add_user_stkpnt(ea, actual_delta + adjust)  # -0x8 + -0x80
                #  idc.auto_wait()
                #  return True

        return False

    def fix_spd_auto(self, l):
        for r in range(50):
            if not self.fix_spd(l):
                break
        return True

    def debase(self, ea):
        if isInt(ea):
            return ea - self._base
        return self.debase(ea[0]), self.debase(ea[1])

    def rebase(self, ea):
        if isInt(ea):
            if ea < self._base:
                return ea + self._base
            return ea
        if isString(ea):
            return self.rebase(long_type(ea))
        if len(ea) == 2:
            if ea[1] < ea[0]:
                return self.rebase(ea[0]), self.rebase(ea[0]) + ea[1]
            return self.rebase(ea[0]), self.rebase(ea[1])

    def save(self, filename):
        if not os.path.isabs(filename):
            base = os.path.splitext(idc.get_idb_path())[0]
            filename = base + ".func_save." + filename
        # 'E:\\ida\\gtasc-2372\\GTA5_dump_b2372.2.exe.i64'
        json_save_safe(filename, self.dump())

    def process_chunks(self, funcea):
        #  global ddd
        #  ddd.clear()

        if not IsValidEA(funcea):
            print("return_unless: IsValidEA(funcea)")
            return

        if not IsFunc_(funcea):
            return
        return GetChunkAddressesZeroOffset(funcea)


    def process_names(self, funcea):
        #  global ddd
        #  ddd.clear()
        names = {}
        jumps = []

        def add_names(ea, *args, **kwargs):
            names[idc.get_func_name(ea)] = self.debase(ea)
            jumps.append(ea)

        try:
            target = SkipJumps(funcea, iteratee=add_names)
        except AdvanceFailure as e:
            print("[add_names] SkipJumps::AdvanceError {}".format('\n'.join(e.args)))
            if 'unpatch_func2' in globals():
                jumps.reverse()
                for ea in jumps:
                    unpatch_func2(ea, unpatch=1)
            return names
        add_names(target, names=names)
        return names

    def process_patches(self, funcea):
        #  pairs = []
        #  for k, v in ddd.items():
        #  pairs.extend([x for x in v])
        if funcea is None:
            c = RecordPatches1([(0, idaapi.BADADDR)])
        else:
            c = RecordPatches1(idautils.Chunks(funcea))

        return c

    def process_spdiffs(self, funcea, **kwargs):
        spdlist = []
        if 0:
            try:
                rv = slowtrace2(funcea, vimlike=-1, spdlist=spdlist)
                if rv != 0:
                    self._failed.append(funcea)
                return [{self.debase(x): y} for x, y in spdlist]
            except Exception:
                self._failed.append(funcea)

        else:
            for start, end in idautils.Chunks(funcea):
                spdlist.append([self.debase(start), idc.get_sp_delta(start)])

        return spdlist

    def process_func_comments(self, funcea):
        cmt = idc.get_func_cmt(funcea, 0)
        if cmt:
            return {self.debase(funcea): cmt}
        return {}

    def process_item_comments(self, funcea):
        r = {}
        for c in idautils.Chunks(funcea):
            for h in idautils.Heads(c[0], c[1]):
                cmt = idc.get_cmt(funcea, 0)
                if cmt:
                    r[self.debase(funcea)] = cmt
        return r

    def _extend(self, obj, *args):
        if hasattr(obj, 'update'):
            for i in args:
                obj.update(i)
        else:
            for i in args:
                if callable(getattr(i, 'keys', None)):
                    for k in i:
                        setattr(obj, k, i[k])
                else:
                    for k, v in i:
                        setattr(obj, k, v)
        return obj

#  if 'fs' in globals():
    #  fs2 = fs
    #  fs = FuncSaver(fs)
