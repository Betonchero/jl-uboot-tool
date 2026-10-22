#!/usr/bin/env python3
"""Offline tests for the loader-free (mask ROM) memory dump.

The fake device implements the ROM's side of the protocol -- FD07 read, FB06
write, FB08 jump -- and scrambles every transfer on its own, the way `CrcDecode`
(ROM 0x111538) does.  That per-transfer rule is what a dump gets wrong when the
cipher is applied to the whole buffer instead.

    python3 -m unittest discover -s tests
"""

import contextlib
import io
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from jltech.cipher import jl_crc_cipher, cipher_bytes          # noqa: E402
from jltech.memio import (MEM_IO_CHUNK, MemReadError, read_chunks,   # noqa: E402
                          rom_cipher, write_chunks)

import jlrunner                                                # noqa: E402


class FakeRom:
    """The mask ROM: memory read/write/jump, scrambling every transfer."""

    def __init__(self, size=0x1000, scramble=True, fill=0x00):
        self.mem = bytearray([fill] * size)
        self.scramble = scramble
        self.jumps = []
        self.writes = []
        self.reads = 0
        self.fail_at = None
        self.max_transfer = 0

    # -- the wire, as JL_UBOOT sees it ------------------------------------

    def mem_read(self, addr, length):
        self.reads += 1
        self.max_transfer = max(self.max_transfer, length)
        if self.fail_at is not None and addr >= self.fail_at:
            raise RuntimeError('SCSI transfer failed')
        data = bytes(self.mem[addr:addr + length])
        return cipher_bytes(jl_crc_cipher, data) if self.scramble else data

    def mem_write(self, addr, data):
        self.writes.append((addr, len(data)))
        self.max_transfer = max(self.max_transfer, len(data))
        data = bytes(data)
        if self.scramble:
            data = cipher_bytes(jl_crc_cipher, data)
        self.mem[addr:addr + len(data)] = data

    def mem_jump(self, addr, arg=0):
        self.jumps.append((addr, arg))


def quiet(fn, *a, **kw):
    """Run fn with stdout/stderr swallowed: the tools print their dumps."""
    with contextlib.redirect_stdout(io.StringIO()), \
         contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **kw)


class ChunkingTest(unittest.TestCase):
    """jltech.memio: the per-transfer rule, on its own."""

    def test_cipher_is_per_transfer_not_per_buffer(self):
        rom = FakeRom(size=0x400)
        rom.mem[:] = bytes(range(256)) * 4
        plain = bytes(rom.mem)

        # 256-byte transfers: each one is a fresh CrcDecode, so it round-trips.
        self.assertEqual(read_chunks(rom.mem_read, 0, 0x300, MEM_IO_CHUNK,
                                     rom_cipher), plain[:0x300])

        # One 0x300-byte transfer would be scrambled as a single stream by the
        # fake, which is not what the chip does -- the point is that the helper
        # never issues one.  Assert on the transfer sizes, not on the bytes.
        rom.reads = 0
        rom.max_transfer = 0
        read_chunks(rom.mem_read, 0, 0x300, MEM_IO_CHUNK, rom_cipher)
        self.assertEqual(rom.reads, 3)
        self.assertEqual(rom.max_transfer, MEM_IO_CHUNK)

    def test_tail_and_short_reads(self):
        rom = FakeRom(size=0x400)
        rom.mem[:] = bytes(range(256)) * 4
        # A length that is not a multiple of the chunk, and one below it.
        for length in (0x101, 0x1, 0x100):
            self.assertEqual(
                read_chunks(rom.mem_read, 0, length, MEM_IO_CHUNK, rom_cipher),
                bytes(rom.mem[:length]))

    def test_zero_length_reads_nothing(self):
        rom = FakeRom()
        self.assertEqual(read_chunks(rom.mem_read, 0, 0, MEM_IO_CHUNK), b'')
        self.assertEqual(rom.reads, 0)

    def test_partial_read_keeps_what_arrived(self):
        rom = FakeRom(size=0x400)
        rom.fail_at = 0x200
        with self.assertRaises(MemReadError) as cm:
            read_chunks(rom.mem_read, 0, 0x300, MEM_IO_CHUNK, rom_cipher)
        self.assertEqual(len(cm.exception.data), 0x200)
        self.assertEqual(cm.exception.addr, 0x200)

    def test_write_chunks_ciphers_per_transfer(self):
        rom = FakeRom(size=0x400)
        data = bytes(range(256)) * 3
        write_chunks(rom.mem_write, 0, data, MEM_IO_CHUNK, rom_cipher)
        self.assertEqual(bytes(rom.mem[:len(data)]), data)
        self.assertEqual(rom.max_transfer, MEM_IO_CHUNK)


class DumpModeTest(unittest.TestCase):
    """jlrunner --dump: reads only, and never executes anything."""

    def setUp(self):
        self.rom = FakeRom(size=0x400, scramble=True)
        self.rom.mem[0x100:0x180] = b'BR23 console line\n' * 5
        self.uboot = self.rom  # JL_UBOOT-shaped: mem_read/mem_write/mem_jump

    def dump(self, argv, uboot=None, product='UBOOT1.00'):
        ap = jlrunner.build_parser()
        args = ap.parse_args(argv)
        jlrunner.check_args(ap, args)
        return quiet(jlrunner.run_dump, args, uboot or self.uboot, product)

    def test_dump_issues_no_jump_and_no_write(self):
        out = os.path.join(HERE, 'dump-mode-test.bin')
        try:
            rc = self.dump(['--dump', '0x100', '--length', '0x80',
                            '--encrypt', '--out', out])
            self.assertEqual(rc, 0)
            self.assertEqual(self.rom.jumps, [])
            self.assertEqual(self.rom.writes, [])
            with open(out, 'rb') as f:
                self.assertEqual(f.read(), bytes(self.rom.mem[0x100:0x180]))
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_dump_is_loader_free(self):
        """Nothing about the ROM path may touch a loader protocol object."""
        # run_dump only ever calls mem_read on what it is handed; a stub with
        # no other method is enough, and proves the surface.
        class ReadOnly:
            def __init__(self):
                self.calls = []

            def mem_read(self, addr, length):
                self.calls.append((addr, length))
                return bytes(length)

        ro = ReadOnly()
        self.assertEqual(self.dump(['--dump', '0x20040', '--length', '0x200'],
                                   uboot=ro), 0)
        self.assertEqual(ro.calls, [(0x20040, 0x100), (0x20140, 0x100)])

    def test_default_length(self):
        self.assertEqual(jlrunner.DUMP_LEN, 0x100)
        out = os.path.join(HERE, 'dump-default-test.bin')
        try:
            self.dump(['--dump', '0x0', '--out', out])
            self.assertEqual(os.path.getsize(out), jlrunner.DUMP_LEN)
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_non_uboot_device_is_refused(self):
        self.assertEqual(self.dump(['--dump', '0x0'], product='Loader'), 2)
        self.assertEqual(self.rom.reads, 0)

    def test_partial_dump_keeps_bytes_and_fails(self):
        self.rom.fail_at = 0x200
        out = os.path.join(HERE, 'dump-partial-test.bin')
        try:
            rc = self.dump(['--dump', '0x0', '--length', '0x300', '--out', out])
            self.assertEqual(rc, 1)
            self.assertEqual(os.path.getsize(out), 0x200)
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_argument_validation(self):
        ap = jlrunner.build_parser()

        def bad(argv):
            args = ap.parse_args(argv)
            with self.assertRaises(SystemExit):
                jlrunner.check_args(ap, args)

        bad(['--dump', '0x0', '0x4000', 'file.bin'])   # positional in dump mode
        bad(['--dump', '0x0', '--arg', '1'])           # arg needs code to run
        bad(['--dump', '0x0', '--mitraddr', '0x10'])   # ditto
        bad(['--dump', '0x0', '--dumpaddr', '0x10'])   # the other dump
        bad(['--dump', '0x0', '--block-size', '512'])  # past the chip's buffer
        bad(['--length', '0x10'])                      # --length without --dump
        bad(['--out', 'f'])                            # --out without --dump
        bad(['0x4000'])                                # load mode, no file
        bad([])                                        # neither mode


class ModeTest(unittest.TestCase):
    """jluboottool.pick_mode: which mode, and which scrambling."""

    BR23 = {'uboot1.00': {'protocol-version': 'v2',
                          'quirks': {'memory-rw-mengli-crypt': True}}}
    PLAIN = {'uboot1.00': {'protocol-version': 'v2'}}

    def mode(self, argv, chipspec=None, product='UBOOT1.00'):
        import jluboottool
        args = jluboottool.parse_args(argv)
        return jluboottool.pick_mode(args, chipspec or self.BR23, product)

    def test_default_installs_the_loader(self):
        install, rom, cipher = self.mode([], self.BR23)
        self.assertTrue(install)
        self.assertFalse(rom)
        self.assertIsNone(cipher)

    def test_no_loader_descrambles_on_a_scrambling_chip(self):
        install, rom, cipher = self.mode(['--no-loader'], self.BR23)
        self.assertFalse(install)
        self.assertTrue(rom)
        self.assertIs(cipher, rom_cipher)

    def test_no_loader_raw(self):
        install, rom, cipher = self.mode(['--no-loader', '--raw'], self.BR23)
        self.assertTrue(rom)
        self.assertIsNone(cipher)

    def test_no_loader_on_a_chip_without_the_quirk(self):
        install, rom, cipher = self.mode(['--no-loader'], self.PLAIN)
        self.assertTrue(rom)
        self.assertIsNone(cipher)

    def test_no_loader_outside_uboot1_exits(self):
        with self.assertRaises(SystemExit):
            quiet(self.mode, ['--no-loader'], self.BR23, 'Loader')

    def test_raw_without_no_loader_exits(self):
        with self.assertRaises(SystemExit):
            quiet(self.mode, ['--raw'], self.BR23)


class ShellRomModeTest(unittest.TestCase):
    """jluboottool --no-loader: the flash commands refuse instead of erroring."""

    def setUp(self):
        import jluboottool
        self.mod = jluboottool
        self.rom = FakeRom(size=0x400, scramble=True)
        self.rom.mem[0:8] = b'ABCDEFGH'

    def shell(self, rom=False, cipher=rom_cipher):
        return self.mod.DasShell(self.rom, rom=rom, cipher=cipher)

    def test_flash_commands_need_the_loader(self):
        sh = self.shell(rom=True)
        for cmd in ('read 0 0x10 out.bin', 'write 0 in.bin', 'erase 0 0x10',
                    'erasechip', 'dump 0 0x10', 'burnchipkey 0x4317', 'reset'):
            # Refused, and nothing reached the device.
            self.assertFalse(quiet(sh.onecmd, cmd), cmd)
        self.assertEqual(self.rom.writes, [])
        self.assertEqual(self.rom.jumps, [])

    def test_memread_descrambles(self):
        sh = self.shell(rom=True)
        out = os.path.join(HERE, 'shell-memread-test.bin')
        try:
            quiet(sh.onecmd, 'memread 0 8 %s' % out)
            with open(out, 'rb') as f:
                self.assertEqual(f.read(), b'ABCDEFGH')
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_memread_raw_does_not_descramble(self):
        sh = self.shell(rom=True, cipher=None)
        out = os.path.join(HERE, 'shell-raw-test.bin')
        try:
            sh.onecmd('memread 0 8 %s' % out)
            with open(out, 'rb') as f:
                self.assertNotEqual(f.read(), b'ABCDEFGH')
        finally:
            if os.path.exists(out):
                os.remove(out)

    def test_memwrite_scrambles_so_the_chip_stores_plain(self):
        sh = self.shell(rom=True)
        src = os.path.join(HERE, 'shell-memwrite-test.bin')
        try:
            with open(src, 'wb') as f:
                f.write(b'roundtrip!')
            quiet(sh.onecmd, 'memwrite 0 %s' % src)
            self.assertEqual(bytes(self.rom.mem[0:10]), b'roundtrip!')
        finally:
            if os.path.exists(src):
                os.remove(src)


if __name__ == '__main__':
    unittest.main()
