from jltech.uboot import JL_MSCDevice, JL_UBOOT
from jltech.cipher import jl_crc_cipher, cipher_bytes
from jltech.memio import MEM_IO_CHUNK, rom_cipher, MemReadError, read_chunks
from jltech.utils import anyint, hexdump
import argparse, struct, sys

# A loader upload is usually encrypted in 512-byte blocks, unlike the chip's
# memory I/O buffer (jltech.memio.MEM_IO_CHUNK).
LOAD_CHUNK = 512

DUMP_LEN = 0x100

DESCRIPTION = '''Load code into memory and execute it, or dump memory without
executing anything.

Loading goes through UBOOT1.00's FB06 (write memory) and FB08 (jump).  Dumping
goes through FD07 (read memory) alone: nothing is written and nothing is
executed, so the mask ROM answers and no loader has to be installed.'''


def build_parser():
    ap = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    ap.add_argument('--device',
                    help='Path to the JieLi disk (e.g. /dev/sg2 or \\\\.\\E:)')

    ap.add_argument('--arg', type=anyint, default=None,
                    help="Numerical argument that's passed to the code (default: 0)")

    ap.add_argument('--encrypt', action='store_true',
                    help="Scramble the data as it goes into the chip, usually used for chips that"
                         "have encrypted loaders and so they decrypt it as it goes in. "
                         "This will be replaced with --raw parameter that will pass the data as-is instead."
                         " With --dump it descrambles instead, which is what the mask ROM returns"
                         " on chips with the memory-rw-mengli-crypt quirk (BR23 and up).")

    ap.add_argument('--block-size', type=anyint, default=None, metavar='SIZE',
                    help="Size of the block that is used when transferring data to the chip."
                         " Defaults to %d bytes for a load (encrypted loaders usually use 512)"
                         " and %d bytes for --dump (the chip's memory I/O buffer). "
                         % (LOAD_CHUNK, MEM_IO_CHUNK))

    ap.add_argument('--mitraddr', type=anyint,
                    help='Address of the "MiZUTraX" thing to dump after execution')

    ap.add_argument('--dumpaddr', type=anyint,
                    help='hexdump the memory at the specified address (256 bytes)')

    ap.add_argument('--dump', type=anyint, metavar='ADDR',
                    help='Dump memory instead of loading: read <length> bytes at ADDR'
                         ' and execute nothing.')

    ap.add_argument('--length', type=anyint, metavar='LEN',
                    help='How many bytes --dump reads (default: 0x%x)' % DUMP_LEN)

    ap.add_argument('--out', metavar='FILE',
                    help='Write the --dump data to FILE instead of hexdumping it')

    ap.add_argument('address', type=anyint, nargs='?',
                    help="Address where the file will be loaded and executed from")

    ap.add_argument('file', nargs='?',
                    help="File that will be loaded and executed")

    return ap


def check_args(ap, args):
    '''Validate the two modes arguments.'''

    if args.dump is not None:
        if args.address is not None or args.file is not None:
            ap.error('--dump takes no <address> <file>: give the address to'
                     ' --dump and the length to --length')
        if args.length is not None and args.length < 0:
            ap.error('--length must not be negative')
        if args.arg is not None:
            ap.error('--arg is passed to the code that is run; --dump runs nothing')
        if args.mitraddr is not None:
            ap.error('--mitraddr needs code to have run; --dump runs nothing')
        if args.dumpaddr is not None:
            ap.error('--dumpaddr is the dump taken around a load; use --dump for'
                     ' a dump on its own')
        if args.block_size is not None and not 0 < args.block_size <= MEM_IO_CHUNK:
            ap.error('--block-size for --dump must be 1..%d: that is the chip\'s'
                     ' memory I/O buffer' % MEM_IO_CHUNK)
        return

    if args.length is not None:
        ap.error('--length only applies to --dump')
    if args.out is not None:
        ap.error('--out only applies to --dump')
    if args.address is None or args.file is None:
        ap.error('give <address> <file> to load and run, or --dump ADDR to dump memory')


def run_dump(args, uboot, product):
    '''Read memory through FD07 only.'''

    if not product.startswith('UBOOT'):
        print('!! this device reports %r, not UBOOT1.00; --dump talks the mask'
              ' ROM and needs download mode' % product, file=sys.stderr)
        return 2

    length = DUMP_LEN if args.length is None else args.length
    chunk = args.block_size or MEM_IO_CHUNK
    cipher = rom_cipher if args.encrypt else None

    # stdout is the data channel when hexdumping, so status goes to stderr.
    print('=== memory dump 0x%08x..0x%08x (%d bytes, %d per transfer, %s) ==='
          % (args.dump, args.dump + length, length, chunk,
             'descrambled' if cipher else 'raw'),
          file=sys.stderr)

    try:
        data = read_chunks(uboot.mem_read, args.dump, length, chunk, cipher)
    except MemReadError as e:
        # A partial dump is evidence; a silently short file is not.
        if args.out:
            with open(args.out, 'wb') as f:
                f.write(e.data)
            print('!! %s; %d byte(s) written to %s'
                  % (e, len(e.data), args.out), file=sys.stderr)
        else:
            hexdump(e.data, base=args.dump)
            print('!! %s; %d of %d byte(s) shown'
                  % (e, len(e.data), length), file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, 'wb') as f:
            f.write(data)
        print('%d B -> %s' % (len(data), args.out), file=sys.stderr)
    else:
        hexdump(data, base=args.dump)

    return 0


def run_load(args, uboot):
    '''Write the file, then jump to it.'''

    arg = 0 if args.arg is None else args.arg
    chunk = args.block_size or LOAD_CHUNK

    def mem_read(addr, size):
        data = uboot.mem_read(addr, size)
        if args.encrypt: data = cipher_bytes(jl_crc_cipher, data)
        return data

    def mem_write(addr, data):
        if args.encrypt: data = cipher_bytes(jl_crc_cipher, data)
        uboot.mem_write(addr, data)

    #----------------------------------------------------

    with open(args.file, 'rb') as f:
        addr = args.address

        while True:
            block = f.read(chunk)
            if block == b'': break
            mem_write(addr, block)
            addr += len(block)

    if args.dumpaddr:
        print("=== Pre-jump memory dump at 0x%08x ===" % args.dumpaddr)
        hexdump(mem_read(args.dumpaddr, 0x40))

    try:
        uboot.mem_jump(args.address, arg)
    except Exception as e:
        print('Something failed during execution, is your code running too long or locking up the USB code, or what?')
        print('Message:', e)
        return 1

    #----------------------------------------------------

    if args.dumpaddr:
        hexdump(mem_read(args.dumpaddr, 0x100))

    def mitrparse(addr):
        magic, buffaddr, buffsize, nbytes = struct.unpack('<8sIII', mem_read(addr, 8+12))

        if magic != b'MiZUTraX':
            print("!!! There isn't any MizuTrax out there!")
            return

        print('////////// MiZU TraX LogTrace thingy //////////')

        print('Data spans %x-%x (%d bytes long), total data written: %d bytes' % (buffaddr, buffaddr + buffsize - 1, buffsize, nbytes))

        data = mem_read(buffaddr, min(buffsize, nbytes))

        if nbytes > buffsize:
            splitpos = nbytes % buffsize
            data = data[splitpos:] + data[:splitpos]
            print('## %d bytes left the scene' % (nbytes - buffsize))

        print('============= The Data =============')
        print(data.decode('utf-8', errors='ignore'))
        print('====================================')

    if args.mitraddr:
        mitrparse(args.mitraddr)

    return 0


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    check_args(ap, args)

    if args.device is not None:
        device = args.device

    else:
        from jldevfind import choose_jl_device

        device = choose_jl_device()
        if device is None:
            return 1

    with JL_MSCDevice(device) as dev:
        # TODO, determine whether we are in UBOOT1.00 or Loader/UBOOT2.00 modes
        uboot = JL_UBOOT(dev.dev)

        if args.dump is not None:
            vendor, product, prodrev = dev.inquiry()
            return run_dump(args, uboot, product)

        return run_load(args, uboot)


if __name__ == '__main__':
    sys.exit(main())
