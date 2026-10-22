""" Chunked memory I/O: one place decides the transfer size and the scrambling. """

__all__ = [
    'MEM_IO_CHUNK',
    'rom_cipher',
    'MemReadError',
    'read_chunks',
    'write_chunks'
]

from jltech.cipher import jl_crc_cipher, cipher_bytes

# BR23 and up use 256 bytes for *all* memory I/O while flash transfers use the
# larger `usb_buffer_size()`; a memory transfer past it overwrites the rest of
# the chip's buffer instead of failing.
MEM_IO_CHUNK = 256


def rom_cipher(data):
    """ The scrambling the mask ROM applies to memory read/write payloads.

    `CrcDecode` (ROM 0x111538 on BR23) re-seeds its keystream on every entry,
    so this applies per transfer -- never to a whole buffer at once.
    """
    return cipher_bytes(jl_crc_cipher, data)


class MemReadError(Exception):
    """ A memory read failed part-way through; `data` holds what did arrive. """

    def __init__(self, addr, data, cause):
        self.addr = addr
        self.data = data
        self.cause = cause
        super().__init__('read failed at 0x%08x after %d byte(s): %s'
                         % (addr, len(data), cause))


def read_chunks(read_fn, addr, length, chunk=MEM_IO_CHUNK, cipher=None):
    """ Read `length` bytes, `chunk` per transfer; raises MemReadError with the
    bytes read so far.  `cipher` is applied per transfer, never across them. """
    out = bytearray()
    done = 0

    while done < length:
        n = min(chunk, length - done)
        try:
            block = read_fn(addr, n)
        except Exception as e:
            raise MemReadError(addr, bytes(out), e) from e

        if len(block) != n:
            raise MemReadError(addr, bytes(out),
                               'short transfer (%d of %d bytes)'
                               % (len(block), n))

        if cipher is not None:
            block = cipher(block)

        out += block
        addr += n
        done += n

    return bytes(out)


def write_chunks(write_fn, addr, data, chunk=MEM_IO_CHUNK, cipher=None):
    """ Write `data`, `chunk` per transfer; returns the byte count. """
    done = 0

    while done < len(data):
        block = data[done:done + chunk]
        if cipher is not None:
            block = cipher(block)
        write_fn(addr + done, block)
        done += len(block)

    return done
