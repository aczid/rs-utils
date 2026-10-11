#!/usr/bin/env python

"""
Manipulate PSARC archives used by Rocksmith 2014.

Usage:
    psarc.py pack DIRECTORY...
    psarc.py unpack FILE...
    psarc.py convert [--pc|--mac|--xbox|--ps3|--ps4] FILE...

Options:
    --pc    Convert to PC (Windows) archive: flags=4, PC_KEY sng, audio/windows
    --mac   Convert to Mac archive: flags=4, MAC_KEY sng, audio/mac
    --xbox  Convert to Xbox 360 archive: flags=0, big-endian plaintext sng,
            audio/xbox360
    --ps3   Convert to PS3 archive: flags=0, big-endian plaintext sng,
            audio/ps3
    --ps4   Convert to PS4 console archive: flags=0 (plaintext TOC and sng),
            audio/generic
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter

import struct
import zlib
import os
import hashlib
import sys
import json

import codecs

import sys
print("psarc.py running on Python version %s.%s" % (sys.version_info.major,sys.version_info.minor))

MAGIC = b'PSAR'
VERSION = 65540
COMPRESSION = b'zlib'
ARCHIVE_FLAGS = 4
ENTRY_SIZE = 30
BLOCK_SIZE = 65536


ARC_KEY = 'C53DB23870A1A2F71CAE64061FDD0E1157309DC85204D4C5BFDF25090DF2572C'
ARC_IV = 'E915AA018FEF71FC508132E4BB4CEB42'

MAC_KEY = '9821330E34B91F70D0A48CBD625993126970CEA09192C0E6CDA676CC9838289D'
PC_KEY = 'CB648DF3D12A16BF71701414E69619EC171CCA5D2A142E3E59DE7ADDA18A3A30'

PRF_KEY = '728B369E24ED0134768511021812AFC0A3C25D02065F166B4BCC58CD2644F29E'

CONFIG_KEY = '378B9026EE7DE70B8AF124C1E30978670F9EC8FD5E7285A86442DD73068C0473'


def pad(data, blocksize=16):
    """Zeros padding"""
    #So we need zeroes in order to match AES's encoding scheme which breaks
    #the data into 16-byte chunks. If we have 52 bytes to decode, then we have
    #3 full 16-byte blocks, and 4 left over. This means we need 12 bytes worth
    #of padding. That means we get 12 bytes worth of zeroes.
    padding = (blocksize - len(data)) % blocksize
    #Modify this to return a bytes object, since that's what pycrypto needs.
    return data + bytes(padding)


def path2dict(path):
    """Reads a path into a dictionary"""
    output = {}
    for dirpath, _, filenames in os.walk(path):
        for filename in filenames:
            fullpath = os.path.join(dirpath, filename)
            name = fullpath[len(path) + 1:]

            with open(fullpath, 'rb') as fstream:
                output[name] = fstream.read()

    return output


def decrypt_profile(stream):
    """For *_prfldb, crd and profile.json files"""
    s = stream.read()
    size = struct.unpack('<L', s[16:20])[0]

    cipher = AES.new(codecs.decode(PRF_KEY,'hex'), AES.MODE_ECB)
    x = zlib.decompress(cipher.decrypt(pad(s[20:])))
    assert(size == len(x))

    return json.loads(x[:-1])  # it's a long C string


def stdout_same_line(line):
    """Prepend carriage return and output to stdout"""
    sys.stdout.write('\r' + line[:80])
    sys.stdout.flush()


def aes_ctr(data, key, ivector, encrypt=True):
    """AES CTR Mode"""
    output = bytes()
    # Counter.new wants the nonce as an int; callers pass 16 raw bytes.
    if isinstance(ivector, (bytes, bytearray)):
        ivector = int(codecs.encode(ivector, 'hex'), 16)
    #First param: Number of bits of the cipher. 64 is not meaningful.
    ctr = Counter.new(128, initial_value = ivector)
    cipher = AES.new(codecs.decode(key,'hex'), mode=AES.MODE_CTR, counter=ctr)

    if encrypt:
        output += cipher.encrypt(pad(data))
    else:
        output += cipher.decrypt(pad(data))

    return output


def decrypt_sng(data, key):
    """Decrypt SNG. Data consist of a 8 bytes header, 16 bytes initialization
    vector and payload and the DSA signature. Payload is first decrypted using
    AES CTR and then zlib decompressed. Size is checked."""
    #Changed conversion from bytes to int for initial value.
    decrypted = aes_ctr(data[24:], key, int(codecs.encode(data[8:24],'hex'),16), encrypt=False)
    length = struct.unpack('<L', decrypted[:4])[0]  # file size
    payload = ''
    try:
        payload = zlib.decompress(decrypted[4:])
        assert len(payload) == length
    except Exception as e:
        #print('An error occurred while processing sng!')
        #print(e)
        payload = decrypted

    return payload


def encrypt_sng(data, key):
    """Encrypt SNG"""
    output = struct.pack('<LL', 0x4a, 3)  # the header

    payload = struct.pack('<L', len(data))
    payload += zlib.compress(data, zlib.Z_BEST_COMPRESSION)

    ivector = bytes(16)
    output += ivector
    output += aes_ctr(payload, key, ivector)
    return output + bytes(56)


def wrap_sng_console(data, endian='<'):
    """Wrap a track payload in the plaintext '4a' container used by
    console (flags == 0) archives: u32 magic, u32 version, u32 size,
    followed by a zlib stream. X360/PS3 store the header big-endian."""
    out = struct.pack(endian + 'LLL', 0x4a, 1, len(data))
    out += zlib.compress(data, zlib.Z_BEST_COMPRESSION)
    return out


def decrypt_config(data):
    """For pkgconfig.ini"""
    data = data[:-56]  # remove signature

    cipher = AES.new(codecs.decode(CONFIG_KEY,'hex'), AES.MODE_ECB)
    t = cipher.decrypt(data)
    if t.find(b'\x00') > -1:  # padding was applied
        return t[:t.index(b'\x00')]
    return t


def encrypt_config(data):
    """For pkgconfig.ini"""
    cipher = AES.new(codecs.decode(CONFIG_KEY,'hex'), AES.MODE_ECB)
    t = cipher.encrypt(pad(data))
    t += bytes(56)
    return t


def read_entry(filestream, entry):
    """Extract zlib for one entry"""
    data = bytes()

    length = entry['length']
    zlength = entry['zlength']
    filestream.seek(entry['offset'])

    i = 0
    while len(data) < length:
        if zlength[i] == 0:
            # Stored block: 0 marks uncompressed. The final block of a file
            # is partial, so never read past the declared entry length.
            data += filestream.read(min(BLOCK_SIZE, length - len(data)))
        else:
            chunk = filestream.read(zlength[i])
            try:
                data += zlib.decompress(chunk)
            except zlib.error:
                data += chunk
        i += 1

    flags = entry.get('flags', ARCHIVE_FLAGS)
    # sng post-processing: PC/Mac wrap the '4a' container in AES-CTR;
    # console archives (flags == 0) store it in the clear.
    if flags != 0:
    # Post process for sng
        if entry['filepath'].find('songs/bin/macos/') > -1:
            data = decrypt_sng(data, MAC_KEY)
        elif entry['filepath'].find('songs/bin/generic/') > -1:
            data = decrypt_sng(data, PC_KEY)
    elif entry['filepath'].find('songs/bin/') > -1 and data[:4] in (b'\x4a\x00\x00\x00', b'\x00\x00\x00\x4a'):
        # Unwrap the plaintext '4a' container (see wrap_sng_console);
        # X360/PS3 archives store it big-endian.
        endian = '<' if data[0] == 0x4a else '>'
        length = struct.unpack(endian + 'L', data[8:12])[0]
        payload = zlib.decompressobj().decompress(data[12:])
        assert len(payload) == length
        data = payload

    # Requires bypass for ini
    # if entry['filepath'] == 'pkgconfig.ini':
    #     data = decrypt_config(data)

    return data


def create_entry(name, data, flags=ARCHIVE_FLAGS, endian='<'):
    """Chunk a file"""

    # Pre process for sng
    if name.find('songs/bin/') > -1:
        if flags == 0:
            data = wrap_sng_console(data, endian)
        elif name.find('songs/bin/macos/') > -1:
            data = encrypt_sng(data, MAC_KEY)
        elif name.find('songs/bin/generic/') > -1:
            data = encrypt_sng(data, PC_KEY)

    # Requires bypass for ini
    # if name == 'pkgconfig.ini':
    #     data = encrypt_config(data)

    zlength = []
    output = b''

    i = 0
    while i < len(data):
        raw = data[i:i + BLOCK_SIZE]
        i += BLOCK_SIZE

        compressed = zlib.compress(raw, zlib.Z_BEST_COMPRESSION)
        if len(compressed) < len(raw):
            output += compressed
            zlength.append(len(compressed))
        else:
            output += raw
            zlength.append(len(raw) if len(raw) < BLOCK_SIZE else 0)

    return {
        'filepath': name,
        'zlength': zlength,
        'length': len(data),
        'data': output,
        'md5': hashlib.md5(name.encode()).digest() if name != '' else bytes(16)
    }


def cipher_toc():
    """AES CFB Mode"""
    return AES.new(codecs.decode(ARC_KEY,'hex'), mode=AES.MODE_CFB,
                   IV=codecs.decode(ARC_IV,'hex'), segment_size=128)


def read_toc(filestream):
    """Read entry list and Z-fragments.
    Returns a list of entries to be used with read_entry. Each entry
    carries the archive's flags byte; flags == 0 means plaintext TOC
    and plaintext sng containers."""

    entries = []
    zlength = []

    filestream.seek(0)
    header = struct.unpack('>4sL4sLLLLL', filestream.read(32))

    flags = header[7] & 0xFF
    toc_size = header[3] - 32
    n_entries = header[5]
    toc = filestream.read(toc_size)
    if flags != 0:
        toc = cipher_toc().decrypt(pad(toc))
    toc_position = 0

    idx = 0
    while idx < n_entries:
        data = toc[toc_position:toc_position + ENTRY_SIZE]

        entries.append({
            'md5': data[:16],
            'zindex': struct.unpack('>L', data[16:20])[0],
            'length': struct.unpack('>Q', b'\x00'*3 + data[20:25])[0],
            'offset': struct.unpack('>Q', b'\x00'*3 + data[25:])[0],
            'flags': flags
        })
        toc_position += ENTRY_SIZE
        idx += 1

    idx = 0
    while idx < (toc_size - ENTRY_SIZE * n_entries) / 2:
        data = toc[toc_position:toc_position + 2]
        zlength.append(struct.unpack('>H', data)[0])
        toc_position += 2
        idx += 1

    for entry in entries:
        entry['zlength'] = zlength[entry['zindex']:]

    # Process the first entry as it contains the file listing
    entries[0]['filepath'] = ''
    filepaths = read_entry(filestream, entries[0]).split()
    for entry, filepath in zip(entries[1:], filepaths):
        entry['filepath'] = filepath.decode("utf-8")

    return entries[1:]


def create_toc(entries, flags=ARCHIVE_FLAGS):
    """Build a TOC (encrypted iff flags != 0) for a given list of entries."""

    offset = 0
    zindex = 0
    zlength = []
    for entry in entries:
        entry['offset'] = offset
        offset += len(entry['data'])

        entry['zindex'] = zindex
        zindex += len(entry['zlength'])

        zlength += entry['zlength']

    toc_size = 32 + ENTRY_SIZE * len(entries) + 2 * len(zlength)

    header = struct.pack('>4sL4sLLLLL', MAGIC, VERSION, COMPRESSION,
                         toc_size, ENTRY_SIZE, len(entries),
                         BLOCK_SIZE, flags)

    toc = b''
    for entry in entries:
        toc += entry['md5']
        toc += struct.pack('>L', entry['zindex'])
        toc += struct.pack('>Q', entry['length'])[-5:]
        toc += struct.pack('>Q', entry['offset'] + toc_size)[-5:]

    for i in zlength:
        toc += struct.pack('>H', i)

    if flags == 0:
        return header + toc
    # the [:toc_size] seems a little odd, but padding is not applied
    # in official PSARC either
    return (header + cipher_toc().encrypt(pad(toc)))[:toc_size]


def extract_psarc(filename):
    """Extract a PSARC to disk"""
    basepath = os.path.basename(filename)[:-6]

    with open(filename, 'rb') as psarc:
        entries = read_toc(psarc)
        logmsg = 'Extracting ' + basepath + ' {0}/' + str(len(entries))
        
        for idx, entry in enumerate(entries):
            stdout_same_line(logmsg.format(idx + 1))
            fname = os.path.join(basepath, entry['filepath'])
            data = read_entry(psarc, entry)
            path = os.path.dirname(fname)
            if not os.path.exists(path):
                os.makedirs(path)
            with open(fname, 'wb') as fstream:
                fstream.write(data)


def create_psarc(files, filename, flags=ARCHIVE_FLAGS, endian='<'):
    """Writes a dictionary filepath -> data to a PSARC file"""
    # Order is reversed
    filenames = reversed(sorted(files.keys()))
    entries = [create_entry('', '\n'.join(filenames).encode(), flags)]

    logmsg = 'Creating ' + filename + ' {0}/' + str(len(files))
    for idx, (name, data) in enumerate(reversed(sorted(files.items()))):
        stdout_same_line(logmsg.format(idx + 1))
        entries.append(create_entry(name, data, flags, endian))

    with open(filename, 'wb') as fstream:
        fstream.write(create_toc(entries, flags))
        for entry in entries:
            fstream.write(entry['data'])


# Per-platform archive differences.
PLATFORMS = {
    'pc':  {'audio': 'audio/windows', 'bin': 'songs/bin/generic',
            'flags': ARCHIVE_FLAGS, 'token': 'dx9', 'suffix': '_p'},
    'mac': {'audio': 'audio/mac', 'bin': 'songs/bin/macos',
            'flags': ARCHIVE_FLAGS, 'token': 'macos', 'suffix': '_m'},
    'xbox': {'audio': 'audio/xbox360', 'bin': 'songs/bin/xbox360',
             'flags': 0, 'token': 'xbox360', 'suffix': '_xbox', 'be': True},
    'ps3': {'audio': 'audio/ps3', 'bin': 'songs/bin/ps3',
            'flags': 0, 'token': 'ps3', 'suffix': '_ps3', 'be': True},
    'ps4': {'audio': 'audio/generic', 'bin': 'songs/bin/generic',
            'flags': 0, 'token': 'dx9', 'suffix': '_ps4'},
}

_AUDIO_DIRS = [p['audio'] for p in PLATFORMS.values()]
_BIN_DIRS = [p['bin'] for p in PLATFORMS.values()]


def detect_platform(entries):
    """Infer the platform a loaded archive was built for."""
    names = [entry['filepath'] for entry in entries]
    flags = entries[0]['flags'] if entries else ARCHIVE_FLAGS
    if any('bin/xbox360/' in n for n in names):
        return 'xbox'
    if any('bin/ps3/' in n for n in names):
        return 'ps3'
    if flags == 0:
        return 'ps4'
    if any('bin/macos/' in n for n in names):
        return 'mac'
    return 'pc'


def _map_path(name, src, dst):
    """Rewrite platform-specific directories inside an entry path."""
    if name.startswith(src['audio'] + '/'):
        name = dst['audio'] + '/' + name[len(src['audio']) + 1:]
    if name.startswith(src['bin'] + '/'):
        name = dst['bin'] + '/' + name[len(src['bin']) + 1:]
    # tolerate archives carrying another platform's dirs
    for other in _AUDIO_DIRS:
        if other != src['audio'] and name.startswith(other + '/'):
            name = dst['audio'] + '/' + name[len(other) + 1:]
    for other in _BIN_DIRS:
        if other != src['bin'] and name.startswith(other + '/'):
            name = dst['bin'] + '/' + name[len(other) + 1:]
    return name


# TODO logic for converting needs cleanup
def convert(filename, target=None):
    """Convert a PSARC between platforms (pc, mac, xbox, ps3, ps4).

    Differences handled: TOC encryption (flags 4 vs 0), the sng wrapper
    (PC_KEY / MAC_KEY CTR vs plaintext '4a' container, big-endian on
    X360/PS3), audio/bin entry directories, and the platform token
    inside aggregategraph.nt.

    Caveat: track chart data is byte-compatible across PC, Mac and PS4
    only. Converting to/from X360/PS3 rewrites container, paths and
    graph tokens; re-serializing the big-endian charts and building
    the audio banks are out of scope.

    With no target flag the classic pairing applies: _p <-> _m,
    console archives convert to PC. Output is <base><suffix>.psarc."""
    content = {}
    with open(filename, 'rb') as psarc:
        entries = read_toc(psarc)
        src_name = detect_platform(entries)
        files = [(entry['filepath'], read_entry(psarc, entry))
                 for entry in entries]

    if target is None:
        target = {'pc': 'mac', 'mac': 'pc', 'xbox': 'pc',
                  'ps3': 'pc', 'ps4': 'pc'}[src_name]
    src, dst = PLATFORMS[src_name], PLATFORMS[target]

    for name, data in files:
        name = _map_path(name, src, dst)
        if name.endswith('aggregategraph.nt'):
            for other in _AUDIO_DIRS:
                if other != dst['audio']:
                    data = data.replace(other.encode(), dst['audio'].encode())
            for other in _BIN_DIRS:
                if other != dst['bin']:
                    data = data.replace(other.encode(), dst['bin'].encode())
            if src['token'] != dst['token']:
                data = data.replace(src['token'].encode(), dst['token'].encode())
        content[name] = data

    base = filename[:-6] if filename.endswith('.psarc') else filename
    for suffix in [p['suffix'] for p in PLATFORMS.values()]:
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    outname = base + dst['suffix'] + '.psarc'
    create_psarc(content, outname, flags=dst['flags'],
                 endian='>' if dst.get('be') else '<')
    return outname


if __name__ == '__main__':
    from docopt import docopt
    args = docopt(__doc__)

    if args['unpack']:
        for f in args['FILE']:
            extract_psarc(f)
    elif args['pack']:
        for d in args['DIRECTORY']:
            d = os.path.normpath(d)
            create_psarc(path2dict(d), d + '.psarc')
    elif args['convert']:
        target = ('pc' if args['--pc'] else
                  'mac' if args['--mac'] else
                  'xbox' if args['--xbox'] else
                  'ps3' if args['--ps3'] else
                  'ps4' if args['--ps4'] else None)
        for f in args['FILE']:
            convert(f, target)
