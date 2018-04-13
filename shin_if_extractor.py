from sys import argv
from os import path, stat, makedirs
from shutil import copyfile
from subprocess import call
from randomtools.psx_file_extractor import FileManager
from randomtools.utils import read_multi, write_multi


POINTER_TABLE_ADDRESSES = {
    16: 0xe4cf4,
    17: 0xe4ce4,
    77: 0xeeb10,
    }

#SCRIPTS = [16, 18, 21, 22, 23, 77] + range(25, 38+1)
SCRIPTS = [18, 21, 22, 23, 77, 16] + range(25, 38+1)
LISTS = [17, 40, 43, 75, 81, 82, 84]

table = {}
f = open("table.txt")
prev_value = -1
for line in f.readlines():
    line = line.rstrip()
    if not line or line[0] == '#':
        continue
    while "  " in line:
        line = line.replace("  ", " ")
    if line[0] == ' ':
        a = ' '
        b = int(line[1:], 0x10)
    else:
        try:
            a, b = line.split(' ')
            b = int(b, 0x10)
        except ValueError:
            a = line
            b = prev_value+1
    if r"\n" in a:
        a = a.replace(r"\n", "\n")
    table[a] = b
    table[b] = a
    a = a.strip()
    if a:
        table[a] = b
    prev_value = b

def bytes2int(data, length=2):
    try:
        data = map(ord, data)
    except TypeError:
        pass
    while len(data) < length:
        data.append(0)
    assert len(data) == length
    value = 0
    for d in reversed(data):
        value <<= 8
        value |= d
    return value


def int2bytes(value, length=2, make_string=False):
    data = []
    for i in xrange(length):
        data.append(value & 0xFF)
        value >>= 8
    if make_string:
        data = "".join(map(chr, data))
    return data


def int2str(value):
    assert isinstance(value, int)
    if value in table:
        return table[value]
    return "${0:0>4}".format("%x" % value)


def partial_str2int(s):
    assert s
    keylength = max(len(key) for key in table if isinstance(key, basestring))
    if s[0] == '$' and len(s) >= 5:
        test = s[1:5]
        for key in table:
            if isinstance(key, basestring):
                assert not key.startswith(("$%s" % test).lower())
        try:
            test = int(test, 0x10)
            return test, s[5:]
        except ValueError:
            pass

    for kl in reversed(xrange(1, keylength+1)):
        key = s[:kl]
        if key == r"\n":
            key = "\n"
        if key in table:
            value = table[key]
            s = s[kl:]
            break
    else:
        raise Exception("No known value corresponds to character %s." % s[0])
    return value, s


def wrap_uncompressed(data):
    if isinstance(data, basestring):
        data = map(ord, data)
    if data:
        assert not isinstance(data[0], basestring)
        assert isinstance(data[0], int)
    # TODO: does the datalength need to be mult. of 4?
    datalength = len(data) + 8
    data = int2bytes(1, length=4) + int2bytes(datalength, length=4) + data
    return "".join(map(chr, data))


def compress(data):
    raise NotImplementedError


class DecompressionError(Exception): pass


def get_compressed_from_file(filename, pointer=0):
    try:
        f = open(filename, "r+b")
    except:
        raise DecompressionError("File not found.")
    datas = []
    while True:
        f.seek(pointer)
        compression_type = read_multi(f, length=4)
        if compression_type == 0:
            break

        assert compression_type == 0x201
        f.seek(pointer + 4)
        compressed_length = read_multi(f, length=4)
        f.seek(pointer)
        datas.append(f.read(compressed_length))
        pointer = f.tell()
    f.close()
    return datas


def decompress_from_file(filename, pointer=0):
    try:
        f = open(filename, "r+b")
    except:
        raise DecompressionError("File not found.")
    datas = []
    while True:
        f.seek(pointer)
        compression_type = read_multi(f, length=4)
        if compression_type == 0:
            break

        if compression_type == 1:
            f.seek(pointer + 4)
            compressed_length = read_multi(f, length=4)
            uncompressed_length = compressed_length-8
            f.seek(pointer + 8)
            data = f.read(uncompressed_length)

        elif compression_type & 0xffff == 0x201:
            f.seek(pointer + 4)
            compressed_length = read_multi(f, length=4)
            f.seek(pointer + 8)
            if f.tell() < pointer + compressed_length:
                uncompressed_length = read_multi(f, length=4)
                f.seek(pointer + 12)
                first_compressed_byte = ord(f.read(1))
            else:
                first_compressed_byte = None
                uncompressed_length = 0
            data = ""
            while True:
                if first_compressed_byte is not None:
                    data += f.read(first_compressed_byte+1)

                if f.tell() >= pointer + compressed_length:
                    break

                length = ord(f.read(1))
                #assert length & 0x80
                if not length & 0x80:
                    first_compressed_byte = length
                    continue
                length = (length & 0x7F) + 3

                lookback = ord(f.read(1))
                window = data[-(lookback+1):]
                assert len(window) == lookback+1
                while len(window) < length:
                    window += window
                data += window[:length]

                if f.tell() >= pointer + compressed_length:
                    break

                first_compressed_byte = ord(f.read(1))
                if first_compressed_byte & 0x80:
                    first_compressed_byte = None
                    f.seek(f.tell()-1)

        else:
            raise DecompressionError("Unknown compression type.")
        pointer += compressed_length
        assert f.tell() == pointer
        offset = pointer % 4
        if offset:
            pointer += 4 - offset
        assert len(data) == uncompressed_length
        datas.append(data)

    f.close()
    return datas


class ShinIfFileManager(FileManager):
    def __init__(self, imgname, dirname=None):
        minute = 0
        second = 2
        sector = 22
        super(ShinIfFileManager, self).__init__(
            imgname, dirname, minute, second, sector)

        zzz = self.get_file("ZZZ.BIN;1")
        self.end_free_sector = zzz.target_sector + zzz.num_sectors
        self.export_file("ZZZ.BIN;1")
        g = open(path.join(self.dirname, "ZZZ.BIN;1"), "r+b")
        g.truncate()
        g.close()
        self.import_file("ZZZ.BIN;1")
        self.start_free_sector = zzz.target_sector + zzz.num_sectors
        assert self.start_free_sector < self.end_free_sector

    def acquire_free_sectors(self, num_sectors):
        sector_index = self.start_free_sector
        self.start_free_sector += num_sectors
        if self.start_free_sector >= self.end_free_sector:
            raise Exception("Out of space.")
        return sector_index

    def import_file(self, name, filepath=None, new_target_sector=None):
        if name.startswith(path.join("D", "F")):
            if filepath is None:
                filepath = path.join(self.dirname, name)
            filesize = stat(filepath).st_size
            if new_target_sector is None:
                num_sectors = filesize / 0x800
                if filesize > num_sectors * 0x800:
                    num_sectors += 1
                num_sectors = max(num_sectors, 1)
                new_target_sector = self.acquire_free_sectors(num_sectors)
            index = int(name[3:7])
            filepos_path = self.export_file("FILEPOS.DAT;1")
            filepos = open(filepos_path, "r+b")
            filepos.seek(8 * index)
            write_multi(filepos, new_target_sector, length=4)
            write_multi(filepos, filesize, length=4)
            filepos.close()
            self.import_file("FILEPOS.DAT;1")

        super(ShinIfFileManager, self).import_file(
            name, filepath, new_target_sector)

    def get_message_pointers(self, address):
        slpm_path = self.export_file("SLPM_871.53;1")
        slpm = open(slpm_path, "r+b")
        slpm.seek(address)
        pointers = []
        while True:
            pointer = read_multi(slpm, length=4)
            continuation = pointer >> 24
            pointer &= 0xFFFFFF
            assert continuation in [0, 2, 4]
            pointers.append(pointer)
            if not continuation:
                break
        slpm.close()
        return pointers

    def set_message_pointers(self, pointers, address):
        index = [key for key in POINTER_TABLE_ADDRESSES
                 if POINTER_TABLE_ADDRESSES[key] == address][0]
        if index in LISTS:
            delimiter = (0x2 << 24)
        else:
            delimiter = (0x4 << 24)
        slpm_path = self.export_file("SLPM_871.53;1")
        slpm = open(slpm_path, "r+b")
        slpm.seek(address)
        for i, pointer in enumerate(pointers):
            assert not pointer & delimiter
            if i != len(pointers)-1:
                pointer |= delimiter
            write_multi(slpm, pointer, length=4)
        assert not pointer & delimiter
        slpm.close()
        self.import_file("SLPM_871.53;1")


class Message:
    def __init__(self, data):
        if len(data) == 0:
            self.data = ""
            return
        #assert bytes2int(data[-2:]) == 0xFFFF
        assert not len(data) % 2
        if not isinstance(data, basestring):
            data = "".join(map(chr, data))
        self.data = data

    def __repr__(self):
        return self.bytes_to_str(self.data)

    @property
    def index(self):
        return self.pack.messages.index(self)

    @staticmethod
    def bytes_to_str(data):
        s = ""
        data = list(data)
        while data:
            s += int2str(bytes2int(data[:2]))
            data = data[2:]
        #assert s.endswith("$END")
        return s

    @staticmethod
    def str_to_bytes(s):
        data = ""
        while s:
            value, s = partial_str2int(s)
            data += "".join(map(chr, int2bytes(value, length=2)))
        return data

    def set_text(self, text):
        self.data = self.str_to_bytes(text)

    def conversion_check(self):
        a = self.bytes_to_str(self.data)
        b = self.str_to_bytes(a)
        try:
            assert len(b) == len(self.data)
            assert not len(b) % 2
            c_str = [p for (i, p) in enumerate(zip(b, b[:1]))
                     if not i % 2]
            d_str = [p for (i, p) in enumerate(zip(self.data, self.data[:1]))
                     if not i % 2]
            for c, d in zip(c_str, d_str):
                c = map(ord, c)
                d = map(ord, d)
                c = c[0] | (c[1] << 8)
                d = d[0] | (d[1] << 8)
                if c != d:
                    assert table[ord(c)] == table[ord(d)]
        except AssertionError:
            import pdb; pdb.set_trace()


class MessagePack:
    def __init__(self, data):
        backup = str(data)
        assert bytes2int(data[:4], length=4) == 1
        size = bytes2int(data[4:8], length=4)
        data = data[8:]
        first_pointer = bytes2int(data[:4], length=4)
        assert not first_pointer % 4
        pointers = []
        for _ in xrange(first_pointer / 4):
            pointers.append(bytes2int(data[:4], length=4)-first_pointer)
            data = data[4:]
        assert all([p >= 0 for p in pointers])
        assert pointers == sorted(pointers)
        pointers.append(None)
        self.messages = []
        for p1, p2 in zip(pointers, pointers[1:]):
            if p2 is None:
                p2 = len(data)
            d = data[p1:p2]
            m = Message(d)
            self.messages.append(m)
            m.pack = self

        while len(backup) % 4:
            backup += "\x00"
        try:
            assert self.data == backup
        except:
            import pdb; pdb.set_trace()

    def __repr__(self):
        s = ""
        for (i, m) in enumerate(self.messages):
            comment = "\n".join(["#%s" % l for l in str(m).split("\n")])
            comment += "\n#" + ("-"*39)
            s += ("@{0:0>3}-{1:0>3}\n" +
                  ("="*40 + "\n") +
                  "{3}\n" +
                  "{2}\n" +
                  ("="*40 + "\n") +
                  "\n").format(self.index, i, m, comment)
        return s.strip()

    @property
    def index(self):
        return self.parent.index

    @property
    def data(self):
        num_messages = len(self.messages)
        base_ptr = num_messages * 4
        pstr = ""
        mstr = ""
        for m in self.messages:
            offset_ptr = len(mstr)
            pstr += int2bytes(base_ptr + offset_ptr, length=4,
                              make_string=True)
            mstr += m.data
            #assert mstr.endswith("\xff\xff")
            assert len(mstr) % 2 == 0
        s = pstr + mstr
        header = "\x01\x00\x00\x00" + int2bytes(
            len(s)+8, length=4, make_string=True)
        s = header + s
        while len(s) % 4:
            s += "\x00"
        return s


class MessagePackPack:
    def __init__(self, index, data):
        self.index = index
        self.message_packs = []
        while True:
            decom = bytes2int(data[:4], length=4)
            if decom == 0:
                break
            assert decom == 1
            size = bytes2int(data[4:8], length=4)
            head = data[:size]
            message_pack = MessagePack(head)
            self.message_packs.append(message_pack)
            message_pack.parent = self
            data = data[size:]
            offset = 4-(size % 4)
            if offset < 4:
                padding = data[:offset]
                data = data[offset:]
                assert bytes2int(padding, length=len(padding)) == 0

    def __repr__(self):
        assert self.index < 10
        s = ""
        for (i, mp) in enumerate(self.message_packs):
            s += "@{0:0>3}-{1:0>3}!\n".format(self.index, i)
            s += "%s\n" % ("="*40)
            for m in mp.messages:
                text = str(m)
                s += "%s\n" % text
                s += "%s\n" % ("="*40)
            s += "\n"
        return s.strip()

    @property
    def data(self):
        s = ""
        for mp in self.message_packs:
            s += mp.data
            while len(s) % 4:
                s += "\x00"
        return s


class EventMessagePack:
    def __init__(self, index, data):
        backup = str(data)
        self.index = index
        assert bytes2int(data[:4], length=4) == 1
        size = bytes2int(data[4:8], length=4)
        self.event = data[8:size]
        data = data[size:]
        offset = 4-(size % 4)
        if offset < 4:
            padding = data[:offset]
            data = data[offset:]
            assert bytes2int(padding, length=len(padding)) == 0

        assert bytes2int(data[:4], length=4) == 1
        #data = data[4:]
        size = bytes2int(data[4:8], length=4)
        #data = data[4:]
        assert not len(data) % 4
        assert 0 <= len(data) - size <= 3
        data = data[:size]
        self.message_pack = MessagePack(data)
        self.message_pack.parent = self
        assert self.data == backup

    def __repr__(self):
        return self.message_pack.__repr__()

    @property
    def messages(self):
        return self.message_pack.messages

    @property
    def data(self):
        header = "\x01\x00\x00\x00" + int2bytes(
            len(self.event)+8, length=4, make_string=True)
        s = header + self.event
        while len(s) % 4:
            s += "\x00"
        return s + self.message_pack.data


def double_expand_f16():
    pointers = fm.get_message_pointers()
    f16_export_path = path.join("D", "F0016.BIN;1")
    f16 = fm.export_file(f16_export_path, "f16.tmp")
    f16_size = stat(f16).st_size
    f16 = open(f16, "r+b")

    new_f16_path = "new_f16.tmp"
    new_f16 = open(new_f16_path, "w+")
    new_f16.truncate()
    new_f16.close()
    new_f16 = open(new_f16_path, "r+b")
    new_pointers = []

    for p, p2 in zip(pointers, pointers[1:]):
        new_p = p * 2
        f16.seek(p)
        data = f16.read(p2-p)
        new_f16.seek(new_p)
        new_f16.write(data)
        new_pointers.append(new_p)

    f16.close()
    new_f16.close()

    assert len(new_pointers) == len(pointers)-1
    new_pointers.append(pointers[-1] * 2)
    assert len(new_pointers) == len(set(new_pointers))
    assert new_pointers == sorted(new_pointers)
    fm.set_message_pointers(new_pointers)
    fm.import_file(f16_export_path, new_f16_path)
    fm.export_file(f16_export_path)


def join_datas(datas, compressed=False):
    s = ""
    for d in datas:
        if compressed:
            s += d
        else:
            s += wrap_uncompressed(d)
        length = len(s)
        offset = length % 4
        if offset:
            s += ("\0"*(4-offset))
        length = len(s)
        offset = length % 4
        assert not offset
    return s


def export_script_file(script_index=16, no_event=False):
    no_pointers = script_index not in POINTER_TABLE_ADDRESSES
    if no_pointers:
        pointers = [0, None]
    else:
        pointer_table_address = POINTER_TABLE_ADDRESSES[script_index]
        pointers = fm.get_message_pointers(pointer_table_address)

    filename = path.join("D", "F{0:0>4}.BIN;1".format(script_index))
    script_filename = "script{0:0>4}.txt".format(script_index)
    script_file = open(script_filename, "w+")
    temp_fname_old = "_temp_old.tmp"
    old_path = fm.export_file(filename, temp_fname_old)

    for i, (p, p2) in enumerate(zip(pointers, pointers[1:])):
        datas = decompress_from_file(old_path, p)
        s = join_datas(datas)

        if not no_event:
            mp = EventMessagePack(i, s)
        else:
            mp = MessagePackPack(i, s)
        script_file.write("%s\n\n" % mp)

    script_file.close()


def import_script_file(script_index=16, script_filename=None, no_event=False):
    no_pointers = script_index not in POINTER_TABLE_ADDRESSES
    if no_pointers:
        pointers = [0, None]
    else:
        pointer_table_address = POINTER_TABLE_ADDRESSES[script_index]
        pointers = fm.get_message_pointers(pointer_table_address)
    filename = path.join("D", "F{0:0>4}.BIN;1".format(script_index))

    if script_filename is None:
        script_filename = "script{0:0>4}.txt".format(script_index)
    script_file = open(script_filename, "r")
    messdict = {}

    reading = False
    for line in script_file.readlines():
        if line and line[0] == '#':
            continue
        if line and line[0] == '@':
            line = line.strip()[1:]
            if line[-1] == '!':
                rapidfire = True
                line = line[:-1]
                pack1, pack2 = line.split("-")
                pack = (int(pack1) * 1000) + int(pack2)
                messnum = 0
            else:
                rapidfire = False
                pack, messnum = line.split("-")
                pack = int(pack)
                messnum = int(messnum)
            reading = False
            message = ""
            continue
        if set(line.strip()) == {'='}:
            reading = not reading
            if reading is False:
                pack, messnum, message
                assert message[-1] == "\n"
                message = message[:-1]
                if pack not in messdict:
                    messdict[pack] = {}
                assert messnum not in messdict[pack]
                messdict[pack][messnum] = message
            if rapidfire and reading is False:
                reading = not reading
                message = ""
                messnum += 1
            continue
        if reading:
            message += line
    script_file.close()

    temp_fname_old = "_temp_old.tmp"
    temp_fname_new = "_temp_new.tmp"
    old_path = fm.export_file(filename, temp_fname_old)

    new_f = open(temp_fname_new, "w+")
    new_f.truncate()
    new_f.close()
    new_f = open(temp_fname_new, "r+b")
    new_pointers = []
    if not no_pointers:
        assert pointers == sorted(pointers)

    for i, (p, p2) in enumerate(zip(pointers, pointers[1:])):
        datas = decompress_from_file(old_path, p)
        s = join_datas(datas)

        print i+1, "/", len(pointers)-1
        if not no_event:
            mp = EventMessagePack(i, s)
            if mp.index not in messdict:
                assert len(mp.messages) == 0
            else:
                assert len(mp.messages) == len(messdict[mp.index])
            for j, m in enumerate(mp.messages):
                m.set_text(messdict[mp.index][j])
            data = mp.data
        else:
            mpp = MessagePackPack(i, s)
            for j, mp in enumerate(mpp.message_packs):
                pack = (i * 1000) + j
                for k, m in enumerate(mp.messages):
                    m.set_text(messdict[pack][k])
            data = mpp.data

        new_p = new_f.tell()
        if new_p > 0:
            offset = new_p % 0x800
            new_p += 0x800 - offset
            assert not new_p % 0x800

        new_f.seek(new_p)
        new_f.write(data)

        new_pointers.append(new_p)

    if not no_pointers:
        new_p = new_f.tell()
        offset = new_p % 0x800
        new_p += 0x800 - offset
        assert not new_p % 0x800
        assert len(new_pointers) == len(pointers)-1
        new_pointers.append(new_p)
        assert len(new_pointers) == len(set(new_pointers))
        assert new_pointers == sorted(new_pointers)
        fm.set_message_pointers(new_pointers, address=pointer_table_address)

    new_f.close()
    fm.import_file(filename, temp_fname_new)
    fm.export_file(filename)


def export_list(list_index=17):
    return export_script_file(list_index, no_event=True)


def import_list(list_index=17, list_filename=None):
    return import_script_file(list_index, script_filename=list_filename,
                              no_event=True)


if __name__ == "__main__":
    filename = argv[1]
    minute, second, sector = 0, 2, 22
    dirname, _ = filename.rsplit('.', 1)
    dirname = "%s.root" % dirname
    if not path.exists(dirname):
        makedirs(dirname)

    outfile = "modified.%s" % filename
    copyfile(filename, outfile)
    filename = None

    fm = ShinIfFileManager(outfile, dirname)

    #export_script_file(script_index=16)
    #export_script_file(script_index=77)
    #import_script_file(script_index=16)
    #for i in [17, 40, 43, 75, 81, 82, 84]:
    #    print i
    #    export_list(i)
    #import_list(17)
    #export_script_file(16)
    #import_script_file(16)
    #export_list(17)
    #raw_input("Edit script 17 now. ")
    #import_list(17)

    for l in LISTS:
        print "LIST", l
        if "export" in argv:
            export_list(l)
        if "import" in argv:
            import_list(l)
        print

    for s in SCRIPTS:
        print "SCRIPT", s
        if "export" in argv:
            export_script_file(s)
        if "import" in argv:
            import_script_file(s)
        print
