import socket
import struct
import sys
import time

import prometheus_client
from prometheus_client import core

PROTO_BASE = 0

VERSION = "3.0.105"

# some constants from MFSCommunication.h
CLTOMA_CSERV_LIST = (PROTO_BASE+500)
MATOCL_CSERV_LIST = (PROTO_BASE+501)
CLTOAN_CHART_DATA = (PROTO_BASE+506)
ANTOCL_CHART_DATA = (PROTO_BASE+507)
CLTOMA_SESSION_LIST = (PROTO_BASE+508)
MATOCL_SESSION_LIST = (PROTO_BASE+509)
CLTOMA_INFO = (PROTO_BASE+510)
MATOCL_INFO = (PROTO_BASE+511)
CLTOMA_FSTEST_INFO = (PROTO_BASE+512)
MATOCL_FSTEST_INFO = (PROTO_BASE+513)
CLTOMA_CHUNKSTEST_INFO = (PROTO_BASE+514)
MATOCL_CHUNKSTEST_INFO = (PROTO_BASE+515)
CLTOMA_CHUNKS_MATRIX = (PROTO_BASE+516)
MATOCL_CHUNKS_MATRIX = (PROTO_BASE+517)
CLTOMA_QUOTA_INFO = (PROTO_BASE+518)
MATOCL_QUOTA_INFO = (PROTO_BASE+519)
CLTOMA_EXPORTS_INFO = (PROTO_BASE+520)
MATOCL_EXPORTS_INFO = (PROTO_BASE+521)
CLTOMA_MLOG_LIST = (PROTO_BASE+522)
MATOCL_MLOG_LIST = (PROTO_BASE+523)
CLTOMA_CSSERV_COMMAND = (PROTO_BASE+524)
MATOCL_CSSERV_COMMAND = (PROTO_BASE+525)
CLTOMA_SESSION_COMMAND = (PROTO_BASE+526)
MATOCL_SESSION_COMMAND = (PROTO_BASE+527)
CLTOMA_MEMORY_INFO = (PROTO_BASE+528)
MATOCL_MEMORY_INFO = (PROTO_BASE+529)
CLTOMA_LIST_OPEN_FILES = (PROTO_BASE+532)
MATOCL_LIST_OPEN_FILES = (PROTO_BASE+533)
CLTOMA_LIST_ACQUIRED_LOCKS = (PROTO_BASE+534)
MATOCL_LIST_ACQUIRED_LOCKS = (PROTO_BASE+535)
CLTOMA_MASS_RESOLVE_PATHS = (PROTO_BASE+536)
MATOCL_MASS_RESOLVE_PATHS = (PROTO_BASE+537)
CLTOMA_SCLASS_INFO = (PROTO_BASE+542)
MATOCL_SCLASS_INFO = (PROTO_BASE+543)
CLTOMA_MISSING_CHUNKS = (PROTO_BASE+544)
MATOCL_MISSING_CHUNKS = (PROTO_BASE+545)

MFS_MESSAGE = 1

MASKORGROUP = 4

MFS_CSSERV_COMMAND_REMOVE = 0
MFS_CSSERV_COMMAND_BACKTOWORK = 1
MFS_CSSERV_COMMAND_MAINTENANCEON = 2
MFS_CSSERV_COMMAND_MAINTENANCEOFF = 3
MFS_CSSERV_COMMAND_TMPREMOVE = 4

MFS_SESSION_COMMAND_REMOVE = 0


STATE_DUMMY = 0
STATE_LEADER = 1
STATE_ELECT = 2
STATE_FOLLOWER = 3
STATE_USURPER = 4

donotresolve =0


def resolve(strip):
    if donotresolve:
        return strip
    try:
        return (socket.gethostbyaddr(strip))[0]
    except Exception:
        return strip


# common auxilinary functions


def state_name(stateid):
    if stateid == STATE_DUMMY:
        return "DUMMY"
    elif stateid == STATE_USURPER:
        return "USURPER"
    elif stateid == STATE_FOLLOWER:
        return "FOLLOWER"
    elif stateid == STATE_ELECT:
        return "ELECT"
    elif stateid == STATE_LEADER:
        return "LEADER"
    else:
        return "???"


def state_color(stateid, sync):
    if stateid == STATE_DUMMY:
        return 8
    elif stateid == STATE_FOLLOWER or stateid == STATE_USURPER:
        if sync:
            return 5
        else:
            return 6
    elif stateid == STATE_ELECT:
        return 3
    elif stateid == STATE_LEADER:
        return 4
    else:
        return 1


def decimal_number(number, sep=' '):
    parts = []
    while number >= 1000:
        number, rest = divmod(number, 1000)
        parts.append("%03u" % rest)
    parts.append(str(number))
    parts.reverse()
    return sep.join(parts)


def humanize_number(number, sep='', suff='B'):
    number *= 100
    scale = 0
    while number >= 99950:
        number = number//1024
        scale += 1
    if number < 995 and scale > 0:
        b = (number+5)//10
        nstr = "%u.%u" % divmod(b, 10)
    else:
        b = (number+50)//100
        nstr = "%u" % b
    if scale > 0:
        return "%s%s%si%s" % (nstr, sep, "-KMGTPEZY"[scale], suff)
    else:
        return "%s%s%s" % (nstr, sep, suff)


def timeduration_to_shortstr(timeduration):
    for l, s in ((86400, 'd'), (3600, 'h'), (60, 'm'), (0, 's')):
        if timeduration >= l:
            if l > 0:
                n = float(timeduration)/float(l)
            else:
                n = float(timeduration)
            rn = round(n, 1)
            if n == round(n, 0):
                return "%.0f%s" % (n, s)
            else:
                return "%s%.1f%s" % (("~" if n != rn else ""), rn, s)
    return "???"


def timeduration_to_fullstr(timeduration):
    if timeduration >= 86400:
        days, dayseconds = divmod(timeduration, 86400)
        daysstr = "%u day%s,  " % (days, ("s" if days != 1 else ""))
    else:
        dayseconds = timeduration
        daysstr = ""
    hours, hourseconds = divmod(dayseconds, 3600)
    minutes, seconds = divmod(hourseconds, 60)
    if seconds == round(seconds, 0):
        return "%u second%s (%s%u:%02u:%02u)" % (timeduration, ("" if timeduration == 1 else "s"), daysstr, hours, minutes, seconds)
    else:
        seconds, fracsec = divmod(seconds, 1)
        return "%.3f seconds (%s%u:%02u:%02u.%03u)" % (timeduration, daysstr, hours, minutes, seconds, round(1000*fracsec, 0))


def label_id_to_char(id):
    return chr(ord('A')+id)


def labelmask_to_str(labelmask):
    str = ""
    m = 1
    for i in range(26):
        if labelmask & m:
            str += label_id_to_char(i)
        m <<= 1
    return str


def labelmasks_to_str(labelmasks):
    if labelmasks[0] == 0:
        return "*"
    r = []
    for labelmask in labelmasks:
        if labelmask == 0:
            break
        r.append(labelmask_to_str(labelmask))
    return "+".join(r)


def version_convert(version):
    if version >= (2, 0, 0):
        return ((version[0], version[1], version[2]//2), version[2]&1)
    elif version >= (1, 7, 0):
        return (version, 1)
    elif version > (0, 0, 0):
        return (version, 0)
    else:
        return (version, -1)


def version_str_and_sort(version):
    version, pro = version_convert(version)
    strver = "%u.%u.%u" % version
    sortver = "%05u_%03u_%03u" % version
    if pro == 1:
        strver += " PRO"
        sortver += "_2"
    elif pro == 0:
        sortver += "_1"
    else:
        sortver += "_0"
    return (strver, sortver)


class MFSConn:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connect()

    def __del__(self):
        try:
            if self.socket:
                self.socket.close()
#                print "connection closed with: %s:%u" % (self.host, self.port)
            self.socket = None
        except AttributeError:
            pass

    def connect(self):
        cnt = 0
        while self.socket == None and cnt<3:
            self.socket = socket.socket()
            self.socket.settimeout(1)
            try:
                self.socket.connect((self.host, self.port))
            except Exception:
                self.socket.close()
                self.socket = None
                cnt += 1
        if self.socket is None:
            self.socket = socket.socket()
            self.socket.settimeout(1)
            self.socket.connect((self.host, self.port))
#        else:
#            print "connected to: %s:%u" % (self.host, self.port)

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def mysend(self, msg):
        if self.socket is None:
            self.connect()
        totalsent = 0
        while totalsent < len(msg):
            sent = self.socket.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def myrecv(self, leng):
        if sys.version_info[0] < 3:
            msg = ''
        else:
            msg = bytes(0)
        while len(msg) < leng:
            chunk = self.socket.recv(leng-len(msg))
            if len(chunk) == 0:
                raise RuntimeError("socket connection broken")
            msg = msg + chunk
        return msg

    def command(self, cmdout, cmdin, dataout=None):
        if dataout:
            l = len(dataout)
            msg = struct.pack(">LL", cmdout, l) + dataout
        else:
            msg = struct.pack(">LL", cmdout, 0)
        cmdok = 0
        errcnt = 0
        while cmdok == 0:
            try:
                self.mysend(msg)
                header = self.myrecv(8)
                cmd, length = struct.unpack(">LL", header)
                if cmd == cmdin:
                    datain = self.myrecv(length)
                    cmdok = 1
                else:
                    raise RuntimeError("MFS communication error - bad answer")
            except Exception:
                if errcnt < 3:
                    self.close()
                    self.connect()
                    errcnt += 1
                else:
                    raise RuntimeError("MFS communication error")
        return datain, length


class Master(MFSConn):
    def __init__(self, host, port):
        MFSConn.__init__(self, host, port)
        self.version = (0, 0, 0)
        self.pro = -1

        data, length = self.command(CLTOMA_INFO, MATOCL_INFO)
        if length == 121 or length == 129 or length == 137:
            offset = 8 if length == 137 else 0
            version = struct.unpack(">HBB", data[:4])
            self.set_version(version)

    def set_version(self, version):
        self.version, self.pro = version_convert(version)

    def version_at_least(self, v1, v2, v3):
        return (self.version >= (v1, v2, v3))

    def version_less_than(self, v1, v2, v3):
        return (self.version < (v1, v2, v3))

    def version_is(self, v1, v2, v3):
        return (self.version == (v1, v2, v3))

    def version_unknown(self):
        return (self.version == (0, 0, 0))

    def is_pro(self):
        return self.pro

    def sort_ver(self):
        sortver = "%05u_%03u_%03u" % self.version
        if self.pro == 1:
            sortver += "_2"
        elif self.pro == 0:
            sortver += "_1"
        else:
            sortver += "_0"
        return sortver


class ExportsEntry:
    def __init__(self, fip1, fip2, fip3, fip4,
                 tip1, tip2, tip3, tip4, path, meta,
                 v1, v2, v3, exportflags, sesflags,
                 umaskval, rootuid, rootgid, mapalluid,
                 mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime):
        self.ipfrom = (fip1, fip2, fip3, fip4)
        self.ipto = (tip1, tip2, tip3, tip4)
        self.version = (v1, v2, v3)
        self.stripfrom = "%u.%u.%u.%u" % (fip1, fip2, fip3, fip4)
        self.sortipfrom = "%03u_%03u_%03u_%03u" % (fip1, fip2, fip3, fip4)
        self.stripto = "%u.%u.%u.%u" % (tip1, tip2, tip3, tip4)
        self.sortipto = "%03u_%03u_%03u_%03u" % (tip1, tip2, tip3, tip4)
        self.strver, self.sortver = version_str_and_sort((v1, v2, v3))
        self.meta = meta
        self.path = path
        self.exportflags = exportflags
        self.sesflags = sesflags
        self.umaskval = umaskval
        self.rootuid = rootuid
        self.rootgid = rootgid
        self.mapalluid = mapalluid
        self.mapallgid = mapallgid
        self.mingoal = mingoal
        self.maxgoal = maxgoal
        self.mintrashtime = mintrashtime
        self.maxtrashtime = maxtrashtime


class Session:
    def __init__(self, sessionid, ip1, ip2, ip3, ip4,
                 info, openfiles, nsocks, expire, v1, v2, v3,
                 meta, path, sesflags, umaskval, rootuid,
                 rootgid, mapalluid, mapallgid, mingoal, maxgoal,
                 mintrashtime, maxtrashtime, stats_c, stats_l):
        self.ip = (ip1, ip2, ip3, ip4)
        self.version = (v1, v2, v3)
        self.strip = "%u.%u.%u.%u" % (ip1, ip2, ip3, ip4)
        self.sortip = "%03u_%03u_%03u_%03u" % (ip1, ip2, ip3, ip4)
        self.strver, self.sortver = version_str_and_sort((v1, v2, v3))
        self.host = resolve(self.strip)
        self.sessionid = sessionid
        self.info = info
        self.openfiles = openfiles
        self.nsocks = nsocks
        self.expire = expire
        self.meta = meta
        self.path = path
        self.sesflags = sesflags
        self.umaskval = umaskval
        self.rootuid = rootuid
        self.rootgid = rootgid
        self.mapalluid = mapalluid
        self.mapallgid = mapallgid
        self.mingoal = mingoal
        self.maxgoal = maxgoal
        self.mintrashtime = mintrashtime
        self.maxtrashtime = maxtrashtime
        self.stats_c = stats_c
        self.stats_l = stats_l


class ChunkServer:
    def __init__(self, ip1, ip2, ip3, ip4,
                 port, csid, v1, v2, v3, flags,
                 used, total, chunks, tdused, tdtotal,
                 tdchunks, errcnt, load, gracetime, labels, mfrstatus):
        self.ip = (ip1, ip2, ip3, ip4)
        self.version = (v1, v2, v3)
        self.strip = "%u.%u.%u.%u" % (ip1, ip2, ip3, ip4)
        self.sortip = "%03u_%03u_%03u_%03u" % (ip1, ip2, ip3, ip4)
        self.strver, self.sortver = version_str_and_sort((v1, v2, v3))
        self.host = resolve(self.strip)
        self.port = port
        self.csid = csid
        self.flags = flags
        self.used = used
        self.total = total
        self.chunks = chunks
        self.tdused = tdused
        self.tdtotal = tdtotal
        self.tdchunks = tdchunks
        self.errcnt = errcnt
        self.load = load
        self.gracetime = gracetime
        self.labels = labels
        self.mfrstatus = mfrstatus


class DataProvider:
    def __init__(self, masterconn):
        self.masterconn = masterconn
        self.sessions = None
        self.chunkservers = None
        self.exports = None

    def get_exports(self):
        if self.exports is None:
            self.exports = []
            if self.masterconn.version_at_least(3, 0, 72):
                data, length = self.masterconn.command(CLTOMA_EXPORTS_INFO, MATOCL_EXPORTS_INFO, struct.pack(">B", 2))
            elif self.masterconn.version_at_least(1, 6, 26):
                data, length = self.masterconn.command(CLTOMA_EXPORTS_INFO, MATOCL_EXPORTS_INFO, struct.pack(">B", 1))
            else:
                data, length = self.masterconn.command(CLTOMA_EXPORTS_INFO, MATOCL_EXPORTS_INFO)
            pos = 0
            while pos < length:
                fip1, fip2, fip3, fip4, tip1, tip2, tip3, tip4, pleng = struct.unpack(">BBBBBBBBL", data[pos:pos+12])
                pos += 12
                path = data[pos:pos+pleng]
                path = path.decode('utf-8', 'replace')
                pos += pleng
                if self.masterconn.version_at_least(3, 0, 72):
                    v1, v2, v3, exportflags, sesflags, umaskval, rootuid, rootgid, mapalluid, mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime = struct.unpack(">HBBBBHLLLLBBLL", data[pos:pos+34])
                    pos += 34
                    if mingoal <= 1 and maxgoal >= 9:
                        mingoal = None
                        maxgoal = None
                    if mintrashtime == 0 and maxtrashtime == 0xFFFFFFFF:
                        mintrashtime = None
                        maxtrashtime = None
                elif self.masterconn.version_at_least(1, 6, 26):
                    v1, v2, v3, exportflags, sesflags, rootuid, rootgid, mapalluid, mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime = struct.unpack(">HBBBBLLLLBBLL", data[pos:pos+32])
                    pos += 32
                    if mingoal <= 1 and maxgoal >= 9:
                        mingoal = None
                        maxgoal = None
                    if mintrashtime == 0 and maxtrashtime == 0xFFFFFFFF:
                        mintrashtime = None
                        maxtrashtime = None
                    umaskval = None
                else:
                    v1, v2, v3, exportflags, sesflags, rootuid, rootgid, mapalluid, mapallgid = struct.unpack(">HBBBBLLLL", data[pos:pos+22])
                    pos += 22
                    mingoal = None
                    maxgoal = None
                    mintrashtime = None
                    maxtrashtime = None
                    umaskval = None
                if path == '.':
                    meta = 1
                    umaskval = None
                else:
                    meta = 0
                expent = ExportsEntry(fip1, fip2, fip3, fip4, tip1, tip2, tip3, tip4, path, meta, v1, v2, v3, exportflags, sesflags, umaskval, rootuid, rootgid, mapalluid, mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime)
                self.exports.append(expent)
        return self.exports

    def get_sessions(self):
        if self.sessions is None:
            self.sessions = []
            if self.masterconn.version_at_least(3, 0, 72):
                data, length = self.masterconn.command(CLTOMA_SESSION_LIST, MATOCL_SESSION_LIST, struct.pack(">B", 3))
            elif self.masterconn.version_at_least(1, 7, 8):
                data, length = self.masterconn.command(CLTOMA_SESSION_LIST, MATOCL_SESSION_LIST, struct.pack(">B", 2))
            elif self.masterconn.version_at_least(1, 6, 26):
                data, length = self.masterconn.command(CLTOMA_SESSION_LIST, MATOCL_SESSION_LIST, struct.pack(">B", 1))
            else:
                data, length = self.masterconn.command(CLTOMA_SESSION_LIST, MATOCL_SESSION_LIST)
            if self.masterconn.version_less_than(1, 6, 21):
                statscnt = 16
                pos = 0
            elif self.masterconn.version_is(1, 6, 21):
                statscnt = 21
                pos = 0
            else:
                statscnt = struct.unpack(">H", data[0:2])[0]
                pos = 2
            while pos < length:
                if self.masterconn.version_at_least(1, 7, 8):
                    sessionid, ip1, ip2, ip3, ip4, v1, v2, v3, openfiles, nsocks, expire, ileng = struct.unpack(">LBBBBHBBLBLL", data[pos:pos+25])
                    pos += 25
                else:
                    sessionid, ip1, ip2, ip3, ip4, v1, v2, v3, ileng = struct.unpack(">LBBBBHBBL", data[pos:pos+16])
                    pos += 16
                    openfiles = 0
                    nsocks = 1
                    expire = 0
                info = data[pos:pos+ileng]
                pos += ileng
                pleng = struct.unpack(">L", data[pos:pos+4])[0]
                pos += 4
                path = data[pos:pos+pleng]
                pos += pleng
                info = info.decode('utf-8', 'replace')
                path = path.decode('utf-8', 'replace')
                if self.masterconn.version_at_least(3, 0, 72):
                    sesflags, umaskval, rootuid, rootgid, mapalluid, mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime = struct.unpack(">BHLLLLBBLL", data[pos:pos+29])
                    pos += 29
                    if mingoal <= 1 and maxgoal >= 9:
                        mingoal = None
                        maxgoal = None
                    if mintrashtime == 0 and maxtrashtime == 0xFFFFFFFF:
                        mintrashtime = None
                        maxtrashtime = None
                elif self.masterconn.version_at_least(1, 6, 26):
                    sesflags, rootuid, rootgid, mapalluid, mapallgid, mingoal, maxgoal, mintrashtime, maxtrashtime = struct.unpack(">BLLLLBBLL", data[pos:pos+27])
                    pos += 27
                    if mingoal <= 1 and maxgoal >= 9:
                        mingoal = None
                        maxgoal = None
                    if mintrashtime == 0 and maxtrashtime == 0xFFFFFFFF:
                        mintrashtime = None
                        maxtrashtime = None
                    umaskval = None
                else:
                    sesflags, rootuid, rootgid, mapalluid, mapallgid = struct.unpack(">BLLLL", data[pos:pos+17])
                    pos += 17
                    mingoal = None
                    maxgoal = None
                    mintrashtime = None
                    maxtrashtime = None
                    umaskval = None
                if statscnt < 16:
                    stats_c = struct.unpack(">"+"L"*statscnt, data[pos:pos+4*statscnt])+(0, )*(16-statscnt)
                    pos += statscnt*4
                    stats_l = struct.unpack(">"+"L"*statscnt, data[pos:pos+4*statscnt])+(0, )*(16-statscnt)
                    pos += statscnt*4
                else:
                    stats_c = struct.unpack(">LLLLLLLLLLLLLLLL", data[pos:pos+64])
                    pos += statscnt*4
                    stats_l = struct.unpack(">LLLLLLLLLLLLLLLL", data[pos:pos+64])
                    pos += statscnt*4
                if path == '.':
                    meta = 1
                else:
                    meta = 0
                ses = Session(sessionid, ip1, ip2, ip3, ip4, info,
                              openfiles, nsocks, expire, v1, v2, v3,
                              meta, path, sesflags, umaskval, rootuid,
                              rootgid, mapalluid, mapallgid, mingoal,
                              maxgoal, mintrashtime, maxtrashtime, stats_c, stats_l)
                self.sessions.append(ses)
        return self.sessions

    def get_chunkservers(self):
        if self.chunkservers is None:
            self.chunkservers = []
            data, length = self.masterconn.command(CLTOMA_CSERV_LIST, MATOCL_CSERV_LIST)
            if self.masterconn.version_at_least(3, 0, 38) and (length % 69) == 0:
                n = length//69
                for i in range(n):
                    d = data[i*69:(i+1)*69]
                    flags, v1, v2, v3, ip1, ip2, ip3, ip4, port, csid, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, labels, mfrstatus = struct.unpack(">BBBBBBBBHHQQLQQLLLLLB", d)
                    cs = ChunkServer(ip1, ip2, ip3, ip4, port, csid, v1, v2, v3, flags, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, labels, mfrstatus)
                    self.chunkservers.append(cs)
            elif self.masterconn.version_at_least(2, 1, 0) and (length % 68) == 0:
                n = length//68
                for i in range(n):
                    d = data[i*68:(i+1)*68]
                    flags, v1, v2, v3, ip1, ip2, ip3, ip4, port, csid, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, labels = struct.unpack(">BBBBBBBBHHQQLQQLLLLL", d)
                    cs = ChunkServer(ip1, ip2, ip3, ip4, port, csid, v1, v2, v3, flags, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, labels, None)
                    self.chunkservers.append(cs)
            elif self.masterconn.version_at_least(1, 7, 25) and self.masterconn.version_less_than(2, 1, 0) and (length%64) == 0:
                n = length//64
                for i in range(n):
                    d = data[i*64:(i+1)*64]
                    flags, v1, v2, v3, ip1, ip2, ip3, ip4, port, csid, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime = struct.unpack(">BBBBBBBBHHQQLQQLLLL", d)
                    cs = ChunkServer(ip1, ip2, ip3, ip4, port, csid, v1, v2, v3, flags, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, None, None)
                    self.chunkservers.append(cs)
            elif self.masterconn.version_at_least(1, 6, 28) and self.masterconn.version_less_than(1, 7, 25) and (length%62) == 0:
                n = length//62
                for i in range(n):
                    d = data[i*62:(i+1)*62]
                    disconnected, v1, v2, v3, ip1, ip2, ip3, ip4, port, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime = struct.unpack(">BBBBBBBBHQQLQQLLLL", d)
                    cs = ChunkServer(ip1, ip2, ip3, ip4, port, csid, v1, v2, v3, 1 if disconnected else 0, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, load, gracetime, None, None)
                    self.chunkservers.append(cs)
            elif self.masterconn.version_less_than(1, 6, 28) and (length % 54) == 0:
                n = length//54
                for i in range(n):
                    d = data[i*54:(i+1)*54]
                    disconnected, v1, v2, v3, ip1, ip2, ip3, ip4, port, used, total, chunks, tdused, tdtotal, tdchunks, errcnt = struct.unpack(">BBBBBBBBHQQLQQLL", d)
                    cs = ChunkServer(ip1, ip2, ip3, ip4, port, None, v1, v2, v3, 1 if disconnected else 0, used, total, chunks, tdused, tdtotal, tdchunks, errcnt, None, None, None, None)
                    self.chunkservers.append(cs)
        return self.chunkservers


def getmasteraddresses(mhost, mport):
    m = []
    for mhost in mhost.replace(';', ' ').replace(', ', ' ').split():
        try:
            for i in socket.getaddrinfo(mhost, mport, socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP):
                if i[0] == socket.AF_INET and i[1] == socket.SOCK_STREAM and i[2] == socket.SOL_TCP:
                    m.append(i[4])
        except Exception:
            pass
    return m


class MooseFSCollector:
    def __init__(self,  masterhost,  masterport=9421):
        self.masterhost = masterhost
        self.masterport = masterport

    def connect_master(self):
        # find leader
        leaderispro = 0
        leaderfound = 0
        leader_exports_checksum = None
        followerfound = 0
        electfound = 0
        leaderconn = None
        electconn = None
        electinfo = None
        elect_exports_checksum = None
        leaderinfo = None
        masterlist = getmasteraddresses(self.masterhost,  self.masterport)
        masterlistver = []
        masterlistinfo = []

        for mhost,  mport in masterlist:
            conn = None
            version = (0, 0, 0)
            statestr = "???"
            statecolor = 1
            memusage = 0
            syscpu = 0
            usercpu = 0
            lastsuccessfulstore = 0
            lastsaveseconds = 0
            lastsavestatus = 0
            metaversion = 0
            exports_checksum = None
            try:
                conn = Master(mhost, mport)
                self.masterconn = conn
                try:
                    data,  length = conn.command(CLTOMA_INFO,  MATOCL_INFO)
                    if length == 52:
                        version = (1, 4, 0)
                        conn.set_version(version)
                        if leaderfound == 0:
                            leaderconn = conn
                            leaderinfo = data
                            leaderfound = 1
                        statestr = "OLD MASTER (LEADER ONLY)"
                        statecolor = 0
                    elif length == 60:
                        version = (1, 5, 0)
                        conn.set_version(version)
                        if leaderfound == 0:
                            leaderconn = conn
                            leaderinfo = data
                            leaderfound = 1
                        statestr = "OLD MASTER (LEADER ONLY)"
                        statecolor = 0
                    elif length == 68 or length == 76 or length == 101:
                        version = struct.unpack(">HBB", data[:4])
                        conn.set_version(version)
                        if leaderfound == 0 and version<(1, 7, 0):
                            leaderconn = conn
                            leaderinfo = data
                            leaderfound = 1
                        if length == 76:
                            memusage = struct.unpack(">Q", data[4:12])[0]
                        if length == 101:
                            memusage, syscpu, usercpu = struct.unpack(">QQQ", data[4:28])
                            syscpu /= 10000000.0
                            usercpu /= 10000000.0
                            lastsuccessfulstore, lastsaveseconds, lastsavestatus = struct.unpack(">LLB", data[92:101])
                        if version < (1, 7, 0):
                            statestr = "OLD MASTER (LEADER ONLY)"
                            statecolor = 0
                        else:
                            statestr = "UPGRADE THIS UNIT !!!"
                            statecolor = 2
                    elif length == 121 or length == 129 or length == 137:
                        offset = 8 if length == 137 else 0
                        version = struct.unpack(">HBB", data[:4])
                        conn.set_version(version)
                        memusage, syscpu, usercpu = struct.unpack(">QQQ", data[4:28])
                        syscpu /= 10000000.0
                        usercpu /= 10000000.0
                        lastsuccessfulstore, lastsaveseconds, lastsavestatus = struct.unpack(">LLB", data[offset+92:offset+101])
                        if conn.version_at_least(2, 0, 14):
                            lastsaveseconds = lastsaveseconds / 1000.0
                        workingstate, nextstate, stablestate, sync, leaderip, changetime, metaversion = struct.unpack(">BBBBLLQ", data[offset+101:offset+121])
                        if length >= 129:
                            exports_checksum = struct.unpack(">Q", data[offset+121:offset+129])[0]
                        if workingstate == 0xFF and nextstate == 0xFF and stablestate == 0xFF and sync == 0xFF:
                            if leaderfound == 0:
                                leaderconn = conn
                                leaderinfo = data
                                leaderfound = 1
                                leader_exports_checksum = exports_checksum
                            statestr = "-"
                            statecolor = 0
                        elif stablestate == 0 or workingstate != nextstate:
                            statestr = "transition %s -> %s" % (state_name(workingstate), state_name(nextstate))
                            statecolor = 8
                        else:
                            statestr = state_name(workingstate)
                            statecolor = state_color(workingstate, sync)
                            if workingstate == STATE_FOLLOWER or workingstate == STATE_USURPER:
                                if sync == 0:
                                    statestr += " (DESYNC)"
                                followerfound = 1
                                followerconn = conn
                                followerinfo = data
                                follower_exports_checksum = exports_checksum
                            if workingstate == STATE_ELECT and electfound == 0:
                                electfound = 1
                                electconn = conn
                                electinfo = data
                                elect_exports_checksum = exports_checksum
                            if workingstate == STATE_LEADER and leaderfound == 0:
                                leaderispro = 1
                                leaderconn = conn
                                leaderinfo = data
                                leaderfound = 1
                                leader_exports_checksum = exports_checksum
                except Exception:
                    statestr = "BUSY"
                    statecolor = 7
            except Exception:
                statestr = "DEAD"
            try:
                iptab = tuple(map(int, mhost.split('.')))
                strip = "%u.%u.%u.%u" % iptab
                sortip = "%03u_%03u_%03u_%03u" % iptab
            except Exception:
                strip = mhost
                sortip = mhost
            strver, sortver = version_str_and_sort(version)
            if conn and conn != leaderconn and conn != electconn:
                del conn
            masterlistver.append((mhost, mport, version))
            masterlistinfo.append((sortip, strip, sortver, strver, statestr, statecolor, metaversion, memusage, syscpu, usercpu, lastsuccessfulstore, lastsaveseconds, lastsavestatus, exports_checksum))

        if leaderfound:
            masterconn = leaderconn
            masterinfo = leaderinfo
            masterispro = leaderispro
            master_exports_checksum = leader_exports_checksum
        elif electfound:
            masterconn = electconn
            masterinfo = electinfo
            masterispro = 1
            master_exports_checksum = elect_exports_checksum
        elif followerfound:
            masterconn = followerconn
            masterinfo = followerinfo
            masterispro = 1
            master_exports_checksum = follower_exports_checksum
        else:
            masterconn = None
            master_exports_checksum = 0
            for sortip, strip, sortver, strver, statestr, statecolor, metaversion, memusage, syscpu, usercpu, lastsuccessfulstore, lastsaveseconds, lastsavestatus, exports_checksum in masterlistinfo:
                if exports_checksum is not None:
                    master_exports_checksum |= exports_checksum

        if leaderfound and masterconn.version_less_than(1, 6, 10):
            if masterconn.version_unknown():
                print("""Can't detect MFS master version""")
            else:
                print("""MFS master version not supported (pre 1.6.10)""")
            sys.exit(1)
        self.masterlistinfo = masterlistinfo

    def collect(self):
        self.connect_master()
        d = DataProvider(self.masterconn)

        collectors = dict(
            moosefs_connected_chunkservers=core.GaugeMetricFamily(
                'moosefs_connected_chunkservers', 'total chunkservers available',
                labels=['host']),
            moosefs_chunkserver_used_bytes=core.GaugeMetricFamily(
                'moosefs_chunkserver_used_bytes', 'chunkserver used bytes',
                labels=['host']),
            moosefs_chunkserver_total_bytes=core.GaugeMetricFamily(
                'moosefs_chunkserver_total_bytes', 'chunkserver total bytes',
                labels=['host']),
            moosefs_up=core.GaugeMetricFamily(
                'moosefs_up', 'Moosefs status checks',
                labels=['host'])
        )
        master_host = self.masterlistinfo[0][1]

        d.get_chunkservers()
        collectors['moosefs_connected_chunkservers'].add_metric([master_host], len(d.chunkservers))
        collectors['moosefs_up'].add_metric([master_host], 1)
        for chunkserver in d.chunkservers:
            collectors['moosefs_chunkserver_used_bytes'].add_metric([chunkserver.host], chunkserver.used)
            collectors['moosefs_chunkserver_total_bytes'].add_metric([chunkserver.host], chunkserver.total)
            collectors['moosefs_up'].add_metric([chunkserver.host], 1)

        for collector in collectors.values():
            yield collector


if __name__ == '__main__':
    mhost = '192.168.128.234'
    mport = 9421
    core.REGISTRY.register(MooseFSCollector(mhost, mport))
    prometheus_client.start_http_server(8000)
    while True:
        time.sleep(1)
