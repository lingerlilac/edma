import socket
import time
import math
from scipy import integrate
import socket
import binascii
import MySQLdb
import traceback
import numpy as np

con = MySQLdb.Connection(host="localhost", user="root",
                         passwd="lin", port=3306)
cur = con.cursor()
con.select_db('record')


HOST = '192.168.0.107'
PORT = 6666
recvSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recvSocket.bind((HOST, PORT))
recvSocket.listen(5)
recv_inter = {}
recv_trans = {}
anthenna = {}
ssl_signal = {}
ap_client = {}
iw_client = {}
Beacon_list = []
IW_list = []
interference = 0.0
drebest = 0.0
links = set()

host1 = '192.168.0.107'
port1 = 8888
tos = 0xfa

R = set([1, 6, 12, 24, 36, 54])


def get_links(values):
    if values[20] != '000000000000':
        links.add((values[20], values[0]))
    return links

fc = [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462]
bw = [5, 10, 20, 40]
# def generate_schedules(links):
#     schedules = []
#     ap = []
#     client = []
#     fc = [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462]
#     bw = [5, 10, 20, 40]
#     for i in links:
#         ap.append(i[0])
#         client.append(i[1])
#     for a in ap:
#         for c in client:
#             for f in fc:
#                 for b in bw:
#                     schedules.append(a, c, f, b)
#     return schedules


def Is_the_set_interfer(I_c, Signal, Noise):
    for i in I_c:
        for j in I_c and i != j:
            interfer += Signal[j]
        Si = Signal[i]
        SINR = math.log(Si / (interfer + Noise[i]), 10)
        if SINR < 10:
            return False
    return True


def Interference_between_links(ft, fr, wt, wr):

    # def fun(x, w, f):
    #     if abs(x - f) >= 1.5 * w:
    #         return 0.0001
    #     elif abs(x - f) >= w and abs(x - f) < 1.5 * w:
    #         return 0.00158489319246111348520210137339
    #     elif abs(x - f) >= 0.55 * w and abs(x - f) < w:
    #         return 0.001
    #     else:
    #         return 1.0
    def fun(x, w, f):
        if abs(x - f) >= 1.1 * w:
            return 0.00001
        elif abs(x - f) >= 0.55 * w and abs(x - f) < 1.1 * w:
            return 0.001
        else:
            return 1.0

    def function(x):
        return fun(x, wr, fr) * fun(x, wt, ft)

    def function1(x):
        return fun(x, wt, ft)
    result1, err1 = integrate.quad(function, -60, 60)
    result2, err2 = integrate.quad(function1, -60, 60)
    result = result1 / result2
    return result, result1, result2


def send_schedules(string):
    data_length = len(string)
    data = chr(data_length) + string
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_IP, socket.IP_TOS, tos)
    s.bind((host1, port1))
    s.listen(1)
    while 1:
        conn, addr = s.accept()
        print 'Connected by', addr
        while 1:
            conn.sendall(data)
            time.sleep(3)
    conn.close()

tvtot = []


def Get_feasible_set(set1):
    # [(ap1, client1), (ap2, client2), ...]
    if len(set1) == 0:
        return
    I_chose = set()
    for i in set1:
        I_chose.add(i)
        for j in set1 and i != j:
            

def Get_deltaS(T):
    # select the measurements from DB
    if T[3] == 5:
        return 0.0
    elif T[3] == 10:
        return 3.0
    elif T[3] == 20:
        return 6.0
    else:
        return 9.0


def Get_epsilonS(T):
    # select the epsilons from DB
    return 0


def Get_measuredS(j):
    # get the meausre S from DB
    mac_address = j[1]
    signal_strength = 0.0
    for iw in IW_list:
        if iw[0] == mac_address:
            signal_strength == iw[10]
    return signal_strength


def Check_if_interfere(l1, l2):


def Get_partical_interference(j, T_i):

    def integration(ft, fr, wt, wr):

        def fun(x, w, f):
            if abs(x - f) >= 1.5 * w:
                return 0.0001
            elif abs(x - f) >= w and abs(x - f) < 1.5 * w:
                return 0.00158489319246111348520210137339
            elif abs(x - f) >= 0.55 * w and abs(x - f) < w:
                return 0.001
            else:
                return 1.0

        def function(x):
            return fun(x, wr, fr) * fun(x, wt, ft)

        def function1(x):
            return fun(x, wt, ft) * fun(x, wt, ft)
        result1, err1 = integrate.quad(function, -60, 60)
        result2, err2 = integrate.quad(function1, -60, 60)
        result = result1 / result2
        return result
    tmp = integration(T_i[3], j[3], T_i[2], j[2])
    return tmp


def Get_rate_from_snr(sinr, T_i, r):
    # compute the expected throughput
    def Rate_and_SNR(x):
        if (0.0 <= x) & (x < 18.0):
            return x / 18.0
        elif (18.0 <= x) & (x < 27.0):
            return 0.11 * x
        elif x >= 27.0:
            return 1.0
    return Rate_and_SNR(sinr)


def Rho(T_i, T):
    interference = 0.0
    S = 0
    for j in T:
        if j == T_i:
            continue
        deltaS5 = Get_deltaS(j)
        epsilonS5 = Get_epsilonS(j)
        S_measure = Get_measuredS(j)
        S = S_measure + deltaS5 + epsilonS5
        S2 = S + 10 * math.log10(Get_partical_interference(j, T_i))
        interference = interference + S2
    deltaS5 = Get_deltaS(T_i)
    epsilonS5 = Get_epsilonS(T_i)
    S_measure = Get_measuredS(T_i)
    S = S_measure + deltaS5 + epsilonS5
    sinr = S - interference
    max_throughput = 0
    drebest = 0
    d = 0
    for r in R:
        expected_thr = Get_rate_from_snr(sinr, T_i, r)
        cur_tput = r * expected_thr
        if cur_tput > max_throughput:
            max_throughput = cur_tput
            drebest = r
            d = expected_thr
    return (drebest, d)


def estimate_throughput(T):
    for T_i in T:
        (d, drebest) = Rho(T_i, T)
        tvtot[T_i] = d * drebest

    return tvtot


def Get_the_transmission_queues():
    queue_of_links = {}
    return queue_of_links


def Rac_pack():
    F = []
    for f in fc:
        for b in bw:
            F.append((f, b))
    Queues = Get_the_transmission_queues()
    T = 0
    Tcur = []


class AP(object):

    def __init__(self, chanbw, mac_timestamp, data_rate,
                 current_channel, channel_type, essid, ssl_signal):
        self.chanbw = chanbw
        self.mac_timestamp = mac_timestamp
        self.data_rate = data_rate
        self.current_channel = current_channel
        self.channel_type = channel_type
        self.essid = essid
        self.ssl_signal = ssl_signal

    def update(self, chanbw, mac_timestamp, data_rate,
               current_channel, channel_type, essid, ssl_signal):
        self.chanbw = chanbw
        self.mac_timestamp = mac_timestamp
        self.data_rate = data_rate
        self.current_channel = current_channel
        self.channel_type = channel_type
        self.essid = essid
        self.ssl_signal = ssl_signal


class IW(object):

    def __init__(self, signal_avg):
        self.signal_avg = signal_avg

    def update(self, signal_avg):
        self.signal_avg = signal_avg


def Send():
    host = '192.168.2.1'
    port = 51888
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
    except Exception:
        msg = traceback.format_exc()
        print 'connected error', msg
    data = 'hello'
    s.send(data)


while 1:
    conn, addr = recvSocket.accept()
    # print'Connected by', addr
    data = conn.recv(4096)
    conn.sendall('OK')
    if data[0:0 + 1] == 'b':
        chanbw = data[1:1 + 2]
        mac_addr = data[3:3 + 6]
        mac_timestamp = data[9:9 + 8].encode('hex')
        data_rate = float(int(binascii.b2a_hex(data[17:17 + 1]), 16)) * 0.5
        # current_channel = int(binascii.b2a_hex(data[27:27 + 2]), 16)
        current_channel = int(binascii.b2a_hex(
            data[19:19 + 1] + data[18:18 + 1]), 16)
        channel_type = data[20:20 + 2].encode('hex')
        anthenna[0] = int(binascii.b2a_hex(data[25:25 + 1]), 16)
        anthenna[1] = int(binascii.b2a_hex(data[26:26 + 1]), 16)
        bssid = data[27:27 + 6]
        essid = data[33:33 + 20]
        for j in range(0, 3):
            ssl_signal_temp = int(binascii.b2a_hex(
                data[22 + j:22 + j + 1]), 16)
            if ssl_signal_temp >= 128:
                ssl_signal[j] = -(256 - ssl_signal_temp)
            else:
                ssl_signal[j] = ssl_signal_temp

        bssid2 = bssid[0].encode('hex') + \
            bssid[1].encode('hex') + bssid[2].encode(
            'hex') + bssid[3].encode('hex') + \
            bssid[4].encode('hex') + bssid[5].encode('hex')
        mac_addr1 = mac_addr[0].encode('hex') + mac_addr[1].encode('hex')\
            + mac_addr[2].encode('hex') + mac_addr[3].encode('hex') \
            + mac_addr[4].encode('hex') + mac_addr[5].encode('hex')
        mac_addr2 = mac_addr.encode('hex')

        if mac_addr2 not in ap_client:
            ap_client[mac_addr2] = {}
            ap_client[mac_addr2][bssid2] = AP(chanbw, mac_timestamp,
                                              data_rate, current_channel,
                                              channel_type,
                                              essid, ssl_signal[0])
            # print "%%%%%%%%%%%%%%%%"
            # print ap_client[mac_addr2][bssid2]
        elif bssid2 not in ap_client[mac_addr2]:
            ap_client[mac_addr2][bssid2] = AP(
                chanbw, mac_timestamp, data_rate, current_channel,
                channel_type, essid, ssl_signal[0])
            # print "@@@@@@@@@@@@@"
            # print ap_client[mac_addr][bssid2]
        else:
            # print "&&&&&&&&&&&"
            # for k, v in vars(ap_client[mac_addr][bssid2]).items():
                # print '\t', k, v
            ap_client[mac_addr2][bssid2].update(chanbw, mac_timestamp,
                                                data_rate, current_channel,
                                                channel_type, essid,
                                                ssl_signal[0])
        values = [mac_timestamp, data_rate,
                  current_channel, channel_type, ssl_signal[
                      0], anthenna[0], bssid2, essid, ssl_signal[1],
                  ssl_signal[2], anthenna[1], mac_addr1, chanbw]
        cur.execute("insert into Beacon (mac_timestamp, data_rate, current_channel,\
         channel_type, ssl_signal, anthenna, bssid, essid, ssl_signal1,\
          ssl_signal2, anthenna1, mac_addr, bw) VALUES\
           (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", values)
        con.commit()
        conn.close()
    else:
        # print "iw dev wlan0 station dump:"
        order = [7, 15, 10, 12, 10, 12, 12, 11, 8,
                 12, 12, 12, 21, 12, 15, 10, 9, 5, 11, 16]
        info = {}
        i = 18
        flag = 0
        iw_mac = data[1:1 + 6]
        iw_mac = iw_mac.encode('hex')
        # print data
        for j in range(18, len(data)):
            if data[j] == '\n':
                i = i + order[flag]
                info[flag] = data[i:i + j - i].lstrip()
                i = j + 1
                flag += 1
                if flag == 20:
                    flag = 0
                    # print iw_mac
                    # for m in range(0, 20):
                    #     print info[m]

                    if iw_mac not in iw_client:
                        iw_client[iw_mac] = {}
                        iw_client[iw_mac][info[0]] = IW(info[9])
                    elif info[0] not in iw_client[iw_mac]:
                        iw_client[iw_mac][info[0]] = IW(info[9])
                    else:
                        iw_client[iw_mac][info[0]].update(info[9])
                    k = info[0].find('tation ')
                    if k != -1:
                        info[0] = info[0][7:7 + 17]
                    # print info[0][0:12], info[0][0:13], info[0][0:14],
                    # info[0][0:15], info[0][0:16], info[0][0:17], 'bbbb'
                    info[0] = info[0][0:17]
                    tmp = list(info[0])
                    k = 0
                    while (k < len(tmp)):
                        if tmp[k] == ':':
                            tmp.pop(k)
                        k = k + 1
                    info[0] = "".join(tmp)
                    # print info[0], 'fuck'
                    k = info[1].find(' ms')
                    if k != -1:
                        info[1] = int(info[1][0:0 + k])
                    for k in range(2, 7):
                        info[k] = int(info[k])

                    info[9] = int(info[9][0:0 + 3])
                    info[8] = int(info[8][0:0 + 3])
                    k = info[10].find(' MBit')
                    if k != -1:
                        info[10] = float(info[10][0:0 + k])
                    k = info[11].find(' MBit')
                    if k != -1:
                        info[11] = float(info[11][0:0 + k])
                    k = info[12].find('Mbps')
                    if k != -1:
                        info[12] = float(info[12][0:0 + k])
                    k = info[19].find(' secon')
                    if k != -1:
                        info[19] = int(info[19][0:0 + k])
                    # print info[0]
                    values = [info[0], info[1], info[2], info[3], info[4],
                              info[5], info[6], info[7], info[
                                  8], info[9], info[10],
                              info[11], info[12], info[13], info[
                                  14], info[15], info[16],
                              info[17], info[18], info[19], iw_mac]
                    l = get_links(values)
                    print l
                    cur.execute("insert into iw (Station, intactive_time,\
                     rx_bytes, rx_packets, tx_bytes, tx_packets, tx_retries,\
                      tx_failed, S_signal, S_signal_avg, tx_bitrate,\
                       rx_bitrate, expected_throughput, authorized,\
                        authenticated, preamble, WMM_WME, MFP, TDLS_peer,\
                         connected_time, mac_addr) VALUES (%s,%s,%s,%s,\
                         %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                values)
                    con.commit()
        conn.close()
    # for mac_addr2 in ap_client:
        # print mac_addr2
        # for bssid2 in ap_client[mac_addr2]:
        #     print ap_client[mac_addr2][bssid2]

cur.close()
con.close()
