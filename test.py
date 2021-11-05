from scapy.all import *
from threading import Thread
from nested_dict import nested_dict as nd
from datetime import datetime, timedelta, timezone
import threading
import time
import os
from module import process_probes
import logging

# datetime.now()
now = datetime.now()
Now = now.replace(microsecond=0)
dt = datetime.now()
start = dt
end = dt
# start2 = dt.replace(microsecond=0)
# end2 = dt.replace(microsecond=0)

after_one_second = now + timedelta(seconds=8)
# print("1초 후 :", after_one_second)

probes = nd(1, list)
seen_probes = set()

# Data is processed and sent to the server at every sent_interval
SENT_INTERVAL = 8


def getserial():
    # Extract serial from cpuinfo file
    cpuserial = "0000000000000000"
    try:
        f = open('/proc/cpuinfo', 'r')
        for line in f:
            if line[0:6] == 'Serial':
                cpuserial = line[10:26]
        f.close()
    except:
        cpuserial = "ERROR000000000"

    return cpuserial


cpuserial = getserial()

print(f'cpuserial:{cpuserial}')


def PacketHandler(packet):
    if packet.haslayer(Dot11ProbeReq):
        mac_addr = packet.addr2
        try:
            rssi = packet.dBm_AntSignal
        except:
            rssi = "N/A"
        # print(mac_addr, rssi)
        if mac_addr == '50:77:05:8C:7D:C8'.lower():
            print('found--------------------------------------------------')
        probes[mac_addr].append({'rssi': rssi})



def change_channel():
    channel = 1
    while True:
        try:
            os.system("iw dev %s set channel %d" % ('mon0', channel))
            channel = channel % 13 + 1
            time.sleep(0.5)
        except KeyboardInterrupt:
            break


channel_changer = Thread(target=change_channel)
channel_changer.daemon = True
channel_changer.start()


def push_count_data():
    print("scan start time : ", start)
    global probes

    f = open("test.log", 'a')
    f.write("\n")
    f.write("Probe : ")
    f.write(str(probes))
    f.write("\n")
    f.close()

    print('------------- Number of probes=', len(probes), ' -------------------$

    threading.Timer(SENT_INTERVAL, push_count_data).start()
    data=probes
    probes=nd(1, list)
    device_count=process_probes(data)

    count_data={
        "serial_number": cpuserial,
        "device_count": device_count
    }
    print("scan finish time : ", after_one_second)
    data.clear()
    print("average scan time : ", SENT_INTERVAL, "s", "\n")

def start_sniffing():
    sniff(iface="mon0", prn=PacketHandler, store=0)


def main():
    Thread(target=start_sniffing).start()
    time.sleep(SENT_INTERVAL)
    Thread(target=push_count_data).start()


if __name__ == "__main__":
    main()

