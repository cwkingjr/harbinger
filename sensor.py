from scapy.all import *
from datetime import datetime
import socket, os, re, sys, sqlite3

#TODO printing should probably use logging instead

global DB_FILENAME, conn
DB_FILENAME = 'node.db'

def open_db_connection():
    global DB_FILENAME, conn

    if not os.path.exists(DB_FILENAME): 
        # open and initialize the database

        print "Creating and initializing database file: %s" % DB_FILENAME

        conn = sqlite3.connect(DB_FILENAME)

        # cursor.execute("CREATE TABLE clients (id, node_id, macaddr, dstaddr, ssid, rssi, timestamp);")

        # clients table
        conn.execute('''CREATE TABLE clients
            (ID INTEGER PRIMARY KEY autoincrement NOT NULL,
            node_id char(20) NOT NULL,
            macaddr char(50) NOT NULL,
            dstaddr char(50) NOT NULL,
            ssid text NOT NULL,
            rssi char(4) NOT NULL,
            timestamp char(50) NOT NULL);''')

        # access points table
        conn.execute('''CREATE TABLE aps
            (ID INTEGER PRIMARY KEY autoincrement NOT NULL,
            node_id char(20) NOT NULL,
            macaddr char(50) NOT NULL,
            ssid text NOT NULL,
            rssi char(10) NOT NULL,
            timestamp char(50) NOT NULL);''')
    else:
        # just open the database
        print "Opening database file: %s" % DB_FILENAME
        conn = sqlite3.connect(DB_FILENAME)

def db_insert_client(mac, dstaddr, ssid, rssi, timestamp):
    global conn
    # TODO there is no domain validation of these variables. Do we trust this?
    conn.execute("insert into clients (node_id, macaddr, dstaddr, ssid, rssi, timestamp) values (?,?,?,?,?,?)", \
                ("test", mac, dstaddr, ssid, rssi, timestamp))
    conn.commit()

def db_insert_access_point(mac, ssid, rssi, timestamp) :
    global conn
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM aps WHERE macaddr=?", (mac,))
    dat = cursor.fetchone()
    if not dat:
        print "New AP found: %s" % (mac,)
        conn.execute("insert into aps (node_id, macaddr, ssid, rssi, timestamp) values (?,?,?,?,?)", \
                    ("test", mac, ssid, rssi, timestamp))
        conn.commit()

def PacketHandler(pkt):
    PROBE_REQUEST_TYPE = 0    # TODO what does 0 stand for?
    PROBE_REQUEST_SUBTYPE = 4 # TODO what does 4 stand for?

    if pkt.haslayer(Dot11) and pkt.type == PROBE_REQUEST_TYPE:
        if pkt.subtype == PROBE_REQUEST_SUBTYPE:
            process_client_packet(pkt)
        # TODO replace magic number 8 below with a variable name
        elif pkt.subtype == 8:
            process_access_point_packet(pkt)

def get_signal_strength(pkt):
    try:
        extra = pkt.notdecoded
    except:
        extra = None

    if extra:
        # TODO this section could use an explanation
        signal_strength = -(256 - ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print "No signal strength found"    

    return signal_strength

def process_client_packet(pkt):
    #print "Probe Request Captured:"
    sig_strength = get_signal_strength(pkt)
    print "Target: %s Source: %s SSID: %s RSSi: %d TIMESTAMP: %s" % \
          (pkt.addr3, pkt.addr2, pkt.getlayer(Dot11ProbeReq).info, sig_strength, datetime.now())
    db_insert_client(pkt.addr2, pkt.addr3, pkt.info, sig_strength, datetime.now())

def process_access_point_packet(pkt):
    sig_strength = get_signal_strength(pkt)
    db_insert_access_point(pkt.addr2, pkt.info, sig_strength, datetime.now())

def main():
    open_db_connection()

    print "[%s] Starting sensor sniff" % datetime.now()
    sniff(iface='mon0',prn=PacketHandler, store=0)

    # manuf is list of mac manufacturers, but isn't used yet
    #ouis = open("manuf").read().split('\n')

if __name__=="__main__":
    main()
