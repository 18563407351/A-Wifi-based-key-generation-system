#!/usr/bin/env python
# -*- coding: utf-8 -*-​

import logging
import os
import time
from datetime import datetime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket
import json
from statistics import mean, StatisticsError

import bchlib
import binascii
import numpy as np
import hashlib
import math

import Tkinter as tk
import tkFont as tf
from PIL import Image
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.backend_bases import key_press_handler
from matplotlib.figure import Figure
import matplotlib.image as mpimg
import matplotlib.animation as animation
import threading 
import ttk
import tkMessageBox as msg

import FrequencyTest as FT
import CumulativeSum as CS
import RunTest as RT
import Serial
import ApproximateEntropy as AE

import sys
from Crypto.Cipher import AES
from binascii import b2a_hex


class Key_Generation :
    
    def __init__(self, master) :
        self.master = master
        self.master.title("Key Generation")
        self.master.geometry("800x480+0+0")

        self.master.rowconfigure(0, weight=2)
        self.master.rowconfigure(1, weight=60)
        self.master.rowconfigure(2, weight=170)
        self.master.rowconfigure(3, weight=10)
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=35)
        
        # logo and title frame
        self.title_frame = tk.Frame(self.master, bg="white", bd=1)
        self.title_frame.grid(row=0, column=0, columnspan=3, sticky=tk.NSEW)
        self.title_frame.rowconfigure(0, weight=1)
        self.title_frame.columnconfigure(0, weight=1)
        self.title_frame.columnconfigure(1, weight=6)

        titlefont = tf.Font(family="Times New Roman", size=12, weight=tf.BOLD)
        self.mytitle = tk.Label(self.title_frame, fg="black", bg="white",text="A WiFi-based Key Generation System", font=titlefont)
        self.mytitle.grid(row=0, column=1, columnspan=2, sticky=tk.NSEW)

        self.logo = tk.PhotoImage(file="logo.gif")
        self.sch_logo = tk.Label(self.title_frame, bg="white", image=self.logo)
        self.sch_logo.grid(row=0, column=0, sticky=tk.NSEW)

        # button frame
        self.button_frame = tk.Frame(self.master, bg="white")
        self.button_frame.grid(row=1, rowspan=3, column=0, sticky=tk.NSEW)
        self.button_frame.rowconfigure(0, weight=1)
        self.button_frame.rowconfigure(1, weight=1)
        self.button_frame.rowconfigure(2, weight=1)
        self.button_frame.rowconfigure(3, weight=1)
        self.button_frame.rowconfigure(4, weight=1)
        self.button_frame.rowconfigure(5, weight=1)
        self.button_frame.rowconfigure(6, weight=1)   
        self.button_frame.rowconfigure(7, weight=1) 
        self.button_frame.rowconfigure(8, weight=1)  
        self.button_frame.columnconfigure(0, weight=1)

        # set up entry
        self.setup_frame = tk.LabelFrame(self.button_frame, text="Set up", bg="WhiteSmoke", bd=2)
        self.setup_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.setup_frame.rowconfigure(0, weight=1)
        self.setup_frame.rowconfigure(1, weight=1)
        self.setup_frame.columnconfigure(0, weight=1)
        self.setup_frame.columnconfigure(1, weight=1)
        
        setup_font = tf.Font(family="Times New Roman", size=10, weight=tf.BOLD)    
        self.setup_interval = tk.Label(self.setup_frame, text="Interval (s)", fg="black", bg="WhiteSmoke", font=setup_font)
        self.setup_interval.grid(row=0, column=0)
        self.interval_value = tk.DoubleVar(self.setup_frame)
        self.interval_value.set(0.5)
        self.interval_entry = tk.Entry(self.setup_frame, textvariable=self.interval_value, bd=3, width=12)
        self.interval_entry.grid(row=0, column=1)

        self.setup_number = tk.Label(self.setup_frame, text="No. pkt", fg="black", bg="WhiteSmoke", font=setup_font)
        self.setup_number.grid(row=1, column=0)
        self.number_value = tk.IntVar(self.setup_frame)
        self.number_value.set(150)
        self.number_entry = tk.Entry(self.setup_frame, textvariable=self.number_value, bd=3, width=12)
        self.number_entry.grid(row=1, column=1)


        # button control
        button_font = tf.Font(family="Times New Roman", size=11, weight=tf.BOLD)
        self.bu_channel_pr = tk.Button(self.button_frame, text="Channel Probing", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.thread_cp)
        self.bu_channel_pr.grid(row=2, column=0)
        self.bu_packet_ma = tk.Button(self.button_frame, text="Packet Matching", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Packet_Matching)
        self.bu_packet_ma.grid(row=3, column=0)
        self.bu_quanti = tk.Button(self.button_frame, text="Quantization", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Quantization)
        self.bu_quanti.grid(row=4, column=0)
        self.bu_info_recon = tk.Button(self.button_frame, text="Information Reconciliation", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Info_Recon)
        self.bu_info_recon.grid(row=5, column=0)
        self.bu_privacy_amp = tk.Button(self.button_frame, text="Privacy Amplification", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Privacy_Amp)
        self.bu_privacy_amp.grid(row=6, column=0)
        self.test = tk.Button(self.button_frame, text="Test", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Test)
        self.test.grid(row=7, column=0)        
        self.bu_reset = tk.Button(self.button_frame, text="Reset", font=button_font, width=23, height=1, bg="LightGrey", activeforeground='red', command=self.Reset)
        self.bu_reset.grid(row=8, column=0)
        

        # main display
        self.main_frame = tk.LabelFrame(self.master, text='Key Generation', bg="WhiteSmoke")
        self.main_frame.grid(row=1, rowspan=2, column=1, sticky=tk.NSEW)
        
        self.fig = Figure(figsize=(5, 2), dpi=60)
        self.fig_plot = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, self.main_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)
        #self.toolbar = NavigationToolbar2TkAgg(self.canvas, self.main_frame)
        #self.toolbar.update()
        

        # Data
        self.data_frame = tk.LabelFrame(self.master, bg="White", text="Statistic")
        self.data_frame.grid(row=3, column=1, sticky=tk.NSEW)
        self.data_frame.rowconfigure(0, weight=1)
        self.data_frame.columnconfigure(0, weight=1)

        self.data = ttk.Treeview(self.data_frame, show="headings")
        self.data.grid(row=0, column=0, sticky=tk.NSEW)
        self.data['columns'] = ('STA side', 'Results')
        self.data['height'] = 3
        self.data.column("STA side", width=120, anchor='center')
        self.data.column("Results", width=10, anchor='center')
        self.data.heading("STA side", text="Station side")
        self.data.heading("Results", text="Results")

        self.pkt_num = self.data.insert('', 0, values=('number of packet received',))
        self.matched_num = self.data.insert('', 1, values=('number of packet after matching',))

        self.ani = animation.FuncAnimation(self.fig, self.animate, interval=100)
 
        self.timestamp=[]
        self.rssi=[]
        self.time_array=([])
        self.rssi_array=([])
        self.matched_ts_sta = []
        self.matched_rssi = []
        self.matched_ts_array=([])
        self.matched_rssi_array=([])

    def channel_probing(self) :
        intfmon='wlan1mon'        # wireless interface on monitor mode
        dst=bssid='00:c0:ca:98:12:58'    # destination MAC address
        apssid='Raspberry_AP'     
        src='00:c0:ca:98:12:b8'    # source MAC address
        self.flag=0
        self.sc=-1
        self.bootime=time.time()
        self.count=0

        # construct probe response frame
        def ProbeReq(src,apssid,dst,bssid, intfmon):
            verbose = 0
            
	        essid = Dot11Elt(ID='SSID',info=apssid, len=len(apssid))
	        WPS_ID = "\x00\x50\xF2\x04"
	        WPS_Elt = Dot11Elt(ID=221,len=9,info="%s\x10\x4a\x00\x01\x10" % WPS_ID)
	        dsset = Dot11Elt(ID='DSset',info='\x01')
	        pkt =  RadioTap()/Dot11(type=0,subtype=4,addr1=dst,addr2=src,addr3=bssid)\
	        /Dot11ProbeReq()/essid/WPS_Elt/dsset
	        # Update timestamp
	        pkt.timestamp = current_timestamp()
            ## Update sequence number
	        pkt.SC = next_sc()
            if verbose: pkt.show()
	        try:
	            sendp(pkt,iface=intfmon,count=1,verbose=verbose)
                myt = datetime.now()
                print('%s Send Probe Request to ESSID=[%s],BSSID=%s') % (myt, apssid, bssid)
	        except:
	            raise


        def current_timestamp():
	        return (time.time() - self.bootime) * 1000000

        def next_sc():
	        self.sc = (self.sc + 1) % 4096
	        return self.sc * 16  # Fragment number -> right 4 bits

        def PacketHandler(pkt) :
            if pkt.haslayer(RadioTap) :
                if pkt.type == 0 and pkt.subtype == 5:  ## probe response
                    if pkt.addr2.upper() == dst.upper() and pkt.addr1.upper() == src.upper() :
                        self.count += 1
	                    myt = datetime.now()
                        self.timestamp.append(myt)
                        print("%s Received a probe response from AP %s RSSI %sdBm") % (myt, pkt.addr2, pkt[RadioTap].dBm_AntSignal)
                        self.flag = 1
                        rssi = pkt[RadioTap].dBm_AntSignal   # obtain RSSI
                        self.rssi.append(int(rssi))
                        f = open("STA.txt","a")
                        f.write(str(myt))
                        f.write(" ")
                        f.write(str(rssi))
                        f.write("\n")
                        f.close() 


        def stopfilter(x) :
       
            if self.flag == 1 :
                self.flag = 0
                return True
            else :
                return False


        i = 0
        fa = open("STA.txt","w")
        fa.close()
        times = self.number_value.get()
        interval = self.interval_value.get()
        while i < times : 
            ProbeReq(src, apssid,dst,bssid, intfmon)
            sniff(iface=intfmon, prn = PacketHandler, stop_filter=stopfilter, timeout=3)
            self.time_array=np.array(self.timestamp)
            self.rssi_array=np.array(self.rssi)
            time.sleep(interval)
            i += 1

        self.ani.event_source.stop()

        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('number of packet received', self.count))

        return self.time_array, self.rssi_array



    def Packet_Matching(self) :
        
        fmt = "%Y-%m-%d %H:%M:%S.%f"   # timestamp format

        f1 = open("STA.txt", "r")
        f2 = open("matchedsta.txt", "w+")

        def parse_datetime(line, fmt) :
        # parse timestamp with date from a string 

            try :
                t = datetime.strptime(line, fmt)
            except ValueError as v : 
                if len(v.args) > 0 and v.args[0].startswith('unconverted data remains: ') :
                    line = line[: - (len(v.args[0]) - 26)]
                    t = datetime.strptime(line, fmt)
                else :
                    raise

            return t
 
        timest = []

        for linef1 in f1 :
            linef1 = linef1.strip('\n')
            timest.append(parse_datetime(linef1, fmt))

        data = ' '.join(map(str, timest))

        se_data = json.dumps(data).encode()
        le_data = json.dumps(len(se_data)).encode()

        s = socket.socket()
        self.host = "10.184.195.158"
        self.port = 12345

        s.connect((self.host, self.port))

        while True :
            buf1 = s.recv(1024)

            if buf1 :
                s.send(le_data)
                time.sleep(2)
                s.send(se_data)
                break

        print("Finish sending")
        print("start receiving")

        recvd = ""

        length = json.loads(s.recv(1024).decode())

        num_index = int(length/1024) + 2

        for i in range(0, num_index) :
            recvd = recvd + s.recv(1024).decode()

        match_data = json.loads(recvd)
        print("Finish receiving")
        s.close

        span = 2
        words = match_data.split(" ")

        fmt_ts = [" ".join(words[i : i+span]) for i in range(0, len(words), span)]

        match_ts = []

        for i in range(0, len(fmt_ts)) :
            match_ts.append(datetime.strptime(fmt_ts[i], fmt))


        f1.seek(0)
        for linef1 in f1 :
            linef1 = linef1.strip('\n')
            t1 = parse_datetime(linef1, fmt)
            for t2 in match_ts :
                diff = t1 - t2 
                if abs(diff.total_seconds()) == 0 :
                    f2.write(linef1 +'\n')

        print("Finish matching")

        f1.close

        f2.seek(0)
        for linef2 in f2 :
            linef2 = linef2.strip('\n')
            columns = linef2.split(" ")
            self.matched_ts_sta.append(parse_datetime(linef2, fmt))
            if len(columns) > 2 :
                self.matched_rssi.append(int(columns[2]))
         
        f2.close
        print(self.matched_ts_sta, self.matched_rssi)
        
        self.matched_ts_array=np.array(self.matched_ts_sta)
        self.matched_rssi_array=np.array(self.matched_rssi)

        self.fig_plot.clear()
        self.fig_plot.plot(self.matched_ts_array, self.matched_rssi_array,'k')
        self.fig_plot.set_xlabel('timestamp', fontsize=14)
        self.fig_plot.set_ylabel('Received Signal Strength (dBm)', fontsize=14)
        self.fig_plot.set_title('Channel Probing', size=16)
        self.canvas.draw()

        data_get_index = self.data.get_children()
        self.data.item(data_get_index[1], values=('number of packet after matching', len(self.matched_rssi)))        

        return self.matched_ts_array, self.matched_rssi_array, self.fig_plot

    

    def Quantization(self) :

        self.fig_plot.clear()
        self.fig_plot.axis('off')

        rs = []
        quantized_rs = []

        try :
            rs = list(map(int, self.matched_rssi))
            avg = mean(rs)
        except StatisticsError, e :
            msg.showinfo("Information", "0 packet collected. Please reset and restart Channel Probing.")

        # mean-based threshold
        for r1 in rs :           
            if r1 >= avg :   
                quantized_rs.append(1)
            else :
                quantized_rs.append(0)

        print "length of quantized rssi is :", len(quantized_rs)
        print "quantized rssi is :", quantized_rs

        shaped_length = int(math.sqrt(len(quantized_rs)))
        del quantized_rs[int(math.pow(shaped_length, 2)):]

        print "shaped key length:", len(quantized_rs)

        self.quantized_rs = quantized_rs
        self.quantized_rs_str = ''.join(str(i) for i in quantized_rs)

        se_data = json.dumps(self.quantized_rs_str).encode()
        le_data = json.dumps(len(se_data)).encode()

        s = socket.socket()
        self.host = "10.184.195.158"
        self.port = 12345

        s.connect((self.host, self.port))

        while True :
            buf1 = s.recv(1024)

            if buf1 :
                s.send(le_data)
                time.sleep(2)
                s.send(se_data)
                break

        print("Finish sending")
        print("start receiving")
        self.kdr_value = s.recv(1024)
        print "KDR: ", self.kdr_value
        s.close

        shaped_array = np.array(quantized_rs).reshape((shaped_length, shaped_length))
        
        quan_fig = plt.figure(figsize=(1, 1))
        quan_fig_plot = plt.subplot(1, 1, 1)
        quan_fig_plot.axes.get_xaxis().set_visible(False)
        quan_fig_plot.axes.get_yaxis().set_visible(False)
        quan_fig_plot.imshow(shaped_array, extent=[0, 100, 0, 1], aspect=100, cmap=plt.cm.gray_r)
        quan_fig.savefig("quantized.png", dpi=quan_fig.dpi)

        img = mpimg.imread("quantized.png")
        self.fig_plot = self.fig.add_subplot(131)
        self.fig_plot.imshow(img)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Quantiztion", size=15)
        self.fig.tight_layout()
        self.canvas.draw()
     
        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('length of key after quantization', len(quantized_rs)))
        self.data.item(data_get_index[1], values=('key disagreement rate', self.kdr_value))


    def Info_Recon(self) :     # information reconciliation

        try :
            key = self.quantized_rs
            key=np.array(key)
        except AttributeError, e:
            msg.showinfo("Information", "No quantized key. Please reset and restart Channel Probing.")

        # create a BCH object
        BCH_POLYNOMIAL = 1033
        BCH_BITS = int(0.25*len(key))
        bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

        # random data
        C_data = bytearray(os.urandom(int((bch.n-bch.ecc_bits)/8)))  
        # encode and make a packet
        C_ecc = bch.encode(C_data) 
        C_packet=C_data+C_ecc
        S_packet=C_data+C_ecc  


        # Exclusive OR
        for i in range(0,int(len(key)/8)+1):
            if i<=int(len(key)/8)-1:
        	    decimal=int((key[0+i*8]*2)**7+(key[1+i*8]*2)**6+(key[2+i*8]*2)**5+(key[3+i*8]*2)**4+(key[4+i*8]*2)**3+(key[5+i*8]*2)**2+(key[6+i*8]*2)**1)
                if key[7+i*8]==1:
                    decimal=decimal+1
                S_packet[i]^=decimal

            else:
                byte=[]
                for j in range(0,len(key)%8):
                    byte.append(key[j+i*8])
                for j in range(0,8-len(key)%8):
                    byte.append(0)
                decimal=int((byte[0]*2)**7+(byte[1]*2)**6+(byte[2]*2)**5+(byte[3]*2)**4+(byte[4]*2)**3+(byte[5]*2)**2+(byte[6]*2)**1)
                S_packet[i]^=decimal

        s=[]   
 
        for i in range(0,len(S_packet)):
            s.append(S_packet[i])

        json_string=json.dumps(s).encode()  
        length=json.dumps(len(json_string)).encode()  

        
        s = socket.socket() 
        host = "192.168.43.11"
        port = 12345

        s.connect((self.host, self.port))
        

        flag=True

        while flag:
            buf1=s.recv(1024)  # ready for sending
            if buf1:
                s.send(length) 
                time.sleep(2)
                s.send(json_string)  
                break;

        print(key)

        recvd = s.recv(1024).decode()
        crc_ap = json.loads(recvd)
        print "CRC AP: ", crc_ap


        # cyclic redundancy check (CRC)
        key_str = ''.join(str(i) for i in key)
        int_key = [int(key_str[i:i+8], 2) for i in range(0, len(key_str), 8)]
        crc_key = hex(binascii.crc32(bytes(int_key)) & 0xffffffff)
        print "CRC STA: ", crc_key

        crc_ap_int = int(crc_ap, 16)
        crc_sta_int = int(crc_key, 16)

        if crc_ap_int == crc_sta_int :    
            print "CRC are the same"
            s.send("y")
        else :
            s.send("n")
            msg.showinfo("Warning", "Cannot correct all keys. Please reset and restart Key Generation.")


        s.close

        self.info_recon = key   

        qr_key = list(key)
        length_qr = int(math.sqrt(len(qr_key)))
        del qr_key[int(math.pow(length_qr, 2)):]
        shaped_array = np.array(qr_key).reshape((length_qr, length_qr))
        
        info_fig = plt.figure(figsize=(1, 1))
        info_fig_plot = plt.subplot(1, 1, 1)
        info_fig_plot.axes.get_xaxis().set_visible(False)
        info_fig_plot.axes.get_yaxis().set_visible(False)
        info_fig_plot.imshow(shaped_array, extent=[0, 100, 0, 1], aspect=100, cmap=plt.cm.gray_r)
        info_fig.savefig("info_recon.png", dpi=info_fig.dpi)

        img = mpimg.imread("info_recon.png")
        self.fig_plot = self.fig.add_subplot(132)
        self.fig_plot.imshow(img)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Information Reconciliation", size=15)
        self.fig.tight_layout()
        self.canvas.draw()
        
        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('length of key after information reconciliation', len(qr_key)))
        self.data.item(data_get_index[1], values=('CRC code', crc_key))

        return self.fig_plot


  
    def Privacy_Amp(self) :
        
        try :
            bi_array = self.info_recon
        except AttributeError, e:
            msg.showinfo("Information", "Lack of steps. Please reset and restart Channel Probing.")

        bi_list = list(bi_array)

        bi_str = ''.join(str(i) for i in bi_array)

        hex_str = "{0:0>4X}".format(int(bi_str, 2))

        if len(hex_str) % 2 != 0 :
            hex_str = "0" + hex_str

        data = binascii.a2b_hex(hex_str)

        hash_hex = hashlib.sha256(data).hexdigest()

        bi_hash = bin(int(hash_hex, 16))[2:]

        hash_list = [int(i) for i in bi_hash]

        len_key = int(math.sqrt(len(bi_list)))
        len_hash = int(math.sqrt(len(hash_list)))

        if len_key<= len_hash :
           len_hash = len_key

        del hash_list[int(math.pow(len_key, 2)):]

        str_hash = ''.join([str(i) for i in hash_list])

        print "key after privacy amplification: ", str_hash

        self.str_hash = str_hash

        shaped_array = np.array(hash_list).reshape((len_key, len_key))
        
        hash_fig = plt.figure(figsize=(1, 1))
        hash_fig_plot = plt.subplot(1, 1, 1)
        hash_fig_plot.axes.get_xaxis().set_visible(False)
        hash_fig_plot.axes.get_yaxis().set_visible(False)
        hash_fig_plot.imshow(shaped_array, extent=[0, 100, 0, 1], aspect=100, cmap=plt.cm.gray_r)
        hash_fig.savefig("privacy_amp.png", dpi=hash_fig.dpi)

        img = mpimg.imread("privacy_amp.png")
        self.fig_plot = self.fig.add_subplot(133)
        self.fig_plot.imshow(img)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Privacy Amplification", size=15)
        self.fig.tight_layout()
        self.canvas.draw()

        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('length of key after privacy amplification', len(hash_list)))
        self.data.delete(data_get_index[1])

        return self.fig_plot


    def thread_cp(self) :
        threading.Thread(target=self.channel_probing).start()

    def animate(self, i) :
        self.fig_plot.clear()
        self.fig_plot.plot(self.time_array, self.rssi_array,'k')
        self.fig_plot.set_xlabel('timestamp', fontsize=14)
        self.fig_plot.set_ylabel('Received Signal Strength (dBm)', fontsize=14)
        self.fig_plot.set_title('Channel Probing', size=16)
        self.canvas.draw()

        return self.fig_plot

    def Test(self) :

        try :
            monobit_test_quant = FT.FrequencyTest.monobit_test(self.quantized_rs_str, True)
        except AttributeError, e :
            msg.showinfo("Information", "Lack of data. Please reset and restart Channel Probing.")
       
        # monobit test results
        re_monobit_test_quant = round(monobit_test_quant[0], 4)
        monobit_test_pri = FT.FrequencyTest.monobit_test(self.str_hash, True)
        re_monobit_test_pri = round(monobit_test_pri[0], 4)

        # block frequency
        block_freq_quant = FT.FrequencyTest.block_frequency(binary_data=self.quantized_rs_str, block_size=128, verbose=True)
        re_block_freq_quant = round(block_freq_quant[0], 4)
        block_freq_pri = FT.FrequencyTest.block_frequency(binary_data=self.str_hash, block_size=128, verbose=True)
        re_block_freq_pri = round(block_freq_pri[0], 4)

        # Cum.Sum (fwd)
        cum_sum_fwd_quant = CS.CumulativeSums.cumulative_sums_test(self.quantized_rs_str, 0, True)
        re_cum_sum_fwd_quant = round(cum_sum_fwd_quant[0], 4)
        cum_sum_fwd_pri = CS.CumulativeSums.cumulative_sums_test(self.str_hash, 0, True)
        re_cum_sum_fwd_pri = round(cum_sum_fwd_pri[0], 4)

        # Cum.Sum (rev)
        cum_sum_rev_quant = CS.CumulativeSums.cumulative_sums_test(self.quantized_rs_str, 1, True)
        re_cum_sum_rev_quant = round(cum_sum_rev_quant[0], 4)
        cum_sum_rev_pri = CS.CumulativeSums.cumulative_sums_test(self.str_hash, 1, True)
        re_cum_sum_rev_pri = round(cum_sum_rev_pri[0], 4)

        # run test
        run_test_quant = RT.RunTest.run_test(self.quantized_rs_str, True)
        re_run_test_quant = round(run_test_quant[0], 4)
        run_test_pri = RT.RunTest.run_test(self.str_hash, True)
        re_run_test_pri = round(run_test_pri[0], 4)
   
        # longest one block test
        longest_block_quant = RT.RunTest.longest_one_block_test(self.quantized_rs_str, True)
        re_longest_block_quant = round(longest_block_quant[0], 4)
        longest_block_pri = RT.RunTest.longest_one_block_test(self.str_hash, True)
        re_longest_block_pri = round(longest_block_pri[0], 4)

        # Serial 1 2
        serial_quant = Serial.Serial.serial_test(self.quantized_rs_str, True, 16)
        re_serial1_quant = round(serial_quant[0][0], 4)
        re_serial2_quant = round(serial_quant[1][0], 4)
        serial_pri = Serial.Serial.serial_test(self.str_hash, True, 16)
        re_serial1_pri = round(serial_pri[0][0], 4)
        re_serial2_pri = round(serial_pri[1][0], 4)

        # ApproximateEntropy
        approx_entropy_quant = AE.ApproximateEntropy.approximate_entropy_test(self.quantized_rs_str, True, 10)
        re_approx_entropy_quant = round(approx_entropy_quant[0], 4)
        approx_entropy_pri = AE.ApproximateEntropy.approximate_entropy_test(self.str_hash, True, 10)
        re_approx_entropy_pri = round(approx_entropy_pri[0], 4)



        self.main_frame = tk.LabelFrame(self.master, text='Key Generation Results', bg="WhiteSmoke", bd=2)
        self.main_frame.grid(row=1, column=1, sticky=tk.NSEW)
        
        self.fig = Figure(figsize=(7, 3), dpi=30)
        self.canvas = FigureCanvasTkAgg(self.fig, self.main_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)

        img1 = mpimg.imread("quantized.png")
        img2 = mpimg.imread("info_recon.png")
        img3 = mpimg.imread("privacy_amp.png")
        self.fig_plot = self.fig.add_subplot(131)
        self.fig_plot.imshow(img1)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Quantization", size=22)    

        self.fig_plot = self.fig.add_subplot(132)
        self.fig_plot.imshow(img2)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Information Reconciliation", size=22)       

        self.fig_plot = self.fig.add_subplot(133)
        self.fig_plot.imshow(img3)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Privacy Amplification", size=22)
        #self.fig.tight_layout()
        self.canvas.draw()


        self.data_frame = tk.Frame(self.master, bg="White")
        self.data_frame.grid(row=2, rowspan=2, column=1, sticky=tk.NSEW)

        self.data_frame.rowconfigure(0, weight=1)
        self.data_frame.columnconfigure(0, weight=7)
        self.data_frame.columnconfigure(1, weight=1)

        # Randomness Test
        self.data = ttk.Treeview(self.data_frame, show="headings")
        self.data.grid(row=0, column=0, sticky=tk.NSEW)
        self.data['columns'] = ('Randomness Test', 'Quant', 'Priv. Amp')
        self.data['height'] = 5
        self.data.column("Randomness Test", width=70, anchor='center')
        self.data.column("Quant", width=15, anchor='center')
        self.data.column('Priv. Amp', wid=15, anchor='center')
        self.data.heading("Randomness Test", text="Randomness Test")
        self.data.heading("Quant", text="Quant")
        self.data.heading('Priv. Amp', text='Priv. Amp')
        #self.data.pack(fill=tk.BOTH, expand=1)

        self.monobit_test = self.data.insert('', 0, values=('Monobit test', re_monobit_test_quant, re_monobit_test_pri), tag=('odd',))
        self.block_freq = self.data.insert('', 1, values=('Block frequency', re_block_freq_quant, re_block_freq_pri), tag=('even',))
        self.cum_fwd = self.data.insert('', 2, values=('Cum.sums (fwd)', re_cum_sum_fwd_quant, re_cum_sum_fwd_pri), tag=('odd',))
        self.cum_rev = self.data.insert('', 3, values=('Cum.sums (rev)', re_cum_sum_rev_quant, re_cum_sum_rev_pri), tag=('even',))
        self.runs = self.data.insert('', 4, values=('Runs', re_run_test_quant, re_run_test_pri), tag=('odd',))
        self.longest_block = self.data.insert('', 5, values=('Longest one block', re_longest_block_quant, re_longest_block_pri), tag=('even',))
        self.serial1 = self.data.insert('', 6, values=('Serial 1', re_serial1_quant, re_serial1_pri), tag=('odd',))
        self.serial2 = self.data.insert('', 7, values=('Serial 2', re_serial2_quant, re_serial2_pri), tag=('even',))
        self.appro_entry = self.data.insert('', 8, values=('Approx.entropy', re_approx_entropy_quant, re_approx_entropy_pri), tag=('odd',))


        self.data.tag_configure('odd', background='White')
        self.data.tag_configure('even', background='WhiteSmoke')

        # Encryption Test
        self.encrypt_test = tk.LabelFrame(self.data_frame, text='Encryption Test', bg="White", bd=2)
        self.encrypt_test.grid(row=0, column=1, sticky=tk.NSEW)
    
        self.encrypt_test.rowconfigure(0, weight=1)
        self.encrypt_test.rowconfigure(1, weight=2)
        self.encrypt_test.rowconfigure(2, weight=1)
        self.encrypt_test.columnconfigure(0, weight=1)
        self.encrypt_test.columnconfigure(1, weight=1)

        encrypt_font = tf.Font(family="Times New Roman", size=12)
        self.info = tk.Label(self.encrypt_test, text="Please enter the text to be encrypted", fg="black", bg="White", font=encrypt_font)
        self.info.grid(row=0, column=0, columnspan=2)
        self.text = tk.Text(self.encrypt_test, width='25', height='5')
        self.text.grid(row=1, column=0, columnspan=2, sticky=tk.N)
        self.clear_button = tk.Button(self.encrypt_test, text="Clear", font=encrypt_font, bg="WhiteSmoke", activeforeground="red", command=self.clear)
        self.clear_button.grid(row=2, column=0, sticky=tk.N)
        self.encrypt_button = tk.Button(self.encrypt_test, text="Encryption", font=encrypt_font, bg="WhiteSmoke", activeforeground="red", command=self.Encryption)
        self.encrypt_button.grid(row=2, column=1, sticky=tk.N)
        

    def Reset(self) :

        self.ani.event_source.start()

        # main display
        self.main_frame = tk.LabelFrame(self.master, text='Key Generation', bg="WhiteSmoke")
        self.main_frame.grid(row=1, rowspan=2, column=1, sticky=tk.NSEW)
        
        self.fig = Figure(figsize=(5, 2), dpi=60)
        self.fig_plot = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, self.main_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=1)
        

        # Data
        self.data_frame = tk.LabelFrame(self.master, bg="White", text="Statistic")
        self.data_frame.grid(row=3, column=1, sticky=tk.NSEW)
        self.data_frame.rowconfigure(0, weight=1)
        self.data_frame.columnconfigure(0, weight=1)

        self.data = ttk.Treeview(self.data_frame, show="headings")
        self.data.grid(row=0, column=0, sticky=tk.NSEW)
        self.data['columns'] = ('STA side', 'Results')
        self.data['height'] = 3
        self.data.column("STA side", width=120, anchor='center')
        self.data.column("Results", width=10, anchor='center')
        self.data.heading("STA side", text="Station side")
        self.data.heading("Results", text="Results")

        self.pkt_num = self.data.insert('', 0, values=('number of packet received',))
        self.matched_num = self.data.insert('', 1, values=('number of packet after matching',))

 
        self.timestamp=[]
        self.rssi=[]
        self.time_array=([])
        self.rssi_array=([])
        self.matched_ts_sta = []
        self.matched_rssi = []
        self.matched_ts_array=([])
        self.matched_rssi_array=([])


    def Encryption(self) :
 
        def encrypt(text):
            cryptor = AES.new(self.key, self.mode, self.key)
            length = 16
            count = len(text)
        
            if(count % length != 0) :
                add = length - (count % length)
            else:
                add = 0
            text = text + ('\0' * add)
            self.ciphertext = cryptor.encrypt(text)

            return b2a_hex(self.ciphertext)
 
 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "10.184.200.36"
        port = 12345
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        conn, addr = s.accept()
        print "connection address: ", addr
      
        h = hashlib.md5(self.str_hash)
        self.key = h.hexdigest()[8:-8]
        self.mode = AES.MODE_CBC

        text_str = self.text.get('0.0', 'end')
        e = encrypt(text_str)
        print "encrypted text: ", e
        se_data = json.dumps(e).encode()
        le_data = json.dumps(len(se_data)).encode()

        while True :
            buf1 = conn.recv(1024)
            if buf1 :
                conn.send(le_data)
                time.sleep(2)
                conn.send(se_data)
                break

        print "Finish sending"
        conn.close()
        s.close()


    def clear(self) :
        self.text.delete('0.0', 'end')


if __name__ == '__main__' :
    gui = tk.Tk()  
    k = Key_Generation(gui)
    gui.mainloop()

