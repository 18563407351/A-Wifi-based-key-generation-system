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
import tkSimpleDialog as simpledialog

import FrequencyTest as FT
import CumulativeSum as CS
import RunTest as RT
import Serial 
import ApproximateEntropy as AE
import Spectral as ST
import Non_overlapping as NO

import sys
from Crypto.Cipher import AES
from binascii import a2b_hex
from Tkinter import StringVar

class Key_Generation :

    def __init__(self, master) :      
        
        self.master = master
        self.master.title("Key Generation")
        self.master.geometry("800x480+0+0")

        # divide the area into grids
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
        self.rcv_timeitle = tk.Label(self.title_frame, fg="black", bg="white",text="A WiFi-based Key Generation System", font=titlefont)
        self.rcv_timeitle.grid(row=0, column=1, columnspan=2, sticky=tk.NSEW)

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
        self.setup_frame.rowconfigure(2, weight=1)
        self.setup_frame.columnconfigure(0, weight=1)
        self.setup_frame.columnconfigure(1, weight=1)
        self.setup_frame.columnconfigure(2, weight=1)
        
        setup_font = tf.Font(family="Times New Roman", size=10, weight=tf.BOLD)    
        self.setup_number = tk.Label(self.setup_frame, text="  No. packet ", fg="black", bg="WhiteSmoke", font=setup_font)
        self.setup_number.grid(row=0, column=0)
        self.number_value = tk.IntVar(self.setup_frame)
        self.number_value.set(160)
        self.number_entry = tk.Entry(self.setup_frame, textvariable=self.number_value, width=12, bd=3)
        self.number_entry.grid(row=0, column=1)
        
        self.setup_channel = tk.Label(self.setup_frame, text="Channel", fg="black", bg="WhiteSmoke", font=setup_font)
        self.setup_channel.grid(row=2, column=0)
        self.channel_value = tk.IntVar(self.setup_frame)
        self.channel_value.set(165)
        self.channel_entry = tk.Entry(self.setup_frame, textvariable=self.channel_value, bd=3, width=12)
        self.channel_entry.grid(row=2, column=1)
        
        self.setup_key = tk.Label(self.setup_frame, text="Key length", fg="black", bg="WhiteSmoke", font=setup_font)
        self.setup_key.grid(row=1, column=0)
        self.key_value = tk.IntVar(self.setup_frame)
        self.key_value.set(128)
        self.key_entry = tk.Entry(self.setup_frame, textvariable=self.key_value, bd=3, width=12)
        self.key_entry.grid(row=1, column=1)


  
        # button control
        button_font = tf.Font(family="Times New Roman", size=11, weight=tf.BOLD)
        self.bu_channel_pr = tk.Button(self.button_frame, text="Channel Probing", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.thread_cp)
        self.bu_channel_pr.grid(row=1, column=0)
        self.bu_packet_ma = tk.Button(self.button_frame, text="Packet Matching", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Packet_Matching)
        self.bu_packet_ma.grid(row=2, column=0)
        self.bu_quanti = tk.Button(self.button_frame, text="Quantization", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Quantization_choose)
        self.bu_quanti.grid(row=3, column=0)
        self.bu_info_recon = tk.Button(self.button_frame, text="Information Reconciliation", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Info_Recon)
        self.bu_info_recon.grid(row=4, column=0)
        self.bu_privacy_amp = tk.Button(self.button_frame, text="Privacy Amplification", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Privacy_Amp)
        self.bu_privacy_amp.grid(row=5, column=0)
        self.test = tk.Button(self.button_frame, text="Test", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Test)
        self.test.grid(row=6, column=0)
        self.bu_reset = tk.Button(self.button_frame, text="Reset", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Reset)
        self.bu_reset.grid(row=7, column=0)
        self.bu_reset = tk.Button(self.button_frame, text="Quit", font=button_font, width=23, height=1, bg="LightGrey", activeforeground="red", command=self.Quit)
        self.bu_reset.grid(row=8, column=0)



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
        self.data['columns'] = ('AP side', 'Results')
        self.data['height'] = 4
        self.data.column("AP side", width=120, anchor='center')
        self.data.column("Results", width=10, anchor='center')
        self.data.heading("AP side", text="AP side")
        self.data.heading("Results", text="Results")

        self.frame_num = self.data.insert('', 0, values=('number of packet received',))
        self.matched_num = self.data.insert('', 3, values=('number of packet after matching',))
        self.frame_loss = self.data.insert('', 1, values=('number of packet loss',))
        self.frame_lossrate = self.data.insert('', 2, values=('packet loss rate',))

        self.animate = animation.FuncAnimation(self.fig, self.realtime_display, interval=100)
 
        self.timestamp=[]
        self.rssi=[]
        self.time_array=([])
        self.rssi_array=([])
        self.matched_rssi = []




    def channel_probing(self) :    # channel probing    
        interface = 'mon0'    # wireless interface on monitor mode
        destination = bssid = 'dc:a6:32:a2:7a:0c'      # destination MAC address
        ssid = 'Access Point'
        source= 'dc:a6:32:ca:6c:da'    # source MAC address
        self.bootime = time.time()
        self.sc = -1
        self.flag = 0  
        self.count=0

        # construct data frame
        def Dataframe(source, channel, ssid, destination, bssid, interface): 
            verbose = 0
            essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
            dsset = Dot11Elt(ID='DSset',info=chr(channel))
            frame =  RadioTap()/Dot11(type=2,subtype=0,addr1=destination,addr2=source,addr3=bssid)\
            /Dot11()/essid/dsset
            # Update timestamp
            frame.timestamp = current_timestamp()
            ## Update sequence number
            frame.SC = next_sc()    
            if verbose: frame.show()
            try:
                sendp(frame, iface=interface, verbose=verbose, count=1)
                rcv_time = datetime.now()
                print("%s send a data packet to STA %s") % (rcv_time, destination)
            except:
                raise
       

        def current_timestamp():
            return (time.time() - self.bootime) * 1000000

        def next_sc():
            self.sc = (self.sc + 1) % 4096
            return self.sc * 16  # Fragment number -> right 4 bits


        def PacketSniff(frame) :
            if frame.haslayer(RadioTap) :
                if frame.type ==2 and frame.subtype == 0:  ## data frame
                        if frame.addr2.upper() == destination.upper() and frame.addr1.upper() == source.upper() :#Lowercase to uppercase
                            self.count += 1
                            rcv_time = datetime.now()
                            timestamp.append(rcv_time)                          
                            print("%s Received a data packet from STA %s RSSI:%sdBm") % (rcv_time, frame.addr2, frame[RadioTap].dBm_AntSignal)
                            self.flag = 1
                            rssi.append(int(frame[RadioTap].dBm_AntSignal))
                            f = open("AP.txt","a")  ## open a file for writing
                            f.write(str(rcv_time)+" "+str(frame[RadioTap].dBm_AntSignal)+"\n")
                            f.close()  ## close the file

        # stop sniffing when receive the frame
        def stopfilter(x) :
            if self.flag == 1:      
                self.flag = 0
                return True  
        
            else :
                return False
       
        
        i = 0
        f_ap = open("AP.txt","w")
        f_ap.close()
        times = self.number_value.get()
        channel=self.channel_value.get()
        keylength=self.key_value.get()
        if keylength>times:
                msg.showinfo("Information", "Please select a key length less thant the number of packets")
                return
        else:
          timestamp=[]
          rssi=[]
          while i < times :
              sniff(iface=interface, prn=PacketSniff, stop_filter=stopfilter, timeout=3)
              #stop sniffing after 3 seconds
              Dataframe(source, channel, ssid, destination, bssid, interface)
              self.time_array=np.array(timestamp)
              self.rssi_array=np.array(rssi)
              i += 1
  


        self.animate.event_source.stop()
        loss=times-self.count
        lossrate=round(float(loss)/times,2)

        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('number of packet received', self.count))
        self.data.item(data_get_index[1], values=('number of packet loss', loss))
        self.data.item(data_get_index[2], values=('packet loss rate', lossrate))

        return self.time_array, self.rssi_array

    def Packet_Matching(self) :  # packet matching
        
        f1 = open("AP.txt", "r")
        f2 = open("matchedAP.txt", "w+")

        fmt = "%Y-%m-%d %H:%M:%S.%f"  # timestamp format

        recvd=""
        
        self.host = "192.168.3.13" #IP address of host
        self.port = 12345
        s =socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creat socket object
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))        
        s.listen(5)
        conn, addr = s.accept()
        print "connection address: " , addr

        conn.send(b'1')   # signal for receiving

        length=json.loads(conn.recv(1024).decode())  # decode the JSON data and receive the packet length first
        if length >= 1024 :
            num_index = int(length/1024) + 1
        else :
            num_index = 1

        #num_index=int(length/1024)+2   

        for i in range(0, num_index) :
            recvd = recvd + conn.recv(1024).decode()

        data = json.loads(recvd)
        print "Finish receiving"
        print(data)

        span = 2
        words = data.split(" ")    # separate data by " "

        ts = [" ".join(words[i:i+span]) for i in range(0, len(words), span)]
        # separate a string every two blank
        print(ts)

        sta_ts = []

        for i in range(0, len(ts)) :
            sta_ts.append(datetime.strptime(ts[i], fmt))

        def Read_datetime(line, fmt) : 
        # parse timestamp with date from a string 
            try :
                timestamp = datetime.strptime(line, fmt)
            except ValueError as v :
                if len(v.args) > 0 and v.args[0].startswith('unconverted data remains: ') :
                    line = line[: - (len(v.args[0]) - 26)]
                    timestamp = datetime.strptime(line, fmt)
                else : 
                    raise
            return timestamp


        match_times2 = []

        f1.seek(0)
        for linef1 in f1 : 
            linef1 = linef1.strip('\n')
            t1 = Read_datetime(linef1, fmt) 

            for t2 in sta_ts : 
            # compare the timestamps of Alice and Bob
                t_diff = t1 - t2
                if abs(t_diff.total_seconds() * 1000000) <= 280000 :
                    match_times2.append(t2)
                    f2.write(linef1 + '\n')

        match_data = ' '.join(map(str, match_times2))

        se_data = json.dumps(match_data).encode() #encode matched timestamps into json
        le_data = json.dumps(len(match_data)).encode() #encode length of matched timestamps into json

        conn.send(le_data) 
        time.sleep(2)
        conn.send(se_data)
        print("Finish sending")
        
        conn.close
        s. close

        f1.close

        f2.seek(0)

        # filter the timestamps
        matched_ts_ap=[]
        matched_rssi=[]
        for linef2 in f2 :
            linef2 = linef2.strip('\n')
            columns = linef2.split(" ")
            matched_ts_ap.append(Read_datetime(linef2, fmt))
            if len(columns) > 2 :
                matched_rssi.append(int(columns[2]))
        self.matched_rssi=matched_rssi
        f2.close
        print(matched_ts_ap, matched_rssi)
        ave=np.mean(matched_rssi)
        matched_ts_array=np.array(matched_ts_ap)
        matched_rssi_array=np.array(matched_rssi)

        self.fig_plot.clear()
        self.fig_plot.plot(matched_ts_array, matched_rssi_array,'k',color='red',marker='o')
        self.fig_plot.axhline(y=ave,color='red',ls='--')
        self.fig_plot.set_xlabel('timestamp', fontsize=13)
        self.fig_plot.set_ylabel('Received Signal Strength (dBm)', fontsize=14)
        self.fig_plot.set_title('Channel Probing', size=16)
        self.canvas.draw()

        data_get_index = self.data.get_children()
        self.data.item(data_get_index[3], values=('number of packet after matching', len(matched_rssi)))
        
        key_length=self.key_value.get()
        if len(self.matched_rssi)<key_length:
            msg.showinfo("Information", "Packet number is not enough. Please reset and restart channel probing.")
            

        return matched_ts_array, matched_rssi_array, self.fig_plot

    def Quantization_choose(self):
        #create the quantization method choosing frame
        self.tl=tk.Toplevel()
        self.tl.geometry("300x150+300+200")
        self.tl.title('Quantization')
        self.tl["background"]="LightGrey"
        tlfont = tf.Font(family="Times New Roman", size=13, weight=tf.BOLD)
        w=tk.Label(self.tl,text="Please choose the Quantization method",bg="LightGrey",font=tlfont).pack()
       
        self.x = tk.IntVar()
         
        self.result=0
        tk.Radiobutton(self.tl,text='1.Mean value-based',variable=self.x,value=1,indicatoron=0,bg="Aqua",command=self.Quantization_type).pack(ipadx=10,ipady=10)
        tk.Radiobutton(self.tl,text='2.Differential-based',variable=self.x,value=2,indicatoron=0,bg="Yellow",command=self.Quantization_type).pack(ipadx=10,ipady=10)
       
    def Quantization_type(self):
         #obtain the selection result of quantization method
         self.result=self.x.get()
         self.tl.destroy()
         self.Quantization()
    
        
    def Quantization(self):
   
        self.fig_plot.clear()
        self.fig_plot.axis('off')
        rs=[]
        quantized_rs = []      

        try :
            rs = list(map(int, self.matched_rssi))
        except StatisticsError, e:
            msg.showinfo("Information", "0 packet collected. Please reset and restart Channel Probing.")
        global result
        if self.result==1:

        # mean-based threshold
            average = mean(rs)
            for r1 in rs :
               if r1 >= average :
                   quantized_rs.append(1)
               else :
                   quantized_rs.append(0)

            print "length of quantized rssi is : ", len(quantized_rs)
            print "quantized rssi is : ", quantized_rs
        else:
            #Differential-based quantization
            quantized_rs=[]
            drop=[]
            a=rs[0]
            x=0
            for i in range(1,len(rs)) :
               if rs[i]>a+x:
                   quantized_rs.append(1)
               elif rs[i]<a-x:
                   quantized_rs.append(0)
               else:
                   quantized_rs.append(2)
                   drop.append(i-1)
               a=rs[i]
            print "length of quantized rssi is : ", len(quantized_rs)
            print "rssi is:", quantized_rs
            print(drop)

            drop_str=','.join(str(v) for v in drop)
            se_drop_str=json.dumps(drop_str).encode()

            s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.host = "192.168.3.13"
            self.port = 1234
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))

            s.listen(5)
            conn, addr = s.accept()
            print "connection address1: " , addr

            conn.send('1')
            drop_recvd=''

            drop_recvd = drop_recvd+conn.recv(1024).decode()#receive the dropped bits of Alice
            print"received:",drop_recvd
 
            print("Finish receiving")
            drop_recvd=eval(drop_recvd.encode('utf-8'))
            drop_recvd=drop_recvd.split(",")
            
            conn.send(se_drop_str)   # send dropped bits
            print("Finish sending")
            conn.close
            s.close
        
            #merge the dropped bits
            drop.extend(list(map(int,drop_recvd)))
            drop_mer=list(set(drop))
            drop_mer.sort()
            print(drop_mer)
        
            print(quantized_rs)
            #delete the dropped bits
            drop_mer.reverse()
            for d in drop_mer:
               del quantized_rs[d]
            print(quantized_rs)
    
        
                

        # reshape the key length
        key_length=self.key_value.get()
        if key_length>len(quantized_rs):
            msg.showinfo("Information", "Key length is not long enough.Please reset and restart channel probing")
            return

        del quantized_rs[key_length:]
        print "shaped key length:", len(quantized_rs)
        if int(math.sqrt(key_length))==math.sqrt(key_length):
            shaped_length=shaped_width=math.sqrt(key_length)
        else:
            shaped_length=2**((math.log(key_length,2)-1)/2)
            shaped_width=2**((math.log(key_length,2)+1)/2)
            
        
        self.quantized_rs_str = ''.join(str(i) for i in quantized_rs)
        self.quantized_rs = quantized_rs
        
        #creat socket object
        s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = "192.168.3.13"
        self.port = 12345
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))

        s.listen(5)
        conn, addr = s.accept()
        print "connection address2: " , addr

        conn.send('1')   

        length=json.loads(conn.recv(1024).decode())
         
        if length >= 1024 :
            num_index = int(length/1024) + 1
        else :
            num_index = 1

        recvd = ""
        for i in range(0, num_index) : 
            recvd = recvd + conn.recv(1024).decode()

        key_sta = json.loads(recvd)
     
        kdr_value = self.KDR(key_sta, self.quantized_rs_str)
        
        conn.send(str(kdr_value))   # send kdr
        conn.close
        s.close

        shaped_array = np.array(quantized_rs).reshape((int(shaped_length), int(shaped_width)))
        
        quan_fig = plt.figure(figsize=(1, 1))
        quan_fig_plot = plt.subplot(1, 1, 1)
        quan_fig_plot.axes.get_xaxis().set_visible(False)
        quan_fig_plot.axes.get_yaxis().set_visible(False)
        quan_fig_plot.imshow(shaped_array, extent=[0, 100, 0, 1], aspect=100, cmap=plt.cm.gray_r)
        # draw the bitmap, black represents '0', white means '1'
        quan_fig.savefig("quantized.png", dpi=quan_fig.dpi)
        
        shaped_array1 = np.array(self.diff).reshape((int(shaped_length), int(shaped_width)))
        quan_fig = plt.figure(figsize=(1, 1))
        quan_fig_plot = plt.subplot(1, 1, 1)
        quan_fig_plot.axes.get_xaxis().set_visible(False)
        quan_fig_plot.axes.get_yaxis().set_visible(False)
        quan_fig_plot.imshow(shaped_array1, extent=[0, 100, 0, 1], aspect=100, cmap=plt.cm.gray_r)
        # draw the bitmap, black represents '0', white means '1'
        quan_fig.savefig("diff.png", dpi=quan_fig.dpi)
        
        img1 = mpimg.imread("quantized.png")
        img2 = mpimg.imread("diff.png")
        self.fig_plot = self.fig.add_subplot(131)
        self.fig_plot.imshow(img1)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Quantiztion", size=15)
        self.fig_plot = self.fig.add_subplot(132)
        self.fig_plot.imshow(img2)
        self.fig_plot.axes.get_xaxis().set_visible(False)
        self.fig_plot.axes.get_yaxis().set_visible(False)
        self.fig_plot.set_title("Diff", size=15)
        self.fig.tight_layout()
        self.canvas.draw()
     
        data_get_index = self.data.get_children()
        self.data.item(data_get_index[0], values=('length of key after quantization', len(quantized_rs)))
        self.data.item(data_get_index[1], values=('key disagreement rate', kdr_value))
        self.data.delete(data_get_index[2])
        self.data.delete(data_get_index[3])

        return self.fig_plot
    
    def KDR(self, key_sta, key_ap):

        key_sta_list = [int(i) for i in key_sta]
        key_ap_list = [int(i) for i in key_ap]
        key_sta_array = np.array(key_sta_list)
        key_ap_array = np.array(key_ap_list)
        KDR = round(float(sum(abs(key_sta_array - key_ap_array))) / float(len(key_ap_array)), 3)
        print "KDR: ", KDR
        self.diff=(key_sta_array - key_ap_array)#obtain the key difference
        self.diff=abs(self.diff)
        print (self.diff)
        return KDR

 
    def Info_Recon(self) :     # information reconciliation
        
        try :
            key = self.quantized_rs
            key=np.array(key)
        except AttributeError, e:
            msg.showinfo("Information", "No quantized key. Please reset and restart Channel Probing.")

        received_info=""
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.port=12346
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))            
        s.listen(5)
        
        conn, addr = s.accept()

        print "connection address: ", addr

        conn.send(b'1')   

        length=json.loads(conn.recv(1024).decode())
       
        if length >= 1024 :
            num_index = int(length/1024) + 1
        else :
            num_index = 1

        #num_index = int(length/1024) + 2   

        for i in range(0, num_index):
            received_info=received_info+conn.recv(1024).decode()  

        received_info=json.loads(received_info) 

        Packet=bytearray()  

        for i in range(0,len(received_info)):
            Packet.append(received_info[i])


        # Exclusive OR 
        for i in range(0,int(len(key)/8)+1):
            if i<=int(len(key)/8)-1:
                decimal=int((key[0+i*8]*2)**7+(key[1+i*8]*2)**6+(key[2+i*8]*2)**5+(key[3+i*8]*2)**4+(key[4+i*8]*2)**3+(key[5+i*8]*2)**2+(key[6+i*8]*2)**1+(key[7+i*8]))
                Packet[i]^=decimal
            else:
                byte=[]
                for j in range(0,len(key)%8):
                    byte.append(key[j+i*8])
                for j in range(0,8-len(key)%8):
                    byte.append(0)
                decimal=int((byte[0]*2)**7+(byte[1]*2)**6+(byte[2]*2)**5+(byte[3]*2)**4+(byte[4]*2)**3+(byte[5]*2)**2+(byte[6]*2)**1)
                Packet[i]^=decimal 


        # create a BCH object
        BCH_POLYNOMIAL=1033
        BCH_BITS=int(0.25*len(key))
        bch=bchlib.BCH(BCH_POLYNOMIAL,BCH_BITS)

        # de-packetize
        Data, Ecc = Packet[:-bch.ecc_bytes], Packet[-bch.ecc_bytes:] 
        Bitflips, Correct_data, Correct_ecc= bch.decode(Data,Ecc)
        Correct_packet=Correct_data+Correct_ecc   


        # Exclusive OR
        for i in range(0,int(len(key)/8)+1):
            Byte=list(bin(Packet[i]))
            Bit=[]
            if len(Byte)<10:
                for j in range(0,8-(len(Byte)-2)):
                    Bit.append('0')
            for j in range(2,len(Byte)):
                Bit.append(Byte[j])
            Correct_Byte=list(bin(Correct_packet[i]))
            Correct_Bit=[]
            if len(Correct_Byte)<10:
                for j in range(0,8-(len(Correct_Byte)-2)):
                    Correct_Bit.append('0')
            for j in range(2,len(Correct_Byte)):
                Correct_Bit.append(Correct_Byte[j])
            for j in range(0,8):
                if Bit[j]!=Correct_Bit[j]:
                    if key[j+i*8]==1:
                        key[j+i*8]=0
                    else:
                        key[j+i*8]=1

        print(key)

        # cyclic redundancy check (CRC)
        key_str = ''.join(str(i) for i in key)
        Key = [int(key_str[i:i+8], 2) for i in range(0, len(key_str), 8)]
        crc = hex(binascii.crc32(bytes(Key)) & 0xffffffff)

        print(crc)

        se_crc = json.dumps(crc).encode()
        conn.send(se_crc) #send CRC result

        res = conn.recv(1024)

        conn.close
        s.close

        if res == "n" :
            msg.showinfo("Warning", "Cannot correct all keys. Please reset and restart Key Generation.")


        self.info_recon = key
        
        qr_key = list(key)

        #reshape the key length
        if int(math.sqrt(len(qr_key)))==math.sqrt(len(qr_key)):
            shaped_length=shaped_width=math.sqrt(len(qr_key))
        else:                                         
            shaped_length=2**((math.log(len(qr_key),2)-1)/2)
            shaped_width=2**((math.log(len(qr_key),2)+1)/2)
        shaped_array = np.array(qr_key).reshape((int(shaped_length), int(shaped_width)))

        
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
        self.data.item(data_get_index[1], values=('CRC code', crc))
        #self.data.delete(data_get_index[2])
        #self.data.delete(data_get_index[3])

        return self.fig_plot

        
    def Privacy_Amp(self) :   # privacy amplification
    
        try :
            bi_array = self.info_recon
        except AttributeError, e:
            msg.showinfo("Information", "Lack of steps. Please reset and restart Channel Probing.")

        #convert the binary sequence to  hexadecimal form
        bi_array = self.info_recon

        bi_list = list(bi_array)

        bi_str = ''.join(str(i) for i in bi_array)

        hex_str = "{0:0>4X}".format(int(bi_str, 2))

        if len(hex_str) % 2 != 0 :
            hex_str = "0" + hex_str

        hex_key = binascii.a2b_hex(hex_str)
    
        hash_hex = hashlib.sha256(hex_key).hexdigest()

        bi_hash = bin(int(hash_hex, 16))[2:]

        hash_list = [int(i) for i in bi_hash]

        len_key = int(len(bi_list))
        len_hash = int(len(hash_list))

        if len_key <= len_hash :
            len_hash = len_key


        del hash_list[len_key:]

        str_hash = ''.join([str(i) for i in hash_list])

        print "key after privacy amplification: ", str_hash
      
        self.str_hash = str_hash
        

        if int(math.sqrt(len_key))==math.sqrt(len_key):
            shaped_length=shaped_width=math.sqrt(len_key)
        else:                                         
            shaped_length=2**((math.log(len_key,2)-1)/2)
            shaped_width=2**((math.log(len_key,2)+1)/2)
        shaped_array = np.array(hash_list).reshape((int(shaped_length), int(shaped_width)))
        
        
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
        # Multithreading
        threading.Thread(target=self.channel_probing).start()

    def realtime_display(self, i):
        self.fig_plot.clear()
        self.fig_plot.plot(self.time_array, self.rssi_array,'k',color='red',marker='o')
        self.fig_plot.set_xlabel('timestamp', fontsize=13)
        self.fig_plot.set_ylabel('Received Signal Strength (dBm)', fontsize=14)
        self.fig_plot.set_title('Channel Probing', size=16)
        self.canvas.draw()

        return self.fig_plot
        

    def Test(self) :

        try :
            monobit_test_quant = FT.FrequencyTest.monobit_test(self.quantized_rs_str, True)
        except AttributeError, e:
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
        serial_quant = Serial.Serial.serial_test(self.quantized_rs_str, True, 5)
        re_serial1_quant = round(serial_quant[0][0], 4)
        re_serial2_quant = round(serial_quant[1][0], 4)
        serial_pri = Serial.Serial.serial_test(self.str_hash, True, 5)
        re_serial1_pri = round(serial_pri[0][0], 4)
        re_serial2_pri = round(serial_pri[1][0], 4)
        
        #Maurer’s Universal Statistical test
        #universaltest_quant = UN.Universal.statistical_test(self.quantized_rs_str, True)
        #re_universaltest_quant = round(universaltest_quant[0], 4)
        #universaltest_pri = UN.Universal.statistical_test(self.str_hash, True)
        #re_universaltest_pri = round(universaltest_pri[0], 4)
        
        #Randomness Excursion
        #ran_excursion_quant = RE.RandomExcursions.random_excursions_test(self.quantized_rs_str, True)
        #re_ran_excursion_quant = round(ran_excursion_quant[0], 4)
        #ran_excursion_pri = RE.RandomExcursions.random_excursions_test(self.str_hash, True)
        #re_ran_excursion_pri = round(ran_excursion_pri[0], 4)
        #ran_excursion_var_quant = RE.RandomExcursions.variant_test(self.quantized_rs_str, True)
        #re_ran_excursion_var_quant = round(ran_excursion_var_quant[0], 4)
        #ran_excursion_var_pri = RE.RandomExcursions.variant_test(self.str_hash, True)
        #re_ran_excursion_var_pri = round(ran_excursion_var_pri[0], 4)

        # ApproximateEntropy 
        approx_entropy_quant = AE.ApproximateEntropy.approximate_entropy_test(self.quantized_rs_str, True, 2)
        re_approx_entropy_quant = round(approx_entropy_quant[0], 4)
        approx_entropy_pri = AE.ApproximateEntropy.approximate_entropy_test(self.str_hash, True, 2)
        re_approx_entropy_pri = round(approx_entropy_pri[0], 4)
        
        # Spectral Test
        #spectraltest_quant = ST.SpectralTest.sepctral_test(self.quantized_rs_str, False)
        #re_spectraltest_quant = round(spectraltest_quant[0], 4)
        #spectraltest_pri = ST.SpectralTest.sepctral_test(self.str_hash, False)
        #re_spectraltest_pri = round(spectraltest_pri[0], 4)
        
        # Non overlapping Test
        #non_overlapping_quant = NO.test(self.quantized_rs_str, len(self.quantized_rs_str))
        #re_non_overlapping_quant = round(non_overlapping_quant[0], 4)
        #non_overlapping_pri = NO.test(self.str_hash, len(self.str_hash))
        #re_non_overlapping_pri = round(non_overlapping_pri[0], 4)

        self.main_frame = tk.LabelFrame(self.master, text="Key Generation Results", bg="WhiteSmoke", bd=2)
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
        self.data_frame.columnconfigure(0, weight=2)
        self.data_frame.columnconfigure(1, weight=1)        

        self.data = ttk.Treeview(self.data_frame, show="headings")
        self.data.grid(row=0, column=0, sticky=tk.NSEW)
        self.data['columns'] = ('Randomness Test', 'Quant', 'Priv. Amp')
        self.data['height'] = 5
        self.data.column("Randomness Test", width=70, anchor='center')
        self.data.column("Quant", width=15, anchor='center')
        self.data.column("Priv. Amp", width=15, anchor='center')
        self.data.heading("Randomness Test", text="Randomness Test")
        self.data.heading("Quant", text="Quant")
        self.data.heading("Priv. Amp", text="Priv. Amp")

        self.monobit_test = self.data.insert('', 0, values=('Monobit test', re_monobit_test_quant, re_monobit_test_pri), tag=('odd',))
        self.block_freq = self.data.insert('', 1, values=('Block frequency', re_block_freq_quant, re_block_freq_pri), tag=('even',))
        self.cum_fwd = self.data.insert('', 2, values=('Cum.sums (fwd)', re_cum_sum_fwd_quant, re_cum_sum_fwd_pri), tag=('odd',))
        self.cum_rev = self.data.insert('', 3, values=('Cum.sums (rev)', re_cum_sum_rev_quant, re_cum_sum_rev_pri), tag=('even',))
        self.runs = self.data.insert('', 4, values=('Runs', re_run_test_quant, re_run_test_pri), tag=('odd',))
        self.longest_block = self.data.insert('', 5, values=('Longest one block', re_longest_block_quant, re_longest_block_pri), tag=('even',))
        self.serial1 = self.data.insert('', 6, values=('Serial 1', re_serial1_quant, re_serial1_pri), tag=('odd',))
        self.serial2 = self.data.insert('', 7, values=('Serial 2', re_serial2_quant, re_serial2_pri), tag=('even',))
        #self.universaltest = self.data.insert('', 8, values=('Maurer universal', re_universaltest_quant, re_universaltest_pri), tag=('odd',))
        #self.ran_excursion = self.data.insert('', 8, values=('Ran.excursion', re_ran_excursion_quant, re_ran_excursion_pri), tag=('odd',))
        #self.ran_excursion_var = self.data.insert('', 9, values=('Ran.excursion.var', re_ran_excursion_var_quant, re_ran_excursion_var_pri), tag=('even',))
        self.appro_entry = self.data.insert('', 8, values=('Approx.entropy', re_approx_entropy_quant, re_approx_entropy_pri), tag=('odd',))
        #self.spectraltest = self.data.insert('', 9, values=('DFT test', re_spectraltest_quant, re_spectraltest_pri), tag=('even',))
        #self.non_overlapping = self.data.insert('', 10, values=('Non-overlapping', re_non_overlapping_quant, re_non_overlapping_pri), tag=('odd',))


        self.data.tag_configure('odd', background='White')
        self.data.tag_configure('even', background='WhiteSmoke')


        # Encryption Test
        self.encrypt_test = tk.LabelFrame(self.data_frame, text='Encryption Test', bg="White", bd=2)
        self.encrypt_test.grid(row=0, column=1, sticky=tk.NSEW)
    
        self.encrypt_test.rowconfigure(0, weight=2)
        self.encrypt_test.rowconfigure(1, weight=1)
        self.encrypt_test.columnconfigure(0, weight=1)
    
        self.v = tk.StringVar()
        self.v.set("")
        self.info = tk.Label(self.encrypt_test, textvariable=self.v, fg = "black", bg="White", font=("Times New Roman", 14))
        self.info.grid(row=0, column=0)
        
        encrypt_font = tf.Font(family="Times New Roman", size=12)
        self.decrypt_button = tk.Button(self.encrypt_test, text="Decryption", font=encrypt_font, bg="WhiteSmoke", activeforeground="red", command=self.Decryption)
        self.decrypt_button.grid(row=1, column=0, sticky=tk.N)
 


                
       
    def Reset(self) :

        self.animate.event_source.start()

        self.main_frame = tk.LabelFrame(self.master, text='Key Generation', bg="WhiteSmoke", bd=2)
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
        self.data['columns'] = ('AP side', 'Results')
        self.data['height'] = 4
        self.data.column("AP side", width=120, anchor='center')
        self.data.column("Results", width=10, anchor='center')
        self.data.heading("AP side", text="AP side")
        self.data.heading("Results", text="Results")

        self.frame_num = self.data.insert('', 0, values=('number of packet received',))
        self.matched_num = self.data.insert('', 3, values=('number of packet after matching',))
        self.frame_loss = self.data.insert('', 1, values=('number of packet loss',))
        self.frame_lossrate = self.data.insert('', 2, values=('packet loss rate',))
        
        self.timestamp=[]
        self.rssi=[]
        self.time_array=([])
        self.rssi_array=([])
        self.matched_rssi = []



    def Decryption(self) :
 
        def decrypt(text):
            cipher = AES.new(self.key, AES.MODE_CBC, self.key)
            plain_text = cipher.decrypt(a2b_hex(text))
            return plain_text.rstrip('\0')

        h = hashlib.md5(self.str_hash)
        self.key = h.hexdigest()[8:-8]
    
        recvd=""
        s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "192.168.3.20"
        port = 12345
        s.connect((host, port))

        s.send(b'1')   

        length=json.loads(s.recv(1024).decode())
         
        if length >= 1024 :
            num_index = int(length/1024) + 1
        else :
            num_index = 1
        #num_index=int(length/1024)+2   

        for i in range(0, num_index) : 
            recvd = recvd + s.recv(1024).decode()

        e = json.loads(recvd)
        print "encrypted text: ", e

        self.de_text = decrypt(e)
        s.close()
        print "Finish decryption"

        self.v.set(self.de_text)
 
    def Quit(self) :
        sys.exit(0)

if __name__ == '__main__': 
    
    gui = tk.Tk()
    k = Key_Generation(gui)
    gui.mainloop()




