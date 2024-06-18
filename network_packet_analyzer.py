import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, raw
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        self.text_area = scrolledtext.ScrolledText(root, width=100, height=30)
        self.text_area.pack()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack()

        self.sniffing = False
        self.sniffer_thread = None
        self.stop_event = threading.Event()

    def start_sniffing(self):
        self.sniffing = True
        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.stop_event.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, filter="ip", store=0, stop_filter=self.stop_filter)

    def stop_filter(self, packet):
        return self.stop_event.is_set()

    def packet_callback(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                payload = raw(packet[TCP].payload)
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                payload = raw(packet[UDP].payload)
            else:
                proto = "Other"
                sport = ""
                dport = ""
                payload = b""
            packet_info = (
                f"IP Packet: {ip_layer.src}:{sport} -> {ip_layer.dst}:{dport} [Proto: {proto}]\n"
                f"Payload: {payload}\n"
            )
            self.text_area.insert(tk.END, packet_info + "\n")
            self.text_area.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
