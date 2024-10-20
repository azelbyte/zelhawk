import tkinter as tk
from tkinter import scrolledtext
from scapy.all import ARP, Ether, srp

# Function to scan the network
def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append(f"IP: {received.psrc}, MAC: {received.hwsrc}")
    
    return clients

# Function to handle the scan button click
def on_scan():
    ip_range = ip_entry.get()
    output.delete(1.0, tk.END)  # Clear previous results
    clients = scan_network(ip_range)
    if clients:
        output.insert(tk.END, "\n".join(clients))
    else:
        output.insert(tk.END, "No devices found.")

# Set up the main window
window = tk.Tk()
window.title("Network Scanner")

# Input field for IP range
ip_label = tk.Label(window, text="Enter IP Range (e.g., 192.168.1.1/24):")
ip_label.pack(pady=10)

ip_entry = tk.Entry(window, width=30)
ip_entry.pack(pady=5)

# Scan button
scan_button = tk.Button(window, text="Scan", command=on_scan)
scan_button.pack(pady=10)

# Text area for output
output = scrolledtext.ScrolledText(window, width=50, height=15)
output.pack(pady=10)

# Start the GUI event loop
window.mainloop()
