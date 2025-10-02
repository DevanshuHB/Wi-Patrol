import tkinter as tk
from tkinter import ttk, messagebox
import os

# Placeholder for ESP32 scan file path
ESP32_SCAN_FILE = 'sample_esp32_scan.txt'
# File to store live network data for comparison
LIVE_NETWORKS_FILE = 'live_networks.txt'

class WifiPatrolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Patrol")
        self.root.geometry("800x600")

        # UI Elements
        self.create_ui()

        # Load initial data
        self.load_wifi_data()

    def create_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        title_label = ttk.Label(main_frame, text="Wi-Patrol - WiFi Scanner & Fake Detector", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=5)

        refresh_btn = ttk.Button(toolbar, text="Refresh Scan", command=self.refresh_scan)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        analyze_btn = ttk.Button(toolbar, text="Analyze Networks", command=self.analyze_networks)
        analyze_btn.pack(side=tk.LEFT, padx=5)

        add_whitelist_btn = ttk.Button(toolbar, text="Add to Whitelist", command=self.add_to_whitelist)
        add_whitelist_btn.pack(side=tk.LEFT, padx=5)

        columns = ("SSID", "BSSID", "RSSI", "Channel", "Encryption", "Status")
        self.tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=20)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=5)

    def load_wifi_data(self):
        self.tree.delete(*self.tree.get_children())
        wifi_data = self.read_scan_file(ESP32_SCAN_FILE)
        for entry in wifi_data:
            self.tree.insert("", tk.END, values=(
                entry['ssid'],
                entry['bssid'],
                entry['rssi'],
                entry['channel'],
                entry['encryption'],
                entry.get('status', 'Unknown: Safe')
            ))
        self.status_var.set(f"Loaded {len(wifi_data)} networks")

    def refresh_scan(self):
        self.status_var.set("Refreshing scan data...")
        self.root.update()
        wifi_data = self.read_scan_file(ESP32_SCAN_FILE)
        # Clear live networks file before writing new data
        try:
            with open(LIVE_NETWORKS_FILE, 'w') as f:
                pass  # Clear file contents
        except Exception as e:
            messagebox.showerror("File Write Error", f"Error clearing live networks file: {e}")
        self.write_live_networks(wifi_data)
        self.load_wifi_data()
        self.status_var.set("Scan refreshed")

    def analyze_networks(self):
        self.status_var.set("Analyzing networks...")
        self.root.update()
        wifi_data = self.read_scan_file(ESP32_SCAN_FILE)
        # Clear live networks file before writing new data
        try:
            with open(LIVE_NETWORKS_FILE, 'w') as f:
                pass  # Clear file contents
        except Exception as e:
            messagebox.showerror("File Write Error", f"Error clearing live networks file: {e}")
        live_data = self.read_scan_file(LIVE_NETWORKS_FILE)

        live_dict = {(entry['bssid'], entry['channel']): entry for entry in live_data}

        # Read whitelist entries
        whitelist = []
        try:
            with open('whitelist.txt', 'r') as wl_file:
                for line in wl_file:
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        wl_entry = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'rssi': int(parts[2]),
                            'channel': int(parts[3]),
                            'encryption': parts[4],
                            'status': parts[5]
                        }
                        whitelist.append(wl_entry)
        except Exception as e:
            messagebox.showerror("Whitelist Error", f"Error reading whitelist.txt: {e}")

        for entry in wifi_data:
            key = (entry['bssid'], entry['channel'])
            status = "Unknown: Safe"

            # Check if network is in whitelist (SSID and BSSID match)
            in_whitelist = False
            for wl_entry in whitelist:
                if entry['ssid'].lower().strip() == wl_entry['ssid'].lower().strip() and entry['bssid'].lower().strip() == wl_entry['bssid'].lower().strip():
                    in_whitelist = True
                    break

            if in_whitelist:
                status = "Known: Safe"
            else:
                # Mark networks with weak encryption as suspicious
                weak_encryptions = ['open', 'wep', 'wpa']
                if entry['encryption'].lower() in weak_encryptions:
                    status = "Unknown: Suspicious"
                # Mark networks with suspicious SSID keywords as suspicious
                elif any(word in entry['ssid'].lower() for word in ['free', 'guest', 'public', 'fake']):
                    status = "Unknown: Suspicious"
                # Check if encryption or SSID changed compared to previous scan
                elif key in live_dict:
                    live_entry = live_dict[key]
                    if live_entry['encryption'] != entry['encryption'] or live_entry['ssid'] != entry['ssid']:
                        status = "Unknown: Suspicious"

            entry['status'] = status

        # Write analyzed data back to live networks file
        self.write_live_networks(wifi_data)

        # Update UI
        self.tree.delete(*self.tree.get_children())
        for entry in wifi_data:
            self.tree.insert("", tk.END, values=(
                entry['ssid'],
                entry['bssid'],
                entry['rssi'],
                entry['channel'],
                entry['encryption'],
                entry['status']
            ))
        self.status_var.set("Analysis complete")

    def analyze_networks(self):
        self.status_var.set("Analyzing networks...")
        self.root.update()
        wifi_data = self.read_scan_file(ESP32_SCAN_FILE)
        live_data = self.read_scan_file(LIVE_NETWORKS_FILE)

        live_dict = {(entry['bssid'], entry['channel']): entry for entry in live_data}

        # Read whitelist entries
        whitelist = []
        try:
            with open('whitelist.txt', 'r') as wl_file:
                for line in wl_file:
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        wl_entry = {
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'rssi': int(parts[2]),
                            'channel': int(parts[3]),
                            'encryption': parts[4],
                            'status': parts[5]
                        }
                        whitelist.append(wl_entry)
        except Exception as e:
            messagebox.showerror("Whitelist Error", f"Error reading whitelist.txt: {e}")

        for entry in wifi_data:
            key = (entry['bssid'], entry['channel'])
            status = "Unknown: Safe"

            # Check if network is in whitelist (SSID and BSSID match)
            in_whitelist = False
            for wl_entry in whitelist:
                if entry['ssid'].lower().strip() == wl_entry['ssid'].lower().strip() and entry['bssid'].lower().strip() == wl_entry['bssid'].lower().strip():
                    in_whitelist = True
                    break

            if in_whitelist:
                status = "Known: Safe"
            else:
                # Mark networks with weak encryption as suspicious
                weak_encryptions = ['open', 'wep', 'wpa']
                if entry['encryption'].lower() in weak_encryptions:
                    status = "Unknown: Suspicious"
                # Mark networks with suspicious SSID keywords as suspicious
                elif any(word in entry['ssid'].lower() for word in ['free', 'guest', 'public', 'fake']):
                    status = "Unknown: Suspicious"
                # Check if encryption or SSID changed compared to previous scan
                elif key in live_dict:
                    live_entry = live_dict[key]
                    if live_entry['encryption'] != entry['encryption'] or live_entry['ssid'] != entry['ssid']:
                        status = "Unknown: Suspicious"

            entry['status'] = status

        # Write analyzed data back to live networks file
        self.write_live_networks(wifi_data)

        # Update UI
        self.tree.delete(*self.tree.get_children())
        for entry in wifi_data:
            self.tree.insert("", tk.END, values=(
                entry['ssid'],
                entry['bssid'],
                entry['rssi'],
                entry['channel'],
                entry['encryption'],
                entry['status']
            ))
        self.status_var.set("Analysis complete")

    def read_scan_file(self, filepath):
        data = []
        if not os.path.exists(filepath):
            return data
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 5:
                        ssid = parts[0]
                        bssid = parts[1]
                        rssi = int(parts[2])
                        channel = int(parts[3])
                        encryption = parts[4]
                        status = parts[5] if len(parts) > 5 else None
                        entry = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'rssi': rssi,
                            'channel': channel,
                            'encryption': encryption,
                        }
                        if status:
                            entry['status'] = status
                        data.append(entry)
        except Exception as e:
            messagebox.showerror("File Read Error", f"Error reading file {filepath}: {e}")
        return data

    def write_live_networks(self, data):
        try:
            with open(LIVE_NETWORKS_FILE, 'w') as f:
                for entry in data:
                    line = f"{entry['ssid']},{entry['bssid']},{entry['rssi']},{entry['channel']},{entry['encryption']},{entry.get('status', 'Unknown: Safe')}\n"
                    f.write(line)
        except Exception as e:
            messagebox.showerror("File Write Error", f"Error writing live networks file: {e}")


    def add_to_whitelist(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a network from the list to add to whitelist.")
            return
        values = self.tree.item(selected[0])['values']
        if len(values) < 6:
            messagebox.showerror("Selection Error", "Selected network data is incomplete.")
            return
        try:
            with open('whitelist.txt', 'a') as wl_file:
                line = ",".join(str(v) for v in values) + "\n"
                wl_file.write(line)
            messagebox.showinfo("Whitelist Updated", f"Network '{values[0]}' added to whitelist.")
            # Refresh analysis after updating whitelist
            self.analyze_networks()
        except Exception as e:
            messagebox.showerror("File Write Error", f"Error updating whitelist.txt: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WifiPatrolApp(root)
    root.mainloop()
