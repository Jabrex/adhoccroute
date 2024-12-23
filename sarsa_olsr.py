#!/usr/bin/env python3

import os
import math
import json
import time
import socket
import threading
import subprocess
import paramiko
import argparse
import tkinter as tk
from tkinter import filedialog

#############################################################################
# Raspberry Pi Bilgileri (username = password)
# pi100: yasarpi1 / yasarpi1
# pi101: yasarpi2 / yasarpi2
# pi102: yasarpi3 / yasarpi3
# pi103: yasarpi4 / yasarpi4
# pi104: yasarpi5 / yasarpi5
#############################################################################
devices = {
    "pi100": {
        "ip": "192.168.1.100",
        "username": "yasarpi1",
        "password": "yasarpi1"
    },
    "pi101": {
        "ip": "192.168.1.101",
        "username": "yasarpi2",
        "password": "yasarpi2"
    },
    "pi102": {
        "ip": "192.168.1.102",
        "username": "yasarpi3",
        "password": "yasarpi3"
    },
    "pi103": {
        "ip": "192.168.1.103",
        "username": "yasarpi4",
        "password": "yasarpi4"
    },
    "pi104": {
        "ip": "192.168.1.104",
        "username": "yasarpi5",
        "password": "yasarpi5"
    }
}

#############################################################################
# MANUEL BAĞLANTILAR (Doğrudan Erişebilen Komşular)
# İstediğiniz topolojiye göre ayarlandı:
# pi100: pi101, pi102
# pi101: pi100, pi103, pi104
# pi102: pi100, pi103, pi104
# pi103: pi101, pi102, pi104
# pi104: pi101, pi102, pi103
#############################################################################
graph_neighbors = {
    "pi100": ["pi101", "pi102"],
    "pi101": ["pi100", "pi103", "pi104"],
    "pi102": ["pi100", "pi103", "pi104"],
    "pi103": ["pi101", "pi102", "pi104"],
    "pi104": ["pi101", "pi102", "pi103"]
}

#############################################################################
# SARSA Ajansı
#############################################################################
class SarsaAgent:
    def __init__(self, node_id, alpha=0.5, gamma=0.9):
        # Q-table -> {(current_node, end_node, next_node): Q-value}
        self.node_id = node_id
        self.q_table = {}
        self.alpha = alpha
        self.gamma = gamma
        self.q_file_path = f"qtable_{node_id}.json"  # Kaydedilecek dosya

        # Dosya varsa yükle
        self.load_q_table()

    def get_q_value(self, s, a):
        return self.q_table.get((s[0], s[1], a), 0.0)

    def update_q(self, s, a, r, s_next, a_next):
        """
        SARSA update:
        Q(s,a) = Q(s,a) + alpha * [r + gamma * Q(s_next,a_next) - Q(s,a)]
        """
        old_q = self.get_q_value(s, a)
        next_q = 0.0
        if a_next is not None:
            next_q = self.get_q_value(s_next, a_next)
        td_target = r + self.gamma * next_q
        new_q = old_q + self.alpha * (td_target - old_q)
        self.q_table[(s[0], s[1], a)] = new_q

        # Güncel tabloyu kaydet
        self.save_q_table()

    def select_action(self, current_node, end_node, possible_next_nodes):
        # Basit max-Q seçimi
        best_a = None
        best_q = -999999
        for nxt in possible_next_nodes:
            q_val = self.get_q_value((current_node, end_node), nxt)
            if q_val > best_q:
                best_q = q_val
                best_a = nxt
        if best_a is None and possible_next_nodes:
            best_a = possible_next_nodes[0]
        return best_a

    def save_q_table(self):
        try:
            with open(self.q_file_path, "w") as f:
                json.dump(self.q_table, f, indent=2)
        except Exception as e:
            print(f"[SARSA-{self.node_id}] Q-table kaydetme hatası: {e}")

    def load_q_table(self):
        if os.path.isfile(self.q_file_path):
            try:
                with open(self.q_file_path, "r") as f:
                    loaded = json.load(f)
                # Key'ler string, tuple'a dönüştürmek gerekiyor
                new_q = {}
                for k, v in loaded.items():
                    # k örn: "('pi100', 'pi104', 'pi101')"
                    tuple_key = eval(k)
                    new_q[tuple_key] = v
                self.q_table = new_q
            except Exception as e:
                print(f"[SARSA-{self.node_id}] Q-table yükleme hatası: {e}")
                self.q_table = {}

#############################################################################
# OLSR Node
# - Periyodik olarak HELLO ve TC mesajlarıyla komşular + topoloji öğrenilir
#############################################################################
UDP_PORT = 698

class OlsrNode(threading.Thread):
    def __init__(self, node_id):
        super().__init__()
        self.node_id = node_id
        self.ip = devices[node_id]["ip"]
        self.stop_flag = False
        self.sock = None

        # OLSR tablosu -> {node: set(komşular)}
        self.olsr_topology = {}
        for n in devices.keys():
            self.olsr_topology[n] = set()

        # Manuel bildiğimiz komşuları baştan ekle
        for nbr in graph_neighbors[self.node_id]:
            self.olsr_topology[self.node_id].add(nbr)
            self.olsr_topology[nbr].add(self.node_id)

        # Kaydedilecek dosya
        self.olsr_file_path = f"olsr_topology_{node_id}.json"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("", UDP_PORT))
        self.sock.settimeout(1.0)

        last_hello_time = 0
        last_tc_time = 0

        while not self.stop_flag:
            # HELLO
            if time.time() - last_hello_time > 3:
                self.send_hello()
                last_hello_time = time.time()

            # TC
            if time.time() - last_tc_time > 5:
                self.send_tc()
                last_tc_time = time.time()

            # Mesaj dinle
            try:
                data, addr = self.sock.recvfrom(4096)
                self.process_packet(data)
            except socket.timeout:
                pass
            except Exception as e:
                print(f"[OLSR-{self.node_id}] Soket hatası: {e}")

            # Topolojiyi kaydet
            self.save_olsr_topology()

        self.sock.close()

    def stop(self):
        self.stop_flag = True

    def send_hello(self):
        msg = {
            "type": "HELLO",
            "sender": self.node_id,
            "neighbors": list(self.olsr_topology[self.node_id])
        }
        self.broadcast_message(msg)

    def send_tc(self):
        msg = {
            "type": "TC",
            "sender": self.node_id,
            "topology": {
                n: list(self.olsr_topology[n]) for n in self.olsr_topology
            }
        }
        self.broadcast_message(msg)

    def broadcast_message(self, msg):
        packet = json.dumps(msg).encode("utf-8")
        self.sock.sendto(packet, ("255.255.255.255", UDP_PORT))

    def process_packet(self, data):
        try:
            msg = json.loads(data.decode("utf-8"))
            if msg["type"] == "HELLO":
                self.handle_hello(msg)
            elif msg["type"] == "TC":
                self.handle_tc(msg)
        except:
            pass

    def handle_hello(self, msg):
        sender = msg["sender"]
        neighbors = msg["neighbors"]
        self.olsr_topology[sender].update(neighbors)
        for nb in neighbors:
            self.olsr_topology[nb].add(sender)

    def handle_tc(self, msg):
        t = msg["topology"]
        for node, nbrs in t.items():
            self.olsr_topology[node].update(nbrs)
            for x in nbrs:
                self.olsr_topology[x].add(node)

    def get_full_topology(self):
        return self.olsr_topology

    def save_olsr_topology(self):
        # JSON'a dönüştürülebilecek form
        dict_topo = {k: list(v) for k, v in self.olsr_topology.items()}
        try:
            with open(self.olsr_file_path, "w") as f:
                json.dump(dict_topo, f, indent=2)
        except Exception as e:
            print(f"[OLSR-{self.node_id}] Topoloji kaydetme hatası: {e}")

#############################################################################
# Ping & Load
#############################################################################
ping_times = {}  # {(src_node, dst_node): rtt}
def get_ping_time(src_node, dst_node):
    """Basitlik: src_node'dan dst_node'a ping atılıyor."""
    ip = devices[dst_node]["ip"]
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], universal_newlines=True)
        idx = output.find("time=")
        if idx == -1:
            rtt = 9999
        else:
            val = ""
            for ch in output[idx+5:]:
                if ch.isdigit() or ch == ".":
                    val += ch
                else:
                    break
            rtt = float(val)
    except:
        rtt = 9999

    ping_times[(src_node, dst_node)] = rtt
    save_ping_times(src_node)
    return rtt

def save_ping_times(src_node):
    """Sadece src_node'un ping kayıtlarını JSON'a kaydedelim."""
    filtered = {}
    for (s, d), val in ping_times.items():
        if s == src_node:
            filtered[f"{s}->{d}"] = val
    try:
        with open(f"ping_times_{src_node}.json", "w") as f:
            json.dump(filtered, f, indent=2)
    except Exception as e:
        print(f"[PingTimes-{src_node}] Kaydetme hatası: {e}")

def get_device_load(node_id):
    ip = devices[node_id]["ip"]
    username = devices[node_id]["username"]
    password = devices[node_id]["password"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=2)
        stdin, stdout, stderr = ssh.exec_command("cat /proc/loadavg")
        output = stdout.read().decode().strip()
        ssh.close()
        first_val = output.split()[0]
        return float(first_val)
    except:
        return 9999

#############################################################################
# SCP Yükleme / İndirme
#############################################################################
def scp_upload(local_file, remote_file, device_id):
    if not os.path.isfile(local_file):
        print(f"[HATA] Lokal dosya yok: {local_file}")
        return False
    ip = devices[device_id]["ip"]
    username = devices[device_id]["username"]
    password = devices[device_id]["password"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5)
        sftp = ssh.open_sftp()
        sftp.put(local_file, remote_file)
        sftp.close()
        ssh.close()
        print(f"[OK] {local_file} --> {ip}:{remote_file}")
        return True
    except Exception as e:
        print(f"[HATA] scp_upload hatası ({ip}): {e}")
        return False

def scp_download(remote_file, local_file, device_id):
    ip = devices[device_id]["ip"]
    username = devices[device_id]["username"]
    password = devices[device_id]["password"]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=5)
        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)
        sftp.close()
        ssh.close()
        print(f"[OK] {ip}:{remote_file} --> {local_file}")
        return True
    except Exception as e:
        print(f"[HATA] scp_download hatası ({ip}): {e}")
        return False

#############################################################################
# Rota Bulma (OLSR + SARSA)
#############################################################################
def find_best_route(olsr_node, sarsa_agent, start, end):
    topology = olsr_node.get_full_topology()
    unvisited = list(topology.keys())
    dist = {node: math.inf for node in topology}
    dist[start] = 0
    prev = {node: None for node in topology}

    while unvisited:
        current = min(unvisited, key=lambda x: dist[x])
        unvisited.remove(current)
        if current == end or dist[current] == math.inf:
            break

        for nxt in topology[current]:
            rtt = get_ping_time(current, nxt)
            load_val = get_device_load(nxt)
            q_val = sarsa_agent.get_q_value((current, end), nxt)
            cost = rtt + load_val * 5 - q_val * 0.1
            alt = dist[current] + cost
            if alt < dist[nxt]:
                dist[nxt] = alt
                prev[nxt] = current

    path = []
    node = end
    while node is not None:
        path.insert(0, node)
        node = prev[node]

    if not path or path[0] != start:
        return []
    return path

def transfer_file_sarsa_olsr(local_file, start, end, olsr_node, sarsa_agent):
    path = find_best_route(olsr_node, sarsa_agent, start, end)
    if len(path) < 2:
        print("[HATA] Geçerli rota yok.")
        return False

    print("[ROTA]:", path)
    current_local_file = local_file

    for i in range(len(path) - 1):
        cnode = path[i]
        nnode = path[i+1]

        # 1) cnode -> local (ilk adımda local'de)
        if i > 0:
            remote_c = f"/home/{devices[cnode]['username']}/transfer_temp"
            dl_ok = scp_download(remote_c, f"/tmp/tmp_{cnode}", cnode)
            if not dl_ok:
                sarsa_agent.update_q((cnode, end), nnode, -10, (nnode, end), None)
                return False
            current_local_file = f"/tmp/tmp_{cnode}"

        # 2) local -> nnode
        remote_n = f"/home/{devices[nnode]['username']}/transfer_temp"
        ul_ok = scp_upload(current_local_file, remote_n, nnode)
        if not ul_ok:
            sarsa_agent.update_q((cnode, end), nnode, -10, (nnode, end), None)
            return False

        # Ödül: RTT
        rtt = ping_times.get((cnode, nnode), 9999)
        reward = max(0, 10 - rtt)
        topology = olsr_node.get_full_topology()
        a_next = sarsa_agent.select_action(nnode, end, list(topology[nnode]))
        sarsa_agent.update_q((cnode, end), nnode, reward, (nnode, end), a_next)

    # Bitiş pi104 ise rotayı kaydet
    if end == "pi104":
        route_file = f"received_route_{end}.json"
        route_info = {
            "final_node": end,
            "route": path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            with open(route_file, "w") as f:
                json.dump(route_info, f, indent=2)
        except Exception as e:
            print(f"[ROTA] Kaydetme hatası: {e}")

    print("[OK] Dosya hedefe ulaştı.")
    return True

#############################################################################
# Tkinter UI (Sadece pi100)
#############################################################################
class App:
    def __init__(self, root, olsr_node, sarsa_agent):
        self.root = root
        self.root.title("OLSR + SARSA Demo - pi100")
        self.olsr_node = olsr_node
        self.sarsa_agent = sarsa_agent

        self.btn_select = tk.Button(root, text="Dosya Seç", command=self.select_file)
        self.btn_select.pack(pady=5)

        self.lbl_file = tk.Label(root, text="Seçilen dosya: Yok")
        self.lbl_file.pack(pady=5)

        self.btn_send = tk.Button(root, text="Gönder (.100 → .104)", command=self.send_file)
        self.btn_send.pack(pady=5)

        self.txt_log = tk.Text(root, height=15, width=60)
        self.txt_log.pack(padx=10, pady=10)

        self.selected_file = None

    def log(self, msg):
        self.txt_log.insert(tk.END, msg + "\n")
        self.txt_log.see(tk.END)

    def select_file(self):
        f = filedialog.askopenfilename(
            title="Gönderilecek Dosyayı Seçin",
            filetypes=[("Tüm Dosyalar", "*.*")]
        )
        if f:
            self.selected_file = f
            self.lbl_file.config(text=f"Seçilen dosya: {f}")

    def send_file(self):
        if not self.selected_file:
            self.log("[HATA] Lütfen önce bir dosya seçiniz.")
            return

        self.log("[INFO] Dosya gönderimi (pi100 -> pi104) başlıyor...")
        ok = transfer_file_sarsa_olsr(
            local_file=self.selected_file,
            start="pi100",
            end="pi104",
            olsr_node=self.olsr_node,
            sarsa_agent=self.sarsa_agent
        )
        if ok:
            self.log("[OK] Dosya gönderildi!")
        else:
            self.log("[HATA] Dosya gönderimi başarısız.")

#############################################################################
# main()
#############################################################################
def main():
    paramiko.util.log_to_file("paramiko_sarsa_olsr.log")

    parser = argparse.ArgumentParser()
    parser.add_argument("--node", type=str, required=True,
                        help="pi100 / pi101 / pi102 / pi103 / pi104")
    args = parser.parse_args()

    node_id = args.node
    if node_id not in devices:
        print(f"[HATA] Geçersiz node_id: {node_id}")
        return

    # SARSA + OLSR
    sarsa = SarsaAgent(node_id)
    olsr_node = OlsrNode(node_id)
    olsr_node.start()

    # pi100 -> UI
    if node_id == "pi100":
        root = tk.Tk()
        app = App(root, olsr_node, sarsa)
        root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, olsr_node))
        root.mainloop()
    else:
        # Diğer nodelerde UI yok
        print(f"[INFO] Node {node_id} arka planda OLSR + SARSA çalışıyor...")
        try:
            while True:
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            olsr_node.stop()
            time.sleep(1)

def on_closing(root, olsr_node):
    olsr_node.stop()
    time.sleep(1)
    root.destroy()

if __name__ == "__main__":
    main()
