import os
import random
import subprocess
from tkinter import Tk, filedialog, messagebox
from tkinter.ttk import Progressbar
import threading
import time

# SARSA Parametreleri
alpha = 0.1  # Öğrenme oranı
gamma = 0.9  # İndirim faktörü
epsilon = 0.1  # Keşif oranı
actions = ["transfer"]  # Tek eylem: dosya transferi
Q_table = {}  # SARSA Q-Tablosu

# Q-Tablosunu Başlatma
def initialize_state(state):
    if state not in Q_table:
        Q_table[state] = {action: 0 for action in actions}

# Epsilon-Greedy Politika
def choose_action(state):
    if random.uniform(0, 1) < epsilon:
        return random.choice(actions)
    else:
        return max(Q_table[state], key=Q_table[state].get)

# SCP Transfer Fonksiyonu
def scp_transfer(file_path, target_ip, destination_path):
    command = f"scp {file_path} pi@{target_ip}:{destination_path}"
    response = os.system(command)
    return response == 0  # Başarılıysa True döner

# Gecikme Hesaplama (Ping)
def calculate_latency(ip):
    try:
        response = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if response.returncode == 0:
            output = response.stdout.decode()
            latency_line = [line for line in output.split('\n') if "time=" in line]
            if latency_line:
                latency = float(latency_line[0].split("time=")[1].split(" ")[0])
                return latency
    except Exception as e:
        print(f"{ip} için gecikme hesaplanamadı: {e}")
    return float('inf')  # Ulaşılamazsa çok yüksek bir gecikme değeri döner

# Ödül Fonksiyonu
def calculate_reward(latency, success):
    reward = 0
    if success:
        reward += 10  # Başarılı transfer ödülü
    else:
        reward -= 10  # Başarısız transfer cezası

    # Gecikmeye Dayalı Ödül
    if latency < 50:
        reward += 5
    elif 50 <= latency < 100:
        reward += 2
    else:
        reward -= 5

    return reward

# SARSA Q-Tablosu Güncellemesi
def update_Q(state, action, reward, next_state, next_action):
    initialize_state(next_state)
    predict = Q_table[state][action]
    target = reward + gamma * Q_table[next_state][next_action]
    Q_table[state][action] += alpha * (target - predict)

# Tkinter ile Dosya Seçim ve Gönderim Arayüzü
def start_transfer_gui():
    # Dosya Seçim
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Gönderilecek Dosyayı Seç", filetypes=[("Tüm Dosyalar", "*.*")])
    if not file_path:
        messagebox.showerror("Hata", "Dosya seçilmedi.")
        return

    # Hedef IP
    target_ip = "192.168.1.101"  # 2. Raspberry Pi
    destination_path = "/home/pi/"  # Hedef dizin

    # Gecikme Hesaplama
    latency = calculate_latency(target_ip)

    # SARSA
    current_state = "transfer"
    initialize_state(current_state)
    action = choose_action(current_state)

    # İlerleme Çubuğu
    def show_progress():
        progress = Tk()
        progress.title("Dosya Gönderiliyor...")
        tk_label = Progressbar(progress, orient="horizontal", length=300, mode="determinate")
        tk_label.pack(pady=20)

        for i in range(1, 101):
            tk_label["value"] = i
            progress.update()
            time.sleep(0.02)  # Gönderim süresine bağlı olarak ayarlanabilir
        progress.destroy()

    # SCP Transferi
    threading.Thread(target=show_progress).start()
    success = scp_transfer(file_path, target_ip, destination_path)

    # Ödül Hesaplama ve SARSA Güncelleme
    reward = calculate_reward(latency, success)
    next_state = "transfer"
    next_action = choose_action(next_state)
    update_Q(current_state, action, reward, next_state, next_action)

    # Mesajlar
    if success:
        messagebox.showinfo("Başarılı", "Dosya başarıyla gönderildi!")
    else:
        messagebox.showerror("Hata", "Dosya gönderimi başarısız oldu.")

# Çalıştırma
if __name__ == "__main__":
    start_transfer_gui()
