import threading
from flask import Flask, jsonify
import tkinter as tk
import os
import re
import time
import nmap
import socket
import subprocess
import json
from tkinter import messagebox
import requests
from tabulate import tabulate
import urllib.request
import ipaddress


ip = None
result_upload= None
result_download = None
time_ping = None
local_ip =  None
Hostname = socket.gethostname()
results_str = None
dns_hostname = None

file_url = "http://192.168.17.131/api/v4/projects/3/repository/files/version.txt/raw?private_token=glpat-HoRSADDiugzHpRxamg6C"

# Récupérer le contenu du fichier en utilisant le token privé
response = requests.get(file_url)

url_content = response.text


def get_local_ip():
    global local_ip
    global dns_hostname
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect to a public address, to get the address of the current network
        s.connect(("8.8.8.8", 1))
        local_ip = s.getsockname()[0]
        dns_hostname = socket.gethostbyaddr(local_ip)[0]

    except:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip



class MainPage(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.grid(sticky="nsew")
        self.master.geometry("840x300")
        

        # Create the left frame for information
        self.left_frame = tk.Frame(self)
        self.left_frame.grid(row=0, column=0, padx=10, sticky="nsew")
        # Create the middle frame for buttons
        self.middle_frame = tk.Frame(self)
        self.middle_frame.grid(row=0, column=1,padx=60, sticky="nsew")
        # Create the right frame for the ping
        self.right_frame = tk.Frame(self)
        self.right_frame.grid(row=0, column=2,padx=30, sticky="nsew")
        # Add widgets to the left frame
        self.hostname_label = tk.Label(self.left_frame, text="Nom de la machine : " + socket.gethostname())
        self.hostname_label.pack()
        self.ip_label = tk.Label(self.left_frame, text="Adresse IP : " + get_local_ip())
        self.ip_label.pack()
        self.public_ip_label = tk.Label(self.left_frame, text="Adresse IP publique : ")
        self.public_ip_label.pack()
        self.dns_hostname_label = tk.Label(self.left_frame, text="Nom de domaine : " + dns_hostname)
        self.dns_hostname_label.pack()
        self.after(5000, self.update_ip)
        


         # Add widgets to the middle frame
        self.scan_button = tk.Button(self.middle_frame, text="Scan réseau", command=self.go_to_second_page)
        self.scan_button.pack()
        self.test_button = tk.Button(self.middle_frame, text="Lancer le test débit", command=self.go_to_third_page)
        self.test_button.pack()


        #Add Widgets to the right frame
        self.ping_label = tk.Label(self.right_frame)
        self.ping()
        self.ping_label.pack()
        self.resultat_label = tk.Label(self.right_frame, text="Résultat du dernier test de débit:")                 
        self.resultat_label.pack()
        self.download_label = tk.Label(self.right_frame, text=self.resultat_speedtest())
        self.download_label.pack()
        self.scan_result_button = tk.Button(self.middle_frame, text="Résultat scan réseau", command=self.go_to_four_page)
        self.scan_result_button.pack()


    def resultat_speedtest(self):
        global result_download
        global download
        global upload
        global result_upload
        try:
            with open(f"/home/client/semaos/speedtestresult.txt") as f:
                download = f.readline().strip()
                upload = f.readline().strip()
                speedtest_result = " " + download + "\n" + " " + upload
                result_download = download.split()[1]
                result_upload = upload.split()[1]
        except FileNotFoundError:
        # Créer un nouveau fichier speedtestresult.txt
            with open(f"/home/client/semaos/speedtestresult.txt", "w") as f:
                f.write("Download speed: 0 Mbps\nUpload speed: 0 Mbps")
            speedtest_result = "Download speed: 0 Mbps\nUpload speed: 0 Mbps"
            result_download = 0
            result_upload = 0
        return speedtest_result


   
    def get_public_ip(self):
        global ip
        try:
            urllib.request.urlopen('https://8.8.8.8', timeout=1) # Vérification de la connexion internet
            response = requests.get("https://api.ipify.org")
            response.raise_for_status()
            ip = response.text
            return response.text
        except requests.exceptions.RequestException as e:
            
            return "Pas accès Internet"
        except OSError:
            
            return "Pas accès Internet"
        
    def update_ip(self):
        self.public_ip_label["text"] = "Adresse IP publique : " + self.get_public_ip()
        self.after(5000, self.update_ip)
    



    

    def ping(self):
        global time_ping
        output = os.popen("ping -c 1 8.8.8.8").read()
        result = re.search("(time|temps)=(\d+)", output)
        if result:
            time_ping = float(result.groups()[1])
            self.ping_label["text"] = "Ping: {} ms".format(time_ping)
        else:        
            time_ping = 'Failed'
            self.ping_label["text"] = "Ping: Failed"
        self.after(5000, self.ping)

    def go_to_second_page(self):
        self.destroy()
        SecondPage(self.master)

    def go_to_third_page(self):
        self.destroy()
        ThirdPage(self.master)

    def go_to_four_page(self):
        self.destroy()
        FourPage(self.master)

        
class SecondPage(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.create_widgets()
        self.master.geometry("700x550")

        self.scan()
    def go_to_main_page(self):
        self.destroy()
        MainPage(self.master)

    def create_widgets(self):

        self.result_text = tk.Text(self)
        self.result_text.pack()
        self.result_text.tag_configure("right", justify='right')

        self.back_button = tk.Button(self)
        self.back_button["text"] = "Retour"
        self.back_button["command"] = self.go_to_main_page
        self.back_button.pack()

        # Start the scan automatically when the page is displayed


    def scan(self):
        global local_ip
        print(local_ip)
        try:
            urllib.request.urlopen('https://www.google.com')
        except:
            self.result_text.insert(tk.END, "Pas de connexion Internet\n")
            return

    # Détecter l'adresse IP locale et le sous-réseau
        local_ip = get_local_ip()
        subnet = ipaddress.ip_network(local_ip + "/24", strict=False)
        print(subnet)
        if not subnet:
            self.result_text.insert(tk.END, "Impossible de détecter le sous-réseau\n")
            return

        nm = nmap.PortScanner()
        self.result_text.insert(tk.END, "Lancement de l'analyse\n")
        self.master.update()

        time.sleep(2)
        try:
            nm.scan(str(subnet.network_address) + "/24", arguments='-sT -p1-1024')

            self.result_text.insert(tk.END, "Analyse terminée\n")
            self.result_text.insert(tk.END, "\n")

            self.result_text.insert(tk.END, "Adresse IP                      Hostname                         Ports\n")
            self.result_text.insert(tk.END, "\n")

            for host in nm.all_hosts():
                try:
                    hostnames = socket.gethostbyaddr(host)[0]
                except socket.herror:
                    hostnames = "unknown"
                    ports = "Pas de port"
                if "tcp" in nm[host] and nm[host]['tcp']:
                    ports = ",".join([str(port) for port in nm[host]['tcp'].keys()])
                    if ports == "":
                        ports = "Pas de port"
                self.result_text.insert(tk.END, "{:<30}{:<30}{}\n".format(host, hostnames, ports))
                self.result_text.insert(tk.END, "\n")

            with open(f'/home/client/semaos/scan_result.txt', 'w') as f:
                f.write("Adresse IP\tHostname\tPorts\n")
                for host in nm.all_hosts():
                    try:
                        hostnames = socket.gethostbyaddr(host)[0]
                    except socket.herror:
                        hostnames = "unknown"
                    if "tcp" in nm[host] and nm[host]['tcp']:
                        ports = ",".join([str(port) for port in nm[host]['tcp'].keys()])
                        if ports == "":
                            ports = "Pas de port"
                    else:
                        ports = "Pas de port"
                    f.write("{}\t{}\t{}\n".format(host, hostnames, ports))
        except Exception as e:
            pass









class ThirdPage(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.create_widgets()
        self.master.geometry("700x450")
        self.test_debit()
    def create_widgets(self):
        self.result_text = tk.Text(self)
        self.result_text.pack()
        self.back_button = tk.Button(self)
        self.back_button["text"] = "Retour"
        self.back_button["command"] = self.go_to_main_page
        self.back_button.pack()

    def go_to_main_page(self):
        self.destroy()
        MainPage(self.master)

    def test_debit(self):


        self.result_text.insert(tk.END, "Vérification de la connexion internet...\n")
        
        try:
            urllib.request.urlopen("http://www.google.com", timeout=1)
        except urllib.request.URLError:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Pas de connexion Internet\n")
            return    
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Lancement du test de débit\n")
        
        self.master.update()
        time.sleep(2)
        # Lancer l'exécutable de Speedtest
        process = subprocess.Popen(['speedtest', '--accept-license'], stdin=subprocess.PIPE)
        process.communicate(input=b'yes\n')

        result = subprocess.run(['speedtest'], stdout=subprocess.PIPE)

        # Récupérer les résultats de la sortie
        output = result.stdout.decode()

        # Rechercher les valeurs de téléchargement et d'upload dans la sortie
        download_match = re.search(r'(Download:\s*)(\d+\.?\d*) (Mbps)', output)
        download = download_match.group(2)

        upload_match = re.search(r'(Upload:\s*)(\d+\.?\d*) (Mbps)', output)
        upload = upload_match.group(2)
        # Afficher les résultats
        self.result_text.insert(tk.END, "Test fini\n")
        self.result_text.insert(tk.END, "Download: " + download + " Mbps\n") 
        self.result_text.insert(tk.END, "Upload: " + upload + " Mbps")


        #Ecrire les résultats dans un fichier txt
        with open(f"/home/client/semaos/speedtestresult.txt", "w") as f:
            f.write("Download: " + download + " Mbps\n") 
            f.write("Upload: " + upload + " Mbps")
        f.close()

class FourPage(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.create_widgets()
        self.master.geometry("800x600")

    def go_to_main_page(self):
        self.destroy()
        MainPage(self.master)
    

    def create_widgets(self):
        self.result_text = tk.Text(self, height=30, width=100)
        self.result_text.tag_configure("center", justify='center')
        self.result_text.tag_configure("right", justify='right')
        self.result_text.pack()

        self.back_button = tk.Button(self)
        self.back_button["text"] = "Retour"
        self.back_button["command"] = self.go_to_main_page
        self.back_button.pack()
        self.display_results()

    def display_results(self):
        try:
            with open(f'/home/client/semaos/scan_result.txt', 'r') as f:
                result = f.readlines()
        except FileNotFoundError:
            self.result_text.insert(tk.END, "Aucun résultat de scan réseau n'a été trouvé.\n")
            return

        for line in result:
            ip, hostname, ports = line.strip().split('\t')
            self.result_text.insert(tk.END, "\n")
            self.result_text.insert(tk.END, "{:<20}{:<30}{}\n".format(ip, hostname, ports))



        



root = tk.Tk()
root.attributes("-type", "tool")
root.title("SemaOS "+ url_content)
app = MainPage(master=root)



def run_flask_app():
    app = Flask(__name__)
    @app.route('/')
    def index():
        return ''

    @app.route('/variables')
    def variables():
        variables = {
            'local_ip': local_ip,
            'time_ping': time_ping,
            'result_download': result_download,
            'result_upload': result_upload,
            'ip': ip,
            'Hostname': Hostname,
            'dns_hostname': dns_hostname,
            'url_content': url_content           
        }
      
        return jsonify(variables)


    @app.route('/restart', methods=['POST'])
    def restart():
        try:
            subprocess.run(['reboot'])
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
        
    # Send the results to the client using the Flask web server
    
    @app.route('/scan_results')
    def scan_results():
        with open('/home/client/semaos/scan_result.txt', 'r') as f:
            result = f.readlines()

    # Create empty lists to store the IP, hostname, and port results
        ips = []
        hostnames = []
        ports = []

        for line in result:
            ip_scan, hostname_scan, ports_scan = line.strip().split('\t')
            ips.append(ip_scan)
            hostnames.append(hostname_scan)
            ports.append(ports_scan)

        scan_results = {
            'ips': ips,
            'hostnames': hostnames,
            'ports': ports
        }

        return jsonify(scan_results)




    app.run(host='0.0.0.0', port=5000)

# Lancer le thread pour l'application Flask
flask_thread = threading.Thread(target=run_flask_app)
flask_thread.start()
app.mainloop()
