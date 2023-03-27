```from flask import Flask, render_template, request, redirect, url_for
import requests
import os
import ipaddress
import subprocess

app = Flask(__name__)

# Adresse IP des agents
#agent_ips = [] # A adapter en fonction des adresses IP des agents disponibles
ips_last_modified = 0

# Définition de la page d'accueil
@app.route('/')
def home():
    global agent_ips
    global ips_last_modified

    ips_path = 'ips.txt'
    ips_last_modified_new = os.stat(ips_path).st_mtime

    # Si le fichier a été modifié depuis la dernière requête, on recharge les adresses IP
    if ips_last_modified != ips_last_modified_new:
        with open(ips_path) as f:
            agent_ips = [ip.strip() for ip in f.read().split(',')]
        ips_last_modified = ips_last_modified_new

    agent_vars = []
    for agent_ip in agent_ips:
        agent_url = f'http://{agent_ip}:5000'
        try:
            response = requests.get(agent_url, timeout=2)
            variables = response.json()['variables']
        except:
            variables = None
        agent_vars.append((agent_ip, variables))
    return render_template('home.html', agent_vars=agent_vars)

# Définition de la page d'affichage des variables d'un agent
@app.route('/agent/<agent_ip>')
def agent(agent_ip):
    agent_url = f'http://{agent_ip}:5000/variables'
    scan_results_url = f'http://{agent_ip}:5000/scan_results'
    try:
        response_variables = requests.get(agent_url, timeout=2)
        variables = response_variables.json()
        local_ip = variables.get('local_ip', None)
        time_ping = variables.get('time_ping', None)
        ip = variables.get('ip', None)
        result_download = variables.get('download', None)
        result_upload = variables.get('upload', None)
        Hostname = variables.get('Hostname', None)
        url_content = variables.get('url_content',None)
        dns_hostname = variables.get('dns_hostname',None)
    except:
        variables = None
        local_ip = None
        time_ping = None
        result_upload = None
        result_download = None
        ip = None
        Hostname = None
        url_content = None
        dns_hostname = None
    try:
        response_scan_results = requests.get(scan_results_url, timeout=2)
        scan_results = response_scan_results.json()
        ips = scan_results.get('ips', None)
        hostnames = scan_results.get('hostnames', None)
        ports = scan_results.get('ports', None)
    except:
        scan_results = None
        ips = None
        hostnames = None
        ports = None

    return render_template('agent.html', agent_ip=agent_ip, variables=variables, local_ip=local_ip, time_ping=time_ping, result_upload=result_upload, result_download=result_download, ip=ip, Hostname=Hostname, ips=ips, hostnames=hostnames, ports=ports, scan_results=scan_results,url_content=url_content, dns_hostname=dns_hostname)

# Route pour redémarrer un agent
@app.route('/restart_agent', methods=['POST'])
def restart_agent():
    agent_ip = request.form['agent_ip']
    agent_url = f'http://{agent_ip}:5000/restart'
    try:
        response = requests.post(agent_url, timeout=2)
        result = 'Agent redémarré avec succès'
    except:
        result = 'Impossible de redémarrer l\'agent'
    return redirect(url_for('home'))

@app.route('/get_ping_value/<agent_ip>')
def get_ping_value(agent_ip):
    agent_url = f'http://{agent_ip}:5000/variables'
    try:
        response_variables = requests.get(agent_url, timeout=2)
        variables = response_variables.json()
        time_ping = variables.get('time_ping', None)
    except:
        time_ping = None
    return {'time_ping': time_ping}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```
message.txt
4 Ko