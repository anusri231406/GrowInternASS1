from scapy.all import sniff, IP, TCP
from flask import Flask, jsonify
import threading

app = Flask(__name__)

# List to store alerts
alerts = []

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            if tcp_dport == 80 or tcp_sport == 80:
                alert = {
                    'source_ip': ip_src,
                    'destination_ip': ip_dst,
                    'source_port': tcp_sport,
                    'destination_port': tcp_dport,
                    'protocol': 'HTTP',
                    'alert': 'Potential HTTP traffic detected'
                }
                alerts.append(alert)
                print(alert)  # Console Output

def start_sniffing():
    # Start sniffing network packets
    sniff(prn=packet_callback, store=0)

@app.route('/alerts', methods=['GET'])
def get_alerts():
    # Return alerts as JSON response
    return jsonify(alerts)

def run_flask():
    # Run the Flask web server
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    # Start packet sniffing in a separate thread
    threading.Thread(target=start_sniffing).start()
    # Start the Flask web server in a separate thread
    threading.Thread(target=run_flask).start()
