from collections import defaultdict

log_file = "traffic.log"
alert_file = "alerts.txt"

# Suspicious ports/protocols
SUSPICIOUS_PORTS = {"21": "FTP", "23": "Telnet", "22": "SSH"}
UDP_MONITOR = {"161": "SNMP"}

def analyze_traffic():
    alerts = []
    ip_activity = defaultdict(int)

    with open(log_file, "r") as file:
        for line in file:
            parts = line.strip().split()

            if len(parts) == 5:
                src_ip = parts[0]
                dst_ip = parts[2]
                protocol = parts[3]
                port = parts[4]

                ip_activity[src_ip] += 1

                # Detect suspicious TCP ports
                if protocol == "TCP" and port in SUSPICIOUS_PORTS:
                    alerts.append(
                        f"[WARNING] {SUSPICIOUS_PORTS[port]} access from {src_ip} to {dst_ip}"
                    )

                # Detect suspicious UDP traffic
                if protocol == "UDP" and port in UDP_MONITOR:
                    alerts.append(
                        f"[WARNING] Suspicious UDP ({UDP_MONITOR[port]}) traffic from {src_ip}"
                    )

    # Detect abnormal traffic volume
    for ip, count in ip_activity.items():
        if count >= 3:
            alerts.append(f"[ALERT] High traffic volume from {ip} ({count} connections)")

    return alerts


def save_alerts(alerts):
    with open(alert_file, "w") as file:
        for alert in alerts:
            file.write(alert + "\n")


if __name__ == "__main__":
    alerts = analyze_traffic()
    save_alerts(alerts)

    print("Traffic analysis complete. Alerts:")
    for alert in alerts:
        print(alert)