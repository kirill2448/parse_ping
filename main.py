
class PingAnalyzer:
    def __init__(self, host):
        self.host = host
        self.ping_times = []

    def ping(self, count=4, timeout=None):
        command = self._get_ping_command(count, timeout)
        output = os.popen(command).read()
        self._parse_ping_output(output)

    def _get_ping_command(self, count, timeout):
        if os.name == 'nt':
            return f'ping -n {count} -w {timeout*1000 if timeout else 2000} {self.host}'
        else:
            return f'ping -c {count} -W {timeout if timeout else 2} {self.host}'

    def _parse_ping_output(self, output):
        if os.name == 'nt':
            pattern = r"time=(\d+)"
        else:
            pattern = r"time=(\d+.\d+)"
        matches = re.findall(pattern, output)
        if matches:
            self.ping_times = [float(time) for time in matches]

    def get_statistics(self):
        statistics = {
            'host': self.host,
            'min_delay': min(self.ping_times) if self.ping_times else None,
            'max_delay': max(self.ping_times) if self.ping_times else None,
            'avg_delay': sum(self.ping_times) / len(self.ping_times) if self.ping_times else None,
            'packet_loss': (len(self.ping_times) / 4) * 100 if self.ping_times else 100,
            'jitter': self._calculate_jitter(),
        }
        return statistics

    def _calculate_jitter(self):
        if len(self.ping_times) < 2:
            return None
        else:
            return sum(abs(time - self.ping_times[i-1]) for i, time in enumerate(self.ping_times[1:])) / (len(self.ping_times) - 1)

    def main(self):
        hosts = ['yadnex.ru', 'facebook.com']
        results = []
        for host in hosts:
            analyzer = PingAnalyzer(host)
            analyzer.ping(count=4, timeout=2)
            result = analyzer.get_statistics()
            results.append(result)

        output = json.dumps(results, indent=4)
        print(output)



def packet_callback(packet):
    if packet[TCP].payload:
        print(str(packet[TCP].payload))

# Запуск сниффера на Windows
def run_sniffer_windows():
    sniff(filter="tcp", prn=packet_callback, iface="Ethernet")

# Запуск сниффера на Linux
def run_sniffer_linux():
    sniff(filter="tcp", prn=packet_callback, iface="eth0")

if __name__ == "__main__":
    import platform
    import json
    import os
    import platform
    import re

    from scapy.all import *
    from scapy.layers.inet import TCP


    p=PingAnalyzer('yadnex.ru')
    p.main()


    # Проверка операционной системы
    os = "Windows"

    if os == "Windows":
        run_sniffer_windows()
    elif os == "Linux":
        run_sniffer_linux()
    else:
        print("Unsupported OS: " + os)