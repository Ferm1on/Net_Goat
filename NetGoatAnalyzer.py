from re import search
from typing import List, Dict
from csv import DictReader
from glob import glob
from statistics import median, stdev
# from pyshark import FileCapture
from subprocess import check_output, CalledProcessError

# _______________________________________________________ Classes and Functions _______________________________________________________
class PingStatistic:
    def __init__(self, filename):
        # Initialize instance attributes
        self.target = ''
        self.minimum = float('inf')
        self.maximum = float('-inf')
        self.average = 0.0
        self.median = 0.0
        self.stdev = 0.0                    # New attribute for standard deviation
        self.success = 0                 # Count of successful pings
        self.timeouts = 0                # Count of pings that timed out or were not successful
        self.success_rate = 0.0          # New attribute for the success rate

        count = 0                       # Count of latency values for successful pings (nonzero)
        latencies = []                  # List to store nonzero latencies

        with open(filename, newline='') as ping_gateway:
            reader = DictReader(ping_gateway)
            rows = list(reader)
            # Extract the target from the first row if available
            if rows:
                self.target = rows[0]['Target']

            for row in rows:
                # Check the status for each ping
                if row['Status'] == 'Success':
                    self.success += 1
                    latency = int(row['Latency(ms)'])
                    # Exclude latency values of 0 from statistical calculations
                    if latency == 0:
                        continue
                    latencies.append(latency)
                    self.average += latency
                    if latency < self.minimum:
                        self.minimum = latency
                    if latency > self.maximum:
                        self.maximum = latency     
                    count += 1
                else:
                    self.timeouts += 1

        # Finalize the average, median, and standard deviation calculations if there were valid latency entries
        if count > 0:
            self.average = round(self.average / count,1)
            self.median = median(latencies)
            # Compute sample standard deviation only if there is more than one latency value
            if len(latencies) > 1:
                self.stdev = round(stdev(latencies),1)
            else:
                self.sd = 0.0
        else:
            self.average = None
            self.median = None
            self.sd = None

        # Calculate success rate if there is at least one ping attempt
        total_attempts = self.success + self.timeouts
        if total_attempts > 0:
            self.success_rate = round(self.success / total_attempts, 2)
        else:
            self.success_rate = None

    def get_report(self):
        """Return a formatted string report of the statistics."""
        report_lines = [
            "\t_________________________________________________________________",
            f"\tPing Statistic Report for {self.target}",
            f"\tMinimum Latency: {self.minimum}",
            f"\tMaximum Latency: {self.maximum}",
            f"\tAverage Latency: {self.average}",
            f"\tMedian Latency: {self.median}",
            f"\tStandard Deviation: {self.stdev}",
            f"\tSuccessful Pings: {self.success}",
            f"\tTimeouts: {self.timeouts}",
            f"\tSuccess Rate: {self.success_rate}",
            "\t_________________________________________________________________",
        ]
        return "\n".join(report_lines)

    def print_report(self):
        """Print the report to the terminal."""
        print(self.get_report())

    def log_report(self, filepath):
        """Append the report to the specified file."""
        with open(filepath, "a") as f:
            f.write(self.get_report())
            f.write("\n")  # Optionally add a newline for separation

class DNSStatistic:
    def __init__(self, filename):
        # Extract source and target from the filename.
        # Example filename: "DNS(8.8.8.8)_LU(www.microsoft.com)_170225113736"
        match = search(r'DNS\((.*?)\)_LU\((.*?)\)', filename)
        if match:
            self.source = match.group(1)
            self.target = match.group(2)
        else:
            self.source = ''
            self.target = ''

        # Initialize statistical attributes
        self.minimum = float('inf')
        self.maximum = float('-inf')
        self.average = 0.0
        self.median = 0.0
        self.stdev = 0.0
        self.success = 0       # Count of successful lookups
        self.timeouts = 0      # Count of lookups that resulted in an error
        self.success_rate = 0.0

        count = 0             # Count of valid lookup times used for statistics
        latencies = []        # List to store valid lookup times

        with open(filename, newline='') as dns_file:
            reader = DictReader(dns_file)
            rows = list(reader)
            for row in rows:
                # Consider the lookup successful if the Error field is empty.
                if row['Error'] == '':
                    self.success += 1
                    lookup_time = float(row['LookUp Time in ms'])
                    # Optionally exclude lookup times of 0 from statistics.
                    if lookup_time == 0:
                        continue
                    latencies.append(lookup_time)
                    self.average += lookup_time
                    if lookup_time < self.minimum:
                        self.minimum = lookup_time
                    if lookup_time > self.maximum:
                        self.maximum = lookup_time
                    count += 1
                else:
                    self.timeouts += 1

        # Compute average, median, and standard deviation if valid data exists.
        if count > 0:
            self.average = round(self.average / count, 1)
            self.median = median(latencies)
            if len(latencies) > 1:
                self.stdev = round(stdev(latencies), 1)
            else:
                self.stdev = 0.0
        else:
            self.average = None
            self.median = None
            self.stdev = None

        total_attempts = self.success + self.timeouts
        if total_attempts > 0:
            self.success_rate = round(self.success / total_attempts, 2)
        else:
            self.success_rate = None

    def get_report(self):
        """Return a formatted string report of the DNS statistics."""
        report_lines = [
            "\t_________________________________________________________________",
            f"\tDNS Statistic Report for {self.target} (Source: {self.source})",
            f"\tMinimum LookUp Time: {self.minimum}",
            f"\tMaximum LookUp Time: {self.maximum}",
            f"\tAverage LookUp Time: {self.average}",
            f"\tMedian LookUp Time: {self.median}",
            f"\tStandard Deviation: {self.stdev}",
            f"\tSuccessful Lookups: {self.success}",
            f"\tTimeouts/Errors: {self.timeouts}",
            f"\tSuccess Rate:\t{self.success_rate}",
            "\t_________________________________________________________________",
        ]
        return "\n".join(report_lines)

    def print_report(self):
        """Print the report to the terminal."""
        print(self.get_report())

    def log_report(self, filepath):
        """Append the report to the specified file."""
        with open(filepath, "a") as f:
            f.write(self.get_report())
            f.write("\n")

# returns number of packets based on supplied command
def count_packets(command):
    try:
        output = check_output(command, text=True)
        # Count non-empty lines in the output
        count = len([line for line in output.splitlines() if line.strip()])
        return count
    except CalledProcessError as e:
        print("Error counting packets:", e)
        return None

def append_report(filepath, report):
    with open(filepath, "a") as f:
        f.write(report)
        f.write("\n")

# _______________________________________________________ BODY _______________________________________________________
# Global Variables

# Ping Working Variables
Ping_Stats = {}
Average_Ping = 0.0
total_ping_success = 0
total_ping_timeouts = 0
all_ping_minimum = float('inf')
all_ping_maximum = float('-inf')
ping_averages = []
ping_medians = []
ping_stdevs = []

# Pass Ping Values
pass_ping_success_rate = 0.97
pass_ping_average = 56.1 + 51 
pass_ping_median = 45.5 + 51 
pass_ping_stdev = 51 * 2   

# Fail Ping Values: Callibrated based on failed WAP
fail_ping_success_rate = 0.69
fail_ping_average = 1894.2 
fail_ping_median = 1633.75 
fail_ping_stdev = 1384.8 

# DNS Working Variables
DNS_Stats = {}
total_dns_success = 0
total_dns_timeouts = 0
all_dns_minimum = float('inf')
all_dns_maximum = float('-inf')
dns_averages = []
dns_medians = []
dns_stdevs = []

# Pass DNS Values
pass_dns_success_rate = 0.98
pass_dns_average = 1080.3 + 463.8   
pass_dns_median = 54.81865 + 463.8      
pass_dns_stdev = 463.8 * 1.5   

# Fail DNS Values: Callibrated based on failed WAPs
fail_dns_success_rate = 0.80
fail_dns_average = 2736.8  
fail_dns_median = 1088.6293500000002     
fail_dns_stdev = 2645.1

# Wireshark Working Variables
total_packets = 0
filtered_packets = 0

# Pass Wireshark Values
pass_packet_loss_rate = 0.06

# Fail Wireshark Values
fail_packet_loss_rate = 0.1

# Open Files
Ping_Files = glob('Ping_*')
DNS_Files = glob('DNS*')
Pcap_File = glob("WireSharkCapture_*")

# Wireshark Pass and Warnings
# Pass_Wireshark = if more than 10% of packages drop wireshark should fail.
# anyway more than 6% should be a warning. 

#=================================== Ping Analysis ===================================

# Load all Ping Files
for index, file in enumerate(Ping_Files):
    Ping_Stats[index] = PingStatistic(file)

# Load all Ping Files and Commpute Global statistics and log local statistics.
for target in Ping_Stats.values():
    target.print_report()
    target.log_report('Report_Ping.txt')

    total_ping_success += target.success
    total_ping_timeouts += target.timeouts
    
    if target.minimum is not None and target.minimum < all_ping_minimum:
        all_ping_minimum = target.minimum
    if target.maximum is not None and target.maximum > all_ping_maximum:
        all_ping_maximum = target.maximum
    if target.average is not None:
        ping_averages.append(target.average)
    if target.median is not None:
        ping_medians.append(target.median)
    if target.stdev is not None:
        ping_stdevs.append(target.stdev)

Ping_Success = total_ping_success
Ping_Timeouts = total_ping_timeouts
Ping_success_rate = round(Ping_Success / (Ping_Success + Ping_Timeouts), 2) if (Ping_Success + Ping_Timeouts) > 0 else None
Ping_Minimum = all_ping_minimum if all_ping_minimum != float('inf') else None
Ping_Maximum = all_ping_maximum if all_ping_maximum != float('-inf') else None
Ping_Average = round(sum(ping_averages) / len(ping_averages), 1) if ping_averages else None
Ping_Median = median(ping_medians) if ping_medians else None
Ping_Stdev = round(sum(ping_stdevs) / len(ping_stdevs), 1) if ping_stdevs else None

# ------------------ Compute Pass/Warning/Fail Status for Ping ------------------
if Ping_success_rate is None:
    ping_success_rate_status = ""
else:
    if Ping_success_rate < fail_ping_success_rate:
        ping_success_rate_status = "(FAIL)"
    elif Ping_success_rate < pass_ping_success_rate:
        ping_success_rate_status = "(WARNING)"
    else:
        ping_success_rate_status = "(PASS)"

if Ping_Average is None:
    ping_average_status = ""
else:
    if Ping_Average > fail_ping_average:
        ping_average_status = "(FAIL)"
    elif Ping_Average > pass_ping_average:
        ping_average_status = "(WARNING)"
    else:
        ping_average_status = "(PASS)"

if Ping_Median is None:
    ping_median_status = ""
else:
    if Ping_Median > fail_ping_median:
        ping_median_status = "(FAIL)"
    elif Ping_Median > pass_ping_median:
        ping_median_status = "(WARNING)"
    else:
        ping_median_status = "(PASS)"

if Ping_Stdev is None:
    ping_stdev_status = ""
else:
    if Ping_Stdev > fail_ping_stdev:
        ping_stdev_status = "(FAIL)"
    elif Ping_Stdev > pass_ping_stdev:
        ping_stdev_status = "(WARNING)"
    else:
        ping_stdev_status = "(PASS)"

#=================================== DNS Analysis ===================================

# Load all DNS Files and Commpute Global statistics and log local statistics.
for index, file in enumerate(DNS_Files):
    DNS_Stats[index] = DNSStatistic(file)

for target in DNS_Stats.values():
    target.print_report()
    target.log_report('Report_DNS.txt')

    total_dns_success += target.success
    total_dns_timeouts += target.timeouts
    
    if target.minimum is not None and target.minimum < all_dns_minimum:
        all_dns_minimum = target.minimum
    if target.maximum is not None and target.maximum > all_dns_maximum:
        all_dns_maximum = target.maximum
    if target.average is not None:
        dns_averages.append(target.average)
    if target.median is not None:
        dns_medians.append(target.median)
    if target.stdev is not None:
        dns_stdevs.append(target.stdev)

DNS_Success = total_dns_success
DNS_Timeouts = total_dns_timeouts
DNS_success_rate = round(DNS_Success / (DNS_Success + DNS_Timeouts), 2) if (DNS_Success + DNS_Timeouts) > 0 else None
DNS_Minimum = all_dns_minimum if all_dns_minimum != float('inf') else None
DNS_Maximum = all_dns_maximum if all_dns_maximum != float('-inf') else None
DNS_Average = round(sum(dns_averages) / len(dns_averages), 1) if dns_averages else None
DNS_Median = median(dns_medians) if dns_medians else None
DNS_Stdev = round(sum(dns_stdevs) / len(dns_stdevs), 1) if dns_stdevs else None

# ------------------ Compute Pass/Warning/Fail Status for DNS ------------------
if DNS_success_rate is None:
    dns_success_rate_status = ""
else:
    if DNS_success_rate < fail_dns_success_rate:
        dns_success_rate_status = "(FAIL)"
    elif DNS_success_rate < pass_dns_success_rate:
        dns_success_rate_status = "(WARNING)"
    else:
        dns_success_rate_status = "(PASS)"

if DNS_Average is None:
    dns_average_status = ""
else:
    if DNS_Average > fail_dns_average:
        dns_average_status = "(FAIL)"
    elif DNS_Average > pass_dns_average:
        dns_average_status = "(WARNING)"
    else:
        dns_average_status = "(PASS)"

if DNS_Median is None:
    dns_median_status = ""
else:
    if DNS_Median > fail_dns_median:
        dns_median_status = "(FAIL)"
    elif DNS_Median > pass_dns_median:
        dns_median_status = "(WARNING)"
    else:
        dns_median_status = "(PASS)"

if DNS_Stdev is None:
    dns_stdev_status = ""
else:
    if DNS_Stdev > fail_dns_stdev:
        dns_stdev_status = "(FAIL)"
    elif DNS_Stdev > pass_dns_stdev:
        dns_stdev_status = "(WARNING)"
    else:
        dns_stdev_status = "(PASS)"

#=================================== Wireshark Analysis ===================================

filter_string = "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack"
tshark_command = ["tshark", "-r", Pcap_File[0], "-T", "fields", "-e", "frame.number"]
tshark_command_filter = [
    "tshark",
    "-r", Pcap_File[0],
    "-Y", filter_string,
    "-T", "fields",
    "-e", "frame.number"
]

total_packets = count_packets(tshark_command)
filtered_packets = count_packets(tshark_command_filter)
packet_loss_rate = round(filtered_packets / total_packets, 2) if total_packets > 0 else None

if packet_loss_rate is None:
    packet_loss_rate_status = ""
else:
    if packet_loss_rate >= fail_packet_loss_rate:
        packet_loss_rate_status = "(FAIL)"
    elif packet_loss_rate >= pass_packet_loss_rate:
        packet_loss_rate_status = "(WARNING)"
    else:
        packet_loss_rate_status = "(PASS)"

# Append the global ping report to the Report_Ping.txt file and the Report_Summary.txt file
global_ping_report = "\n".join([
    "\t==============================================",
    "\tGLOBAL PING STATISTICS REPORT",
    f"\tTotal Successful Pings:\t{Ping_Success}",
    f"\tTotal Timeouts:\t\t{Ping_Timeouts}",
    f"\tMinimum Latency:\t{Ping_Minimum}",
    f"\tMaximum Latency:\t{Ping_Maximum}",
    f"\tSuccess Rate:\t\t{Ping_success_rate*100:.2f}% {ping_success_rate_status}",
    f"\tAverage Latency:\t{Ping_Average} {ping_average_status}",
    f"\tMedian Latency:\t\t{Ping_Median} {ping_median_status}",
    f"\tStandard Deviation:\t{Ping_Stdev} {ping_stdev_status}",
    "\t=============================================="
])

print(global_ping_report)

append_report("Report_Ping.txt", global_ping_report)
append_report("Report_Summary.txt", global_ping_report)

# Append the global DNS report to the Report_DNS.txt file and the Report_Summary.txt file

global_dns_report = "\n".join([
    "\t==============================================",
    "\tGLOBAL DNS STATISTICS REPORT",
    f"\tTotal Successful Lookups:\t{DNS_Success}",
    f"\tTotal Errors/Timeouts:\t\t{DNS_Timeouts}", 
    f"\tMinimum LookUp Time:\t\t{DNS_Minimum}",
    f"\tMaximum LookUp Time:\t\t{DNS_Maximum}",
    f"\tSuccess Rate:\t\t\t{DNS_success_rate*100:.2f}% {dns_success_rate_status}",
    f"\tAverage LookUp Time:\t\t{DNS_Average} {dns_average_status}",
    f"\tMedian LookUp Time:\t\t{DNS_Median} {dns_median_status}",
    f"\tStandard Deviation:\t\t{DNS_Stdev} {dns_stdev_status}",
    "\t=============================================="
])

print(global_dns_report)

append_report("Report_DNS.txt", global_dns_report)
append_report("Report_Summary.txt", global_dns_report)


# Append the global packet report to the Summary_Report.txt file

global_packet_report = "\n".join([
    "\t==============================================",
    "\tGLOBAL PACKET STATISTICS REPORT",
    f"\tTotal Packets:\t{total_packets}",
    f"\tRetransmited, Lost or Duplicated Packets:\t{filtered_packets}",
    f"\tPacket Loss Rate:\t{packet_loss_rate*100:.2f}% {packet_loss_rate_status}",
    "\t=============================================="
])

print(global_packet_report)

append_report("Report_Summary.txt", global_packet_report)