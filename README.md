# palo-alto-security-policy-visualizer
A visualizer for Palo Alto Security Policies

**Requirements**
- A CSV export of Security Policies from Palo Alto Firewalls

**Getting Started**
<br>If you don't already have the additional packages installed you will need to install them with pip
- pip install pandas
- pip install argparse
- pip install pyvis

**File Storage**
- The CSV files of Security Policies can be left in the current working directory of the script or can be targeted with \
the -f argument.
- Example: sp-visualizer.py -f /home/user/Downloads/export_policies_security_rulebase_post-rules_01082023_130023edt.csv

**Command Line Arguments**
- "-sz", "--src_zone", "Filter Visualization by Source Zone"
- "-dz", "--dst_zone", "Filter Visualization by Destination Zone"
- "-sip", "--src_ip", "Filter Visualization by Source IP"
- "-dip", "--dst_ip", "Filter Visualization by Destination IP"
- "-t", "--tags", "Filter Visualization by Tag"
- "-g", "--group", "Filter Visualization by Group"
- "-n", "--policy_name", "Filter Visualization by Security Policy Name"
- "-f", "--file", "Specify a file not in the current working directory"

**Visualizer Usage**
- python sp-visualizer.py -f /home/user/Downloads/export_policies_security_rulebase_post-rules_01082023_130023edt.csv
- python sp-visualizer.py -dz untrust
- python sp-visualizer.py -sz trust -dz untrust
- python sp-visualizer.py -sz trust -dz untrust -t critical-asset -n ssh

**Visualization**
- The visualization will be created as a .html file in the working directory of the script.