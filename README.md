# Wifi Sniffer Tool
## Overview
A python-based tool to sniff the packet transmitting over the network.
 
> [!WARNING]
> This project is developed strictly for educational and research purposes. It is intended to demonstrate how network packet analysis works and to help understand network security concepts.

## Learning Outcomes

- Understand how packet sniffing works at the network layer
- Learn how monitor mode operates in wireless adapters
- Explore how protocols like HTTP, HTTPS, and TLS transmit data
- Understand ethical considerations in network security testing
- Practice building GUI-based networking tools using Python and Tkinter

## Project Structure
## Project Structure

```text
packet-sniffer/
├── main.py
├── gui.py
├── sniffer_core.py
├── ip-viewer.py
├── requirements.txt
└── README.md
```

## Quick Start

```bash
# clone the repo
git clone https://github.com/Arch-x86/WiFi-Sniffer-Python.git
cd WiFi-Sniffer-Python

# install required libraries
pip install -r requirements.txt

# run the applicaiton
python3 main.py
```
## Steps to take for the program to run.

When the interface is shown after running. you have to enter your network interface. There are several options shoen in the netwrok interface box. 
SO to identify what is your network interface. Follow these steps:
1. open the powersehll,
2. Run the command ipconfig
3. look for your IPv4 Address
4. after finding your IPv4 address 
5. Open the VS code and run the ip-viewer.py 
6. It wil show all the interfaces in your device
7. match the IPv4 address with the ip of interface.
8. The matching interface will have exact ip.
9. look at the interface name of that ip 
10. The interface name will be inside {}.eg {D35E3520-B9CE-41E0-8940-0E11591F7DB7}
11. run the main.py and look for the first 4 letters of your interface. Eg {D35E....}
12. choose it 
13. select the protocal you want to sniff the packet.
14. click on start button.


## Author
- **Ankit Thebe** - Initial Demonstration

## License
This project is licensed under MIT License. See more about [License]()

