MAC Telnet Client RouterOS
A Python-based MAC Telnet Client that connects to devices using MAC addresses for authentication. This client implements the required protocol to establish a telnet session with the target device.

Features

Secure Authentication: Utilizes elliptic curve cryptography for secure authentication.

Control Packet Handling: Efficient handling of control packets for various operations.

Terminal Integration: Supports terminal interactions with character-by-character input processing.

Keep-Alive Mechanism: Maintains session with periodic keep-alive messages.

Signal Handling: Graceful handling of termination signals and special key presses like Ctrl+C and Tab.

Requirements

Python 3.7+

Linux, or Windows

Installation

Clone the repository and navigate into the project directory:

git clone https://github.com/petrunetworking/MAC-Telnet-Routeros.git

cd mac-telnet-client

Install the required Python packages:

pip install -r requirements.txt

Usage

Run the MAC Telnet Client with the following command:

python mactelnet_windows.py  [-u USERNAME] [-p PASSWORD] <MAC_ADDRESS> #for Windows

python3 mac_telnet_linux.py  [-u USERNAME] [-p PASSWORD] <MAC_ADDRESS> #for Linux

Arguments

MAC_ADDRESS: The MAC address of the device to connect to (format: XX:XX:XX:XX:XX:XX).

-u, --username: (Optional) The username for authentication. If not provided, the user will be prompted.

-p, --password: (Optional) The password for authentication. If not provided, the user will be prompted.

Example

python mactelnet_windows.py  -u admin -p secret AA:BB:CC:DD:EE:FF

Interactive Usage

If the username and/or password are not provided via command-line arguments, the client will prompt the user to enter them.

Special Key Bindings

Ctrl+C: Sends a stop command to the device.

Ctrl+BREAK: Sends a signal closing session  to the device.

Tab: Sends a tab key press to the device.

Technical Details

Control Packet Structure

The client communicates using specific control packet types for various operations:

CP_BEGIN_AUTHENTICATION: Initiates authentication.

CP_ENCRYPTION_KEY: Exchanges encryption keys.

CP_PASSWORD: Sends the hashed password for authentication.

CP_USERNAME: Sends the username for authentication.

CP_TERMINAL_TYPE: Specifies the terminal type.

CP_TERMINAL_WIDTH: Specifies the terminal width.

CP_TERMINAL_HEIGHT: Specifies the terminal height.

CP_END_AUTHENTICATION: Ends the authentication phase.

Message Types

SYS_START_SESSION: Starts a session with the target device.

SYS_DATA: Sends data to the device.

SYS_ACKNOWLEDGE: Acknowledges received packets.

SYS_END_SESSION: Ends the session.

Contributing

We welcome contributions to enhance the functionality of this MAC Telnet Client. Please fork the repository and create a pull request with your improvements.
or open a issue to add improvements in code 

License

This project is licensed under the GNU GENERAL PUBLIC LICENSE V3. See the LICENSE file for details.

Author

petrunetworking

