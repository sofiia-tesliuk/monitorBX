import json
import socket
from flask import Flask, Response, render_template

application = Flask(__name__)

LISTEN_PORT = 8080
SOCKET = None
SERVER_ADDRESS = ('192.168.99.157', LISTEN_PORT)
CONNECTION = None
CLIENT_ADDRESS = None


def data_to_dict(data):
    new_d = {}
    lines = data.strip(b'\x00').split(b'\n')
    for line in lines:
        if not line:
            continue
        line = line.decode("utf-8")
        if line.startswith('Speed'):
            new_d['speed'] = float(line.split()[-1])
        elif line.startswith('Packets passed'):
            new_d['passed'] = int(line.split()[-1])
        elif line.startswith('Packets dropped'):
            new_d['dropped'] = int(line.split()[-1])
        elif line.startswith('Packets with TCP protocol'):
            new_d['tcp'] = int(line.split()[-1])
        elif line.startswith('Packets with UDP protocol'):
            new_d['udp'] = int(line.split()[-1])
        elif line.startswith('Packets with ICMP protocol'):
            new_d['icmp'] = int(line.split()[-1])
        elif line.startswith('Packets with Other protocol'):
            new_d['other'] = int(line.split()[-1])
        elif line.startswith('Unique IPs'):
            new_d['ips'] = int(line.split()[-1])
        elif line.startswith('Unique PORTs'):
            new_d['ports'] = int(line.split()[-1])
        elif line.startswith('Time'):
            new_d['time'] = line.split()[-2]
        else:
            print("Undefined data line: {}".format(line))
    return new_d


@application.route('/')
def index():
    return render_template('index.html')


@application.route('/chart-data')
def chart_data():
    def listen_to_port():
        try:
            while True:
                size = SOCKET.recv(2)
                data = SOCKET.recv(int.from_bytes(size, "big"))
                if data:
                    json_data = json.dumps(data_to_dict(data))
                    print(json_data)
                    yield f"data:{json_data}\n\n"
                else:
                    print('No more data from ', CLIENT_ADDRESS)
                    break

        finally:
            print('Connection from closed from ', CLIENT_ADDRESS)
            SOCKET.close()

    # Create a TCP/IP socket
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to {} port {}".format(SERVER_ADDRESS[0], SERVER_ADDRESS[1]))
    SOCKET.connect(SERVER_ADDRESS)

    return Response(listen_to_port(), mimetype='text/event-stream')


if __name__ == '__main__':
    application.run(debug=True, threaded=True)
