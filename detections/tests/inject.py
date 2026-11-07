"""Feed agent-format Windows events to wazuh-analysisd.

Runs inside the throwaway Wazuh manager container started by run.sh. It writes
to the analysis queue exactly like the agent's eventchannel reader does, so the
events go through the real Windows decoder and the full ruleset.
"""

import socket
import sys
import time

QUEUE = "/var/ossec/queue/sockets/queue"
EVENTCHANNEL_QUEUE_ID = "f"

with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
    sock.connect(QUEUE)
    with open(sys.argv[1], encoding="utf-8") as events:
        for line in events:
            if line.strip():
                sock.send(f"{EVENTCHANNEL_QUEUE_ID}:EventChannel:{line.strip()}".encode())
                time.sleep(0.05)  # keep the order stable for frequency rules
