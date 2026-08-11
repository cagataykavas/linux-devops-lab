from __future__ import annotations

import signal
import time

running = True


def shutdown(signum, frame):
    global running
    print(f"received signal {signum}; stopping cleanly")
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

print("service started")
while running:
    time.sleep(0.5)
print("cleanup complete")
