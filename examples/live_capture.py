import time

import beefi

source = beefi.DataSource.Live(interface="wlp1s0")
bee = beefi.Bee(source)
print("Capture started in the background! Polling for data...")

try:
    while True:
        if data := bee.poll():
            bfm = beefi.bfa_to_bfm(data)
            print(f"data: {bfm.bfm}")
        else:
            # No data in the queue; Sleep to avoid busy wait
            time.sleep(0.1)
except KeyboardInterrupt:
    print("Keyboard interrupt detected; Stopping capture.")
finally:
    bee.stop()
