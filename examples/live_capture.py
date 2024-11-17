import beefi
import time

source = beefi.DataSource.Live("wlp1s0")
bee = beefi.Bee(source)
bee.start()

try:
    while True:
        if data := bee.poll():
            print(f"data: {data}")
        else:
            # No data in the queue; Sleep 10 ms to avoid busy wait
            time.sleep(0.01)
except KeyboardInterrupt:
    print("Keyboard interrupt detected; Stopping capture.")
finally:
    bee.stop()

