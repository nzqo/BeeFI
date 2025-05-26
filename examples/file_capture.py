"""
Example on how to read BFA from file and convert to BFM.
"""

import beefi

bfa_batch = beefi.extract_from_pcap("bfi_capture.pcap")
bfm_batch = beefi.bfa_to_bfm_batch(bfa_batch)
print(bfm_batch.bfm.shape)
