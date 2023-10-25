def sslv3Pad(msg):
    padNeeded = (16 - (len(msg) % 16)) - 1
    padding = padNeeded.to_bytes(padNeeded+1, "big")
    return msg+padding
def sslv3Unpad(padded_msg):
    paddingLen = padded_msg[-1] + 1
    return padded_msg[:-paddingLen]