def create_forgery(oracle):
    msgs = []
    macs = []
    for i in range(10):
        msgs.append("msg %d" % i)
        macs.append(oracle(msgs[i]))
    return (msgs[-1], macs[-1])
