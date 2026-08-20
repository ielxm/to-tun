import os

print("AAA", flush=True)
print("PID:", os.getpid(), flush=True)

PID=67389

fd = os.open(f"/proc/{PID}/ns/user", os.O_RDONLY)
fd_net = os.open(f"/proc/{PID}/ns/net", os.O_RDONLY)

print("BBBB fd =", fd, flush=True)

os.setns(fd, os.CLONE_NEWUSER)
os.setns(fd_net, os.CLONE_NEWNET)

print("CCC", flush=True)

