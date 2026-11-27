import time

def drain_observed(sample,clock=time.monotonic,sleep=time.sleep,budget=180,quiet=15,minimum=125):
    """Bounded observation; zero sessions is not proof of pool eviction."""
    if not (0<quiet<=budget and 0<=minimum<=budget):
        raise ValueError('DRAIN_POLICY_INVALID')
    start=clock()
    end=start+budget
    zero_since=None
    while True:
        count=sample()
        now=clock()
        if now>end:return False
        if count==0:
            if zero_since is None:zero_since=now
            if now-start>=minimum and now-zero_since>=quiet:return True
        else:
            zero_since=None
        if now>=end:return False
        sleep(min(5,end-now))
