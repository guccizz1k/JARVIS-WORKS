import os,threading,time
import pytest
from scripts import p1_cleanroom_key_recovery_v223 as c

def test_fragmented_frame():
    r,w=os.pipe()
    def writer():
        try:
            os.write(w,b"first");time.sleep(.02);os.write(w,b"second")
        finally:os.close(w)
    t=threading.Thread(target=writer);t.start()
    try:assert c._read_pipe(str(r),32,"PIPE_INVALID")==b"firstsecond"
    finally:os.close(r);t.join(timeout=1)
def test_exact_bound_and_oversize():
    for payload,ok in ((b"x"*8,True),(b"x"*9,False),(b"",False)):
        r,w=os.pipe()
        try:
            os.write(w,payload);os.close(w);w=None
            if ok:assert c._read_pipe(str(r),8,"PIPE_INVALID")==payload
            else:
                with pytest.raises(c.Blocked,match="PIPE_INVALID"):c._read_pipe(str(r),8,"PIPE_INVALID")
        finally:
            os.close(r)
            if w is not None:os.close(w)
def test_unclosed_writer_times_out(monkeypatch):
    monkeypatch.setattr(c,"PIPE_READ_TIMEOUT_SECONDS",.05)
    r,w=os.pipe()
    try:
        os.write(w,b"partial")
        with pytest.raises(c.Blocked,match="PIPE_INVALID"):c._read_pipe(str(r),32,"PIPE_INVALID")
    finally:os.close(r);os.close(w)
