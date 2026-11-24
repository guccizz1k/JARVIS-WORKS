#!/usr/bin/env python3
"""Local candidate key escrow. No network, no old key read, no activation."""
import argparse, hashlib, hmac, os, resource, secrets, stat, sys, termios, tty
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC=b'JW-KEY-ESCROW-V1\x00'
N=2**17; R=8; P=1
SIZE=len(MAGIC)+16+12+48

def validate_passphrase(p):
    if not isinstance(p,bytes) or not 24<=len(p)<=256 or any(x<32 or x>126 for x in p):
        raise ValueError('PASSPHRASE_FORMAT')

def derive(p,salt):
    validate_passphrase(p)
    return hashlib.scrypt(p,salt=salt,n=N,r=R,p=P,maxmem=256*1024*1024,dklen=32)

def seal(key,p):
    if len(key)!=32: raise ValueError('KEY_LENGTH')
    salt=secrets.token_bytes(16); nonce=secrets.token_bytes(12)
    head=MAGIC+salt+nonce
    return head+AESGCM(derive(p,salt)).encrypt(nonce,key,head)

def unseal(raw,p):
    if len(raw)!=SIZE or not raw.startswith(MAGIC): raise ValueError('ENVELOPE_FORMAT')
    i=len(MAGIC); salt=raw[i:i+16]; nonce=raw[i+16:i+28]; head=raw[:i+28]
    key=AESGCM(derive(p,salt)).decrypt(nonce,raw[i+28:],head)
    if len(key)!=32: raise ValueError('KEY_LENGTH')
    return key

def masked(prompt):
    if not sys.stdin.isatty() or not sys.stdout.isatty(): raise ValueError('TTY_REQUIRED')
    fd=sys.stdin.fileno(); state=termios.tcgetattr(fd); chars=[]
    print(prompt,end='',flush=True)
    try:
        tty.setcbreak(fd)
        while True:
            c=sys.stdin.read(1)
            if not c: raise ValueError('INPUT_EOF')
            if c in '\r\n': break
            if c in ('\b','\x7f'):
                if chars: chars.pop(); print('\b \b',end='',flush=True)
            elif c.isascii() and c.isprintable():
                if len(chars)>=256: raise ValueError('INPUT_TOO_LONG')
                chars.append(c); print('*',end='',flush=True)
            else: raise ValueError('INPUT_INVALID_CHARACTER')
    finally:
        termios.tcsetattr(fd,termios.TCSADRAIN,state); print(flush=True)
    p=''.join(chars).encode('ascii'); validate_passphrase(p); return p

def private_dir(path):
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o700 or st.st_uid!=os.getuid(): raise ValueError('PRIVATE_DIR_REQUIRED')

def read_private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size!=SIZE or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600: raise ValueError('PRIVATE_FILE_REQUIRED')
        raw=f.read(SIZE+1); end=os.fstat(f.fileno())
        if len(raw)!=SIZE or (st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=(end.st_size,end.st_mtime_ns,end.st_ctime_ns): raise ValueError('FILE_CHANGED')
        return raw

def create(path,p,q):
    validate_passphrase(p); validate_passphrase(q)
    if not hmac.compare_digest(p,q): raise ValueError('PASSPHRASE_MISMATCH')
    private_dir(path.parent)
    if os.path.lexists(path): raise ValueError('ENVELOPE_ALREADY_EXISTS')
    key=secrets.token_bytes(32); raw=seal(key,p)
    if not hmac.compare_digest(key,unseal(raw,q)): raise ValueError('ENVELOPE_SELF_CHECK_FAILED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    got=read_private(path)
    if not hmac.compare_digest(key,unseal(got,q)): raise ValueError('DISK_READBACK_FAILED')
    return hashlib.sha256(got).hexdigest()

def main():
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=['create','verify']); parser.add_argument('--file',type=Path)
    args=parser.parse_args(); root=Path.home()/'.jw-key-escrow-20261124'; target=args.file or root/'candidate-key.jwescrow'
    if args.action=='create':
        if args.file: raise ValueError('CREATE_FIXED_PRIVATE_PATH')
        root.mkdir(mode=0o700,exist_ok=True); private_dir(root)
        if os.path.lexists(target): raise ValueError('ENVELOPE_ALREADY_EXISTS')
        p=masked('New escrow passphrase (24+ ASCII chars): '); q=masked('Repeat passphrase: ')
        digest=create(target,p,q)
        print('CANDIDATE_KEY_ESCROW_LOCAL_PASS; activated=false; old_key_read=false')
    else:
        p=masked('Escrow passphrase: '); raw=read_private(target); unseal(raw,p); digest=hashlib.sha256(raw).hexdigest()
        print('ESCROW_DECRYPT_PASS; independent_custody=NOT_ATTESTED')
    print('ENVELOPE_SHA256='+digest)
    print('ENVELOPE_PATH='+str(target))

if __name__=='__main__':
    try: main()
    except InvalidTag: print('BLOCKED: ESCROW_AUTH_FAILED',file=sys.stderr); sys.exit(1)
    except (ValueError,OSError,KeyboardInterrupt) as e:
        msg=str(e); safe=msg if isinstance(e,ValueError) and msg.isascii() and msg.replace('_','').isalnum() and msg.isupper() else type(e).__name__
        print('BLOCKED: '+safe,file=sys.stderr); sys.exit(1)
