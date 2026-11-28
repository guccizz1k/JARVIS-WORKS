"""Private single-host fixture store; no external provider IO or customer data.
Caller must supply a trusted, owner-private directory descriptor.
Opaque hashed filenames bind each tenant/key. Immutable outputs per lease.
"""
import os,stat,hashlib,json,re,secrets,fcntl
from review_gates import Blocked,need

def filename(tenant,key,proposal):
    need(type(tenant) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',tenant) and type(key) is str,'QUEUE_STORE_SCOPE')
    suffix=r'/ocr-result/[0-9a-f]{32}/[0-9a-f]{64}' if proposal else r'/[0-9a-f]{32}'
    need(re.fullmatch(r'tenant/'+re.escape(tenant)+suffix,key),'QUEUE_STORE_SCOPE')
    return ('p-' if proposal else 'o-')+hashlib.sha256(key.encode('ascii')).hexdigest()

def read_file(fd,name,limit):
    f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
    with os.fdopen(f,'rb') as stream:
        st=os.fstat(stream.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=limit,'QUEUE_STORE_FILE')
        raw=stream.read(limit+1);need(len(raw)==st.st_size and len(raw)<=limit,'QUEUE_STORE_SIZE');return raw

class FixtureStore:
    def __init__(self,fd):
        st=os.fstat(fd);need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,'QUEUE_STORE_DIRECTORY');self.fd=os.dup(fd)
    def __enter__(self):return self
    def __exit__(self,*args):os.close(self.fd)
    def read_bounded(self,tenant,key,limit):
        need(type(limit) is int and 1<=limit<=2*1024*1024,'QUEUE_STORE_LIMIT')
        return read_file(self.fd,filename(tenant,key,False),limit)
    def write_proposal(self,tenant,key,result):
        name=filename(tenant,key,True)
        need(type(result) is dict and result.get('posting_authorized') is False and result.get('recognition_authorized') is False and result.get('requires_human_review') is True,'QUEUE_STORE_AUTHORITY')
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii');need(0<len(raw)<=65536,'QUEUE_STORE_SIZE')
        fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.fd);tmp='.tmp-'+secrets.token_hex(16)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            f=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            try:
                with os.fdopen(f,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                try:os.link(tmp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd,follow_symlinks=False)
                except FileExistsError:pass
            finally:os.unlink(tmp,dir_fd=self.fd)
            os.fsync(self.fd);need(read_file(self.fd,name,65536)==raw,'QUEUE_STORE_PROPOSAL_CONFLICT')
        finally:os.close(fd)
