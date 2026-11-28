"""Synthetic template worker; socket restriction only, not full sandbox."""
import resource,sys,json,subprocess,os
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(20,21));resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2));resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from network_fence import install
from review_gates import Blocked
try:
    fence=install()
    from ocr_grid import review
    from PIL import ImageOps
    inp,conf=sys.argv[1:];cfg=json.loads(Path(conf).read_text());raw=Path(inp).read_bytes()
    def read(crop,lang,mode):
        crop=ImageOps.expand(crop,border=16,fill=255);crop.save('crop.png')
        with open('ocr.txt','wb') as f:
            p=subprocess.run(['/usr/bin/tesseract','crop.png','stdout','-l',lang,'--psm',str(mode)],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,timeout=3,check=False)
        if p.returncode or Path('ocr.txt').stat().st_size>1024:return None
        return Path('ocr.txt').read_text().strip()
    result=review(raw,read=read,**cfg);result['network_fence']=fence
except Blocked as e:result={'status':'BLOCKED','code':str(e)}
except Exception:result={'status':'BLOCKED','code':'GRID_WORKER_FAILED'}
print(json.dumps(result,ensure_ascii=True,separators=(',',':')))
