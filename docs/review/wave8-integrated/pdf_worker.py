"""Child entry point. Limits before importing PDF parser."""
import json, sys, resource
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(5,6))
resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024,64*1024))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from document_candidates import review_candidates
from pinned.naruv_document_review import review_document
from review_gates import Blocked
try:
    path,h,tenant=sys.argv[1:]
    with open(path,'rb') as f:raw=f.read(1024*1024+1)
    r=review_candidates(tenant=tenant,raw=raw,registered=h,format='pdf',review_document=review_document)
except Blocked as e:r={'status':'BLOCKED','code':str(e)}
except Exception:r={'status':'BLOCKED','code':'PDF_WORKER_FAILED'}
print(json.dumps(r,separators=(',',':'),ensure_ascii=True))
