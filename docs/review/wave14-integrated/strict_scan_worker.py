"""One-shot lab worker. Linux socket fence, not a complete sandbox."""
import os,sys,resource
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(90,91));resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
sys.path.insert(0,str(Path(__file__).resolve().parent))
try:
    from network_fence import install
    install()
    executable=sys.argv[1]
    if not os.path.isabs(executable):raise ValueError('absolute executable required')
    os.execve(executable,sys.argv[1:],{'PATH':os.defpath,'LANG':'C','HOME':os.getcwd(),'TMPDIR':os.getcwd()})
except Exception:sys.exit(2)
