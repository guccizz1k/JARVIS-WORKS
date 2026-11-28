"""Isolated adapter for documented cl_init/cl_cvdverify API; no network update."""
import ctypes,ctypes.util,resource,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(60,61));resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(Path(__file__).resolve().parent))
try:
    from network_fence import install
    # Resolve lib before syscall restriction; local system loader only.
    name=ctypes.util.find_library('clamav')
    if not name:raise RuntimeError('missing')
    lib=ctypes.CDLL(name);install()
    lib.cl_init.argtypes=[ctypes.c_uint];lib.cl_init.restype=ctypes.c_int
    lib.cl_cvdverify.argtypes=[ctypes.c_char_p];lib.cl_cvdverify.restype=ctypes.c_int
    ok=lib.cl_init(0)==0 and lib.cl_cvdverify(bytes(Path(sys.argv[1])))==0
except Exception:ok=False
sys.exit(0 if ok else 2)
