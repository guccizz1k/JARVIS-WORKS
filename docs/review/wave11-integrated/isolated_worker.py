"""Worker entry point; install before PDF or image parsing. No network namespace claim."""
import hashlib,io,json,resource,sys,subprocess,warnings
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CPU,(12,13))
resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from network_fence import install,FenceError
from review_gates import Blocked,need
def recognize_image(img,page_no):
    from PIL import ImageOps
    from korean_observations import observations
    img=ImageOps.autocontrast(ImageOps.grayscale(img));base=f'ocr-page-{page_no}';normalized=base+'.png';img.save(normalized)
    # Bounded files; primary engine writes text and TSV in the same pass.
    r=subprocess.run(['/usr/bin/tesseract',normalized,base,'-l','kor+eng','--psm','6','txt','tsv'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=12,check=False,close_fds=True)
    need(r.returncode==0 and Path(base+'.txt').stat().st_size<=64000 and Path(base+'.tsv').stat().st_size<=250000,'OCR_ENGINE_FAILED')
    pages=[Path(base+'.txt').read_text('utf-8')]
    from ocr_id_views import id_boxes,add_id_views
    primary=observations(pages)
    boxes=id_boxes(Path(base+'.tsv').read_text('utf-8'),img.width,img.height)
    def read_crop(box,mode):
        x,y,x2,y2=box
        # Pad crop to keep glyph edges, no forced prefix or character substitutions.
        crop=ImageOps.expand(img.crop((max(0,x-2),max(0,y-2),min(img.width,x2+2),min(img.height,y2+2))),border=20,fill=255)
        crop.save('id-crop.png')
        with open('id-crop.txt','wb') as f:
            rr=subprocess.run(['/usr/bin/tesseract','id-crop.png','stdout','-l','eng','--psm',str(mode)],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,timeout=3,check=False,close_fds=True)
        if rr.returncode!=0 or Path('id-crop.txt').stat().st_size>256:return None
        return Path('id-crop.txt').read_text('utf-8').strip()
    obs=add_id_views(primary,boxes,read_crop)
    from id_candidate import propose
    def read_exact(box,view):
        crop=img.crop(box)
        if view=='binary':crop=crop.point(lambda z:255 if z>180 else 0)
        crop=ImageOps.expand(crop,border=20,fill=255)
        crop.save('id-exact.png')
        with open('id-exact.txt','wb') as f:
            rr=subprocess.run(['/usr/bin/tesseract','id-exact.png','stdout','-l','eng','--psm','8'],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.DEVNULL,timeout=3,check=False,close_fds=True)
        if rr.returncode!=0 or Path('id-exact.txt').stat().st_size>256:return None
        return Path('id-exact.txt').read_text('utf-8').strip()
    candidate,count=propose(primary,boxes,read_exact)
    return ([dict(o,page=page_no) for o in obs],[dict(o,page=page_no) for o in candidate],count)

try:
    fence=install()
    from korean_observations import observations
    from pinned.naruv_document_review import review_document
    path,h,tenant,fmt=sys.argv[1:]
    with open(path,'rb') as f:raw=f.read(2*1024*1024+1)
    need(0<len(raw)<=2*1024*1024 and hashlib.sha256(raw).hexdigest()==h,'DOC_SOURCE_CHANGED')
    candidate_count=0
    if fmt=='pdf':
        import pdfplumber,math
        need(raw.startswith(b'%PDF-'),'OCR_FORMAT')
        with pdfplumber.open(io.BytesIO(raw)) as pdf:
            need(1<=len(pdf.pages)<=20,'OCR_PAGE_LIMIT')
            pages=[];size=0
            for p in pdf.pages:
                t=p.extract_text() or '';size+=len(t);need(size<=64000,'OCR_TEXT_LIMIT');pages.append(t)
        scan=[i for i,p in enumerate(pages) if not p.strip()]
        need(len(scan)<=3,'OCR_SCAN_PAGE_LIMIT')
        obs=observations(pages,allow_empty=bool(scan)); candidate_obs=list(obs)
        if scan:
            import pypdfium2 as pdfium
            with pdfium.PdfDocument(raw) as pdf:
                need(len(pdf)==len(pages),'OCR_PDF_PAGE_MISMATCH')
                total_pixels=0
                for i in scan:
                    page=pdf[i]
                    try:
                        w,h_page=page.get_size();scale=200/72
                        need(math.isfinite(w) and math.isfinite(h_page) and 0<w<=1800 and 0<h_page<=1800,'OCR_RENDER_DIMENSIONS')
                        pixels=math.ceil(w*scale)*math.ceil(h_page*scale);total_pixels+=pixels
                        need(pixels<=12_000_000 and total_pixels<=24_000_000,'OCR_RENDER_DIMENSIONS')
                        bitmap=page.render(scale=scale)
                        try:
                            img=bitmap.to_pil().copy()
                            original,candidate,n=recognize_image(img,i+1)
                            obs.extend(original);candidate_obs.extend(candidate);candidate_count+=n
                        finally:bitmap.close()
                        need(len(obs)<=128,'OCR_OBSERVATION_LIMIT')
                    finally:page.close()
    elif fmt in ('png','jpeg'):
        from PIL import Image
        Image.MAX_IMAGE_PIXELS=12_000_000
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as im:
                need(im.format=={'png':'PNG','jpeg':'JPEG'}[fmt] and getattr(im,'n_frames',1)==1 and 0<im.width<=5000 and 0<im.height<=5000 and im.width*im.height<=12_000_000,'OCR_IMAGE_DIMENSIONS')
                im.verify()
            with Image.open(io.BytesIO(raw)) as im:
                obs,candidate_obs,candidate_count=recognize_image(im,1)
    else:raise Blocked('OCR_FORMAT')
    r=review_document(tenant=tenant,source_bytes=raw,registered_sha256=h,observations=obs)
    r['network_fence']=fence;r['recognition_authorized']=False
    # Separate preview hash may match the reference even when authoritative review conflicts.
    # Never post, clear a conflict, or claim independent engines.
    if candidate_count:
        preview=review_document(tenant=tenant,source_bytes=raw,registered_sha256=h,observations=candidate_obs)
        r['id_preview']={'review_sha256':preview['review_sha256'],'field_count':preview['field_count'],'issues':preview['issues'],'two_view_candidate_count':candidate_count,'requires_human_review':True,'posting_authorized':False}
except (Blocked,FenceError) as e:r={'status':'BLOCKED','code':str(e)}
except Exception:r={'status':'BLOCKED','code':'OCR_WORKER_FAILED'}
print(json.dumps(r,separators=(',',':'),ensure_ascii=True))
