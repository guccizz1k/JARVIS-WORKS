"""Explicit template for separate field cells in a synthetic raster form.
No learned layout or automatic field assignment. Two OCR passes are not independent engines.
Strict template hash and original source hash; never automatically post or approve.
"""
import hashlib,json,io,os,subprocess,tempfile,warnings
from pathlib import Path
from PIL import Image,ImageOps,ImageChops
from review_gates import need,digest,Blocked
from korean_observations import value
from pinned.naruv_document_review import review_document,FIELDS

def pin(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def observations(raw,template,expected_pin,read):
    need(type(template) is dict and set(template)=={'width','height','cells'} and digest(expected_pin) and pin(template)==expected_pin,'GRID_TEMPLATE_PIN')
    w,h=template['width'],template['height'];need(type(w) is int and type(h) is int and 1<=w<=3000 and 1<=h<=3000 and w*h<=6_000_000,'GRID_DIMENSIONS')
    cells=template['cells'];need(type(cells) is dict and set(cells)==FIELDS,'GRID_FIELDS');boxes=[]
    for box in cells.values():
        need(type(box) is list and len(box)==4 and all(type(x) is int for x in box),'GRID_BOX');x,y,x2,y2=box
        need(0<=x<x2<=w and 0<=y<y2<=h and 20<=x2-x<=1200 and 20<=y2-y<=400,'GRID_BOX')
        need(not any(x<b[2] and x2>b[0] and y<b[3] and y2>b[1] for b in boxes),'GRID_OVERLAP');boxes.append(box)
    need(type(raw) is bytes and 0<len(raw)<=2*1024*1024,'GRID_INPUT')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as img:
                need(img.format in ('PNG','JPEG') and img.size==(w,h) and getattr(img,'n_frames',1)==1,'GRID_IMAGE');img.verify()
            with Image.open(io.BytesIO(raw)) as img:
                img=ImageOps.autocontrast(ImageOps.grayscale(img));out=[]
                for field,box in sorted(cells.items()):
                    crop=img.crop(box);lang='kor+eng' if field=='document_kind' else 'eng'
                    # Trim whitespace from the independently pinned value cell only.
                    bounds=ImageChops.invert(crop).point(lambda p:255 if p>60 else 0).getbbox()
                    if bounds is None:
                        out.append(dict(field=field,value=None,page=1));continue
                    crop=crop.crop(bounds)
                    # Separate grayscale/binary views, no substitutions or character whitelist.
                    mode=8 if field in ('counterparty_id','reference_number') else 7
                    for view in (crop,crop.point(lambda p:255 if p>180 else 0)):
                        v=read(view,lang,mode);out.append(dict(field=field,value=value(field,v) if type(v) is str else None,page=1))
                return out
    except (OSError,Image.DecompressionBombWarning,Image.DecompressionBombError):raise Blocked('GRID_IMAGE') from None

def review(raw,*,template,expected_pin,registered,tenant,read):
    need(type(raw) is bytes and digest(registered) and hashlib.sha256(raw).hexdigest()==registered,'DOC_SOURCE_CHANGED')
    r=review_document(tenant=tenant,source_bytes=raw,registered_sha256=registered,observations=observations(raw,template,expected_pin,read))
    return dict(r,template_sha256=expected_pin,recognition_authorized=False,production_authorized=False)
