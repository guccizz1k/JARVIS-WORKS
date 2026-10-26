"""Offline comparison of approved PNG/JPEG UI design reference to capture.

Pillow is optional and never installed by this script. Pixel parity is not
proof of usability, keyboard accessibility, functional tests or release.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any

def compare(reference: Path, candidate: Path, *, approved_reference: bool,
            tolerance: int = 0, max_pixels: int = 16_000_000) -> dict[str,Any]:
    base={'status':'BLOCKED','pixel_parity_only':True,'ux_approved':False,
          'production_release':'BLOCKED','browser_e2e_verified':False}
    if approved_reference is not True:
        return {**base,'reason':'APPROVED_REFERENCE_REQUIRED'}
    if type(tolerance) is not int or not 0 <= tolerance <= 32 or type(max_pixels) is not int or not 1 <= max_pixels <= 16_000_000:
        return {**base,'reason':'INVALID_COMPARISON_LIMITS'}
    reference,candidate=Path(reference),Path(candidate)
    if any(x.is_symlink() or not x.is_file() or x.suffix.lower() not in ('.png','.jpg','.jpeg') for x in (reference,candidate)):
        return {**base,'reason':'INVALID_LOCAL_IMAGE_PATH'}
    try:
        from PIL import Image,ImageChops,ImageStat
    except ImportError:
        return {**base,'reason':'OPTIONAL_PILLOW_NOT_INSTALLED'}
    Image.MAX_IMAGE_PIXELS=16_000_000
    try:
        with Image.open(reference) as a,Image.open(candidate) as b:
            if a.width*a.height > max_pixels or b.width*b.height > max_pixels:
                return {**base,'reason':'IMAGE_SIZE_LIMIT'}
            if a.size != b.size:
                return {**base,'reason':'VIEWPORT_OR_DPR_MISMATCH',
                        'reference_dimensions':list(a.size),'candidate_dimensions':list(b.size)}
            a.load();b.load()
            diff=ImageChops.difference(a.convert('RGB'),b.convert('RGB'))
            rgb=list(diff.get_flattened_data() if hasattr(diff,'get_flattened_data') else diff.getdata())
            changed=sum(any(x > tolerance for x in pixel) for pixel in rgb)
            mean=round(sum(ImageStat.Stat(diff).mean)/3,4)
            return {**base,'status':'PIXEL_MATCH_ONLY' if changed==0 else 'VISUAL_DIFFERENCE_REVIEW',
                    'reference_sha256':hashlib.sha256(reference.read_bytes()).hexdigest(),
                    'candidate_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
                    'dimensions':list(a.size),'changed_pixels':changed,
                    'changed_fraction':round(changed/len(rgb),6),
                    'mean_channel_difference':mean,'reason':'MATCHED_LOCAL_CAPTURE_ENV_REQUIRED'}
    except (OSError,ValueError,Image.DecompressionBombError):
        return {**base,'reason':'IMAGE_DECODE_OR_LIMIT_FAILURE'}

def main() -> int:
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--approved-reference',action='store_true')
    p.add_argument('--tolerance',type=int,default=0)
    args=p.parse_args()
    result=compare(args.reference,args.candidate,approved_reference=args.approved_reference,
                   tolerance=args.tolerance)
    print(json.dumps(result,sort_keys=True,ensure_ascii=False))
    return 0 if result['status']=='PIXEL_MATCH_ONLY' else 3

if __name__=='__main__':
    raise SystemExit(main())
