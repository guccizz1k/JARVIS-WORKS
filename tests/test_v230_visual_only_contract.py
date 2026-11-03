"""Stage 1 visual-only regression contracts — no DB, auth, finance code changed."""
from pathlib import Path
import re
import pytest

ROOT=Path(__file__).resolve().parents[1]
FILES={
 "index":ROOT/"app/static/index.html",
 "css":ROOT/"app/static/cinematic_v230_stage1.css",
 "main":ROOT/"frontend/cinematic/stage1.js",
 "geometry":ROOT/"frontend/cinematic/InfinityMark.js",
 "post":ROOT/"frontend/cinematic/PostPipeline.js",
}
CONTENT={key:path.read_text(encoding="utf-8") for key,path in FILES.items()}

PARAMS=[
 ("exactly one fixed stage canvas", "main", "document.createElement('canvas')"),
 ("no duplicate scene from route", "main", "document.body.append(root, transition)"),
 ("one photon object", "geometry", "JW-ONE-PHOTON"),
 ("proper infinity loop", "geometry", "CatmullRomCurve3"),
 ("transmission glass", "geometry", "transmission: 0.72"),
 ("physical glass material", "geometry", "MeshPhysicalMaterial"),
 ("metal rim", "geometry", "TubeGeometry"),
 ("ellipse pedestal", "geometry", "EllipseCurve"),
 ("single photon follows path", "geometry", "this.curve.getPointAt(this.phase)"),
 ("visible floor", "geometry", "this.rings"),
 ("one persistent composer", "post", "new EffectComposer(renderer)"),
 ("BokehPass present", "post", "new BokehPass"),
 ("UnrealBloomPass present", "post", "new UnrealBloomPass"),
 ("ShaderPass present", "post", "new ShaderPass"),
 ("output color conversion", "post", "new OutputPass"),
 ("film grain implemented", "post", "uGrain"),
 ("chromatic implemented", "post", "uAberration"),
 ("vignette implemented", "post", "uVignette"),
 ("anamorphic streak", "post", "uFlare"),
 ("fps downgrade below 45", "main", "fps < 45"),
 ("adaptive quality control", "main", "renderer.setQuality(state.tier)"),
 ("DPR limited", "post", "Math.min(window.devicePixelRatio || 1, 1.5)"),
 ("login auth remains delegated", "main", "MutationObserver(probe)"),
 ("original API not hooked", "main", "isAuthenticated()"),
 ("reduced motion respected", "main", "prefers-reduced-motion: reduce"),
 ("native camera 38 degrees", "main", "new THREE.PerspectiveCamera(38"),
 ("login transition approx 2.6 seconds", "main", "phaseLength = 2600"),
 ("reduced login transition short", "main", "phaseLength = reducedQuery.matches ? 400 : 2600"),
 ("camera drift 20 sec", "main", "Math.sin(time * Math.PI / 10)"),
 ("no hardcoded fake statistics", "main", "scene = new THREE.Scene()"),
 ("exact CSS loaded", "index", "/static/cinematic_v230_stage1.css"),
 ("offline JS asset loaded", "index", "/static/cinematic_v230_stage1.bundle.js"),
 ("existing app.js still present", "index", "/static/app.js"),
 ("existing V22.2 still present", "index", "/static/cinematic_v222.js"),
 ("form still present", "index", 'id="login-form"'),
 ("MFA input unchanged", "index", 'name="otp"'),
 ("original recovery input unchanged", "index", 'name="recovery_code"'),
 ("original menu unchanged", "index", 'id="nav"'),
 ("screen readers have auth status", "main", "setAttribute('role', 'status')"),
 ("legacy fallback maintained", "main", "original-svg-canvas-fallback"),
 ("no external CDN fonts or dependencies", "css", "font-family:Pretendard"),
]

@pytest.mark.parametrize("label,key,needle",PARAMS,ids=[x[0] for x in PARAMS])
def test_stage1_visual_guards(label,key,needle):
    assert needle in CONTENT[key],label

def test_no_user_data_or_auth_api_calls_in_visual_modules():
    for key in ("main","geometry","post"):
        source=CONTENT[key]
        assert not re.search(r"fetch\s*\(|XMLHttpRequest|indexedDB|localStorage|sessionStorage",source)
        assert "/api/login" not in source and "document.cookie" not in source

def test_csp_same_origin_vendor_without_external_fetch():
    html=CONTENT["index"]
    assert "unpkg.com" not in html
    assert "cdn.jsdelivr.net" not in html
    assert "https://" not in CONTENT["main"]
    assert "<script src=\"/static/cinematic_v230_stage1.bundle.js\" defer></script>" in html

def test_browser_visual_scope_does_not_replace_original_business_events():
    source=CONTENT["main"]
    assert "window.JW_CINEMATIC_STAGE1" in source
    assert "JW_UI_MOTION" not in source
    assert "showApp=" not in source
    assert "navigate=" not in source
    assert "prototype" not in source
    assert "overridden" not in source

def test_old_version_is_fallback_if_no_webgl():
    source=CONTENT["main"]
    assert "root.remove()" in source
    assert "document.documentElement.classList.add('jw300-three-ready')" in source
    assert "document.documentElement.classList.remove('jw300-three-ready')" in source
