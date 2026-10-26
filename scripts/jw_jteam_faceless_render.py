"""Owner-only offline text-motion Shorts renderer: zero filming, recording or supplied assets.

Uses project-authored editorial JSON, Pillow and ffmpeg. No online providers,
copyrighted stock media, external models, auto posting or user credentials.
This is an editorial build artifact, NOT evidence of monetization suitability.
"""
from __future__ import annotations

import argparse
from array import array
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import wave

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EPISODE = ROOT / "agents/team/jarvis_v1/creator/episodes/faceless-001.json"
W, H = 720, 1280
COLORS = {
    "bg": (11, 18, 32), "panel": (19, 32, 50),
    "muted": (174, 196, 210), "white": (247, 250, 255),
    "aqua": (67, 235, 197), "blue": (79, 141, 255),
}


def validate_episode(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("UNSAFE_EPISODE_PATH")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (type(data) is not dict or data.get("schema") != "jw-original-short-v1"
        or data.get("publication") != "DRAFT_ONLY"
        or data.get("rights") != "PROJECT_ORIGINAL_TEXT_AND_PROGRAMMATIC_GRAPHICS"
        or data.get("aspect_ratio") != "9:16"):
        raise ValueError("INVALID_EPISODE_POLICY")
    slides = data.get("slides")
    if type(slides) is not list or len(slides) != 5:
        raise ValueError("FIVE_SCENES_REQUIRED")
    for slide in slides:
        if type(slide) is not dict or not isinstance(slide.get("title"), str):
            raise ValueError("INVALID_SCENE")
        if not 2 <= len(slide["title"]) <= 28:
            raise ValueError("INVALID_TITLE_LENGTH")
        if not isinstance(slide.get("subtitle"), str) or len(slide["subtitle"]) > 40:
            raise ValueError("INVALID_SUBTITLE")
        points = slide.get("points")
        if type(points) is not list or len(points) != 3 or any(
            type(point) is not str or not 2 <= len(point) <= 29 for point in points
        ):
            raise ValueError("INVALID_SCENE_POINTS")
    return data


def choose_font() -> str:
    paths = (
        "/usr/share/fonts/truetype/nanum/NanumSquareB.ttf",
        "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf",
    )
    return next((path for path in paths if Path(path).is_file()), "")


def slide_image(slide: dict, index: int, output: Path, font_file: str) -> None:
    from PIL import Image, ImageDraw, ImageFont
    font = lambda n: ImageFont.truetype(font_file, n)
    image = Image.new("RGB", (W, H), COLORS["bg"])
    d = ImageDraw.Draw(image)
    for x in range(0, W, 72):
        d.line((x, 0, x, H), fill=(17, 29, 44))
    for y in range(0, H, 75):
        d.line((0, y, W, y), fill=(17, 29, 44))
    d.rounded_rectangle((45, 75, 257, 130), radius=23, fill=(25, 65, 70))
    d.text((63, 89), "AI 실전노트", font=font(25), fill=COLORS["aqua"])
    d.text((645, 91), f"{index+1:02d}/05", font=font(27),
           fill=COLORS["muted"], anchor="ra")
    d.text((51, 191), slide["title"], font=font(48), fill=COLORS["white"])
    d.text((52, 270), slide["subtitle"], font=font(27), fill=COLORS["muted"])
    d.rounded_rectangle((62, 383, 660, 965), radius=40, fill=COLORS["panel"])
    for k, point in enumerate(slide["points"]):
        y = 451 + k * 157
        d.rounded_rectangle((96, y, 628, y+127), radius=26, fill=(30, 51, 70))
        d.rounded_rectangle((119, y+42, 151, y+74), radius=8,
                            fill=COLORS["blue"] if k != 1 else COLORS["aqua"])
        d.text((180, y+43), point, font=font(30), fill=COLORS["white"])
    d.text((W//2, 1041), "AI로 줄이는 반복 업무",
           font=font(29), fill=COLORS["aqua"], anchor="mm")
    for k in range(5):
        x = 50 + k*124
        d.rounded_rectangle((x, 1186, x+101, 1199), radius=6,
                            fill=COLORS["aqua"] if k<=index else (44, 61, 80))
    d.text((54, 1235), "AI 실전노트 | 무료 자동화 팁",
           font=font(22), fill=COLORS["muted"])
    image.save(output)


def synth_sound(output: Path, *, sample_rate: int = 12000) -> None:
    samples = array("h")
    for n in range(int(17.0*sample_rate)):
        t = n/sample_rate
        value = 0.0
        for scene in range(5):
            u = t - scene*3.35
            if 0 <= u < 0.8:
                value += 0.05 * math.sin(2 * math.pi * 330 * u) * math.exp(-7*u)
                value += 0.025 * math.sin(2 * math.pi * 440 * u) * math.exp(-7*u)
        samples.append(int(max(-1,min(1,value))*32767))
    with wave.open(str(output), "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(sample_rate)
        f.writeframes(samples.tobytes())


def render(episode_path: Path, output: Path) -> dict:
    episode = validate_episode(episode_path)
    font_file = choose_font()
    if not font_file:
        raise RuntimeError("KOREAN_FONT_NOT_FOUND")
    if not output.name.endswith(".mp4") or not output.parent.is_dir() or output.is_symlink():
        raise ValueError("UNSAFE_OUTPUT")
    with tempfile.TemporaryDirectory(prefix="jw-faceless-render-") as temp:
        root = Path(temp)
        for index, scene in enumerate(episode["slides"]):
            slide_image(scene, index, root/f"scene-{index}.png", font_file)
        synth_sound(root/"original-tone.wav")
        command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y"]
        for index in range(5):
            command += ["-framerate","15","-loop","1","-t","3.6",
                        "-i",str(root/f"scene-{index}.png")]
        command += ["-i",str(root/"original-tone.wav")]
        transitions = [
            f"[{i}:v]fps=15,format=yuv420p[v{i}]" for i in range(5)
        ]
        transitions += [
            "[v0][v1]xfade=transition=fade:duration=0.25:offset=3.35[x1]",
            "[x1][v2]xfade=transition=fade:duration=0.25:offset=6.70[x2]",
            "[x2][v3]xfade=transition=fade:duration=0.25:offset=10.05[x3]",
            "[x3][v4]xfade=transition=fade:duration=0.25:offset=13.40[v]"
        ]
        command += [
            "-filter_complex",";".join(transitions),"-map","[v]","-map","5:a",
            "-t","17.0","-c:v","libx264","-preset","ultrafast","-crf","27",
            "-pix_fmt","yuv420p","-c:a","aac","-b:a","80k",
            "-movflags","+faststart",str(output)
        ]
        subprocess.run(command, check=True, timeout=180, stdout=subprocess.DEVNULL)
    if not output.is_file() or output.stat().st_size < 10240:
        raise RuntimeError("RENDER_OUTPUT_EMPTY")
    return {
        "status":"VIDEO_RENDERED_OFFLINE",
        "episode_id":episode["episode_id"],
        "duration_seconds":17,
        "resolution":[W,H],
        "user_provided_media":0,
        "user_camera_recordings":0,
        "provider_calls":0,
        "publication":"NOT_PERFORMED",
        "rights":"PROJECT_ORIGINAL_MOTION_AND_TONE",
        "content_review":"REQUIRED_BEFORE_PUBLICATION",
        "output_size_bytes":output.stat().st_size,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--episode", type=Path, default=DEFAULT_EPISODE)
    p.add_argument("--output", type=Path, default=Path("jteam-short.mp4"))
    args = p.parse_args(argv)
    report = render(args.episode, args.output)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
