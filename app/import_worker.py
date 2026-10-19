"""Subprocess entrypoint; input and output are single JSON records, no debug data."""
import base64
import json
import sys
from .import_engine import extract, DocumentError

def main():
    try:
        payload=json.loads(sys.stdin.buffer.read(7_100_000))
        raw=base64.b64decode(payload['base64'],validate=True)
        result=extract(payload['filename'],raw,allow_missing=True)
        print(json.dumps({'result':result},ensure_ascii=False))
    except DocumentError as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=False))
    except Exception:
        print(json.dumps({'error':'파일 분석에 실패했습니다. 입력 문서를 확인하세요'},ensure_ascii=False))

if __name__=='__main__':main()
