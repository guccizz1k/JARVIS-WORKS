"""Real curl + TLS against disposable local server, no external services."""
import http.server
import ssl
import subprocess
import threading
import pytest
import qa_probe

@pytest.fixture
def local_tls(tmp_path,monkeypatch):
    cert=tmp_path/'cert.pem';key=tmp_path/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/api/health':
                body=b'{"status":"ok","version":"2.2.0-candidate"}';self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            else:
                self.send_response(401);self.send_header('Content-Length','0');self.send_header('WWW-Authenticate','Basic realm="JARVIS-WORKS isolated review", charset="UTF-8"');self.end_headers()
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    monkeypatch.setattr(qa_probe,'HOST',f'https://localhost:{server.server_port}')
    monkeypatch.setenv('NO_PROXY','localhost,127.0.0.1')
    try:yield cert
    finally:server.shutdown();server.server_close();thread.join(timeout=3)

def test_trusted_local_https(local_tls,monkeypatch):
    monkeypatch.setenv('CURL_CA_BUNDLE',str(local_tls))
    result=qa_probe.assess(budget=10)
    assert result['status']=='QA_HEALTH_AND_UNAUTHENTICATED_BARRIER_PASS',result

def test_untrusted_local_certificate(local_tls,monkeypatch):
    monkeypatch.delenv('CURL_CA_BUNDLE',raising=False)
    result=qa_probe.assess(budget=10)
    assert result['status']=='BLOCKED_TRANSPORT' and result['observations'][0]['curl_exit']==60
