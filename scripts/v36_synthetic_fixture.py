"""Fictional-only SQLite messenger archive fixture for V3.6.

No file-path argument, network, secret or real user import. All data in memory.
"""
import sqlite3


def fixture():
    db=sqlite3.connect(':memory:')
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
    CREATE TABLE messenger_companies(org_id TEXT PRIMARY KEY,business_number TEXT,verified_at TEXT,verification_kind TEXT);
    CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT,requester_org TEXT,
      status TEXT,created_at TEXT,accepted_at TEXT,connection_seq INTEGER);
    CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,connection_id TEXT REFERENCES messenger_connections(id),
      sender_org TEXT,sender_user TEXT,kind TEXT,body TEXT,order_id TEXT,immutable_order_snapshot TEXT,
      actor_name TEXT,request_id TEXT,version INTEGER,created_at TEXT,edited_at TEXT,message_seq INTEGER);
    CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT REFERENCES messenger_messages(id),
      previous_body TEXT,new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER);
    CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY REFERENCES messenger_messages(id),
      filename TEXT,mime TEXT,data BLOB,size_bytes INTEGER,content_hash TEXT);
    CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_rowid INTEGER,
      updated_at TEXT,last_read_seq INTEGER,PRIMARY KEY(connection_id,org_id));
    CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY REFERENCES messenger_messages(id),
      receiver_org TEXT,actor_name TEXT,receiver_user TEXT,received_at TEXT);
    ''')
    db.executemany('INSERT INTO messenger_companies VALUES(?,?,?,?)',(
      ('tenant_a','0000000001','2026-10-20T08:01:00+09:00','demo'),
      ('tenant_b','0000000002','2026-10-20T08:01:00+09:00','demo')))
    db.execute('INSERT INTO messenger_connections VALUES(?,?,?,?,?,?,?,?)',(
      'thread_ab','tenant_a','tenant_b','tenant_a','active','2026-10-20T08:02:00+09:00',None,1))
    db.executemany('INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(
      ('msg_text','thread_ab','tenant_a','ua','text','안녕하세요',None,None,'',
       'request_text',2,'2026-10-20T08:03:00+09:00','2026-10-20T08:04:00+09:00',1),
      ('msg_file','thread_ab','tenant_b','ub','text','첨부',None,None,'',
       'request_file',1,'2026-10-20T08:05:00+09:00',None,2),
      ('msg_order','thread_ab','tenant_a','ua','order','발주서 확인','order_fake_001',
       '{"orderId":"order_fake_001","lineItems":[{"name":"부품","qty":3}]}','담당자',
       'request_order',1,'2026-10-20T08:06:00+09:00',None,3)))
    db.execute('INSERT INTO messenger_edits VALUES(?,?,?,?,?,?,?)',(
      'edit1','msg_text','안녕','안녕하세요','ua','2026-10-20T08:04:00+09:00',2))
    from hashlib import sha256
    blob=b'\x00\xff\x01\xfePNG-demo-bytes\x00'
    db.execute('INSERT INTO messenger_attachments VALUES(?,?,?,?,?,?)',(
      'msg_file','synthetic-한글.png','image/png',blob,len(blob),sha256(blob).hexdigest()))
    db.executemany('INSERT INTO messenger_read_positions VALUES(?,?,?,?,?)',(
      ('thread_ab','tenant_a',1,'2026-10-20T08:07:00+09:00',1),
      ('thread_ab','tenant_b',2,'2026-10-20T08:07:01+09:00',2)))
    db.execute('INSERT INTO messenger_receipts VALUES(?,?,?,?,?)',(
      'msg_order','tenant_b','담당자 B','ub','2026-10-20T08:10:00+09:00'))
    db.commit()
    return db
