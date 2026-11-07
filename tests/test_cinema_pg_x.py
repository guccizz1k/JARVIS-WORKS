"""Recovery accepts only the original local disposable target and never Supabase."""
from __future__ import annotations
import json
import os
import subprocess
import unittest
from unittest.mock import patch
from scripts import ci_cinema_pg_x as x
from scripts.pg_backup_v223 import BackupError

def container(running=False):
    return {
        "Name": "/jw-v223-restore",
        "Config": {"Image": "postgres:17"},
        "HostConfig": {
            "PortBindings": {"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"55432"}]},
            "RestartPolicy":{"Name":"no"},
            "Privileged":False,"PublishAllPorts":False,
        },
        "State":{"Running":running,"Dead":False,"Removing":False},
    }

class ResumeSafety(unittest.TestCase):
    def test_valid_known_container(self):
        self.assertTrue(x.verified_container(container()))

    def test_wrong_container_name_refused(self):
        obj=container()
        obj["Name"]="/prod-db"
        self.assertFalse(x.verified_container(obj))

    def test_wrong_image_refused(self):
        obj=container()
        obj["Config"]["Image"]="postgres:18"
        self.assertFalse(x.verified_container(obj))

    def test_all_interfaces_refused(self):
        obj=container()
        obj["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"]="0.0.0.0"
        self.assertFalse(x.verified_container(obj))

    def test_other_port_refused(self):
        obj=container()
        obj["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostPort"]="5432"
        self.assertFalse(x.verified_container(obj))

    def test_privileged_and_publish_all_refused(self):
        for key in ("Privileged","PublishAllPorts"):
            obj=container()
            obj["HostConfig"][key]=True
            self.assertFalse(x.verified_container(obj))

    def test_dead_or_removing_refused(self):
        for key in ("Dead","Removing"):
            obj=container()
            obj["State"][key]=True
            self.assertFalse(x.verified_container(obj))

    def test_off_codespaces_denied_before_io(self):
        with patch.dict(os.environ,{"CODESPACES":"false"}), \
             patch.object(x,"read_private_target") as read, \
             patch.object(x,"docker") as docker:
            with self.assertRaises(BackupError):
                x.ensure_local_target()
            read.assert_not_called()
            docker.assert_not_called()

    def test_stopped_existing_is_started_not_recreated(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}), \
             patch.object(x,"read_private_target",return_value={
                 "JW_PG_TARGET_ADMIN_DSN":"postgresql://postgres:dummy@127.0.0.1:55432/postgres",
                 "JW_PG_TARGET_EPHEMERAL_TOKEN":"synthetic_test_token"}), \
             patch.object(x,"inspect_target",return_value=container(False)), \
             patch.object(x,"docker",return_value=subprocess.CompletedProcess([],0,"","")) as docker, \
             patch.object(x,"connect_marked",return_value=True):
            x.ensure_local_target()
            docker.assert_called_once_with("start","jw-v223-restore")

    def test_running_container_not_restarted(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}), \
             patch.object(x,"read_private_target",return_value={
                 "JW_PG_TARGET_ADMIN_DSN":"d","JW_PG_TARGET_EPHEMERAL_TOKEN":"t"}), \
             patch.object(x,"inspect_target",return_value=container(True)), \
             patch.object(x,"docker") as docker, \
             patch.object(x,"connect_marked",return_value=True):
            x.ensure_local_target()
            docker.assert_not_called()

    def test_failed_marker_blocks_restore(self):
        with patch.dict(os.environ,{"CODESPACES":"true"}), \
             patch.object(x,"ensure_local_target",side_effect=BackupError("BLOCKED_MARKER")), \
             patch("scripts.ci_cinema_pg_w.main") as restore:
            self.assertEqual(x.main(),2)
            restore.assert_not_called()

    def test_no_unverified_container_start(self):
        with patch.object(x,"docker",return_value=subprocess.CompletedProcess(
            [],0,json.dumps([{"Name":"/prod-db"}]),"")) as docker:
            with self.assertRaisesRegex(BackupError,"IDENTITY"):
                x.inspect_target()
            docker.assert_called_once_with("inspect","--type","container","jw-v223-restore")

if __name__=="__main__":
    unittest.main()
