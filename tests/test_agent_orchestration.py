class _FakeTarget:
    @staticmethod
    def preflight():
        return []

    def __init__(self, scenario, run_id):
        self.project = "t9agentfake"
        self.host = "127.0.0.1"
        self.port = 8080
        self.target_container_id = "deadbeefcafe"
        self.target_ip = "172.27.0.2"
        self.down_called = False

    def up(self):
        pass

    def down(self):
        self.down_called = True


class _FakeCapture:
    instances: list["_FakeCapture"] = []

    def __init__(self, name, cid, peer, path, config, require_packets=False, max_drop_fraction=0.0):
        self.path = Path(path)
        self.stopped = False
        self.aborted = False
        _FakeCapture.instances.append(self)

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)  # pcap-ish header + data

    def stop(self):
        self.stopped = True
        return {"path": str(self.path), "packets_captured": 12, "empty": False, "size_bytes": 64}

    def abort(self):
        self.aborted = True


def _install_fakes(monkeypatch):
    _FakeCapture.instances.clear()
    monkeypatch.setattr(orchestrator.VulhubTarget, "preflight", staticmethod(lambda: []))