"""Nightly OSV refresh replaces the archive only with a complete, valid zip."""
import io
import zipfile


class Resp:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, n):
        yield self.data


class HTTP:
    def __init__(self, data):
        self.data = data

    def get(self, url, stream, timeout):
        return Resp(self.data)


def test_valid_archive_replaces_old_one(tmp_path):
    from guardian.scoring.intel_refresh import refresh_osv
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("GHSA-x.json", "{}")
    dest = tmp_path / "all.zip"
    dest.write_bytes(b"old")
    assert "updated" in refresh_osv(dest, "u", HTTP(buf.getvalue()))
    assert zipfile.is_zipfile(dest)


def test_corrupt_download_keeps_previous_archive(tmp_path):
    from guardian.scoring.intel_refresh import refresh_osv
    dest = tmp_path / "all.zip"
    dest.write_bytes(b"old")
    assert "kept previous" in refresh_osv(dest, "u", HTTP(b"not a zip"))
    assert dest.read_bytes() == b"old" and not (tmp_path / "all.zip.part").exists()
