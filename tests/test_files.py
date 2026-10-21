import stat
import sys

import pytest

from lazyios.files import create_private, private_dir, write_private

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


def test_write_private_creates_parents_and_refuses_to_overwrite(tmp_path):
    path = write_private(tmp_path / "a" / "b" / "shot.png", b"data")
    assert path.read_bytes() == b"data"
    with pytest.raises(FileExistsError):
        create_private(path)
    assert path.read_bytes() == b"data"


@posix_only
def test_files_are_owner_only(tmp_path):
    path = write_private(tmp_path / "out" / "capture.pcap", b"x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@posix_only
def test_private_dir_tightens_an_existing_folder(tmp_path):
    folder = tmp_path / "lazyios"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    private_dir(folder)
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


@posix_only
def test_create_private_does_not_follow_a_planted_symlink(tmp_path):
    target = tmp_path / "victim"
    target.write_bytes(b"keep")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "capture.pcap").symlink_to(target)
    with pytest.raises(FileExistsError):
        create_private(tmp_path / "out" / "capture.pcap")
    assert target.read_bytes() == b"keep"
