"""Run the app against a disposable database for offline browser tests."""
import os
from pathlib import Path
import tempfile

import uvicorn


if __name__ == "__main__":
    os.chdir(Path(__file__).resolve().parents[1])
    with tempfile.TemporaryDirectory(prefix="scopeforge-browser-") as directory:
        os.environ["SCOPEFORGE_DB"] = str(Path(directory) / "test.sqlite3")
        uvicorn.run("scopeforge.main:app", host="127.0.0.1", port=8000, workers=1)
