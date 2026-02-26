"""
Run Alembic migration — avoids local alembic/ dir shadowing the package.

Usage: python run_migration.py
"""
import sys
import os
import subprocess

project_root = os.path.dirname(os.path.abspath(__file__))
env = os.environ.copy()
env["PYTHONPATH"] = project_root

# Use the alembic.exe directly from user scripts
alembic_exe = os.path.join(
    os.path.expanduser("~"),
    "AppData", "Roaming", "Python", "Python314", "Scripts", "alembic.exe"
)

if not os.path.exists(alembic_exe):
    # Fallback: try to find it
    import shutil
    alembic_exe = shutil.which("alembic") or "alembic"

print(f"Using alembic: {alembic_exe}")
print(f"PYTHONPATH: {project_root}")
print(f"CWD: {project_root}")

result = subprocess.run(
    [alembic_exe, "upgrade", "head"],
    cwd=project_root,
    env=env,
    capture_output=True,
    text=True,
)

print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("Exit code:", result.returncode)
sys.exit(result.returncode)
