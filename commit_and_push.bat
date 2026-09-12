@echo off
echo Adding modified files to Git...
git add src/arkshield/api/server.py
git add src/arkshield/api/models.py
git add src/arkshield/api/routes/threat_intel.py
git add src/arkshield/agent/core.py
git add src/arkshield/agent/monitors/registry_monitor.py

echo.
echo Committing changes...
git commit -m "Refactor: Modularize API and add Registry Persistence Monitor" -m "- Fixed global state memory leaks in server.py by using bounded deques." -m "- Extracted 20+ Pydantic models from server.py into models.py." -m "- Extracted threat intelligence routes into a new FastAPI APIRouter in routes/threat_intel.py." -m "- Created RegistryMonitor module for detecting registry-based persistence." -m "- Registered RegistryMonitor within the NexusSentinel core orchestrator."

echo.
echo Pushing to GitHub...
git push origin main

echo.
echo Done!
pause
