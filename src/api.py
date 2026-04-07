from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Awaitable, Callable, Dict, List, Optional
import os

from .matcher import add_custom_tool, delete_custom_tool, load_tools
from .models import get_alert, get_stats, list_alerts, update_alert_status


class ToolCreate(BaseModel):
    name: str
    keywords: List[str]
    version: Optional[str] = None
    cpe: Optional[str] = None


class AlertUpdate(BaseModel):
    status: str


def create_app(
    db_path: str,
    lifespan: Optional[Callable] = None,
    dashboard_enabled: bool = False,
    dashboard_path: Optional[str] = None,
    collect_handler: Optional[Callable[[], Awaitable[Dict[str, object]]]] = None,
) -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/")
    def api_root():
        return {"status": "ok", "service": "veille-secu"}

    if dashboard_enabled:
        resolved_path = dashboard_path or os.path.join(
            os.path.dirname(__file__), "..", "web", "index.html"
        )

        @app.get("/dashboard", response_class=HTMLResponse)
        def api_dashboard():
            try:
                with open(resolved_path, "r", encoding="utf-8") as handle:
                    return handle.read()
            except OSError:
                return "<h1>Dashboard indisponible</h1>"

    @app.get("/api/alerts")
    def api_list_alerts(
        severity: Optional[str] = None,
        tool: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ):
        return {
            "alerts": list_alerts(
                db_path,
                severity=severity,
                tool=tool,
                status=status,
                limit=min(limit, 200),
                offset=offset,
            )
        }

    @app.get("/api/alerts/{alert_id}")
    def api_get_alert(alert_id: int):
        alert = get_alert(db_path, alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert

    @app.patch("/api/alerts/{alert_id}")
    def api_update_alert(alert_id: int, payload: AlertUpdate):
        if payload.status not in {"new", "read", "dismissed"}:
            raise HTTPException(status_code=400, detail="Invalid status")
        updated = update_alert_status(db_path, alert_id, payload.status)
        if not updated:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "ok"}

    @app.get("/api/tools")
    def api_list_tools():
        return {"tools": load_tools()}

    @app.post("/api/tools")
    def api_add_tool(payload: ToolCreate):
        tool = add_custom_tool(payload.name, payload.keywords, payload.version, payload.cpe)
        return tool

    @app.delete("/api/tools/{tool_id}")
    def api_delete_tool(tool_id: str):
        deleted = delete_custom_tool(tool_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Tool not found")
        return {"status": "ok"}

    @app.get("/api/stats")
    def api_stats():
        return get_stats(db_path)

    if collect_handler:
        @app.post("/api/collect")
        async def api_collect_now():
            return await collect_handler()

    @app.get("/health")
    def api_health():
        return {"status": "ok"}

    return app
