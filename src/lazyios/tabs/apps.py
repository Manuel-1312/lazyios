from __future__ import annotations

from typing import Any

from textual.widgets import DataTable

from ..backend import App, BackendError
from .base import TableTab


class AppsTab(TableTab[App]):
    title = "apps"
    columns = (("name", False), ("bundle id", False), ("version", False))

    def key(self, item: App) -> str:
        return item.bundle_id

    def cells(self, item: App) -> tuple[Any, ...]:
        return (item.name, item.bundle_id, item.version)

    def haystack(self, item: App) -> tuple[str, ...]:
        return (item.name, item.bundle_id)

    async def load(self) -> None:
        try:
            apps = await self.lazy.backend.apps()
        except BackendError as e:
            self.notice(str(e))
            self.lazy.report(e)
            return
        self.notice("")
        self.set_items(apps)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if (app := self.selected()) is not None:
            self.lazy.run_task(self.lazy.launch(app.bundle_id), group="launch")
