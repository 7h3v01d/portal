# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""PyQt6 viewer widget — Windows/desktop rendering surface for the decoded stream.

Deliberately thin: all the hard, testable logic (transport, decode, frame
delivery, keyframe resync) lives in ScreenViewer and is exercised in tests. This
widget only blits the RGB frames ScreenViewer yields, so the untested-here surface
is minimal. Qt is imported lazily and the `ui` extra installs it; validated on the
rig, not in the headless test container.

Dark-industrial house style: obsidian background, teal accent on the status line.
"""

from __future__ import annotations

from ..common.errors import PortalError
from ..decode.pyav_decoder import DecodedFrame


def build_viewer_widget():
    """Construct the QWidget subclass lazily so importing this module doesn't pull
    in PyQt6 where it isn't installed."""
    try:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QImage, QPainter, QPixmap
        from PyQt6.QtWidgets import QWidget
    except Exception as exc:  # noqa: BLE001
        raise PortalError("PyQt6 is required for the viewer widget (install the 'ui' extra)") from exc

    class ViewerWidget(QWidget):
        _OBSIDIAN = "#0b0f14"

        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            self.setStyleSheet(f"background-color: {self._OBSIDIAN};")
            self._pixmap: QPixmap | None = None
            self.setMinimumSize(320, 240)

        def show_frame(self, frame: DecodedFrame) -> None:
            image = QImage(
                frame.rgb, frame.width, frame.height, frame.width * 3, QImage.Format.Format_RGB888
            )
            self._pixmap = QPixmap.fromImage(image)
            self.update()

        def paintEvent(self, _event) -> None:  # noqa: N802 (Qt naming)
            if self._pixmap is None:
                return
            painter = QPainter(self)
            scaled = self._pixmap.scaled(
                self.size(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)

    return ViewerWidget
