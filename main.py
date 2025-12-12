"""
Network Monitor & Security Scanner - Desktop Application
Main Entry Point with Logo
"""

import sys
from PySide6.QtWidgets import QApplication, QSplashScreen
from PySide6.QtGui import QIcon, QPixmap, QFont, QPainter, QColor
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPen

# Import the main window from the original file
from monitor_app import MainWindow


def create_logo(size=64):
    """Create a simple logo/icon"""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    
    # Draw shield/network icon
    painter.setBrush(QColor("#1f6feb"))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(8, 8, size-16, size-16)
    
    # Draw network waves
    painter.setPen(QPen(QColor("#ffffff"), 3))
    for i in range(3):
        y = size // 2
        radius = 8 + i * 6
        painter.drawArc(size//2 - radius, y - radius, radius*2, radius*2, 0, 180*16)
    
    painter.end()
    return pixmap


def create_splash_screen():
    """Create splash screen with logo"""
    splash_pixmap = QPixmap(400, 300)
    splash_pixmap.fill(QColor("#0f1115"))
    
    painter = QPainter(splash_pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    
    # Draw logo
    logo = create_logo(80)
    painter.drawPixmap(160, 50, logo)
    
    # Draw title
    painter.setPen(QColor("#58a6ff"))
    font = QFont("Segoe UI", 20, QFont.Bold)
    painter.setFont(font)
    painter.drawText(0, 160, 400, 40, Qt.AlignCenter, "Network Security Scanner")
    
    # Draw subtitle
    painter.setPen(QColor("#aab2c5"))
    font = QFont("Segoe UI", 10)
    painter.setFont(font)
    painter.drawText(0, 200, 400, 30, Qt.AlignCenter, "Advanced Network Monitor & Vulnerability Scanner")
    
    painter.end()
    return splash_pixmap


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Network Security Scanner")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Mohamed Ahmed")
    
    # Create and show splash screen
    splash_pixmap = create_splash_screen()
    splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
    splash.show()
    app.processEvents()
    
    # Create main window
    window = MainWindow()
    
    # Set window icon
    icon = QIcon(create_logo(256))
    window.setWindowIcon(icon)
    
    # Update window title
    window.setWindowTitle("Network Security Scanner - Advanced Network Monitor")
    
    # Close splash and show main window after delay
    def show_main():
        splash.close()
        window.show()
    
    QTimer.singleShot(1500, show_main)
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

