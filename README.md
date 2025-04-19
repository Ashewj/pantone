
# Pantone Color Finder 🎨

A sleek PyQt5-based Pantone color search tool that uses async web scraping to deliver fast and responsive results. Easily search and view color information with a clean interface.

---

## 🚀 How to Run

1. **Install required Python libraries:**

```bash
pip install pyinstaller
pip install aiohttp beautifulsoup4 PyQt5
```

2. **Build the executable (Windows):**

```bash
pyinstaller pantone.py --onefile --noconsole
```

> The standalone `.exe` will be located in the `dist/` folder after the build completes.

---

## 🧠 Libraries Used

- `sys` — base Python
- `asyncio` — for async control flow
- `aiohttp` — for asynchronous HTTP requests
- `bs4 (BeautifulSoup)` — for parsing HTML
- `PyQt5` — for GUI:
  - `Qt`, `QThread`, `pyqtSignal`
  - `QColor`, `QIcon`, `QPixmap`
  - `QApplication`, `QWidget`, `QVBoxLayout`, `QLineEdit`, `QPushButton`, `QLabel`, `QListWidget`, `QListWidgetItem`, `QHBoxLayout`, `QFrame`, `QTextBrowser`, `QCheckBox`, `QGroupBox`

---

## 📦 Output

The compiled `.exe` will run on any Windows machine, no Python installation required.

---

## ✅ License

MIT License
