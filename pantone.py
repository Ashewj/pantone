import sys
import os
import json
import asyncio
import aiohttp
import pandas as pd

from collections import defaultdict, Counter
from functools import lru_cache
from bs4 import BeautifulSoup

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QAbstractTableModel
from PyQt5.QtGui import QColor, QIcon, QPainter, QPixmap, QBrush
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel,
    QListWidget, QListWidgetItem, QHBoxLayout, QFrame, QTextBrowser, QCheckBox,
    QGroupBox, QTabWidget, QColorDialog, QStyledItemDelegate, QStyle, QTableView
)

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="openpyxl.worksheet._reader")

loop = asyncio.new_event_loop()
MAX_CONCURRENT_REQUESTS = 10
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

CORES_FIXAS = {
            "PRETO": "PRETO BLACK C",
            "BRANCO": "PROCESS WHITE C",
            "AMARELO": "PROCESS YELLOW C",
            "CYAN": "PROCESS CYAN C",
            "MAGENTA": "PROCESS MAGENTA C",
        }

CACHE_FILE = "pantone_cache.json"
_cache = None
_cached_excel_df = None

class Pantone:
    def __init__(self, codigo, rgb, hex, categoria, pagina_origem):
        self.codigo = codigo
        self.rgb = rgb
        self.hex = hex
        self.categoria = categoria
        self.pagina_origem = pagina_origem

    def to_dict(self):
        return {
            "codigo": self.codigo,
            "rgb": self.rgb,
            "hex": self.hex,
            "categoria": self.categoria,
            "pagina_origem": self.pagina_origem
        }
        
def custom_pantone_to_cache(codigo, rgb, hex_value, categoria, pagina_origem, cache_file='pantone_cache.json'):
    pantone = Pantone(codigo, rgb, hex_value, categoria, pagina_origem)
    pantone_dict = pantone.to_dict()
    try:
        with open(cache_file, 'r') as file:
            cache_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        cache_data = []
    cache_data.append(pantone_dict)
    with open(cache_file, 'w') as file:
        json.dump(cache_data, file, indent=4)
        
def hex_para_rgb(hex_code):
    hex_code = hex_code.lstrip('#')
    if len(hex_code) != 6:
        return None
    return tuple(int(hex_code[i:i+2], 16) / 255.0 for i in (0, 2, 4))

def distancia_rgb(hex1, hex2):
    rgb1 = hex_para_rgb(hex1)
    rgb2 = hex_para_rgb(hex2)
    if not rgb1 or not rgb2:
        return float('inf')
    return sum((a - b) ** 2 for a, b in zip(rgb1, rgb2)) ** 0.5

def salvar_em_cache(dados):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

@lru_cache(maxsize=1)
def carregar_do_cache():
    global _cache
    if _cache is None:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _cache = json.load(f)
        else:
            _cache = []
    return _cache

async def buscar(session, url):
    async with semaphore:
        async with session.get(url) as response:
            return await response.text()

async def buscar_pagina(session, url, categoria, pagina):
    try:
        html = await buscar(session, url)
        soup = BeautifulSoup(html, 'html.parser')
        resultados = []
        for row in soup.find_all('tr')[1:]:
            cells = row.find_all("td")
            if not cells or len(cells) < 5:
                continue
            resultados.append({
                'codigo': cells[0].get_text(strip=True).upper(),
                'rgb': cells[1].get_text(strip=True),
                'hex': cells[2].get_text(strip=True),
                'categoria': cells[4].get_text(strip=True),
                'pagina_origem': f"{categoria}/{pagina}"
            })
        return resultados
    except Exception as e:
        return []

async def buscar_pantone_async(_, categorias_selecionadas):
    urls = [
        ("fashion-and-interior-designers", 15),
        ("industrial-designers", 11),
        ("graphic-designers", 33)
    ]
    tarefas = []
    async with aiohttp.ClientSession() as session:
        for categoria, paginas in urls:
            if categoria in categorias_selecionadas:
                for i in range(1, paginas + 1):
                    url = f"https://www.numerosamente.it/pantone-list/{categoria}/{i}"
                    tarefas.append(buscar_pagina(session, url, categoria, i))
        resultados = await asyncio.gather(*tarefas)
        return [item for sublist in resultados for item in sublist if item]

def baixar_todos_os_dados():
    categorias = [
        "fashion-and-interior-designers",
        "industrial-designers",
        "graphic-designers"
    ]
    resultado = loop.run_until_complete(buscar_pantone_async("", categorias))
    salvar_em_cache(resultado)
    
    custom_pantone_to_cache("PROCESS WHITE C", "rgb(255,255,255)", "#FFFFFF", "Graphic Designers", "Custom")
    custom_pantone_to_cache("PRETO BLACK C", "rgb(0,0,0)", "#000000", "Graphic Designers", "Custom")
    custom_pantone_to_cache("4146 C", "rgb(27,29,54)", "#1B1D36", "Graphic Designers", "Custom")

    return len(resultado)

class ThreadDeBusca(QThread):
    resultados_prontos = pyqtSignal(list)

    def __init__(self, valor_para_buscar, categorias_selecionadas, buscar_por_codigo=True):
        super().__init__()
        self.valor_para_buscar = valor_para_buscar
        self.categorias_selecionadas = categorias_selecionadas
        self.buscar_por_codigo = buscar_por_codigo

    def run(self):
        if not os.path.exists(CACHE_FILE):
            baixar_todos_os_dados()

        resultados_filtrados = [u for u in carregar_do_cache() if any(s in u['categoria'] for s in self.categorias_selecionadas)]
        
        if self.buscar_por_codigo:
            match = next((r for r in resultados_filtrados if r['codigo'].lower() == self.valor_para_buscar.lower()), None)
            if match:       
                filtrados = [match]
            else:
                filtrados = [r for r in resultados_filtrados if self.valor_para_buscar in r['codigo']]
        else:
            try:
                match = next((r for r in resultados_filtrados if r['hex'].lower() == self.valor_para_buscar.lower()), None)
                if match:       
                   filtrados = [match] 
                else:
                    resultados_aproximados = [r for r in resultados_filtrados if distancia_rgb(self.valor_para_buscar, r['hex']) <= 0.04]
                    filtrados = sorted(resultados_aproximados, key=lambda r: distancia_rgb(self.valor_para_buscar, r['hex']))
            except:
                filtrados = []

        self.resultados_prontos.emit(filtrados)

class BlendDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        super().paint(painter, option, index)

        if option.state & QStyle.State_Selected:
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setBrush(QColor(255,255,255,120))
            painter.setPen(Qt.NoPen)
            painter.drawRect(option.rect)
            painter.restore()

class PandasModel(QAbstractTableModel):
    def __init__(self, df=pd.DataFrame()):
        super().__init__()
        self._df = df
        self.cache = {}
        
    def rowCount(self, parent=None): # NAO MEXER
        return self._df.shape[0]

    def columnCount(self, parent=None): # NAO MEXER
        return self._df.shape[1]

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        
        value = self._df.iloc[index.row(), index.column()]
        # headers_cor = self.headerData(index.column(), Qt.Horizontal, Qt.DisplayRole) in [f"CORF{i}" for i in range(1, 9)] + [f"CORV{i}" for i in range(1, 9)]
        
        if role == Qt.DisplayRole:
            if pd.isna(value):
                return ""
            return str(value)
        else:
            if pd.isna(value):
                return None
            
            codigo = self.get_codigo(value)
            
            if not codigo.endswith(" C"):
                return None
        
            if codigo in self.cache:
                brush = self.cache[codigo]
            else:
                brush = None
                cor = self.get_color_from_pantone(codigo)
                if cor is not None:
                    brush = QBrush(QColor(cor))
                    self.cache[codigo] = brush

            if role == Qt.BackgroundRole and brush:
                return brush
            
            if role == Qt.ForegroundRole and brush:
                color = brush.color()
                brightness = color.red() * 0.299 + color.green() * 0.587 + color.blue() * 0.114
                return QColor(Qt.black) if brightness > 186 else QColor(Qt.white)
            
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return str(self._df.columns[section])
            elif orientation == Qt.Vertical:
                return str(self._df.index[section])
        return None

    def get_codigo(self, code):
        codigo = str(code).strip().upper()
        codigo = CORES_FIXAS.get(codigo, codigo)

        if codigo.isdigit() and len(codigo) > 2 and len(codigo) <= 4:
            return codigo.strip() + " C"

        if codigo.startswith("PANTONE"):
            return codigo.replace("PANTONE", "").strip() + " C"
        return codigo

    def get_color_from_pantone(self, pantone_code):
        cache_filtrado = [u for u in carregar_do_cache() if u['categoria'] in "Graphic Designers"]
        match = next((r for r in cache_filtrado if r['codigo'].upper() == self.get_codigo(pantone_code)), None)
        return match['hex'] if match else None
    
    def get_filtered_cells(self):
        col_colors = defaultdict(list)

        for row in range(self.rowCount()):
            for col in range(self.columnCount()):
                value = self._df.iloc[row, col]
                if pd.isna(value):
                    continue
                
                value = str(value).strip().upper()

                if any(color in value for color in CORES_FIXAS) or "PANTONE" in value:
                    col_colors[col].append((row, value))

        sorted_cells = []
        for col, values in col_colors.items():
            for row, codigo in values:
                hex_color = self.get_color_from_pantone(codigo)
                hex_color and sorted_cells.append((row, col, self.get_codigo(codigo), hex_color))
        
        return sorted_cells

class AbaDeBusca(QWidget):
    def __init__(self, buscar_por_codigo=True, comparar_codigo=False):
        super().__init__()
        self.matches = []
        self.current_index = 0
        self.busca_em_andamento = False
        self.buscar_por_codigo = buscar_por_codigo
        self.comparar_codigo = comparar_codigo
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)
   
        if self.comparar_codigo:

            self.excel_table = QTableView()
            self.result_table = QTableView()

            # df = pd.read_csv("", sep="\t") # clipboard
            # df = pd.read_excel("C:/Users/Administrator/Documents/pantone_t.xlsx") # excel

            global _cached_excel_df
            if _cached_excel_df is None:
                _cached_excel_df = pd.read_excel("C:/Users/Administrator/Downloads/cores_ajustadas_separadas.xlsx")

            """ cols = list(_cached_excel_df.columns)
                first_col = cols[0]
                corf_corv_cols = [c for c in cols if c.startswith("CORF") or c.startswith("CORV")]
                rest_cols = [c for c in cols if c not in [first_col] + corf_corv_cols]
                new_order = [first_col] + corf_corv_cols + rest_cols
                _cached_excel_df = _cached_excel_df[new_order] """   
            
            model = PandasModel(_cached_excel_df)

            sorted_cells = model.get_filtered_cells()
            # print(sorted_cells)

            layout.addWidget(self.excel_table) 
            self.excel_table.setModel(model)
            #layout.addWidget(self.result_table)
            #self.result_table.setModel(model)
        else:
            barra_layout = QHBoxLayout()
            self.search_bar = QLineEdit(self)

            if self.buscar_por_codigo:
                self.search_bar.setPlaceholderText("Código Pantone (ex: 186 C)")
            else:
                self.search_bar.setPlaceholderText("Código Hex (ex: #FF5733)")

                conta_gotas_btn = QPushButton("💧", self)
                conta_gotas_btn.setFixedWidth(30)
                conta_gotas_btn.clicked.connect(self.usar_conta_gotas)
                barra_layout.addWidget(conta_gotas_btn)

            barra_layout.addWidget(self.search_bar)
            layout.addLayout(barra_layout)
        
            self.graphic_checkbox = QCheckBox("Graphic", self)
            self.fashion_checkbox = QCheckBox("Fashion", self)
            self.industrial_checkbox = QCheckBox("Industrial", self)
        
            self.graphic_checkbox.setChecked(True)
 
            self.filter_groupbox = QGroupBox("Filtros de Categoria", self)
            self.filter_layout = QVBoxLayout(self.filter_groupbox)
            self.filter_layout.addWidget(self.graphic_checkbox)
            self.filter_layout.addWidget(self.fashion_checkbox)
            self.filter_layout.addWidget(self.industrial_checkbox)
            layout.addWidget(self.filter_groupbox)
       
            self.result_widget = QFrame(self)
            self.result_layout = QVBoxLayout(self.result_widget)
            self.result_widget.setFixedSize(200, 150)
            layout.addWidget(self.result_widget)

            self.list_widget = QListWidget(self)
            self.list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.list_widget.currentItemChanged.connect(lambda _, __: self.on_item_click())
            self.list_widget.setItemDelegate(BlendDelegate())
            layout.addWidget(self.list_widget)

            self.prev_button = QPushButton("<", self)
            self.prev_button.clicked.connect(self.show_previous)
            self.next_button = QPushButton(">", self)
            self.next_button.clicked.connect(self.show_next)
            self.counter_label = QLabel("", self)

            bottom_layout = QHBoxLayout()
            bottom_layout.addWidget(self.prev_button)
            bottom_layout.addWidget(self.counter_label)
            bottom_layout.addWidget(self.next_button)
        
            self.counter_label.setAlignment(Qt.AlignCenter)

            layout.addLayout(bottom_layout)

            self.search_bar.textChanged.connect(self.on_search)
            self.graphic_checkbox.toggled.connect(self.on_checkbox_change)
            self.fashion_checkbox.toggled.connect(self.on_checkbox_change)
            self.industrial_checkbox.toggled.connect(self.on_checkbox_change)

    def usar_conta_gotas(self):
        cor = QColorDialog.getColor()
        if cor.isValid():
            self.search_bar.setText(cor.name().upper())

    def display_result(self, index):
        for i in reversed(range(self.result_layout.count())):
            widget = self.result_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        if not self.matches:
            return

        r = self.matches[index]
        color_box = QLabel(self)
        color_box.setStyleSheet(f"background-color: #{r['hex'].lstrip('#')}")
        color_box.setMinimumHeight(50)
        self.result_layout.addWidget(color_box)

        detalhes_texto = (
            f"Código: {r['codigo']}\n"
            f"RGB: {r['rgb']}\n"
            f"Hex: {r['hex']}\n"
            f"Categoria: {r['categoria']}\n"
            f"Página: {r['pagina_origem']}")

        detalhes_browser = QTextBrowser(self)
        detalhes_browser.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        detalhes_browser.setPlainText(detalhes_texto)

        detalhes_browser.setReadOnly(True)
        detalhes_browser.setOpenExternalLinks(True)

        detalhes_browser.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        detalhes_browser.viewport().setCursor(Qt.IBeamCursor)

        self.result_layout.addWidget(detalhes_browser)
        self.counter_label.setText(f"{index + 1} / {len(self.matches)}")

    def on_search(self):
        if self.busca_em_andamento:
            return

        valor_input = self.search_bar.text().strip().upper()

        categorias = []
        if self.graphic_checkbox.isChecked():
            categorias.append("Graphic Designers")
        if self.fashion_checkbox.isChecked():
            categorias.append("Fashion and Interior Designers")
        if self.industrial_checkbox.isChecked():
            categorias.append("Industrial Designers")

        if not categorias:
            self.list_widget.clear()
            self.matches = []
            self.current_index = 0
            self.counter_label.setText("")
            for i in reversed(range(self.result_layout.count())):
                widget = self.result_layout.itemAt(i).widget()
                if widget:
                    widget.deleteLater()
            return

        self.busca_em_andamento = True
        self.search_thread = ThreadDeBusca(valor_input, categorias, buscar_por_codigo=self.buscar_por_codigo)
        self.search_thread.resultados_prontos.connect(self.on_search_complete)
        self.search_thread.start()

    def on_checkbox_change(self):
        self.on_search()

    def on_search_complete(self, results):
        self.busca_em_andamento = False
        self.matches = results

        self.list_widget.clear()

        if not self.matches:
            return

        for r in self.matches:
            item = QListWidgetItem(f"{r['codigo']} - {r['hex']}")
            bg_color = QColor(r['hex'])
            item.setBackground(bg_color)

            brightness = bg_color.red() * 0.299 + bg_color.green() * 0.587 + bg_color.blue() * 0.114
            text_color = Qt.black if brightness > 186 else Qt.white
            item.setForeground(QColor(text_color))

            self.list_widget.addItem(item)

        self.display_result(self.current_index)

    def on_item_click(self):
        selected_item = self.list_widget.currentItem()
        index = self.list_widget.row(selected_item)
        self.current_index = index
        self.display_result(index)

    def show_next(self):
        if self.matches:
            self.current_index = (self.current_index + 1) % len(self.matches)
            self.display_result(self.current_index)
            self.list_widget.setCurrentRow(self.current_index)
            self.list_widget.scrollToItem(self.list_widget.currentItem())

    def show_previous(self):
        if self.matches:
            self.current_index = (self.current_index - 1) % len(self.matches)
            self.display_result(self.current_index)
            self.list_widget.setCurrentRow(self.current_index)
            self.list_widget.scrollToItem(self.list_widget.currentItem())

class PantoneFinder(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pant1")
        self.setGeometry(100, 100, 900, 500)
        
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor("#ffb6c1"))
        self.setWindowIcon(QIcon(pixmap))
        
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #dddddd;
            }
            QLineEdit, QPushButton, QListWidget {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #333;
            }
            QPushButton:pressed {
                background-color: #555;
            }
            QPushButton:disabled {
                background-color: #555;
                color: #888;
                border: 1px solid #333;
            }
            QTabBar::tab {
                background: #444;
                color: #6b6b6b;
                padding: 6px;
                border: 1px solid #444;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #2a2a2a;
                color: white;
                padding: 6px;
                border: 1px solid #444;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                top: -1px;
            }
            QTableView  {
                background-color: #2a2a2a;
                color: white;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: white;
            }
            QTableCornerButton::section {
                background-color: #2a2a2a;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        self.atualizar_button = QPushButton("Atualizar Dados", self)
        self.atualizar_button.clicked.connect(self.forcar_atualizacao_cache)
        layout.addWidget(self.atualizar_button)
        
        self.tabs = QTabWidget(self)
        
        self.tabs.addTab(AbaDeBusca(buscar_por_codigo=True, comparar_codigo=False), "Busca por Código")
        self.tabs.addTab(AbaDeBusca(buscar_por_codigo=False, comparar_codigo=False), "Busca por Hex")
        self.tabs.addTab(AbaDeBusca(buscar_por_codigo=False, comparar_codigo=True), "Comparar")    
        layout.addWidget(self.tabs)
        
        self.setLayout(layout)
        
    def forcar_atualizacao_cache(self):
        self.atualizar_button.setText("Atualizando dados...")
        quantidade = baixar_todos_os_dados()
        self.atualizar_button.setText(f"{quantidade} cores atualizadas com sucesso!")
         
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PantoneFinder()
    window.show()
    sys.exit(app.exec_())