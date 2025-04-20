import sys
import os
import json
import asyncio
import aiohttp
from functools import lru_cache
from bs4 import BeautifulSoup
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel,
    QListWidget, QListWidgetItem, QHBoxLayout, QFrame, QTextBrowser, QCheckBox,
    QGroupBox, QTabWidget, QColorDialog
)

loop = asyncio.new_event_loop()
MAX_CONCURRENT_REQUESTS = 10
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

CACHE_FILE = "pantone_cache.json"
_cache = None

def hex_para_rgb(hex_str):
    hex_str = hex_str.lstrip('#')
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))

def distancia_rgb(cor1, cor2):
    return sum((a - b) ** 2 for a, b in zip(cor1, cor2)) ** 0.5

def salvar_em_cache(dados):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

@lru_cache(maxsize=1)
def carregar_do_cache():
    global _cache
    if _cache is None:
        if os.path.exists(CACHE_FILE):
            print("cache carregado")
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
        print(f"[Erro ao buscar {url}]: {e}")
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
            filtrados = [r for r in resultados_filtrados if self.valor_para_buscar in r['codigo']]
        else:
            try:
                cor_base = hex_para_rgb(self.valor_para_buscar)
                filtrados = sorted(
                    resultados_filtrados,
                    key=lambda r: distancia_rgb(cor_base, hex_para_rgb(r['hex']))
                )[:10]
            except:
                filtrados = []

        self.resultados_prontos.emit(filtrados)

class AbaDeBusca(QWidget):
    def __init__(self, buscar_por_codigo=True):
        super().__init__()
        self.matches = []
        self.current_index = 0
        self.busca_em_andamento = False
        self.buscar_por_codigo = buscar_por_codigo
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)

        barra_layout = QHBoxLayout()
        self.search_bar = QLineEdit(self)
        if self.buscar_por_codigo:
            self.search_bar.setPlaceholderText("Código Pantone (ex: 186 C)")
        else:
            self.search_bar.setPlaceholderText("Código Hex (ex: #FF5733)")
            conta_gotas_btn = QPushButton("🎨", self)
            conta_gotas_btn.setFixedWidth(30)
            conta_gotas_btn.clicked.connect(self.usar_conta_gotas)
            barra_layout.addWidget(conta_gotas_btn)

        barra_layout.addWidget(self.search_bar)
        layout.addLayout(barra_layout)

        self.filter_groupbox = QGroupBox("Filtros de Categoria", self)
        self.filter_layout = QVBoxLayout(self.filter_groupbox)
        self.graphic_checkbox = QCheckBox("Graphic", self)
        self.graphic_checkbox.setChecked(True)
        self.fashion_checkbox = QCheckBox("Fashion", self)
        self.industrial_checkbox = QCheckBox("Industrial", self)

        self.filter_layout.addWidget(self.graphic_checkbox)
        self.filter_layout.addWidget(self.fashion_checkbox)
        self.filter_layout.addWidget(self.industrial_checkbox)
        layout.addWidget(self.filter_groupbox)

        self.result_widget = QFrame(self)
        self.result_layout = QVBoxLayout(self.result_widget)
        self.result_widget.setFixedSize(200, 150)
        layout.addWidget(self.result_widget)

        self.list_widget = QListWidget(self)
        self.list_widget.setFixedWidth(200)
        self.list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_widget.clicked.connect(self.on_item_click)
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
        layout.addLayout(bottom_layout)

        self.search_bar.textChanged.connect(self.on_search)

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
        color = r['hex'].lstrip('#')
        color_box = QLabel(self)
        color_box.setStyleSheet(f"background-color: #{color}; width: 100px; height: 100px;")
        color_box.setFixedHeight(50)
        self.result_layout.addWidget(color_box)

        detalhes_texto = (
            f"Código: {r['codigo']}\n"
            f"RGB: {r['rgb']}\n"
            f"Hex: {r['hex']}\n"
            f"Categoria: {r['categoria']}\n"
            f"Página: {r['pagina_origem']}")

        detalhes_browser = QTextBrowser(self)
        detalhes_browser.setPlainText(detalhes_texto)
        detalhes_browser.setOpenExternalLinks(True)
        self.result_layout.addWidget(detalhes_browser)
        self.counter_label.setText(f"{index + 1} / {len(self.matches)}")

    def on_search(self):
        if self.busca_em_andamento:
            return

        valor_input = self.search_bar.text().strip().upper()

        # Verifica se há pelo menos uma categoria selecionada
        categorias = []
        if self.graphic_checkbox.isChecked():
            categorias.append("Graphic Designers")
        if self.fashion_checkbox.isChecked():
            categorias.append("Fashion and Interior Designers")
        if self.industrial_checkbox.isChecked():
            categorias.append("Industrial Designers")

        if not categorias:
            # Exibe um aviso para o usuário caso nenhuma categoria tenha sido selecionada
            # self.show_error_message("Por favor, selecione ao menos uma categoria.")
            return

        self.busca_em_andamento = True
        self.search_thread = ThreadDeBusca(valor_input, categorias, buscar_por_codigo=self.buscar_por_codigo)
        self.search_thread.resultados_prontos.connect(self.on_search_complete)
        self.search_thread.start()

    def show_error_message(self, message):
        # Exibe uma mensagem de erro se necessário
        error_label = QLabel(message, self)
        error_label.setStyleSheet("color: red;")
        self.result_layout.addWidget(error_label)

    def on_search_complete(self, results):
        self.busca_em_andamento = False
        self.matches = results

        if not self.matches:
            return

        self.list_widget.clear()
        for i, r in enumerate(self.matches):
            item = QListWidgetItem(f"{r['codigo']} - {r['hex']}")
            item.setBackground(QColor(r['hex']))
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

    def show_previous(self):
        if self.matches:
            self.current_index = (self.current_index - 1) % len(self.matches)
            self.display_result(self.current_index)

class PantoneFinder(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pant1")
        self.setGeometry(100, 100, 222, 500)
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
            QLabel, QTextBrowser {
                color: #dddddd;
            }
            QTabBar::tab {
                background: #2a2a2a;
                color: white;
                padding: 6px;
                border: 1px solid #444;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #444;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                top: -1px;
            }
        """)

        # Layout principal
        main_layout = QVBoxLayout(self)

        self.atualizar_button = QPushButton("Atualizar Dados", self)
        self.atualizar_button.clicked.connect(self.forcar_atualizacao_cache)
        main_layout.addWidget(self.atualizar_button)

        tabs = QTabWidget(self)
        tabs.addTab(AbaDeBusca(buscar_por_codigo=True), "Buscar Código Pantone")
        tabs.addTab(AbaDeBusca(buscar_por_codigo=False), "Buscar por Hex")

        main_layout.addWidget(tabs)

    def forcar_atualizacao_cache(self):
        self.atualizar_button.setText("Atualizando dados...")
        quantidade = baixar_todos_os_dados()
        self.atualizar_button.setText(f"{quantidade} cores atualizadas com sucesso!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PantoneFinder()
    window.show()
    sys.exit(app.exec_())