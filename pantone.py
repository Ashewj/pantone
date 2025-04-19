import sys
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPixmap
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QLabel, QListWidget, QListWidgetItem, QHBoxLayout, QFrame, QTextBrowser, QCheckBox, QGroupBox

loop = asyncio.new_event_loop()
MAX_CONCURRENT_REQUESTS = 10
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

matches = []
current_index = 0

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
                'codigo': cells[0].text.strip().upper(),
                'rgb': cells[1].text.strip(),
                'hex': cells[2].text.strip(),
                'categoria': cells[4].text.strip(),
                'name': cells[3],  # Adicionando o campo 'name'
                'pagina_origem': f"{categoria}/{pagina}"
            })
        return resultados
    except:
        return []

async def buscar_pantone_async(codigo_para_buscar, categorias_selecionadas):
    urls = [
        ("fashion-and-interior-designers", 15),
        ("industrial-designers", 11),
        ("graphic-designers", 33)
    ]
    tarefas = []
    async with aiohttp.ClientSession() as session:
        for categoria, paginas in urls:
            # Filtra as categorias selecionadas
            if categoria in categorias_selecionadas:
                for i in range(1, paginas + 1):
                    url = f"https://www.numerosamente.it/pantone-list/{categoria}/{i}"
                    tarefas.append(buscar_pagina(session, url, categoria, i))
        resultados = await asyncio.gather(*tarefas)
        resultados_flat = [item for sublist in resultados for item in sublist if item]
        return resultados_flat

class ThreadDeBusca(QThread):
    resultados_prontos = pyqtSignal(list)

    def __init__(self, codigo_para_buscar, categorias_selecionadas):
        super().__init__()
        self.codigo_para_buscar = codigo_para_buscar
        self.categorias_selecionadas = categorias_selecionadas

    def run(self):
        todos_resultados = loop.run_until_complete(buscar_pantone_async(self.codigo_para_buscar, self.categorias_selecionadas))
        filtrados = [r for r in todos_resultados if self.codigo_para_buscar in r['codigo']]
        filtrados = sorted(filtrados, key=lambda r: len(r['codigo']))
        self.resultados_prontos.emit(filtrados)

class PantoneFinder(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pant1")  # Título curto
        self.setGeometry(100, 100, 222, 500)  # Atualizado para altura 500
        
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor("#ffb6c1"))  # rosa claro
        self.setWindowIcon(QIcon(pixmap))

        # Definindo o tema escuro e customização da barra de rolagem
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
            QListWidget {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444;
            }
            QListWidget::item {
                padding: 5px;
                background-color: #2a2a2a;  # Cor de fundo para itens da lista
            }
            QListWidget::item:selected {
                background-color: #333;  # Cor de fundo para item selecionado
                color: #ffffff;  # Cor do texto para item selecionado
            }
            QLabel, QTextBrowser {
                color: #dddddd;
            }
        """)

        self.matches = []
        self.current_index = 0
        self.busca_em_andamento = False
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)

        # Campo de busca
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Código Pantone (ex: 186 C)")
        layout.addWidget(self.search_bar)

        # Filtros com checkboxes (permite seleção múltipla)
        self.filter_groupbox = QGroupBox("Filtros de Categoria", self)
        self.filter_layout = QVBoxLayout(self.filter_groupbox)
        
        # Checkbox "Graphic" é o primeiro e já está selecionado
        self.graphic_checkbox = QCheckBox("Graphic", self)
        self.graphic_checkbox.setChecked(True)  # Marca como selecionado por padrão
        self.fashion_checkbox = QCheckBox("Fashion", self)
        self.industrial_checkbox = QCheckBox("Industrial", self)

        self.filter_layout.addWidget(self.graphic_checkbox)
        self.filter_layout.addWidget(self.fashion_checkbox)
        self.filter_layout.addWidget(self.industrial_checkbox)

        layout.addWidget(self.filter_groupbox)

        # Botão de busca
        self.search_button = QPushButton("Buscar", self)
        self.search_button.clicked.connect(self.on_search)
        layout.addWidget(self.search_button)

        # Rótulo de status
        self.status_label = QLabel("", self)
        layout.addWidget(self.status_label)

        # Caixa de resultados e layout (sem área rolável)
        self.result_widget = QFrame(self)
        self.result_layout = QVBoxLayout(self.result_widget)
        self.result_widget.setFixedSize(200, 150)  # Tamanho aumentado para a caixa de resultados
        layout.addWidget(self.result_widget)

        # Lista de resultados
        self.list_widget = QListWidget(self)
        self.list_widget.setFixedWidth(200)
        self.list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_widget.clicked.connect(self.on_item_click)
        layout.addWidget(self.list_widget)

        # Navegação inferior (Anterior/Próximo)
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

        # Permitir apenas o redimensionamento da altura, não da largura
        self.setFixedWidth(222)  # Largura fixa
        self.setMinimumHeight(500)  # Altura mínima ajustada para 500
        self.setMaximumHeight(752)  # Altura máxima ajustada para 752

    def display_result(self, index):
        # Limpar resultados anteriores
        for i in reversed(range(self.result_layout.count())):
            widget = self.result_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        if not self.matches:
            return

        r = self.matches[index]
        color = r['hex'].lstrip('#')

        # Caixa de cor
        color_box = QLabel(self)
        color_box.setStyleSheet(f"background-color: #{color}; width: 100px; height: 100px;")
        color_box.setFixedHeight(50)
        self.result_layout.addWidget(color_box)

        # Detalhes do texto (incluindo o campo "name")
        detalhes_texto = (
            f"Código: {r['codigo']}\n"
            f"RGB: {r['rgb']}\n"
            f"Hex: {r['hex']}\n"
            f"Categoria: {r['categoria']}\n"
            f"Página: {r['pagina_origem']}"
        )

        detalhes_browser = QTextBrowser(self)
        detalhes_browser.setPlainText(detalhes_texto)
        detalhes_browser.setOpenExternalLinks(True)
        self.result_layout.addWidget(detalhes_browser)

        self.counter_label.setText(f"{index + 1} / {len(self.matches)}")

    def on_search(self):

        if self.busca_em_andamento:
            return  # Impede nova busca se já estiver buscando

        self.busca_em_andamento = True
        self.search_button.setEnabled(False)
        self.matches.clear()
        self.list_widget.clear()

        for i in reversed(range(self.result_layout.count())):
            widget = self.result_layout.itemAt(i).widget()
            if widget:
                    widget.deleteLater()
            
        self.status_label.setText("Buscando...")

        codigo_input = self.search_bar.text().strip().upper()

        # Filtros
        categorias = []
        if self.graphic_checkbox.isChecked():
            categorias.append("graphic-designers")
        if self.fashion_checkbox.isChecked():
            categorias.append("fashion-and-interior-designers")
        if self.industrial_checkbox.isChecked():
            categorias.append("industrial-designers")

        # Se não houver filtros selecionados, exibe um alerta
        if not categorias:
            self.status_label.setText("Selecione ao menos uma categoria.")
            self.search_button.setEnabled(True)
            self.busca_em_andamento = False
            return

        self.search_thread = ThreadDeBusca(codigo_input, categorias)
        self.search_thread.resultados_prontos.connect(self.on_search_complete)
        self.search_thread.start()

    def on_search_complete(self, results):
        self.busca_em_andamento = False
        self.search_button.setEnabled(True)
        self.matches = results

        if not self.matches:
            self.status_label.setText("Nenhum resultado encontrado.")
            return

        for i, r in enumerate(self.matches):
            item = QListWidgetItem(f"{r['codigo']} - {r['hex']}")
            color = QColor(r['hex'])
            item.setBackground(color)
            self.list_widget.addItem(item)

        self.display_result(self.current_index)
        self.status_label.setText(f"Encontrado(s) {len(self.matches)} resultado(s)")

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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PantoneFinder()
    window.show()
    sys.exit(app.exec_())
