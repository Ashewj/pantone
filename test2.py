import pandas as pd

# Data provided
data = [
['PROCESS WHITE C', 'PRETO BLACK C', 'PROCESS YELLOW C', '130 C', 'PROCESS MAGENTA C', '187 C', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', 'PROCESS YELLOW C', 'VAZIO', 'PROCESS MAGENTA C', '187 C', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', '871 C', 'VAZIO', 'VAZIO', 'VAZIO', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', 'PROCESS YELLOW C', 'REFLEX BLUE C', 'PROCESS MAGENTA C', 'VAZIO', 'VAZIO', 'PROCESS CYAN C'],
['PROCESS WHITE C', 'VAZIO', 'PROCESS YELLOW C', 'REFLEX BLUE C', '485 C', 'VAZIO', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', '116 C', 'REFLEX BLUE C', '1795 C', 'VAZIO', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', '116 C', '4146 C', 'VAZIO', 'VAZIO', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', 'PROCESS YELLOW C', 'VAZIO', 'PROCESS MAGENTA C', 'VAZIO', 'VAZIO', 'PROCESS CYAN C'],
['PROCESS WHITE C', 'VAZIO', 'VAZIO', 'REFLEX BLUE C', '485 C', 'VAZIO', 'VAZIO', 'VAZIO'],
['PROCESS WHITE C', 'PRETO BLACK C', 'PROCESS YELLOW C', '7509 C', 'PROCESS MAGENTA C', 'VAZIO', 'VAZIO', 'PROCESS CYAN C'],
]

# print(f"{grid[row]},")
df = pd.DataFrame(data, columns=['cor1', 'cor2', 'cor3', 'cor4', 'cor5', 'cor6', 'cor7', 'cor8'])

# print(f"{grid[row]},")
df.to_excel('C:/Users/Administrator/Downloads/cores_ajustadas_separadas.xlsx', index=False)