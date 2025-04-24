import numpy as np
from sklearn.cluster import DBSCAN
from collections import defaultdict

# Helper function to convert hex to RGB
def hex_to_rgb(hex_code):
    hex_code = hex_code.lstrip('#')
    return tuple(int(hex_code[i:i+2], 16) for i in (0, 2, 4))

# Function to apply DBSCAN clustering on RGB colors
def apply_clustering(colors, eps=0.2, min_samples=2):
    rgb_values = np.array([hex_to_rgb(color[3]) for color in colors])  # Extract RGB values from hex
    db = DBSCAN(eps=eps, min_samples=min_samples).fit(rgb_values)  # Fit DBSCAN
    return db.labels_

# Function to sort colors based on their clusters and RGB similarity
def sort_colors_by_clusters(colors, labels):
    clustered_colors = defaultdict(list)
    
    for i, label in enumerate(labels):
        clustered_colors[label].append(colors[i])
    
    # Sort each cluster based on color intensity (e.g., brightness)
    sorted_clusters = []
    for cluster in clustered_colors.values():
        cluster.sort(key=lambda x: sum(hex_to_rgb(x[3])))  # Sort by RGB brightness (sum of R, G, B)
        sorted_clusters.extend(cluster)
    
    return sorted_clusters

# Function to arrange the colors into rows with 8 columns
def arrange_colors_into_rows(sorted_colors, max_columns=8):
    rows = []
    current_row = []
    
    for color in sorted_colors:
        current_row.append(color)
        if len(current_row) == max_columns:
            rows.append(current_row)
            current_row = []
    
    # If there are any remaining colors in the last row, pad with 'VAZIO'
    if current_row:
        while len(current_row) < max_columns:
            current_row.append(('VAZIO', 'VAZIO', 'VAZIO', 'VAZIO'))
        rows.append(current_row)
    
    return rows

# Main function to process and cluster the colors
def process_colors(colors):
    # Apply clustering to the colors based on RGB values
    labels = apply_clustering(colors)
    
    # Sort colors by cluster and RGB similarity
    sorted_colors = sort_colors_by_clusters(colors, labels)
    
    # Arrange sorted colors into rows with 8 columns, padding with 'VAZIO' as needed
    rows = arrange_colors_into_rows(sorted_colors)
    
    return rows

# Example data structure as provided
colors = [
    (0, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (1, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (2, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (3, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (4, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (5, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (6, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (7, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (8, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (9, 0, 'PROCESS WHITE C', '#FFFFFF'),
    (0, 1, 'PROCESS YELLOW C', '#F6E500'),
    (1, 1, 'PROCESS YELLOW C', '#F6E500'),
    (2, 1, '871 C', '#84754E'),
    (3, 1, 'PROCESS YELLOW C', '#F6E500'),
    (4, 1, 'PROCESS YELLOW C', '#F6E500'),
    (5, 1, '116 C', '#FFCD00'),
    (6, 1, '4146 C', '#1B1D36'),
    (7, 1, 'PROCESS YELLOW C', '#F6E500'),
    (8, 1, 'REFLEX BLUE C', '#001489'),
    (9, 1, 'PROCESS YELLOW C', '#F6E500'),
    (0, 2, 'PROCESS MAGENTA C', '#D9017A'),
    (1, 2, 'PROCESS MAGENTA C', '#D9017A'),
    (2, 2, 'PRETO BLACK C', '#000000'),
    (3, 2, 'PROCESS MAGENTA C', '#D9017A'),
    (4, 2, 'REFLEX BLUE C', '#001489'),
    (5, 2, '1795 C', '#D22630'),
    (6, 2, '116 C', '#FFCD00'),
    (7, 2, 'PROCESS MAGENTA C', '#D9017A'),
    (8, 2, '485 C', '#DA291C'),
    (9, 2, 'PROCESS MAGENTA C', '#D9017A'),
    (0, 3, 'PRETO BLACK C', '#000000'),
    (1, 3, 'PRETO BLACK C', '#000000'),
    (3, 3, 'PROCESS CYAN C', '#009FDF'),
    (4, 3, '485 C', '#DA291C'),
    (5, 3, 'REFLEX BLUE C', '#001489'),
    (6, 3, 'PRETO BLACK C', '#000000'),
    (7, 3, 'PROCESS CYAN C', '#009FDF'),
    (9, 3, 'PROCESS CYAN C', '#009FDF'),
    (0, 4, '187 C', '#A6192E'),
    (1, 4, '187 C', '#A6192E'),
    (3, 4, 'REFLEX BLUE C', '#001489'),
    (5, 4, 'PRETO BLACK C', '#000000'),
    (7, 4, 'PRETO BLACK C', '#000000'),
    (9, 4, '7509 C', '#D6A461'),
    (0, 5, '130 C', '#F2A900'),
    (3, 5, 'PRETO BLACK C', '#000000'),
    (9, 5, 'PRETO BLACK C', '#000000')
]

# Run the program to process and arrange the colors
rows = process_colors(colors)

# Output the result
for row in rows:
    print([color[2] for color in row])  # Print only the color names
