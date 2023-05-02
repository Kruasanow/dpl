import matplotlib.pyplot as plt
import numpy as np
import base64
import os
from flask import Response


def do_grath(arr1, arr2, xlabel, ylabel, title):
    x = np.array(arr1)
    y = np.array(arr2)

    plt.plot(x, y)
    plt.plot(x, y)
    plt.xlabel(str(xlabel))
    plt.ylabel(str(ylabel))
    plt.title(str(title))

    # save graph as PNG file
    plt.savefig(f'/home/ubuntu18/Desktop/dpl/static/graph_{title}.png', format='png')
    plt.close()
    # read PNG file and encode as base64 string
    with open(f'/home/ubuntu18/Desktop/dpl/static/graph_{title}.png', 'rb') as f:
        graph = base64.b64encode(f.read()).decode('utf-8')
    
    return graph
# do_grath(arr1,arr2,xlabel,ylabel,title)


def histogram(arr):
    plt.hist(arr, bins=10)
    plt.savefig('histogram.png')
    with open('histogram.png', 'rb') as f:
        image = f.read()
    os.remove('histogram.png')
    return Response(image, mimetype='image/png')

def build_circle(labels,sizes):

    import io
    # Создаем круговую диаграмму
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    ax.axis('equal')
    plt.tight_layout()

    # Сохраняем диаграмму в буфер
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)

    # Кодируем буфер в base64
    image_png = buffer.getvalue()
    graphic = base64.b64encode(image_png).decode('utf-8')
    return graphic