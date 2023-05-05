import matplotlib.pyplot as plt
import numpy as np
import base64
import os
from flask import Response
import io

def do_grath(arr1, arr2, xlabel, ylabel, title):
    x = np.array(arr1)
    y = np.array(arr2)

    plt.plot(x, y)
    plt.plot(x, y)
    plt.xlabel(str(xlabel))
    plt.ylabel(str(ylabel))
    plt.title(str(title))

    # get the image as a base64-encoded string
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    # graph.append(image_base64)
    graph = image_base64
    plt.close()
    return graph
# arr1 = [1,2,1,13,2,1]
# arr2 = [2,3,3,1,12,3]
# print(do_grath(arr1,arr2,'x','y','title'))

def histogram(arr):
    plt.hist(arr, bins=10)
    plt.savefig('histogram.png')
    with open('histogram.png', 'rb') as f:
        image = f.read()
    os.remove('histogram.png')
    return Response(image, mimetype='image/png')

def build_circle(labels,sizes):

    # import io
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
    plt.close()
    return graphic