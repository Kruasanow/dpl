import matplotlib.pyplot as plt
import numpy as np
import base64
import os
from flask import Response
import io

def do_grath(arr1, arr2, xlabel, ylabel, title):
    x = np.array(arr1)
    y = np.array(arr2)

    # plot the data
    fig, ax = plt.subplots()
    ax.plot(x, y)

    # set the labels and title
    ax.set_xlabel(str(xlabel), color='#151515')
    ax.set_ylabel(str(ylabel), color='#151515')
    ax.set_title(str(title), color='black')

    # set the color of the spines (i.e. the frame around the plot)
    ax.spines['bottom'].set_color('#151515')
    ax.spines['top'].set_color('#151515')
    ax.spines['left'].set_color('#151515')
    ax.spines['right'].set_color('#151515')

    # set the background color
    ax.set_facecolor('#151515')

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
    # Создаем круговую диаграмму
    colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99']
    fig, ax = plt.subplots()
    fig.set_facecolor('#151515')
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors)
    ax.axis('equal')
    ax.set_facecolor('#151515')  # изменяем цвет заднего фона
    plt.tight_layout()
    for text in ax.texts:
        text.set_color('white')  # изменяем цвет всех текстов на белый

    # Сохраняем диаграмму в буфер
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)

    # Кодируем буфер в base64
    image_png = buffer.getvalue()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

