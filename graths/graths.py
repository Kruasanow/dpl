import matplotlib.pyplot as plt
import numpy as np
import base64
import os
from flask import Response

def do_grath(arr1,arr2,xlabel,ylabel,title):
    x = np.array(arr1)
    y = np.array(arr2)

    plt.plot(x, y)
    plt.plot(x, y)
    plt.xlabel(str(xlabel))
    plt.ylabel(str(ylabel))
    plt.title(str(title))

    # save grath to buffer
    from io import BytesIO
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)

    # buffer with grath to var
    graph = base64.b64encode(buf.read()).decode('utf-8')
    
    return graph

def histogram(arr):
    plt.hist(arr, bins=10)
    plt.savefig('histogram.png')
    with open('histogram.png', 'rb') as f:
        image = f.read()
    os.remove('histogram.png')
    return Response(image, mimetype='image/png')