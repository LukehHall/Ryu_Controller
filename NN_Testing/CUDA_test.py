# Python file to test Neural Network training on CUDA cores
from tensorflow.python.client import device_lib
from keras import backend as K
K.tensorflow_backend._get_available_gpus()
print("--------------------------------")
print(device_lib.list_local_devices())
