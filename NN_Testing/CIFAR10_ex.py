import numpy as np
import matplotlib.pyplot as plt

from keras.datasets import cifar10
from keras.models import Sequential
from keras.layers.core import Dense, Dropout, Activation, Flatten
from keras.layers import Conv2D, MaxPooling2D, BatchNormalization
from keras.utils import np_utils

nb_classes = 10
(X_train, y_train), (X_test, y_test) = cifar10.load_data()

X_train = X_train.astype('float32')
X_test = X_test.astype('float32')

# Normalization through feature scaling
X_train /= 255
X_test /= 255

# Convert class vectors to binary class matrices.
Y_train = np_utils.to_categorical(y_train, nb_classes)
Y_test = np_utils.to_categorical(y_test, nb_classes)

# Building CNN Model
model = Sequential()

# Add new layer (Input Layer)
model.add(Conv2D(32, (3, 3), input_shape=X_train.shape[1:]))
model.add(Activation('sigmoid'))
model.add(BatchNormalization())

# Add second layer (Hidden layer)
model.add(Conv2D(32, (3, 3)))
model.add(Activation('sigmoid'))

model.add(MaxPooling2D(pool_size=(2,2)))

model.add(Dropout(0.2))

model.add(Conv2D(64, (3, 3), padding='same'))
model.add(Activation('sigmoid'))

model.add(Conv2D(64, (3, 3)))
model.add(Activation('sigmoid'))

model.add(MaxPooling2D(pool_size=(2,2)))

model.add(Dropout(0.2))

model.add(Flatten())
model.add(Dense(512))
model.add(Activation('sigmoid'))

model.add(Dropout(0.2))

# Add third layer (Visible/Output Layer)
model.add(Dense(nb_classes))
model.add(Activation('softmax'))

# Train Model
model.compile(loss='categorical_crossentropy',
             optimizer='adam',
             metrics=['accuracy'])
model.fit(X_train, Y_train,
          batch_size=128, epochs=6,
          validation_data=(X_test, Y_test))
score = model.evaluate(X_test, Y_test)
print(score)

