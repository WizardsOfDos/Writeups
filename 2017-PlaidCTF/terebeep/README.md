### Solution in one Word
SSTV

### Setp 1: Demodulation
After listening to the wav file, the spectrogram was viewed ind Inspectrum.
The image shows the beginning of the .wav File.
![Alternativtext](spectrogram.jpg "Raw Spectrogram")

It seems, that there is a carrier of non constant frequency, that would be an indicator for Frequency modulation
We tried to demodulate the Signal using GNURadio.
First we have to transform the real Signal to a complex one using the hilbert transform.
To achieve better results, we used a large window size of 1024 as smaler windows seems to create additional noise on the signal, that woulkd cause problems later.
The signal is then frequency demodulated using the "Qadrature Demod" block and the result is written to a .wav file.

![Alternativtext](flowgraph.jpg "GNURadio Flowgraph")

The deomdulated signal was then analyzed in Audacity, which shows a somehow structured signal.
Even though this seems to be no digital modulation we know.

![Alternativtext](demod.jpg "Demodulated Signal")

### Setp 2: Convert to in Image
We noticed periodic dips in the signal with a pattern that repeats 3 times between the dips.
At some point we cam up with the idea, that these dips ('clicks' in the original signal) could be a clock signal for the beginning of a row of an image.
The demodulated signal was then split into rows an visualized with matplotlib.

```python
from scipy.io.wavfile import read
import numpy as np
import pylab as plt


plt.ion()
plt.set_cmap("gray")
a = read("fmdemod.wav")
x = map(float, a[1])

while True:
    #Rowlen: 41109
    rowlen = int(raw_input("Rowlen: "))
    i = int(raw_input("Offset: "))
    img = []
    while i+rowlen < len(x):
        img += [x[i:i+rowlen]]
        i += rowlen
    img = np.array(img)

    plt.imshow(img, interpolation='bilinear', aspect='auto')
    plt.draw()
```

By experimenting with the parameters, an image is visible with separated RGB channels.
![Alternativtext](flag1.jpg "Image")

By zooming in we can barely read the Flag: PCTF{Did_You_Know_the_ISS_Sends_Slow_Scan_TV_Images?_506063fd}
![Alternativtext](flag2.jpg "Flag")
