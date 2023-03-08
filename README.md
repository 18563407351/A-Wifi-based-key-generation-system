# Build a wifi-based key generation system  
The WIFI-based key generation system is designed and built on Raspberry Pis(Alice and Bob), applying the unpredictable features of the wireless channel to realize protection on the
physical layer. 
## Principle Description
The key generation procedure contains four steps:  
* channel probing  
* quantization  
* information reconciliation  
* privacy amplification  
![key generation procedure](https://github.com/18563407351/Liverpool-FYP/blob/main/images/1603971639(1).png)
## Environment dependencis
### 1. Signal processing:  
* numpy 
* scipy
* PyWavelets
* sklearn
### 2. GUI design:  
* pyqtgraph
* PyQT5
* opencv-python(4.2.0.32)
* matplotlib
### 3. Serial read:  
* pyserial
* serial
### 4. Key generation and encryption:  
* bchlib
* hashlib
* Crypto.Cipher
* pybase64
