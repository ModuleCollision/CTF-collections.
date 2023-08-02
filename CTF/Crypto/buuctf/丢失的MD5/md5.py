import hashlib   
for i in range(32,127):
    for j in range(32,127):
        for k in range(32,127):
            m=hashlib.md5()
            m.update('TASC'.encode()+chr(i).encode()+'O3RJMV'.encode()+chr(j).encode()+'WDJKX'.encode()+chr(k).encode()+'ZM'.encode())
            des=m.hexdigest()
            if 'e9032' in des and 'da' in des and '911513' in des:
                print(des)
