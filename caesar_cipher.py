def ccEn(value, rot):
    if rot not in range(1,8):
        raise ValueError
    outV = []
    for i in value:
        if i == " ":
            outV.append(i)
        else:
            if 90 < (ord(i) + rot) < 97:
                asciiCode = (ord(i) + rot) - 26
                outV.append(chr(asciiCode))
            elif (ord(i) + rot) > 122:
                asciiCode = (ord(i) + rot) - 26
                outV.append(chr(asciiCode))
            else:
                outV.append(chr(ord(i) + rot))
    return "".join(outV)

def ccDe(value, rot):
    if rot not in range(1,8):
        raise ValueError
    outV = []
    for i in value:
        if i ==" ":
            outV.append(i)
        else:
            if (ord(i) - rot) < 65:
                asciiCode = (ord(i) - rot) + 26
                outV.append(chr(asciiCode))
            elif 90 < (ord(i) - rot) < 97:
                asciiCode = (ord(i) - rot) + 26
                outV.append(chr(asciiCode))
            else:
                outV.append(chr(ord(i) - rot))
    return "".join(outV)