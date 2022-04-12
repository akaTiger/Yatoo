from tkinter import *
import random
import string
import hashlib
from Crypto.Cipher import ARC4
import base64
from morse_code import *
from caesar_cipher import *
from rail_fence_cipher import *
from oldCode import *

def oldCodeFunc():
    choice = oldCodeChoice.get()
    value = oldCodeEntryBlock.get()
    if choice == "uuDe":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, uuDe(value))
    elif choice == "uuEn":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, uuEn(value))
    elif choice == "hexEn":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, hexEn(value))
    elif choice == "hexDe":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, hexDe(value))
    elif choice == "binEn":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, binEn(value))
    elif choice == "binDe":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, binDe(value))
    elif choice == "s2t":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, s2t(value))
    elif choice == "t2s":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, t2s(value))
    elif choice == "s2twp":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, s2twp(value))
    elif choice == "s2hk":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, s2hk(value))
    elif choice == "m2h":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, int(value)/60)
    elif choice == "h2m":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, int(value)*60)
    elif choice == "s2h":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, int(value)/60/60)
    elif choice == "h2s":
        oldCodeResultBlock.delete(0, "end")
        oldCodeResultBlock.insert(0, int(value)*60*60)

def rfcFunc():
    choice = rfcChoice.get()
    value = rfcEntryBlock.get()
    key = int(choice[4:5])
    way = choice[5:]
    mode = choice[:1]
    if len(value) <= key:
        rfcResultBlock.delete(0, "end")
        rfcResultBlock.insert(0, "not safe")
    else:
        if way == "en":
            if mode == "n":
                rfcResultBlock.delete(0, "end")
                rfcResultBlock.insert(0, Nencipher(plaintext=value, key=key))
            elif mode == "v":
                rfcResultBlock.delete(0, "end")
                rfcResultBlock.insert(0, Vencipher(plaintext=value, key=key))
        elif way == "de":
            if mode == "n":
                rfcResultBlock.delete(0, "end")
                rfcResultBlock.insert(0, Ndecipher(ciphertext=value, key=key))
            elif mode == "v":
                rfcResultBlock.delete(0, "end")
                rfcResultBlock.insert(0, Vdecipher(ciphertext=value, key=key))

def ocdFunc():
    choice = ocdChoice.get()
    value = ocdEntryBlock.get()
    if choice == "MorseDe":
        ocdResultBlock.delete(0, "end")
        ocdResultBlock.insert(0, morseDe(value))
    elif choice == "MorseEn":
        ocdResultBlock.delete(0, "end")
        ocdResultBlock.insert(0, morseEn(value))
    else:
        rot = int(choice[4:5])
        way = choice[5:]
        if way == "en":
            ocdResultBlock.delete(0, "end")
            ocdResultBlock.insert(0, ccEn(value, rot))
        elif way == "de":
            ocdResultBlock.delete(0, "end")
            ocdResultBlock.insert(0, ccDe(value, rot))

def cdFunc():
    mode = cdMode.get()
    value = valueEntry.get()
    key = keyEntry.get()
    if mode == "rc4de":
        resultFunc = str((ARC4.new(bytes(key, encoding='utf-8'))).decrypt(base64.b64decode(value)),'utf8')
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "rc4en":
        resultFunc = str((base64.b64encode((ARC4.new(bytes(key, encoding='utf-8'))).encrypt(value.encode('utf-8')))),'utf8')
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b16en":
        resultFunc = base64.b16encode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b16de":
        resultFunc = base64.b16decode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b32en":
        resultFunc = base64.b32encode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b32de":
        resultFunc = base64.b32decode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b64en":
        resultFunc = base64.b64encode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b64de":
        resultFunc = base64.b64decode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b85en":
        resultFunc = base64.b85encode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "b85de":
        resultFunc = base64.b85decode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "a85en":
        resultFunc = base64.a85encode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)
    elif mode == "a85de":
        resultFunc = base64.a85decode(value.encode("utf-8"))
        cdResultEntry.delete(0, "end")
        cdResultEntry.insert(0, resultFunc)

def genCode():
    lenChoice = digitChoiceVar.get()
    modeChoice = modeChoiceVar.get()
    outLst = []
    
    if modeChoice == "Low":
        for i in range(lenChoice):
            sampleD = random.choice(string.digits)
            outLst.append(sampleD)
    elif modeChoice == "Normal":
        for i in range(lenChoice):
            sampleD = random.choice(string.ascii_lowercase + string.digits)
            outLst.append(sampleD)
    elif modeChoice == "Medium":
        for i in range(lenChoice):
            sampleD = random.choice(string.ascii_letters + string.digits)
            outLst.append(sampleD)
    elif modeChoice == "High":
        sampleD = random.sample(string.ascii_letters + string.digits, lenChoice)
        for i in range(lenChoice // 3):
            popOne = random.randint(0, lenChoice - 1)
            sampleD.pop(popOne)
            sampleD.insert(popOne, random.choice("!@#$%^&*"))
        outLst.append("".join(sampleD))
    elif modeChoice == "Extreme":
        for i in range(lenChoice):
            sampleD = random.choice(chr(random.randint(33, 126)) + chr(random.randint(174, 225)))
            outLst.append(sampleD)
    
    resultEntry.delete(0, "end")
    finalCode = "".join(outLst)
    resultEntry.insert(0, finalCode)
    
def genHash():
    inCode = inputEntry.get()
    hashM = hashModeChoiceVar.get()
    if hashM == "MD4":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.new('md4', inCode.encode('utf-8')).hexdigest())
    elif hashM == "MD5":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.md5(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-1":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha1(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-2/224":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha224(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-2/256":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha256(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-2/384":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha384(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-2/512":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha512(inCode.encode('utf-8')).hexdigest())
    elif hashM == "Blake2B":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.blake2b(inCode.encode('utf-8')).hexdigest())
    elif hashM == "Blake2S":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.blake2s(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-3/224":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha3_224(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-3/256":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha3_256(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-3/384":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha3_384(inCode.encode('utf-8')).hexdigest())
    elif hashM == "SHA-3/512":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.sha3_512(inCode.encode('utf-8')).hexdigest())
    elif hashM == "Shake-128":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.shake_128(inCode.encode('utf-8')).hexdigest(length=256))
    elif hashM == "Shake-256":
        outputEntry.delete(0, "end")
        outputEntry.insert(0, hashlib.shake_256(inCode.encode('utf-8')).hexdigest(length=512))

if __name__ == "__main__":
    # tk init
    rootWindow = Tk()
    rootWindow.title("Yatoo")
    # function frame init
    passwdGen = Frame(rootWindow, padx=20, pady=20)
    passwdGen.grid(column=0, row=0, sticky="n")
    hashGen = Frame(rootWindow, padx=20, pady=20)
    hashGen.grid(column=1, row=0, sticky="n")
    codeDecode = Frame(rootWindow, padx=20, pady=20)
    codeDecode.grid(column=0, row=1, sticky="n")
    otherCodeDecode = Frame(rootWindow, padx=20, pady=20)
    otherCodeDecode.grid(column=1, row=1, sticky="n")
    railFenceC = Frame(rootWindow, padx=20, pady=20)
    railFenceC.grid(column=2, row=0, sticky="n")
    oldCode = Frame(rootWindow, padx=20, pady=20)
    oldCode.grid(column=2, row=1, sticky="n")
    # passwd gen start
    if True:
        # dynamic var init
        digitChoiceVar = IntVar()
        modeChoiceVar = StringVar()
        # Inner Frame
        digitChoiceDisplay = Frame(passwdGen)
        digitChoiceDisplay.grid(column=0, row=0, sticky="n")
        modeChoiceDisplay = Frame(passwdGen)
        modeChoiceDisplay.grid(column=1, row=0, sticky="n")
        resultDisplay = Frame(passwdGen)
        resultDisplay.grid(row=2, sticky="n", columnspan=2)
        # len button
        Radiobutton(digitChoiceDisplay, text="16 Digits", value=16, variable=digitChoiceVar).grid(column=0, row=0, sticky="w")
        Radiobutton(digitChoiceDisplay, text="32 Digits", value=32, variable=digitChoiceVar).grid(column=0, row=1, sticky="w")
        Radiobutton(digitChoiceDisplay, text="64 Digits", value=64, variable=digitChoiceVar).grid(column=0, row=2, sticky="w")
        Radiobutton(digitChoiceDisplay, text="128 Digits", value=128, variable=digitChoiceVar).grid(column=0, row=3, sticky="w")
        Radiobutton(digitChoiceDisplay, text="256 Digits", value=256, variable=digitChoiceVar).grid(column=0, row=4, sticky="w")
        Radiobutton(digitChoiceDisplay, text="512 Digits", value=512, variable=digitChoiceVar).grid(column=0, row=5, sticky="w")
        digitChoiceVar.set(16)
        # mode button
        Radiobutton(modeChoiceDisplay, text="Low", value="Low", variable=modeChoiceVar).grid(column=0, row=0, sticky="w")
        Radiobutton(modeChoiceDisplay, text="Normal", value="Normal", variable=modeChoiceVar).grid(column=0, row=1, sticky="w")
        Radiobutton(modeChoiceDisplay, text="Medium", value="Medium", variable=modeChoiceVar).grid(column=0, row=2, sticky="w")
        Radiobutton(modeChoiceDisplay, text="High", value="High", variable=modeChoiceVar).grid(column=0, row=3, sticky="w")
        Radiobutton(modeChoiceDisplay, text="Extreme", value="Extreme", variable=modeChoiceVar).grid(column=0, row=4, sticky="w")
        modeChoiceVar.set("Low")
        # output
        resultEntry = Entry(resultDisplay)
        resultEntry.pack()
        resultEntry.insert(0, "<Value>")
        # gen button
        Button(resultDisplay, text="Generate!", command=genCode).pack()
    # hash gen start
    if True:
        # hash choice var init
        hashModeChoiceVar = StringVar()
        hashModeChoiceVar.set("MD4")
        # inner frame
        hashMode1 = Frame(hashGen)
        hashMode1.grid(column=0, row=0, sticky="n")
        hashMode2 = Frame(hashGen)
        hashMode2.grid(column=1,row=0, sticky="n")
        inputAndRun = Frame(hashGen)
        inputAndRun.grid(columnspan=2, row=1, sticky="n")
        # mode lst 1
        Radiobutton(hashMode1, text="MD4", value="MD4", variable=hashModeChoiceVar).grid(column=0, row=0, sticky="w")
        Radiobutton(hashMode1, text="MD5", value="MD5", variable=hashModeChoiceVar).grid(column=0, row=1, sticky="w")
        Radiobutton(hashMode1, text="SHA-1", value="SHA-1", variable=hashModeChoiceVar).grid(column=0, row=2, sticky="w")
        Radiobutton(hashMode1, text="SHA-2/224", value="SHA-2/224", variable=hashModeChoiceVar).grid(column=0, row=3, sticky="w")
        Radiobutton(hashMode1, text="SHA-2/256", value="SHA-2/256", variable=hashModeChoiceVar).grid(column=0, row=4, sticky="w")
        Radiobutton(hashMode1, text="SHA-2/384", value="SHA-2/384", variable=hashModeChoiceVar).grid(column=0, row=5, sticky="w")
        Radiobutton(hashMode1, text="SHA-2/512", value="SHA-2/512", variable=hashModeChoiceVar).grid(column=0, row=6, sticky="w")
        # mode lst 2
        Radiobutton(hashMode2, text="Blake2B", value="Blake2B", variable=hashModeChoiceVar).grid(column=0, row=0, sticky="w")
        Radiobutton(hashMode2, text="Blake2S", value="Blake2S", variable=hashModeChoiceVar).grid(column=0, row=1, sticky="w")
        Radiobutton(hashMode2, text="SHA-3/224", value="SHA-3/224", variable=hashModeChoiceVar).grid(column=0, row=2, sticky="w")
        Radiobutton(hashMode2, text="SHA-3/256", value="SHA-3/256", variable=hashModeChoiceVar).grid(column=0, row=3, sticky="w")
        Radiobutton(hashMode2, text="SHA-3/384", value="SHA-3/384", variable=hashModeChoiceVar).grid(column=0, row=4, sticky="w")
        Radiobutton(hashMode2, text="SHA-3/512", value="SHA-3/512", variable=hashModeChoiceVar).grid(column=0, row=5, sticky="w")
        Radiobutton(hashMode2, text="Shake-128", value="Shake-128", variable=hashModeChoiceVar).grid(column=0, row=6, sticky="w")
        Radiobutton(hashMode2, text="Shake-256", value="Shake-256", variable=hashModeChoiceVar).grid(column=0, row=7, sticky="w")
        # string before gen
        inputEntry = Entry(inputAndRun)
        inputEntry.pack()
        inputEntry.insert(0, "<Value>")
        outputEntry = Entry(inputAndRun)
        outputEntry.pack()
        outputEntry.insert(0, "<Hash>")
        # gen button
        Button(inputAndRun, text="Generate!", command=genHash).pack()
    # hash gen end
    
    # code decode start
    if True:
        # cd var init
        cdMode = StringVar()
        cdMode.set("rc4de")
        # inner frame
        cd1 = Frame(codeDecode)
        cd1.grid(row=0, column=0, sticky="n")
        cd2 = Frame(codeDecode)
        cd2.grid(row=0, column=1, sticky="n")
        usrPrompt = Frame(codeDecode)
        usrPrompt.grid(columnspan=2, row=1, sticky="n")
        # cd lst1
        Radiobutton(cd1, text="RC4 De", value="rc4de", variable=cdMode).grid(column=0, row=0, sticky="w")
        Radiobutton(cd1, text="Base16 De", value="b16de", variable=cdMode).grid(column=0, row=1, sticky="w")
        Radiobutton(cd1, text="Base32 De", value="b32de", variable=cdMode).grid(column=0, row=2, sticky="w")
        Radiobutton(cd1, text="Base64 De", value="b64de", variable=cdMode).grid(column=0, row=3, sticky="w")
        Radiobutton(cd1, text="Base85 De", value="b85de", variable=cdMode).grid(column=0, row=4, sticky="w")
        Radiobutton(cd1, text="Ascii85 De", value="a85de", variable=cdMode).grid(column=0, row=5, sticky="w")
        # cd lst2
        Radiobutton(cd2, text="RC4 En", value="rc4en", variable=cdMode).grid(column=0, row=0, sticky="w")
        Radiobutton(cd2, text="Base16 En", value="b16en", variable=cdMode).grid(column=0, row=1, sticky="w")
        Radiobutton(cd2, text="Base32 En", value="b32en", variable=cdMode).grid(column=0, row=2, sticky="w")
        Radiobutton(cd2, text="Base64 En", value="b64en", variable=cdMode).grid(column=0, row=3, sticky="w")
        Radiobutton(cd2, text="Base85 En", value="b85en", variable=cdMode).grid(column=0, row=4, sticky="w")
        Radiobutton(cd2, text="Ascii85 En", value="a85en", variable=cdMode).grid(column=0, row=5, sticky="w")
        # interface
        valueEntry = Entry(usrPrompt)
        valueEntry.pack()
        valueEntry.insert(0, "<Value>")
        keyEntry = Entry(usrPrompt)
        keyEntry.pack()
        keyEntry.insert(0, "<Key if needed>")
        cdResultEntry = Entry(usrPrompt)
        cdResultEntry.pack()
        cdResultEntry.insert(0, "<Result>")
        # de or en button
        Button(usrPrompt, text="Process!", command=cdFunc).pack()
    
    # other code decode
    if True:
        # choice var init
        ocdChoice = StringVar()
        ocdChoice.set("MorseEn")
        # frame init
        ocd1 = Frame(otherCodeDecode)
        ocd1.grid(row=0, column=0, sticky="n")
        ocd2 = Frame(otherCodeDecode)
        ocd2.grid(row=0, column=1, sticky="n")
        ocdEntry = Frame(otherCodeDecode)
        ocdEntry.grid(columnspan=2, row=1, sticky="n")
        # ocd1 button init
        Radiobutton(ocd1, text="Morse En", value="MorseEn", variable=ocdChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT1", value="cROT1en", variable=ocdChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT2", value="cROT2en", variable=ocdChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT3", value="cROT3en", variable=ocdChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT4", value="cROT4en", variable=ocdChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT5", value="cROT5en", variable=ocdChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT6", value="cROT6en", variable=ocdChoice).grid(column=0, row=6, sticky="w")
        Radiobutton(ocd1, text="Csr EnROT7", value="cROT7en", variable=ocdChoice).grid(column=0, row=7, sticky="w")
        # ocd2 button init
        Radiobutton(ocd2, text="Morse De", value="MorseDe", variable=ocdChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT1", value="cROT1de", variable=ocdChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT2", value="cROT2de", variable=ocdChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT3", value="cROT3de", variable=ocdChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT4", value="cROT4de", variable=ocdChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT5", value="cROT5de", variable=ocdChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT6", value="cROT6de", variable=ocdChoice).grid(column=0, row=6, sticky="w")
        Radiobutton(ocd2, text="Csr DeROT7", value="cROT7de", variable=ocdChoice).grid(column=0, row=7, sticky="w")
        # Entry init
        ocdEntryBlock = Entry(ocdEntry)
        ocdEntryBlock.insert(0, "<Value>")
        ocdEntryBlock.pack()
        ocdResultBlock = Entry(ocdEntry)
        ocdResultBlock.insert(0, "<Result>")
        ocdResultBlock.pack()
        # button
        Button(ocdEntry, text="Process!", command=ocdFunc).pack()
    
    # Railfence
    if True:
        # var init
        rfcChoice = StringVar()
        rfcChoice.set("nRFC2en")
        # frame init
        rfc1 = Frame(railFenceC)
        rfc1.grid(row=0, column=0, sticky="n")
        rfc2 = Frame(railFenceC)
        rfc2.grid(row=0, column=1, sticky="n")
        rfcEntry = Frame(railFenceC)
        rfcEntry.grid(columnspan=2, row=1, sticky="n")
        # rfc1
        Radiobutton(rfc1, text="NFence En2", value="nRFC2en", variable=rfcChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(rfc1, text="NFence En4", value="nRFC4en", variable=rfcChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(rfc1, text="NFence En6", value="nRFC6en", variable=rfcChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(rfc1, text="NFence En8", value="nRFC8en", variable=rfcChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(rfc1, text="VFence En2", value="vRFC2en", variable=rfcChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(rfc1, text="VFence En4", value="vRFC4en", variable=rfcChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(rfc1, text="VFence En6", value="vRFC6en", variable=rfcChoice).grid(column=0, row=6, sticky="w")
        Radiobutton(rfc1, text="VFence En8", value="vRFC8en", variable=rfcChoice).grid(column=0, row=7, sticky="w")
        # rfc2
        Radiobutton(rfc2, text="NFence De2", value="nRFC2de", variable=rfcChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(rfc2, text="NFence De4", value="nRFC4de", variable=rfcChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(rfc2, text="NFence De6", value="nRFC6de", variable=rfcChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(rfc2, text="NFence De8", value="nRFC8de", variable=rfcChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(rfc2, text="VFence De2", value="vRFC2de", variable=rfcChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(rfc2, text="VFence De4", value="vRFC4de", variable=rfcChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(rfc2, text="VFence De6", value="vRFC6de", variable=rfcChoice).grid(column=0, row=6, sticky="w")
        Radiobutton(rfc2, text="VFence De8", value="vRFC8de", variable=rfcChoice).grid(column=0, row=7, sticky="w")
        # Entry init
        rfcEntryBlock = Entry(rfcEntry)
        rfcEntryBlock.insert(0, "<Value>")
        rfcEntryBlock.pack()
        rfcResultBlock = Entry(rfcEntry)
        rfcResultBlock.insert(0, "<Result>")
        rfcResultBlock.pack()
        # button
        Button(rfcEntry, text="Process!", command=rfcFunc).pack()
        
    # oldcode
    if True:
        # var init
        oldCodeChoice = StringVar()
        oldCodeChoice.set("uuEn")
        # frame init
        oldCode1 = Frame(oldCode)
        oldCode1.grid(row=0, column=0, sticky="n")
        oldCode2 = Frame(oldCode)
        oldCode2.grid(row=0, column=1, sticky="n")
        oldCodeEntry = Frame(oldCode)
        oldCodeEntry.grid(columnspan=2, row=1, sticky="n")
        # oldCode1
        Radiobutton(oldCode1, text="Unix-Unix En", value="uuEn", variable=oldCodeChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(oldCode1, text="Hex En", value="hexEn", variable=oldCodeChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(oldCode1, text="Binary En", value="binEn", variable=oldCodeChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(oldCode1, text="Simp/Trad ZH", value="s2t", variable=oldCodeChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(oldCode1, text="Simp/HK ZH", value="s2hk", variable=oldCodeChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(oldCode1, text="Mins/Hours", value="m2h", variable=oldCodeChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(oldCode1, text="Secs/Hours", value="s2h", variable=oldCodeChoice).grid(column=0, row=6, sticky="w")
        # rfc2
        Radiobutton(oldCode2, text="Unix-Unix De", value="uuDe", variable=oldCodeChoice).grid(column=0, row=0, sticky="w")
        Radiobutton(oldCode2, text="Hex De", value="hexDe", variable=oldCodeChoice).grid(column=0, row=1, sticky="w")
        Radiobutton(oldCode2, text="Binary De", value="binDe", variable=oldCodeChoice).grid(column=0, row=2, sticky="w")
        Radiobutton(oldCode2, text="Trad/Simp ZH", value="t2s", variable=oldCodeChoice).grid(column=0, row=3, sticky="w")
        Radiobutton(oldCode2, text="Simp/TW ZH", value="s2twp", variable=oldCodeChoice).grid(column=0, row=4, sticky="w")
        Radiobutton(oldCode2, text="Hours/Mins", value="h2m", variable=oldCodeChoice).grid(column=0, row=5, sticky="w")
        Radiobutton(oldCode2, text="Hours/Secs", value="h2s", variable=oldCodeChoice).grid(column=0, row=6, sticky="w")
        # Entry init
        oldCodeEntryBlock = Entry(oldCodeEntry)
        oldCodeEntryBlock.insert(0, "<Value>")
        oldCodeEntryBlock.pack()
        oldCodeResultBlock = Entry(oldCodeEntry)
        oldCodeResultBlock.insert(0, "<Result>")
        oldCodeResultBlock.pack()
        # button
        Button(oldCodeEntry, text="Process!", command=oldCodeFunc).pack()
    
    # main loop
    rootWindow.mainloop()
    