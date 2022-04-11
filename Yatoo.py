from tkinter import *
import random
import string
import hashlib

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
    # function frame init
    passwdGen = Frame(rootWindow)
    passwdGen.pack()
    hashGen = Frame(rootWindow)
    hashGen.pack()
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
        inputAndRun.grid(columnspan=4, row=1, sticky="n")
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
        outputEntry = Entry(inputAndRun)
        outputEntry.pack()
        # gen button
        Button(inputAndRun, text="Generate!", command=genHash).pack()
    
    
    
    
    
    
    
    
    
    rootWindow.mainloop()
    