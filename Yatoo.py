from tkinter import *
import random
import string

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

if __name__ == "__main__":
    rootWindow = Tk()
    
    overAll = Frame(rootWindow)
    overAll.pack()
    
    digitChoiceVar = IntVar()
    modeChoiceVar = StringVar()
    
    digitChoiceDisplay = Frame(overAll)
    digitChoiceDisplay.grid(column=0, row=0, sticky="n")
    modeChoiceDisplay = Frame(overAll)
    modeChoiceDisplay.grid(column=1, row=0, sticky="n")
    
    resultDisplay = Frame(rootWindow)
    resultDisplay.pack()
    
    Radiobutton(digitChoiceDisplay, text="16 Digits", value=16, variable=digitChoiceVar).grid(column=0, row=0, sticky="w")
    Radiobutton(digitChoiceDisplay, text="32 Digits", value=32, variable=digitChoiceVar).grid(column=0, row=1, sticky="w")
    Radiobutton(digitChoiceDisplay, text="64 Digits", value=64, variable=digitChoiceVar).grid(column=0, row=2, sticky="w")
    Radiobutton(digitChoiceDisplay, text="128 Digits", value=128, variable=digitChoiceVar).grid(column=0, row=3, sticky="w")
    Radiobutton(digitChoiceDisplay, text="256 Digits", value=256, variable=digitChoiceVar).grid(column=0, row=4, sticky="w")
    Radiobutton(digitChoiceDisplay, text="512 Digits", value=512, variable=digitChoiceVar).grid(column=0, row=5, sticky="w")
    digitChoiceVar.set(16)
    
    Radiobutton(modeChoiceDisplay, text="Low", value="Low", variable=modeChoiceVar).grid(column=0, row=0, sticky="w")
    Radiobutton(modeChoiceDisplay, text="Normal", value="Normal", variable=modeChoiceVar).grid(column=0, row=1, sticky="w")
    Radiobutton(modeChoiceDisplay, text="Medium", value="Medium", variable=modeChoiceVar).grid(column=0, row=2, sticky="w")
    Radiobutton(modeChoiceDisplay, text="High", value="High", variable=modeChoiceVar).grid(column=0, row=3, sticky="w")
    Radiobutton(modeChoiceDisplay, text="Extreme", value="Extreme", variable=modeChoiceVar).grid(column=0, row=4, sticky="w")
    modeChoiceVar.set("Low")
    
    Button(resultDisplay, text="Generate!", command=genCode).pack()
    
    resultEntry = Entry(resultDisplay)
    resultEntry.pack()
    
    rootWindow.mainloop()
    