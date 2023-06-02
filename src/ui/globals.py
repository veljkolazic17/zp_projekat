def init():
    global currentWindow
    currentWindow = None
    global pgp
    pgp = None
    global pgpOptions
    pgpOptions = None
    global message
    message = ""
    global filePath
    filePath = ""

    global algoAsymEncryption
    algoAsymEncryption = None
    global algoAsymSignature
    algoAsymSignature = None
    global algoSym
    algoSym = None
    
    global publicKeyEntry
    publicKeyEntry = None
    global privateKeyEntry
    privateKeyEntry = None
    global previousRowPublic
    previousRowPublic = None
    global previousRowPrivate
    previousRowPrivate = None
    global email
    email = None
