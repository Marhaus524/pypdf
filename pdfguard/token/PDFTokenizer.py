from pdfguard.bytecode import *
from io import StringIO
class cPDFTokenizer:
    def __init__(self, file):
        self.oPDF = cPDFDocument(file)
        self.ungetted = []

    def Token(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        if self.oPDF == None:
            return None
        self.byte = self.oPDF.byte()
        if self.byte == None:
            self.oPDF = None
            return None
        elif CharacterClass(self.byte) == CHAR_WHITESPACE:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_WHITESPACE:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_WHITESPACE, self.token)
        elif CharacterClass(self.byte) == CHAR_REGULAR:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_REGULAR:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_REGULAR, self.token)
        else:
            if self.byte == 0x3C:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3C:
                    return (CHAR_DELIMITER, "<<")
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, "<")
            elif self.byte == 0x3E:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3E:
                    return (CHAR_DELIMITER, ">>")
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, ">")
            elif self.byte == 0x25:
                file_str = StringIO()
                while self.byte != None:
                    file_str.write(chr(self.byte))
                    if self.byte == 10 or self.byte == 13:
                        self.byte = self.oPDF.byte()
                        break
                    self.byte = self.oPDF.byte()
                if self.byte != None:
                    if self.byte == 10:
                        file_str.write(chr(self.byte))
                    else:
                        self.oPDF.unget(self.byte)
                else:
                    self.oPDF = None
                self.token = file_str.getvalue()
                return (CHAR_DELIMITER, self.token)
            return (CHAR_DELIMITER, chr(self.byte))

    def TokenIgnoreWhiteSpace(self):
        token = self.Token()
        while token != None and token[0] == CHAR_WHITESPACE:
            token = self.Token()
        return token

    def Tokens(self):
        tokens = []
        token = self.Token()
        while token != None:
            tokens.append(token)
            token = self.Token()
        return tokens

    def unget(self, byte):
        self.ungetted.append(byte)