from pdfguard.bytecode import *
from pdfguard.element.PDFElement import cPDFElementComment, cPDFElementIndirectObject, cPDFElementMalformed, \
    cPDFElementStartxref, cPDFElementTrailer, cPDFElementXref
from pdfguard.token.PDFTokenizer import cPDFTokenizer
from pdfguard.utils import IsNumeric


class cPDFParser:
    def __init__(self, file, verbose=False, extract=None, objstm=None):
        self.context = CONTEXT_NONE
        self.content = []
        self.oPDFTokenizer = cPDFTokenizer(file)
        self.verbose = verbose
        self.extract = extract
        self.objstm = objstm

    def GetObject(self):
        while True:
            if self.context == CONTEXT_OBJ:
                self.token = self.oPDFTokenizer.Token()
            else:
                self.token = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
            if self.token:
                if self.token[0] == CHAR_DELIMITER:
                    if self.token[1][0] == "%":
                        if self.context == CONTEXT_OBJ:
                            self.content.append(self.token)
                        else:
                            return cPDFElementComment(self.token[1])
                    elif self.token[1] == "/":
                        self.token2 = self.oPDFTokenizer.Token()
                        if self.token2[0] == CHAR_REGULAR:
                            if self.context != CONTEXT_NONE:
                                self.content.append(
                                    (CHAR_DELIMITER, self.token[1] + self.token2[1])
                                )
                            elif self.verbose:
                                print(("todo 1: %s" % (self.token[1] + self.token2[1])))
                        else:
                            self.oPDFTokenizer.unget(self.token2)
                            if self.context != CONTEXT_NONE:
                                self.content.append(self.token)
                            elif self.verbose:
                                print(
                                    (
                                            "todo 2: %d %s"
                                            % (self.token[0], repr(self.token[1]))
                                    )
                                )
                    elif self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print(("todo 3: %d %s" % (self.token[0], repr(self.token[1]))))
                elif self.token[0] == CHAR_WHITESPACE:
                    if self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print(("todo 4: %d %s" % (self.token[0], repr(self.token[1]))))
                else:
                    if self.context == CONTEXT_OBJ:
                        if self.token[1] == "endobj":
                            self.oPDFElementIndirectObject = cPDFElementIndirectObject(
                                self.objectId,
                                self.objectVersion,
                                self.content,
                                self.objstm,
                            )
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementIndirectObject
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_TRAILER:
                        if self.token[1] == "startxref" or self.token[1] == "xref":
                            self.oPDFElementTrailer = cPDFElementTrailer(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementTrailer
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_XREF:
                        if self.token[1] == "trailer" or self.token[1] == "xref":
                            self.oPDFElementXref = cPDFElementXref(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementXref
                        else:
                            self.content.append(self.token)
                    else:
                        if IsNumeric(self.token[1]):
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if IsNumeric(self.token2[1]):
                                self.token3 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                                if self.token3[1] == "obj":
                                    self.objectId = int(self.token[1], 10)
                                    self.objectVersion = int(self.token2[1], 10)
                                    self.context = CONTEXT_OBJ
                                else:
                                    self.oPDFTokenizer.unget(self.token3)
                                    self.oPDFTokenizer.unget(self.token2)
                                    if self.verbose:
                                        print(
                                            (
                                                    "todo 6: %d %s"
                                                    % (self.token[0], repr(self.token[1]))
                                            )
                                        )
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print(
                                        (
                                                "todo 7: %d %s"
                                                % (self.token[0], repr(self.token[1]))
                                        )
                                    )
                        elif self.token[1] == "trailer":
                            self.context = CONTEXT_TRAILER
                            self.content = [self.token]
                        elif self.token[1] == "xref":
                            self.context = CONTEXT_XREF
                            self.content = [self.token]
                        elif self.token[1] == "startxref":
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if self.token2 and IsNumeric(self.token2[1]):
                                return cPDFElementStartxref(int(self.token2[1], 10))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print(
                                        (
                                                "todo 9: %d %s"
                                                % (self.token[0], repr(self.token[1]))
                                        )
                                    )
                        elif self.extract:
                            self.bytes = ""
                            while self.token:
                                self.bytes += self.token[1]
                                self.token = self.oPDFTokenizer.Token()
                            return cPDFElementMalformed(self.bytes)
                        elif self.verbose:
                            print(
                                (
                                        "todo 10: %d %s"
                                        % (self.token[0], repr(self.token[1]))
                                )
                            )
            else:
                break
