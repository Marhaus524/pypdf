import re
import zlib

from pdfguard.bytecode import *
from pdfguard.decode.Decoder import FlateDecode, ASCII85Decode, ASCIIHexDecode, RunLengthDecode, LZWDecode, cIdentity
from pdfguard.utils import IsNumeric, Canonicalize, EqualCanonical, IIf


class cPDFElementComment:
    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment


class cPDFElementXref:
    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content


class cPDFElementTrailer:
    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

    def Contains(self, keyword):
        data = ""
        for i in range(0, len(self.content)):
            if self.content[i][1] == "stream":
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1


class cPDFElementIndirectObject:
    def __init__(self, id, version, content, objstm=None):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = id
        self.version = version
        self.content = content
        self.objstm = objstm
        # fix stream for Ghostscript bug reported by Kurt
        if self.ContainsStream():
            position = len(self.content) - 1
            if position < 0:
                return
            while self.content[position][0] == CHAR_WHITESPACE and position >= 0:
                position -= 1
            if position < 0:
                return
            if self.content[position][0] != CHAR_REGULAR:
                return
            if self.content[position][1] == "endstream":
                return
            if not self.content[position][1].endswith("endstream"):
                return
            self.content = (
                    self.content[0:position]
                    + [
                        (
                            self.content[position][0],
                            self.content[position][1][: -len("endstream")],
                        )
                    ]
                    + [(self.content[position][0], "endstream")]
                    + self.content[position + 1:]
            )

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == "<<":
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == ">>":
                dictionary -= 1
            if (
                    dictionary == 1
                    and content[i][0] == CHAR_DELIMITER
                    and EqualCanonical(content[i][1], "/Type")
                    and i < len(content) - 1
            ):
                return content[i + 1][1]
        return ""

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if (
                    i > 1
                    and content[i][0] == CHAR_REGULAR
                    and content[i][1] == "R"
                    and content[i - 2][0] == CHAR_REGULAR
                    and IsNumeric(content[i - 2][1])
                    and content[i - 1][0] == CHAR_REGULAR
                    and IsNumeric(content[i - 1][1])
            ):
                references.append((content[i - 2][1], content[i - 1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == "stream":
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ""
        for i in range(0, len(self.content)):
            if self.content[i][1] == "stream":
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def ContainsName(self, keyword):
        for token in self.content:
            if token[1] == "stream":
                return False
            if token[0] == CHAR_DELIMITER and EqualCanonical(token[1], keyword):
                return True
        return False

    def StreamContains(self, keyword, filter, casesensitive, regex, overridingfilters):
        if not self.ContainsStream():
            return False
        streamData = self.Stream(filter, overridingfilters)
        if filter and streamData == "No filters":
            streamData = self.Stream(False, overridingfilters)
        if regex:
            return re.search(keyword, streamData, IIf(casesensitive, 0, re.I))
        elif casesensitive:
            return keyword in streamData
        else:
            return keyword.lower() in streamData.lower()

    def Stream(self, filter=True, overridingfilters=""):
        state = "start"
        countDirectories = 0
        data = ""
        filters = []
        for i in range(0, len(self.content)):
            if state == "start":
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "<<":
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ">>":
                    countDirectories -= 1
                if (
                        countDirectories == 1
                        and self.content[i][0] == CHAR_DELIMITER
                        and EqualCanonical(self.content[i][1], "/Filter")
                ):
                    state = "filter"
                elif (
                        countDirectories == 0
                        and self.content[i][0] == CHAR_REGULAR
                        and self.content[i][1] == "stream"
                ):
                    state = "stream-whitespace"
            elif state == "filter":
                if (
                        self.content[i][0] == CHAR_DELIMITER
                        and self.content[i][1][0] == "/"
                ):
                    filters = [self.content[i][1]]
                    state = "search-stream"
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "[":
                    state = "filter-list"
            elif state == "filter-list":
                if (
                        self.content[i][0] == CHAR_DELIMITER
                        and self.content[i][1][0] == "/"
                ):
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "]":
                    state = "search-stream"
            elif state == "search-stream":
                if (
                        self.content[i][0] == CHAR_REGULAR
                        and self.content[i][1] == "stream"
                ):
                    state = "stream-whitespace"
            elif state == "stream-whitespace":
                if self.content[i][0] == CHAR_WHITESPACE:
                    whitespace = self.content[i][1]
                    if whitespace.startswith("\x0D\x0A") and len(whitespace) > 2:
                        data += whitespace[2:]
                    elif whitespace.startswith("\x0A") and len(whitespace) > 1:
                        data += whitespace[1:]
                else:
                    data += self.content[i][1]
                state = "stream-concat"
            elif state == "stream-concat":
                if (
                        self.content[i][0] == CHAR_REGULAR
                        and self.content[i][1] == "endstream"
                ):
                    if filter:
                        if overridingfilters == "":
                            return self.Decompress(data, filters)
                        elif overridingfilters == "raw":
                            return data
                        else:
                            return self.Decompress(data, overridingfilters.split(" "))
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return "Unexpected filter state"
        return filters

    def Decompress(self, data, filters):
        for filter in filters:
            if EqualCanonical(filter, "/FlateDecode") or EqualCanonical(filter, "/Fl"):
                try:
                    data = FlateDecode(data)
                except zlib.error as e:
                    message = "FlateDecode decompress failed"
                    if len(data) > 0 and ord(data[0]) & 0x0F != 8:
                        message += ", unexpected compression method: %02x" % ord(
                            data[0]
                        )
                    return message + ". zlib.error %s" % e.message
            elif EqualCanonical(filter, "/ASCIIHexDecode") or EqualCanonical(
                    filter, "/AHx"
            ):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return "ASCIIHexDecode decompress failed"
            elif EqualCanonical(filter, "/ASCII85Decode") or EqualCanonical(
                    filter, "/A85"
            ):
                try:
                    data = ASCII85Decode(data.rstrip(">"))
                except:
                    return "ASCII85Decode decompress failed"
            elif EqualCanonical(filter, "/LZWDecode") or EqualCanonical(filter, "/LZW"):
                try:
                    data = LZWDecode(data)
                except:
                    return "LZWDecode decompress failed"
            elif EqualCanonical(filter, "/RunLengthDecode") or EqualCanonical(
                    filter, "/R"
            ):
                try:
                    data = RunLengthDecode(data)
                except:
                    return "RunLengthDecode decompress failed"
            #            elif i.startswith('/CC')                        # CCITTFaxDecode
            #            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return "Unsupported filter: %s" % repr(filters)
        if len(filters) == 0:
            return "No filters"
        else:
            return data

    def StreamYARAMatch(
            self, rules, decoders, decoderoptions, filter, overridingfilters
    ):
        if not self.ContainsStream():
            return None
        streamData = self.Stream(filter, overridingfilters)
        if filter and streamData == "No filters":
            streamData = self.Stream(False, overridingfilters)

        oDecoders = [cIdentity(streamData, None)]
        for cDecoder in decoders:
            try:
                oDecoder = cDecoder(streamData, decoderoptions)
                oDecoders.append(oDecoder)
            except Exception as e:
                print(("Error instantiating decoder: %s" % cDecoder.name))
                raise e
        results = []
        for oDecoder in oDecoders:
            while oDecoder.Available():
                yaraResults = rules.match(data=oDecoder.Decode())
                if yaraResults != []:
                    results.append([oDecoder.Name(), yaraResults])

        return results


class cPDFElementStartxref:
    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index


class cPDFElementMalformed:
    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content
