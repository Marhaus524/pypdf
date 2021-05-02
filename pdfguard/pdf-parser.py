import binascii
import configparser
import hashlib
import optparse
import os
import re
import sys
import urllib.request
import zipfile
from io import StringIO

from pdfguard.bytecode import *
from pdfguard.parser.PDFparser import cPDFParser
from pdfguard.token.PDFTokenizer import cPDFTokenizer
from pdfguard.utils import to_bytes, to_string, IFF, IsNumeric, Timestamp, ConditionalCanonicalize, EqualCanonical

try:
    import yara
except:
    pass


class cPDFDocument:
    def __init__(self, file):
        self.file = file
        if type(file) != str:
            self.infile = file
        elif file.lower().startswith("http://") or file.lower().startswith("https://"):
            try:
                if sys.hexversion >= 0x020601F0:
                    self.infile = urllib.request.urlopen(file, timeout=5)
                else:
                    self.infile = urllib.request.urlopen(file)
            except urllib.request.HTTPError:
                print(("Error accessing URL %s" % file))
                print((sys.exc_info()[1]))
                sys.exit()
        elif file.lower().endswith(".zip"):
            try:
                self.zipfile = zipfile.ZipFile(file, "r")
                self.infile = self.zipfile.open(
                    self.zipfile.infolist()[0], "r", to_bytes("infected")
                )
            except:
                print(("Error opening file %s" % file))
                print((sys.exc_info()[1]))
                sys.exit()
        else:
            try:
                self.infile = open(file, "rb")
            except:
                print(("Error opening file %s" % file))
                print((sys.exc_info()[1]))
                sys.exit()
        self.ungetted = []
        self.position = -1

    def byte(self):
        if len(self.ungetted) != 0:
            self.position += 1
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == "":
            self.infile.close()
            return None
        self.position += 1
        return ord(inbyte)

    def unget(self, byte):
        self.position -= 1
        self.ungetted.append(byte)


def TrimLWhiteSpace(data):
    while data != [] and data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data


def TrimRWhiteSpace(data):
    while data != [] and data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data


class cPDFParseDictionary:
    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if dataTrimmed == []:
            self.parsed = None
        elif self.isOpenDictionary(dataTrimmed[0]) and (
                self.isCloseDictionary(dataTrimmed[-1])
                or self.couldBeCloseDictionary(dataTrimmed[-1])
        ):
            self.parsed = self.ParseDictionary(dataTrimmed)[0]
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == "<<"

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == ">>"

    def couldBeCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1].rstrip().endswith(">>")

    def ParseDictionary(self, tokens):
        state = 0  # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None, tokens
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary, tokens
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(
                        tokens[0][1], self.nocanonicalizedoutput
                    )
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    value, tokens = self.ParseDictionary(tokens)
                    dictionary.append((key, value))
                    state = 1
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary, tokens
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value == [] and tokens[0][1] == "[":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "[" and tokens[0][1] != "]":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "[" and tokens[0][1] == "]":
                    value.append(tokens[0][1])
                    dictionary.append((key, value))
                    value = []
                    state = 1
                elif value == [] and tokens[0][1] == "(":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "(" and tokens[0][1] != ")":
                    if tokens[0][1][0] == "%":
                        tokens = (
                                [tokens[0]]
                                + cPDFTokenizer(StringIO(tokens[0][1][1:])).Tokens()
                                + tokens[1:]
                        )
                        value.append("%")
                    else:
                        value.append(tokens[0][1])
                elif value != [] and value[0] == "(" and tokens[0][1] == ")":
                    value.append(tokens[0][1])
                    balanced = 0
                    for item in value:
                        if item == "(":
                            balanced += 1
                        elif item == ")":
                            balanced -= 1
                    if balanced < 0 and self.verbose:
                        print(("todo 11: " + repr(value)))
                    if balanced < 1:
                        dictionary.append((key, value))
                        value = []
                        state = 1
                elif value != [] and tokens[0][1][0] == "/":
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(
                        tokens[0][1], self.nocanonicalizedoutput
                    )
                    value = []
                    state = 2
                else:
                    value.append(
                        ConditionalCanonicalize(
                            tokens[0][1], self.nocanonicalizedoutput
                        )
                    )
            tokens = tokens[1:]

    def Retrieve(self):
        return self.parsed

    def PrettyPrintSubElement(self, prefix, e):
        if e[1] == []:
            print(("%s  %s" % (prefix, e[0])))
        elif type(e[1][0]) == type(""):
            if (
                    len(e[1]) == 3
                    and IsNumeric(e[1][0])
                    and e[1][1] == "0"
                    and e[1][2] == "R"
            ):
                joiner = " "
            else:
                joiner = ""
            value = joiner.join(e[1]).strip()
            reprValue = repr(value)
            if "'" + value + "'" != reprValue:
                value = reprValue
            print(("%s  %s %s" % (prefix, e[0], value)))
        else:
            print(("%s  %s" % (prefix, e[0])))
            self.PrettyPrintSub(prefix + "    ", e[1])

    def PrettyPrintSub(self, prefix, dictionary):
        if dictionary != None:
            print(("%s<<" % prefix))
            for e in dictionary:
                self.PrettyPrintSubElement(prefix, e)
            print(("%s>>" % prefix))

    def PrettyPrint(self, prefix):
        self.PrettyPrintSub(prefix, self.parsed)

    def Get(self, select):
        for key, value in self.parsed:
            if key == select:
                return value
        return None

    def GetNestedSub(self, dictionary, select):
        for key, value in dictionary:
            if key == select:
                return self.PrettyPrintSubElement("", [select, value])
            if (
                    type(value) == type([])
                    and len(value) > 0
                    and type(value[0]) == type((None,))
            ):
                result = self.GetNestedSub(value, select)
                if result != None:
                    return self.PrettyPrintSubElement("", [select, result])
        return None

    def GetNested(self, select):
        return self.GetNestedSub(self.parsed, select)


def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return "".join([x[1] for x in data])
        else:
            return data
    elif sys.version_info[0] > 2:
        return ascii(data)
    else:
        return repr(data)


# Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != "":
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]


def IfWIN32SetBinary(io):
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(io.fileno(), os.O_BINARY)


def PrintOutputObject(object, options):
    if options.dump == "-":
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ""
        IfWIN32SetBinary(sys.stdout)
        StdoutWriteChunked(filtered)
        return

    print(("obj %d %d" % (object.id, object.version)))
    if object.objstm != None:
        print((" Containing /ObjStm: %d %d" % object.objstm))
    print(
        (
                " Type: %s"
                % ConditionalCanonicalize(object.GetType(), options.nocanonicalizedoutput)
        )
    )
    print(
        (
                " Referencing: %s"
                % ", ".join(["%s %s %s" % x for x in object.GetReferences()])
        )
    )
    dataPrecedingStream = object.ContainsStream()
    oPDFParseDictionary = None
    if dataPrecedingStream:
        print(" Contains stream")
        if options.debug:
            print((" %s" % FormatOutput(dataPrecedingStream, options.raw)))
        oPDFParseDictionary = cPDFParseDictionary(
            dataPrecedingStream, options.nocanonicalizedoutput
        )
        if options.hash:
            streamContent = object.Stream(False, options.overridingfilters)
            print("  unfiltered")
            print(
                (
                        "   len: %6d md5: %s"
                        % (len(streamContent), hashlib.md5(streamContent).hexdigest())
                )
            )
            print(("   %s" % HexAsciiDumpLine(streamContent)))
            streamContent = object.Stream(True, options.overridingfilters)
            print("  filtered")
            print(
                (
                        "   len: %6d md5: %s"
                        % (len(streamContent), hashlib.md5(streamContent).hexdigest())
                )
            )
            print(("   %s" % HexAsciiDumpLine(streamContent)))
            streamContent = None
    else:
        if options.debug or options.raw:
            print((" %s" % FormatOutput(object.content, options.raw)))
        oPDFParseDictionary = cPDFParseDictionary(
            object.content, options.nocanonicalizedoutput
        )
    print("")
    oPDFParseDictionary.PrettyPrint("  ")
    print("")
    if options.filter and not options.dump:
        filtered = object.Stream(overridingfilters=options.overridingfilters)
        if filtered == []:
            print((" %s" % FormatOutput(object.content, options.raw)))
        else:
            print((" %s" % FormatOutput(filtered, options.raw)))
    if options.content:
        if object.ContainsStream():
            stream = object.Stream(False, options.overridingfilters)
            if stream != []:
                print((" %s" % FormatOutput(stream, options.raw)))
        else:
            print(("".join([token[1] for token in object.content])))

    if options.dump:
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ""
        try:
            fDump = open(options.dump, "wb")
            try:
                fDump.write(to_bytes(filtered))
            except:
                print(("Error writing file %s" % options.dump))
            fDump.close()
        except:
            print(("Error writing file %s" % options.dump))
    print("")
    return


def PrintGenerateObject(object, options, newId=None):
    if newId == None:
        objectId = object.id
    else:
        objectId = newId
    dataPrecedingStream = object.ContainsStream()
    if dataPrecedingStream:
        if options.filter:
            decompressed = object.Stream(True, options.overridingfilters)
            if decompressed == "No filters" or decompressed.startswith(
                    "Unsupported filter: "
            ):
                print(
                    (
                            "    oPDF.stream(%d, %d, %s, %s)"
                            % (
                                objectId,
                                object.version,
                                repr(
                                    object.Stream(False, options.overridingfilters).rstrip()
                                ),
                                repr(
                                    re.sub(
                                        "/Length\s+\d+",
                                        "/Length %d",
                                        FormatOutput(dataPrecedingStream, True),
                                    ).strip()
                                ),
                            )
                    )
                )
            else:
                dictionary = FormatOutput(dataPrecedingStream, True)
                dictionary = re.sub(r"/Length\s+\d+", "", dictionary)
                dictionary = re.sub(r"/Filter\s*/[a-zA-Z0-9]+", "", dictionary)
                dictionary = re.sub(r"/Filter\s*\[.+\]", "", dictionary)
                dictionary = re.sub(r"^\s*<<", "", dictionary)
                dictionary = re.sub(r">>\s*$", "", dictionary)
                dictionary = dictionary.strip()
                print(
                    (
                            "    oPDF.stream2(%d, %d, %s, %s, 'f')"
                            % (
                                objectId,
                                object.version,
                                repr(decompressed.rstrip()),
                                repr(dictionary),
                            )
                    )
                )
        else:
            print(
                (
                        "    oPDF.stream(%d, %d, %s, %s)"
                        % (
                            objectId,
                            object.version,
                            repr(object.Stream(False, options.overridingfilters).rstrip()),
                            repr(
                                re.sub(
                                    "/Length\s+\d+",
                                    "/Length %d",
                                    FormatOutput(dataPrecedingStream, True),
                                ).strip()
                            ),
                        )
                )
            )
    else:
        print(
            (
                    "    oPDF.indirectobject(%d, %d, %s)"
                    % (
                        objectId,
                        object.version,
                        repr(FormatOutput(object.content, True).strip()),
                    )
            )
        )


def PrintObject(object, options):
    if options.generate:
        PrintGenerateObject(object, options)
    else:
        PrintOutputObject(object, options)


def File2Strings(filename):
    try:
        f = open(filename, "r")
    except:
        return None
    try:
        return [line.rstrip("\n") for line in f.readlines()]
    except:
        return None
    finally:
        f.close()


def ProcessAt(argument):
    if argument.startswith("@"):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception("Error reading %s" % argument)
        else:
            return strings
    else:
        return [argument]


def YARACompile(ruledata):
    if ruledata.startswith("#"):
        if ruledata.startswith("#h#"):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith("#b#"):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith("#s#"):
            rule = (
                    'rule string {strings: $a = "%s" ascii wide nocase condition: $a}'
                    % ruledata[3:]
            )
        elif ruledata.startswith("#q#"):
            rule = ruledata[3:].replace("'", '"')
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule)
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths)


def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)


def GetScriptPath():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])


def LoadDecoders(decoders, verbose):
    if decoders == "":
        return
    scriptPath = GetScriptPath()
    for decoder in sum(list(map(ProcessAt, decoders.split(","))), []):
        try:
            if not decoder.lower().endswith(".py"):
                decoder += ".py"
            if os.path.dirname(decoder) == "":
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, "r").read(), globals(), globals())
        except Exception as e:
            print(("Error loading decoder: %s" % decoder))
            if verbose:
                raise e


def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()


class cDumpStream:
    def __init__(self):
        self.text = ""

    def Addline(self, line):
        if line != "":
            self.text += line + "\n"

    def Content(self):
        return self.text


def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ""
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != "":
            oDumpStream.Addline(hexDump)
            hexDump = ""
        hexDump += IFF(hexDump == "", "", " ") + "%02X" % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()


def CombineHexAscii(hexDump, asciiDump):
    if hexDump == "":
        return ""
    return hexDump + "  " + (" " * (3 * (dumplinelength - len(asciiDump)))) + asciiDump


def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ""
    asciiDump = ""
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != "":
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = "%08X:" % i
            asciiDump = ""
        hexDump += " %02X" % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, ".")
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()


def HexAsciiDumpLine(data):
    return HexAsciiDump(data[0:16])[10:-1]


def ParseINIFile():
    oConfigParser = configparser.ConfigParser(allow_no_value=True)
    oConfigParser.optionxform = str
    oConfigParser.read(os.path.join(GetScriptPath(), "pdfid.ini"))
    keywords = []
    if oConfigParser.has_section("keywords"):
        for key, value in oConfigParser.items("keywords"):
            if not key in keywords:
                keywords.append(key)
    return keywords


def MatchObjectID(id, selection):
    return str(id) in selection.split(",")


def GetArguments():
    arguments = sys.argv[1:]
    envvar = os.getenv("PDFPARSER_OPTIONS")
    if envvar == None:
        return arguments
    return envvar.split(" ") + arguments


def main():
    """pdf-parser, use it to parse a PDF document"""

    global decoders

    oParser = optparse.OptionParser(
        usage="usage: %prog [options] pdf-file|zip-file|url\n"
    )
    oParser.add_option(
        "-m", "--man", action="store_true", default=False, help="Print manual"
    )
    oParser.add_option(
        "-s", "--search", help="string to search in indirect objects (except streams)"
    )
    oParser.add_option(
        "-f",
        "--filter",
        action="store_true",
        default=False,
        help="pass stream object through filters (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode and RunLengthDecode only)",
    )
    oParser.add_option(
        "-o",
        "--object",
        help="id(s) of indirect object(s) to select, use comma (,) to separate ids (version independent)",
    )
    oParser.add_option(
        "-r",
        "--reference",
        help="id of indirect object being referenced (version independent)",
    )
    oParser.add_option("-e", "--elements", help="type of elements to select (cxtsi)")
    oParser.add_option(
        "-w",
        "--raw",
        action="store_true",
        default=False,
        help="raw output for data and filters",
    )
    oParser.add_option(
        "-a",
        "--stats",
        action="store_true",
        default=False,
        help="display stats for pdf document",
    )
    oParser.add_option("-t", "--type", help="type of indirect object to select")
    oParser.add_option(
        "-O",
        "--objstm",
        action="store_true",
        default=False,
        help="parse stream of /ObjStm objects",
    )
    oParser.add_option(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="display malformed PDF elements",
    )
    oParser.add_option(
        "-x", "--extract", help="filename to extract malformed content to"
    )
    oParser.add_option(
        "-H",
        "--hash",
        action="store_true",
        default=False,
        help="display hash of objects",
    )
    oParser.add_option(
        "-n",
        "--nocanonicalizedoutput",
        action="store_true",
        default=False,
        help="do not canonicalize the output",
    )
    oParser.add_option("-d", "--dump", help="filename to dump stream content to")
    oParser.add_option(
        "-D", "--debug", action="store_true", default=False, help="display debug info"
    )
    oParser.add_option(
        "-c",
        "--content",
        action="store_true",
        default=False,
        help="display the content for objects without streams or with streams without filters",
    )
    oParser.add_option("--searchstream", help="string to search in streams")
    oParser.add_option(
        "--unfiltered",
        action="store_true",
        default=False,
        help="search in unfiltered streams",
    )
    oParser.add_option(
        "--casesensitive",
        action="store_true",
        default=False,
        help="case sensitive search in streams",
    )
    oParser.add_option(
        "--regex",
        action="store_true",
        default=False,
        help="use regex to search in streams",
    )
    oParser.add_option(
        "--overridingfilters",
        type=str,
        default="",
        help="override filters with given filters (use raw for the raw stream content)",
    )
    oParser.add_option(
        "-g",
        "--generate",
        action="store_true",
        default=False,
        help="generate a Python program that creates the parsed PDF file",
    )
    oParser.add_option(
        "--generateembedded",
        type=int,
        default=0,
        help="generate a Python program that embeds the selected indirect object as a file",
    )
    oParser.add_option(
        "-y",
        "--yara",
        help="YARA rule (or directory or @file) to check streams (can be used with option --unfiltered)",
    )
    oParser.add_option(
        "--yarastrings", action="store_true", default=False, help="Print YARA strings"
    )
    oParser.add_option(
        "--decoders",
        type=str,
        default="",
        help="decoders to load (separate decoders with a comma , ; @file supported)",
    )
    oParser.add_option(
        "--decoderoptions", type=str, default="", help="options for the decoder"
    )
    oParser.add_option("-k", "--key", help="key to search in dictionaries")
    (options, args) = oParser.parse_args(GetArguments())

    if options.man:
        oParser.print_help()

        return 0

    if len(args) != 1:
        oParser.print_help()
        print("")
        print("  Source code put in the public domain by Didier Stevens, no Copyright")
        print("  Use at your own risk")
        print("  https://DidierStevens.com")

    else:
        decoders = []
        LoadDecoders(options.decoders, True)

        oPDFParser = cPDFParser(args[0], options.verbose, options.extract)
        cntComment = 0
        cntXref = 0
        cntTrailer = 0
        cntStartXref = 0
        cntIndirectObject = 0
        dicObjectTypes = {}
        keywords = [
            "/JS",
            "/JavaScript",
            "/AA",
            "/OpenAction",
            "/AcroForm",
            "/RichMedia",
            "/Launch",
            "/EmbeddedFile",
            "/XFA",
            "/URI",
        ]
        for extrakeyword in ParseINIFile():
            if not extrakeyword in keywords:
                keywords.append(extrakeyword)

        #        dKeywords = {keyword: [] for keyword in keywords}
        # Done for compatibility with 2.6.6
        dKeywords = {}
        for keyword in keywords:
            dKeywords[keyword] = []

        selectComment = False
        selectXref = False
        selectTrailer = False
        selectStartXref = False
        selectIndirectObject = False
        if options.elements:
            for c in options.elements:
                if c == "c":
                    selectComment = True
                elif c == "x":
                    selectXref = True
                elif c == "t":
                    selectTrailer = True
                elif c == "s":
                    selectStartXref = True
                elif c == "i":
                    selectIndirectObject = True
                else:
                    print(("Error: unknown --elements value %s" % c))
                    return
        else:
            selectIndirectObject = True
            if (
                    not options.search
                    and not options.object
                    and not options.reference
                    and not options.type
                    and not options.searchstream
                    and not options.key
            ):
                selectComment = True
                selectXref = True
                selectTrailer = True
                selectStartXref = True
            if options.search or options.key or options.reference:
                selectTrailer = True

        if options.type == "-":
            optionsType = ""
        else:
            optionsType = options.type

        if options.generate or options.generateembedded != 0:
            savedRoot = ["1", "0", "R"]
            print("#!/usr/bin/python")
            print("")
            print('"""')
            print("")
            print("Program generated by pdf-parser.py by Didier Stevens")
            print("https://DidierStevens.com")
            print("Use at your own risk")
            print("")
            print(("Input PDF file: %s" % args[0]))
            print(("This Python program was created on: %s" % Timestamp()))
            print("")
            print('"""')
            print("")
            print("import mPDF")
            print("import sys")
            print("")
            print("def Main():")
            print("    if len(sys.argv) != 2:")
            print("        print('Usage: %s pdf-file' % sys.argv[0])")
            print("        return")
            print("    oPDF = mPDF.cPDF(sys.argv[1])")

        if options.generateembedded != 0:
            print("    oPDF.header('1.1')")
            print(r"    oPDF.comment('\xd0\xd0\xd0\xd0')")
            print(
                r"    oPDF.indirectobject(1, 0, '<<\r\n /Type /Catalog\r\n /Outlines 2 0 R\r\n /Pages 3 0 R\r\n /Names << /EmbeddedFiles << /Names [(test.bin) 7 0 R] >> >>\r\n>>')"
            )
            print(
                r"    oPDF.indirectobject(2, 0, '<<\r\n /Type /Outlines\r\n /Count 0\r\n>>')"
            )
            print(
                r"    oPDF.indirectobject(3, 0, '<<\r\n /Type /Pages\r\n /Kids [4 0 R]\r\n /Count 1\r\n>>')"
            )
            print(
                r"    oPDF.indirectobject(4, 0, '<<\r\n /Type /Page\r\n /Parent 3 0 R\r\n /MediaBox [0 0 612 792]\r\n /Contents 5 0 R\r\n /Resources <<\r\n             /ProcSet [/PDF /Text]\r\n             /Font << /F1 6 0 R >>\r\n            >>\r\n>>')"
            )
            print(
                r"    oPDF.stream(5, 0, 'BT /F1 12 Tf 70 700 Td 15 TL (This PDF document embeds file test.bin) Tj ET', '<< /Length %d >>')"
            )
            print(
                r"    oPDF.indirectobject(6, 0, '<<\r\n /Type /Font\r\n /Subtype /Type1\r\n /Name /F1\r\n /BaseFont /Helvetica\r\n /Encoding /MacRomanEncoding\r\n>>')"
            )
            print(
                r"    oPDF.indirectobject(7, 0, '<<\r\n /Type /Filespec\r\n /F (test.bin)\r\n /EF << /F 8 0 R >>\r\n>>')"
            )

        if options.yara != None:
            if not "yara" in sys.modules:
                print("Error: option yara requires the YARA Python module.")
                return
            rules = YARACompile(options.yara)

        oPDFParserOBJSTM = None
        while True:
            if oPDFParserOBJSTM == None:
                object = oPDFParser.GetObject()
            else:
                object = oPDFParserOBJSTM.GetObject()
                if object == None:
                    oPDFParserOBJSTM = None
                    object = oPDFParser.GetObject()
            if (
                    options.objstm
                    and hasattr(object, "GetType")
                    and EqualCanonical(object.GetType(), "/ObjStm")
                    and object.ContainsStream()
            ):
                # parsing objects inside an /ObjStm object by extracting & parsing the stream content to create a synthesized PDF document, that is then parsed by cPDFParser
                oPDFParseDictionary = cPDFParseDictionary(
                    object.ContainsStream(), options.nocanonicalizedoutput
                )
                numberOfObjects = int(oPDFParseDictionary.Get("/N")[0])
                offsetFirstObject = int(oPDFParseDictionary.Get("/First")[0])
                indexes = list(
                    map(
                        int,
                        to_string(object.Stream())[:offsetFirstObject].strip().split(" "),
                    )
                )
                if len(indexes) % 2 != 0 or len(indexes) / 2 != numberOfObjects:
                    raise Exception("Error in index of /ObjStm stream")
                streamObject = to_string(object.Stream()[offsetFirstObject:])
                synthesizedPDF = ""
                while len(indexes) > 0:
                    objectNumber = indexes[0]
                    offset = indexes[1]
                    indexes = indexes[2:]
                    if len(indexes) >= 2:
                        offsetNextObject = indexes[1]
                    else:
                        offsetNextObject = len(streamObject)
                    synthesizedPDF += "%d 0 obj\n%s\nendobj\n" % (
                        objectNumber,
                        streamObject[offset:offsetNextObject],
                    )
                oPDFParserOBJSTM = cPDFParser(
                    StringIO(synthesizedPDF),
                    options.verbose,
                    options.extract,
                    (object.id, object.version),
                )
            if object != None:
                if options.stats:
                    if object.type == PDF_ELEMENT_COMMENT:
                        cntComment += 1
                    elif object.type == PDF_ELEMENT_XREF:
                        cntXref += 1
                    elif object.type == PDF_ELEMENT_TRAILER:
                        cntTrailer += 1
                    elif object.type == PDF_ELEMENT_STARTXREF:
                        cntStartXref += 1
                    elif object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                        cntIndirectObject += 1
                        type1 = object.GetType()
                        if not type1 in dicObjectTypes:
                            dicObjectTypes[type1] = [object.id]
                        else:
                            dicObjectTypes[type1].append(object.id)
                        for keyword in list(dKeywords.keys()):
                            if object.ContainsName(keyword):
                                dKeywords[keyword].append(object.id)
                else:
                    if object.type == PDF_ELEMENT_COMMENT and selectComment:
                        if options.generate:
                            comment = object.comment[1:].rstrip()
                            if re.match("PDF-\d\.\d", comment):
                                print(("    oPDF.header('%s')" % comment[4:]))
                            elif comment != "%EOF":
                                print(("    oPDF.comment(%s)" % repr(comment)))
                        elif options.yara == None and options.generateembedded == 0:
                            print(
                                (
                                        "PDF Comment %s"
                                        % FormatOutput(object.comment, options.raw)
                                )
                            )
                            print("")
                    elif object.type == PDF_ELEMENT_XREF and selectXref:
                        if (
                                not options.generate
                                and options.yara == None
                                and options.generateembedded == 0
                        ):
                            if options.debug:
                                print(
                                    (
                                            "xref %s"
                                            % FormatOutput(object.content, options.raw)
                                    )
                                )
                            else:
                                print("xref")
                            print("")
                    elif object.type == PDF_ELEMENT_TRAILER and selectTrailer:
                        oPDFParseDictionary = cPDFParseDictionary(
                            object.content[1:], options.nocanonicalizedoutput
                        )
                        if options.generate:
                            result = oPDFParseDictionary.Get("/Root")
                            if result != None:
                                savedRoot = result
                        elif options.yara == None and options.generateembedded == 0:
                            if (
                                    not options.search
                                    and not options.key
                                    and not options.reference
                                    or options.search
                                    and object.Contains(options.search)
                            ):
                                if oPDFParseDictionary == None:
                                    print(
                                        (
                                                "trailer %s"
                                                % FormatOutput(object.content, options.raw)
                                        )
                                    )
                                else:
                                    print("trailer")
                                    oPDFParseDictionary.PrettyPrint("  ")
                                print("")
                            elif options.key:
                                if oPDFParseDictionary.parsed != None:
                                    result = oPDFParseDictionary.GetNested(options.key)
                                    if result != None:
                                        print(result)
                            elif options.reference:
                                for key, value in oPDFParseDictionary.Retrieve():
                                    if value == [str(options.reference), "0", "R"]:
                                        print("trailer")
                                        oPDFParseDictionary.PrettyPrint("  ")
                    elif object.type == PDF_ELEMENT_STARTXREF and selectStartXref:
                        if (
                                not options.generate
                                and options.yara == None
                                and options.generateembedded == 0
                        ):
                            print(("startxref %d" % object.index))
                            print("")
                    elif (
                            object.type == PDF_ELEMENT_INDIRECT_OBJECT
                            and selectIndirectObject
                    ):
                        if options.search:
                            if object.Contains(options.search):
                                PrintObject(object, options)
                        elif options.key:
                            contentDictionary = object.ContainsStream()
                            if not contentDictionary:
                                contentDictionary = object.content[1:]
                            oPDFParseDictionary = cPDFParseDictionary(
                                contentDictionary, options.nocanonicalizedoutput
                            )
                            if oPDFParseDictionary.parsed != None:
                                result = oPDFParseDictionary.GetNested(options.key)
                                if result != None:
                                    print(result)
                        elif options.object:
                            if MatchObjectID(object.id, options.object):
                                PrintObject(object, options)
                        elif options.reference:
                            if object.References(options.reference):
                                PrintObject(object, options)
                        elif options.type:
                            if EqualCanonical(object.GetType(), optionsType):
                                PrintObject(object, options)
                        elif options.hash:
                            print(("obj %d %d" % (object.id, object.version)))
                            rawContent = FormatOutput(object.content, True)
                            print(
                                (
                                        " len: %d md5: %s"
                                        % (
                                            len(rawContent),
                                            hashlib.md5(rawContent).hexdigest(),
                                        )
                                )
                            )
                            print("")
                        elif options.searchstream:
                            if object.StreamContains(
                                    options.searchstream,
                                    not options.unfiltered,
                                    options.casesensitive,
                                    options.regex,
                                    options.overridingfilters,
                            ):
                                PrintObject(object, options)
                        elif options.yara != None:
                            results = object.StreamYARAMatch(
                                rules,
                                decoders,
                                options.decoderoptions,
                                not options.unfiltered,
                                options.overridingfilters,
                            )
                            if results != None and results != []:
                                for result in results:
                                    for yaraResult in result[1]:
                                        print(
                                            (
                                                    "YARA rule%s: %s (%s)"
                                                    % (
                                                        IFF(
                                                            result[0] == "",
                                                            "",
                                                            " (stream decoder: %s)"
                                                            % result[0],
                                                        ),
                                                        yaraResult.rule,
                                                        yaraResult.namespace,
                                                    )
                                            )
                                        )
                                        if options.yarastrings:
                                            for stringdata in yaraResult.strings:
                                                print(
                                                    (
                                                            "%06x %s:"
                                                            % (stringdata[0], stringdata[1])
                                                    )
                                                )
                                                print(
                                                    (
                                                            " %s"
                                                            % binascii.hexlify(
                                                        to_bytes(stringdata[2])
                                                    )
                                                    )
                                                )
                                                print((" %s" % repr(stringdata[2])))
                                    PrintObject(object, options)
                        elif options.generateembedded != 0:
                            if object.id == options.generateembedded:
                                PrintGenerateObject(object, options, 8)
                        else:
                            PrintObject(object, options)
                    elif object.type == PDF_ELEMENT_MALFORMED:
                        try:
                            fExtract = open(options.extract, "wb")
                            try:
                                fExtract.write(to_bytes(object.content))
                            except:
                                print(("Error writing file %s" % options.extract))
                            fExtract.close()
                        except:
                            print(("Error writing file %s" % options.extract))
            else:
                break

        if options.stats:
            print(("Comment: %s" % cntComment))
            print(("XREF: %s" % cntXref))
            print(("Trailer: %s" % cntTrailer))
            print(("StartXref: %s" % cntStartXref))
            print(("Indirect object: %s" % cntIndirectObject))
            for key in sorted(dicObjectTypes.keys()):
                print(
                    (
                            " %s %d: %s"
                            % (
                                key,
                                len(dicObjectTypes[key]),
                                ", ".join(["%d" % x for x in dicObjectTypes[key]]),
                            )
                    )
                )
            if sum(map(len, list(dKeywords.values()))) > 0:
                print("Search keywords:")
                for keyword in keywords:
                    if len(dKeywords[keyword]) > 0:
                        print(
                            (
                                    " %s %d: %s"
                                    % (
                                        keyword,
                                        len(dKeywords[keyword]),
                                        ", ".join(["%d" % x for x in dKeywords[keyword]]),
                                    )
                            )
                        )

        if options.generate or options.generateembedded != 0:
            print(("    oPDF.xrefAndTrailer('%s')" % " ".join(savedRoot)))
            print("")
            print("if __name__ == '__main__':")
            print("    Main()")


if __name__ == "__main__":
    main()
