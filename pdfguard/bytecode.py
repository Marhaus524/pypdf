CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

dumplinelength = 16


def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if (
            byte == 0x28
            or byte == 0x29
            or byte == 0x3C
            or byte == 0x3E
            or byte == 0x5B
            or byte == 0x5D
            or byte == 0x7B
            or byte == 0x7D
            or byte == 0x2F
            or byte == 0x25
    ):
        return CHAR_DELIMITER
    return CHAR_REGULAR


def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result
