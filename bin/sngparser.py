"""
Parser/builder for binary Rocksmith 2014 SNG files.

Field signedness follows the on-disk format: array count prefixes and
the id/difficulty fields are signed Int32, the note and chord byte
fields are unsigned (0..255; the 0xFF "none" sentinel is written and
read as 255), and note and chord hashes are unsigned Int32. Requires
the construct library.

Usage:
    >>> from sngparser import SONG
    >>> raw_input = open('myfile.sng','rb').read()
    >>> sng = SONG.parse(raw_input)
    >>> build_output = SONG.build(sng)
    >>> build_output == raw_input
    True
"""

from construct import Struct, If, Array, Padding, PaddedString, \
    PrefixedArray, Default, Int8ul, Int16sl, Int32sl, \
    Float32l, Float64l, Int32ul


def array(struct):
    """Standard prefixed arrays (in-band signed Int32 count)."""
    return PrefixedArray(Int32sl, struct)


# Bpm
BEAT = Struct(
    ('time' / Float32l),
    ('measure' / Int16sl),
    ('beat' / Int16sl),
    ('phraseIteration' / Int32sl),
    ('mask' / Int32sl)
)

# Phrase: solo/disparity/ignore are unsigned bytes; name is raw 32 bytes.
PHRASE = Struct(
    ('solo' / Int8ul),
    ('disparity' / Int8ul),
    ('ignore' / Int8ul),
    Padding(1),
    ('maxDifficulty' / Int32sl),
    ('phraseIterationLinks' / Int32sl),
    ('name' / PaddedString(32, 'utf8'))
)

# Chord: mask is unsigned; frets and fingers are raw byte[6].
CHORD_TEMPLATE = Struct(
    ('mask' / Int32ul),
    ('fret0' / Int8ul),
    ('fret1' / Int8ul),
    ('fret2' / Int8ul),
    ('fret3' / Int8ul),
    ('fret4' / Int8ul),
    ('fret5' / Int8ul),
    ('finger0' / Int8ul),
    ('finger1' / Int8ul),
    ('finger2' / Int8ul),
    ('finger3' / Int8ul),
    ('finger4' / Int8ul),
    ('finger5' / Int8ul),
    ('notes' / Array(6, Int32sl)),
    ('chordName' / PaddedString(32, 'utf8'))
)

# Bend value: two floats, then a signed Int16 and two unsigned bytes.
BEND_VALUE = Struct(
    ('time' / Float32l),
    ('step' / Float32l),
    ('unk3' / Int16sl),
    ('unk4' / Int8ul),
    # Seens values: 0 1 3 31 32 36..49 51..54 56
    ('unk5' / Int8ul)
)

# BendData: fixed 32 bend values + signed Int32 used count.
BEND_VALUES_32 = Struct(
    ('bendValues' / Array(32, BEND_VALUE)),
    ('usedCount' / Int32sl)
)

# ChordNotes: unsigned Int32[6], BendData[6], byte[6], byte[6], Int16[6].
CHORD_NOTE = Struct(
    ('mask' / Array(6, Int32ul)),
    ('bendValues32' / Array(6, BEND_VALUES_32)),
    ('slideTo' / Array(6, Int8ul)),
    ('slideUnpitchTo' / Array(6, Int8ul)),
    ('vibrato' / Array(6, Int16sl))
)

# Vocal: lyric field is raw 48 bytes.
VOCAL = Struct(
    ('time' / Float32l),
    ('note' / Int32sl),
    ('length' / Float32l),
    ('lyric' / PaddedString(48, 'utf8'))
)

# Texture: font path is raw 128 bytes, then four signed Int32.
TEXTURE = Struct(
    ('fontPath' / PaddedString(128, 'utf8')),
    ('fontPathLength' / Int32sl),
    ('unk1' / Int32sl),
    ('width' / Int32sl),
    ('height' / Int32sl)
)

# Rect: read order is yMin, xMin, yMax, xMax.
RECT = Struct(
    ('yMin' / Float32l),
    ('xMin' / Float32l),
    ('yMax' / Float32l),
    ('xMax' / Float32l)
)

# Symbol definition: raw 12-byte text + two inline rects.
DEFINITION = Struct(
    ('utf8' / PaddedString(12, 'utf8')),
    ('rectOuter' / RECT),
    ('rectInner' / RECT)
)

# Symbols header is eight Int32 values; modeled as an array.
SYMBOLS = Struct(
    ('header' / array(Array(8, Int32sl))),
    ('textures' / array(TEXTURE)),
    ('definitions' / array(DEFINITION))
)

# PhraseIteration: signed Int32 phrase id, times, signed Int32[3] difficulty.
PHRASE_ITERATION = Struct(
    ('phraseId' / Int32sl),
    ('time' / Float32l),
    ('endTime' / Float32l),
    ('difficulty' / Array(3, Int32sl))
)

# PhraseExtraInfoByLevel: levelJump is an unsigned byte; padding byte.
PHRASE_EXTRA_INFO_BY_LEVEL = Struct(
    ('phraseId' / Int32sl),
    ('difficulty' / Int32sl),
    ('empty' / Int32sl),
    ('levelJump' / Int8ul),
    ('redundant' / Int16sl),
    Padding(1)
)

NEW_LINKED_DIFF = Struct(
    ('levelBreak' / Int32sl),
    ('nld_phrase' / array(Int32sl))
)

ACTION = Struct(
    ('time' / Float32l),
    ('name' / PaddedString(256, 'utf8'))
)

EVENT = Struct(
    ('time' / Float32l),
    ('code' / PaddedString(256, 'utf8'))
)

TONE = Struct(
    ('time' / Float32l),
    ('id' / Int32sl)
)

DNA = Struct(
    ('time' / Float32l),
    ('id' / Int32sl)
)

# Section: stringMask is raw byte[36] (string letters).
SECTION = Struct(
    ('name' / PaddedString(32, 'utf8')),
    ('number' / Int32sl),
    ('startTime' / Float32l),
    ('endTime' / Float32l),
    ('startPhraseIterationId' / Int32sl),
    ('endPhraseIterationId' / Int32sl),
    ('stringMask' / Array(36, Int8ul))
)

# Anchor: unsigned-byte fret + explicit 3-byte padding + signed Int32 width.
ANCHOR = Struct(
    ('time' / Float32l),
    ('endTime' / Float32l),
    ('UNK_time' / Float32l),
    ('UNK_time2' / Float32l),
    ('fret' / Int8ul),
    Padding(3),
    ('width' / Int32sl),
    ('phraseIterationId' / Int32sl)
)

# AnchorExtension: unsigned-byte fret, then Int32 + Int16 + unsigned byte.
ANCHOR_EXTENSION = Struct(
    ('time' / Float32l),
    ('fret' / Int8ul),
    ('unk1' / Int32sl),
    ('unk2' / Int16sl),
    ('unk3' / Int8ul)
)

FINGERPRINT = Struct(
    ('chordId' / Int32sl),
    ('startTime' / Float32l),
    ('endTime' / Float32l),
    ('UNK_startTime' / Float32l),
    ('UNK_endTime' / Float32l)
)

# Notes: mask/flags/hash are unsigned Int32; the seven technique bytes
# and string/fret/anchorFret/anchorWidth are unsigned bytes.
NOTE = Struct(
    ('mask' / Int32ul),
    ('flags' / Int32ul),
    ('hash' / Int32ul),
    ('time' / Float32l),
    ('string' / Int8ul),
    ('fret' / Int8ul),
    ('anchorFret' / Int8ul),
    ('anchorWidth' / Int8ul),
    ('chordId' / Int32sl),
    ('chordNoteId' / Int32sl),
    ('phraseId' / Int32sl),
    ('phraseIterationId' / Int32sl),
    ('fingerPrintId' / Array(2, Int16sl)),
    ('nextIterNote' / Int16sl),
    ('prevIterNote' / Int16sl),
    ('parentPrevNote' / Int16sl),
    ('slideTo' / Int8ul),
    ('slideUnpitchTo' / Int8ul),
    ('leftHand' / Int8ul),
    ('tap' / Int8ul),
    ('pickDirection' / Int8ul),
    ('slap' / Int8ul),
    ('pluck' / Int8ul),
    ('vibrato' / Int16sl),
    ('sustain' / Float32l),
    ('bend' / Float32l),
    ('bendValues' / array(BEND_VALUE))
)

LEVEL = Struct(
    ('difficulty' / Int32sl),
    ('anchors' / array(ANCHOR)),
    ('anchorExtensions' / array(ANCHOR_EXTENSION)),
    ('fingerPrints' / Array(2, array(FINGERPRINT))),
    ('notes' / array(NOTE)),
    ('averageNotesPerIter' / array(Float32l)),
    ('notesInIterCountNoIgnored' / array(Int32sl)),
    ('notesInIterCount' / array(Int32sl))
)

# Metadata: first four numbers are doubles; capo is an unsigned byte.
METADATA = Struct(
    ('maxScore' / Float64l),
    ('maxNotes' / Float64l),
    ('maxNotesNoIgnored' / Float64l),
    ('pointsPerNote' / Float64l),
    ('firstBeatLength' / Float32l),
    ('startTime' / Float32l),
    ('capo' / Int8ul),
    ('lastConversionDateTime' / PaddedString(32, 'utf8')),
    ('part' / Int16sl),
    ('songLength' / Float32l),
    ('tuning' / array(Int16sl)),
    ('firstNoteTime' / Float32l),
    ('firstNoteTime2' / Float32l),
    ('maxDifficulty' / Int32sl)
)

SONG = Struct(
    ('ebeats' / array(BEAT)),
    ('phrases' / array(PHRASE)),
    ('chordTemplates' / array(CHORD_TEMPLATE)),
    ('chordNotes' / array(CHORD_NOTE)),
    ('vocals' / array(VOCAL)),
    ('symbols' / If(lambda ctx: len(ctx['vocals']) > 0,
                    Default(SYMBOLS, None))),
    ('phraseIterations' / array(PHRASE_ITERATION)),
    ('phraseExtraInfoByLevel' / array(PHRASE_EXTRA_INFO_BY_LEVEL)),
    ('newLinkedDiffs' / array(NEW_LINKED_DIFF)),
    ('actions' / array(ACTION)),
    ('events' / array(EVENT)),
    ('tones' / array(TONE)),
    ('dnas' / array(DNA)),
    ('sections' / array(SECTION)),
    ('levels' / array(LEVEL)),
    ('metadata' / METADATA)
)
