//
// Copyright 2018 Daniel Reiter Horn
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package rsync

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
)

const RS_OP_END = byte(0)

const RS_OP_LITERAL_1 = byte(0x1)
const RS_OP_LITERAL_64 = byte(0x40)
const RS_OP_LITERAL_N1 = byte(0x41)

const RS_OP_LITERAL_N2 = byte(0x42)
const RS_OP_LITERAL_N4 = byte(0x43)

const RS_OP_LITERAL_N8 = byte(0x44)
const RS_OP_COPY_N1_N1 = byte(0x45)

/*
const RS_OP_COPY_N1_N2 = byte(0x46)
const RS_OP_COPY_N1_N4 = byte(0x47)
const RS_OP_COPY_N1_N8 = byte(0x48)
const RS_OP_COPY_N2_N1 = byte(0x49)
const RS_OP_COPY_N2_N2 = byte(0x4a)
const RS_OP_COPY_N2_N4 = byte(0x4b)
const RS_OP_COPY_N2_N8 = byte(0x4c)
const RS_OP_COPY_N4_N1 = byte(0x4d)
const RS_OP_COPY_N4_N2 = byte(0x4e)
const RS_OP_COPY_N4_N4 = byte(0x4f)
const RS_OP_COPY_N4_N8 = byte(0x50)
const RS_OP_COPY_N8_N1 = byte(0x51)
const RS_OP_COPY_N8_N2 = byte(0x52)
const RS_OP_COPY_N8_N4 = byte(0x53)
*/
const RS_OP_COPY_N8_N8 = byte(0x54)

var DeltaMagic = []byte{0x72, 0x73, 0x02, 0x36}

var earlyEOF = errors.New("Early End of File")

func beRead(data []byte) int {
	var retval uint64
	for _, byt := range data {
		retval <<= 8
		retval |= uint64(byt)
	}
	return int(retval)
}

func ApplyPatch(base []byte, patch []byte, output io.Writer) error {
	var index int
	if len(patch) < len(DeltaMagic) {
		return errors.New("Too short 0x" + hex.EncodeToString(patch))
	}
	if !bytes.Equal(patch[:len(DeltaMagic)], DeltaMagic) {
		return errors.New("Bad magic number 0x" +
			hex.EncodeToString(patch[:len(DeltaMagic)]) +
			" != 0x" + hex.EncodeToString(DeltaMagic))
	}
	index += len(DeltaMagic)
	for index < len(patch) {
		cmd := patch[index]
		index += 1
		if cmd == RS_OP_END {
			return nil
		}
		if cmd <= RS_OP_LITERAL_N8 {
			numLiterals := int(cmd)
			if cmd >= RS_OP_LITERAL_N1 {
				beLiteralsToRead := 1 << (cmd - RS_OP_LITERAL_N1)
				if index+beLiteralsToRead > len(patch) {
					return earlyEOF
				}
				numLiterals = beRead(patch[index : index+beLiteralsToRead])
				index += beLiteralsToRead
			}
			if index+numLiterals > len(patch) {
				return earlyEOF
			}
			_, werr := output.Write(patch[index : index+numLiterals])
			index += numLiterals
			if werr != nil {
				return werr
			}
		} else if cmd > RS_OP_COPY_N8_N8 {
			return errors.New("Reserved command: 0x" + hex.EncodeToString([]byte{cmd}))
		} else { // we are in copy territory
			copyLenIndex := cmd - RS_OP_COPY_N1_N1
			lower2bits := copyLenIndex & 0x3
			upper2bits := copyLenIndex >> 2
			whereNumBytes := 1 << upper2bits
			lenNumBytes := 1 << lower2bits
			if index+whereNumBytes+lenNumBytes > len(patch) {
				return earlyEOF
			}
			where := beRead(patch[index : index+whereNumBytes])
			index += whereNumBytes
			numBytes := beRead(patch[index : index+lenNumBytes])
			index += lenNumBytes
			_, werr := output.Write(base[where : where+numBytes])
			if werr != nil {
				return werr
			}
		}
	}
	return earlyEOF
}
