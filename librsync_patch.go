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
	"fmt"
	"os"

	"io"

	"golang.org/x/crypto/md4"
)

type Sig struct {
	crc32       uint32
	crypto_hash []byte
}

type SigFileStat struct {
	file_size  int
	block_size uint32
	blake5     bool
}

type SigFile struct {
	block_size       uint32
	signatures       []Sig
	crypto_hash_size uint32
	blake5           bool
}

func be_to_u32(data []byte) uint32 {
	return uint32(data[3]) + uint32(data[2])*256 + uint32(data[1])*65536 + uint32(data[0])*65536*256
}
func u32_to_le(val uint32) [4]byte {
	var data [4]byte
	data[3] = byte((val >> 24) & 0xff)
	data[2] = byte((val >> 16) & 0xff)
	data[1] = byte((val >> 8) & 0xff)
	data[0] = byte(val & 0xff)
	return data
}
func u32_to_be(val uint32) [4]byte {
	var data [4]byte
	data[0] = byte((val >> 24) & 0xff)
	data[1] = byte((val >> 16) & 0xff)
	data[2] = byte((val >> 8) & 0xff)
	data[3] = byte(val & 0xff)
	return data
}
func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
func NewSigFile(block_size uint32, buf []byte, crypto_sig_size uint32) SigFile {
	num_signatures := (len(buf) + int(block_size) - 1) / int(block_size)
	sig := make([]Sig, num_signatures)
	for index, item := range sig {
		slice := buf[index*int(block_size) : min((index+1)*int(block_size), len(buf))]
		md4_hasher := md4.New()
		_, _ = md4_hasher.Write(slice)
		sig[index] = Sig{
			crypto_hash: md4_hasher.Sum(nil)[:crypto_sig_size],
			crc32:       crcUpdate(item.crc32, slice),
		}
	}
	return SigFile{
		block_size:       block_size,
		signatures:       sig,
		blake5:           false,
		crypto_hash_size: crypto_sig_size,
	}
}

const HEADER_SIZE = 12

var MD4_MAGIC = [4]byte{0x72, 0x73, 0x01, 0x36}
var BLAKE5_MAGIC = [4]byte{0x72, 0x73, 0x01, 0x37}

func DeserializeSigFileView(on_disk_format []byte) (SigFile, error) { // don't reuse this buffer
	if len(on_disk_format) < 12 {
		return SigFile{}, errors.New("File too short " + hex.EncodeToString(on_disk_format))
	}
	//fmt.Fprintf(os.Stderr, "File is ok %d\n", len(on_disk_format))
	var is_md4 = bytes.Equal(MD4_MAGIC[:], on_disk_format[:4])
	var is_blake5 = bytes.Equal(BLAKE5_MAGIC[:], on_disk_format[:4])
	if !(is_md4 || is_blake5) {
		return SigFile{}, errors.New("File sig not recognized " + hex.EncodeToString(on_disk_format[:4]))
	}
	var desired_crypto_hash_size = be_to_u32(on_disk_format[8:HEADER_SIZE])
	var stride = 4 + int(desired_crypto_hash_size)
	if (len(on_disk_format)-HEADER_SIZE)%stride != 0 {
		return SigFile{}, errors.New("File not a multiple of stride bytes")
	}
	numRecords := (len(on_disk_format) - HEADER_SIZE) / stride
	//fmt.Fprintf(os.Stderr, "File has %d records (stride %d)\n", numRecords, stride)
	var sigs = make([]Sig, numRecords)
	for index, _ := range sigs {
		var record_start = on_disk_format[index*stride+HEADER_SIZE:]
		sigs[index] = Sig{
			crypto_hash: record_start[4 : 4+int(desired_crypto_hash_size)],
			crc32:       be_to_u32(record_start),
		}
	}
	return SigFile{
		block_size:       be_to_u32(on_disk_format[4:8]),
		signatures:       sigs,
		crypto_hash_size: desired_crypto_hash_size,
		blake5:           is_blake5,
	}, nil

}

type SigHint struct {
	crc32_to_sig_index map[uint32][]int
}

func (self *SigFile) Serialize(output io.Writer) error {
	var headerBuffer [12]byte
	if self.blake5 {
		copy(headerBuffer[:4], BLAKE5_MAGIC[:])
	} else {
		copy(headerBuffer[:4], MD4_MAGIC[:])
	}
	var le_buffer [4]byte
	le_buffer = u32_to_be(self.block_size)
	copy(headerBuffer[4:8], le_buffer[:])
	le_buffer = u32_to_be(self.crypto_hash_size)
	copy(headerBuffer[8:12], le_buffer[:])
	_, err := output.Write(headerBuffer[:])
	if err != nil {
		return err
	}
	sigBuffer := make([]byte, 4+self.crypto_hash_size)
	for _, sig := range self.signatures {
		le_buffer = u32_to_be(sig.crc32)
		copy(sigBuffer[:4], le_buffer[:])
		copy(sigBuffer[4:], sig.crypto_hash)
		_, err = output.Write(sigBuffer)
		if err != nil {
			return err
		}
	}
	if closer, ok := output.(io.WriteCloser); ok {
		return closer.Close()
	}
	return nil
}

func (self *SigFile) create_sig_hint() SigHint {
	var hint = SigHint{
		crc32_to_sig_index: make(map[uint32][]int, len(self.signatures)),
	}
	for index, item := range self.signatures {
		hint.crc32_to_sig_index[item.crc32] = append(hint.crc32_to_sig_index[item.crc32], index)
	}
	return hint
}

type RsyncPatchWriter struct {
	sig              SigFile
	hint             SigHint
	buffer           []byte
	ring_buffer_ptr  int
	buffer_fill      int
	output           io.Writer
	crc32            uint32
	pending_literals []byte
}

func NewRsyncPatchWriter(sig []byte, output io.Writer) (*RsyncPatchWriter, error) {
	var ret RsyncPatchWriter
	var err error
	ret.sig, err = DeserializeSigFileView(sig)
	if err != nil {
		return nil, err
	}
	ret.hint = ret.sig.create_sig_hint()
	ret.buffer = make([]byte, ret.sig.block_size)
	ret.output = output
	//fmt.Fprintf(os.Stderr, "Ret buffer is %d\n", ret.sig.block_size)
	_, err = output.Write(DeltaMagic[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "fail at a a %v\n", err)
		return nil, err
	}
	return &ret, nil
}

func writeVarInt(val int, output []byte) uint {
	if val < 256 {
		output[0] = byte(val)
		return 0
	}
	if val < 65536 {
		output[0] = byte(val / 256)
		output[1] = byte(val & 255)
		return 1
	}
	if val <= 4294967295 {
		output[0] = byte(val / 256 / 65536)
		output[1] = byte((val / 65536) & 255)
		output[2] = byte((val / 256) & 255)
		output[3] = byte(val & 255)
		return 2
	}
	hlen := val / 256 / 256 / 256 / 256

	copy(output, []byte{
		byte(hlen / 256 / 65536),
		byte((hlen / 65536) & 255),
		byte((hlen / 256) & 255),
		byte(hlen & 255),
		byte(val / 256 / 65536),
		byte((val / 65536) & 255),
		byte((val / 256) & 255),
		byte(val & 255),
	})
	return 3

}

func select_insert_command(len int) []byte {
	if len <= 64 {
		return []byte{RS_OP_LITERAL_1 + byte(len) - 1}
	}
	if len < 256 { //is this 256 or 256 + 64
		return []byte{RS_OP_LITERAL_N1, byte(len)}
	}
	if len < 65536 { //is this 65536 or 65536 + 256 + 66
		return []byte{RS_OP_LITERAL_N2, byte(len / 256), byte(len & 255)}
	}
	if len <= 4294967295 {
		return []byte{RS_OP_LITERAL_N4, byte(len / 256 / 65536), byte((len / 65536) & 255),
			byte((len / 256) & 255), byte(len & 255)}
	}
	hlen := len / 256 / 256 / 256 / 256

	return []byte{RS_OP_LITERAL_N8,
		byte(hlen / 256 / 65536),
		byte((hlen / 65536) & 255),
		byte((hlen / 256) & 255),
		byte(hlen & 255),
		byte(len / 256 / 65536),
		byte((len / 65536) & 255),
		byte((len / 256) & 255),
		byte(len & 255)}
}

func select_copy_command(where int, len int) []byte {
	var output [9]byte
	logWhereNumBytes := writeVarInt(where, output[1:])
	logLenNumBytes := writeVarInt(len, output[(1<<logWhereNumBytes)+1:])
	cmdIndex := logWhereNumBytes*4 + logLenNumBytes
	output[0] = RS_OP_COPY_N1_N1 + byte(cmdIndex)
	return output[:1+(1<<logWhereNumBytes)+(1<<logLenNumBytes)]
}

// this function writes any remaining literals to the output stream to make the way for copies or close
// it can also write the close command (NUL), if the stream is truly done
func (self *RsyncPatchWriter) flush_literals(close_stream bool) error {
	pending := self.pending_literals
	self.pending_literals = self.pending_literals[:0]

	if len(pending) != 0 {
		_, err := self.output.Write(select_insert_command(len(pending)))
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Failed at X (%d) %v\n", select_insert_command(len(pending)), err)
			return err
		}
		_, err = self.output.Write(pending)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Failed at Y %d %v\n", len(pending), err)
			return err
		}
	}
	if close_stream {
		_, err := self.output.Write([]byte{RS_OP_END})
		if err != nil {
			//fmt.Fprintf(os.Stderr, "Failed at Z 1 %v\n", err)
		}
		return err
	}
	return nil
}

func (self *RsyncPatchWriter) emit_copy(where int, xlen int) error {
	_, err := self.output.Write(select_copy_command(where, xlen))
	if err != nil {
		//fmt.Fprintf(os.Stderr, "Failed at U %d %v\n", len(select_copy_command(where, xlen)), err)
	}
	return err
}
func (self *RsyncPatchWriter) findAndActOnMatch() (bool, error) {
	if matchLocations, ok := self.hint.crc32_to_sig_index[self.crc32]; ok {
		for _, match := range matchLocations {
			sigInstance := self.sig.signatures[match]
			if sigInstance.crc32 != self.crc32 {
				panic("Corrupt hash index")
			}
			md4_hasher := md4.New()
			_, _ = md4_hasher.Write(self.buffer[self.ring_buffer_ptr:])
			_, _ = md4_hasher.Write(self.buffer[:self.ring_buffer_ptr])
			hash := md4_hasher.Sum(nil)
			if bytes.Equal(hash[:len(sigInstance.crypto_hash)],
				sigInstance.crypto_hash) {
				self.flush_literals(false)
				err := self.emit_copy(match*len(self.buffer), len(self.buffer))
				self.ring_buffer_ptr = 0
				self.buffer_fill = 0
				return true, err
			}
		}
	}
	return false, nil
}
func (self *RsyncPatchWriter) AssertSameCrc() {
	sum := uint32(0)
	sum = crcUpdate(sum, self.buffer[self.ring_buffer_ptr:])
	sum = crcUpdate(sum, self.buffer[:self.ring_buffer_ptr])
	if sum != self.crc32 {
		panic(fmt.Sprintf("%x != %x\n", sum, self.crc32))
	}
}
func (self *RsyncPatchWriter) rotate(next byte) (bool, error) {
	if self.buffer_fill != len(self.buffer) { // the write code didn't get to it
		panic("buffer fill needs to equal buffer length")
	}
	foundMatch, err := self.findAndActOnMatch()
	if foundMatch {
		//fmt.Fprintf(os.Stderr, "FoundMatch; resetting buffer_fill at %d\n", self.ring_buffer_ptr)
		self.buffer_fill = 1
		self.ring_buffer_ptr = 0
		self.crc32 = 0
		self.buffer[0] = next
		return true, err
	} else {
		self.pending_literals = append(self.pending_literals,
			self.buffer[self.ring_buffer_ptr])
	}
	oldCrc := self.crc32
	self.crc32 = crcRotate(self.crc32, uint32(len(self.buffer)), self.buffer[self.ring_buffer_ptr], next)
	_ = oldCrc
	//fmt.Fprintf(os.Stderr, "Rotating %x -> %x results in %x -> %x\n",  self.buffer[self.ring_buffer_ptr], next, oldCrc, self.crc32)
	self.buffer[self.ring_buffer_ptr] = next
	self.ring_buffer_ptr += 1
	if self.ring_buffer_ptr == len(self.buffer) {
		self.ring_buffer_ptr = 0
	}
	return false, err
}
func (self *RsyncPatchWriter) compute_full_crc() {
	if self.ring_buffer_ptr != 0 {
		panic("full CRC can only be computed from contiguous buffer")
	}
	self.crc32 = crcUpdate(0, self.buffer[:self.buffer_fill])
}
func (self *RsyncPatchWriter) Close() error {
	if self.buffer_fill != len(self.buffer) { // the write code didn't get to it
		self.compute_full_crc()
	}
	for self.buffer_fill != 0 {
		match, err := self.findAndActOnMatch()
		if err != nil {
			return err
		}
		if match {
			self.pending_literals = append(self.pending_literals,
				self.buffer[self.ring_buffer_ptr:self.buffer_fill]...)

			self.pending_literals = append(self.pending_literals,
				self.buffer[:self.ring_buffer_ptr]...)
			self.ring_buffer_ptr = 0
			self.buffer_fill = 0 // won't be read, but just for cleanliness
			break
		}
		self.crc32 = crcRollout(self.crc32, uint32(len(self.buffer)), self.buffer[self.ring_buffer_ptr])
		self.pending_literals = append(self.pending_literals,
			self.buffer[self.ring_buffer_ptr])
		self.ring_buffer_ptr += 1
		if self.ring_buffer_ptr == len(self.buffer) {
			self.ring_buffer_ptr = 0
		}
		self.buffer_fill -= 1
	}
	err := self.flush_literals(true)
	if err != nil {
		return err
	}
	if closer, ok := self.output.(io.WriteCloser); ok {
		xerr := closer.Close()
		fmt.Fprintf(os.Stderr, "X_X %v\n", xerr)
		return xerr
	}
	return nil
}

func (self *RsyncPatchWriter) Write(data []byte) (int, error) {
	//fmt.Fprintf(os.Stderr, "Patch Writer writing %d bytes\n", len(data))
	var data_written = 0
	for {
		if len(data) != 0 && self.buffer_fill < len(self.buffer) {
			to_copy := min(self.buffer_fill+len(data), len(self.buffer)) - self.buffer_fill
			copy(self.buffer[self.buffer_fill:self.buffer_fill+to_copy], data[:to_copy])
			self.buffer_fill += to_copy
			data_written += to_copy
			data = data[to_copy:]
			if self.buffer_fill == len(self.buffer) {
				self.compute_full_crc()
			}
		}
		if len(data) == 0 || self.buffer_fill < len(self.buffer) {
			return data_written, nil
		}
		// buffer is full
		lastProcessedIndex := 0
		for index, cur := range data {
			lastProcessedIndex = index
			emittedMatch, err := self.rotate(cur)
			data_written += 1
			if err != nil {
				return data_written, err
			}
			if emittedMatch {
				//fmt.Fprintf(os.Stderr, "EmittedMatch at %d\n", data_written)
				break
			}
		}
		data = data[lastProcessedIndex+1:]
	}
}
