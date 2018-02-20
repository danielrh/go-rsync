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

const CRC_MAGIC_16 uint16 = 31
const CRC_MAGIC uint32 = uint32(CRC_MAGIC_16)

func crcRollout(sum uint32, size uint32, old_byte_u8 byte) uint32 {
	size_16 := uint16(size)
	old_byte := uint16(old_byte_u8)
	s1 := uint16(sum & 0xffff)
	s2 := uint16(sum >> 16)
	s1 = s1 - (old_byte + CRC_MAGIC_16)
	s2 = s2 - (size_16 * uint16(old_byte+CRC_MAGIC_16))
	return uint32(s1) | (uint32(s2) << 16)
}

func crcRotate(sum uint32, size uint32, old_byte_u8 byte, new_byte_u8 byte) uint32 {
	size_16 := uint16(size)
	old_byte := uint16(old_byte_u8)
	new_byte := uint16(new_byte_u8)
	s1 := uint16(sum & 0xffff)
	s2 := uint16(sum >> 16)
	s1 = s1 + (new_byte - old_byte)
	s2 = s2 + (s1 - (size_16 * (old_byte + CRC_MAGIC_16)))
	return uint32(s1) | (uint32(s2) << 16)
}

func crcUpdate(sum uint32, buf []byte) uint32 {
	s1 := uint16(sum & 0xffff)
	s2 := uint16(sum >> 16)
	for _, item := range buf {
		s1 = s1 + uint16(item)
		s2 = s2 + s1
	}
	len := uint32(len(buf))
	s1 = s1 + uint16(len*CRC_MAGIC)
	s2 = s2 + uint16(((len*(len+1))/2)*CRC_MAGIC)
	return uint32(s1) | (uint32(s2) << 16)
}
