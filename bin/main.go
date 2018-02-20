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

package main

import (
    . "github.com/danielrh/go-rsync"
	"bytes"
	"io"
	"os"
)

func main() {
	if os.Args[1] == "patch" {
		baseFile, err := os.Open(os.Args[2])
		if err != nil {
			panic(err)
		}
		patchFile, err := os.Open(os.Args[3])
		if err != nil {
			panic(err)
		}
		var patch bytes.Buffer
		var base bytes.Buffer
		_, err = io.Copy(&patch, patchFile)
		if err != nil {
			panic(err)
		}
		_, err = io.Copy(&base, baseFile)
		if err != nil {
			panic(err)
		}
		err = ApplyPatch(patch.Bytes(), base.Bytes(), os.Stdout)
		if err != nil {
			panic(err)
		}
	} else if os.Args[1] == "signature" {
		baseFile, err := os.Open(os.Args[2])
		if err != nil {
			panic(err)
		}
		var base bytes.Buffer
		_, err = io.Copy(&base, baseFile)
		if err != nil {
			panic(err)
		}
		sig := NewSigFile(2048, base.Bytes(), 8)
        err = sig.Serialize(os.Stdout)
        if err != nil {
        panic(err)
        }
	} else if os.Args[1] == "delta" {
		sigFile, err := os.Open(os.Args[2])
		if err != nil {
			panic(err)
		}
		newFile, err := os.Open(os.Args[3])
		if err != nil {
			panic(err)
		}
		var sigBuffer bytes.Buffer
		_, err = io.Copy(&sigBuffer, sigFile)
		if err != nil {
			panic(err)
		}
		var newFileBuffer bytes.Buffer
		_, err = io.Copy(&newFileBuffer, newFile)
		if err != nil {
			panic(err)
		}
		patchWriter, perr := NewRsyncPatchWriter(sigBuffer.Bytes(), os.Stdout)
		if perr != nil {
			panic(perr)
		}
        //var leendat int64
        
		//leendat, err = io.Copy(patchWriter, newFile)
        //fmt.Fprintf(os.Stderr, "%d %v\n", leendat, err)
        _, err = patchWriter.Write(newFileBuffer.Bytes()) // simpler for now...single write call to debug
		if err != nil {
			panic(err)
		}
		err = patchWriter.Close()
		if err != nil {
			panic(err)
		}
	} else {
		panic("UNKNOWN COMMAND " + os.Args[1])
	}
}
