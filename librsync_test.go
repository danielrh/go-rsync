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
"testing"
)

var baseFile = []byte(`Mary had a little lamb
her fleece was white as snow.
Everywhere that mary went her lamb was sure to go.
It followed her to school one day
which was against the rule.
It made the children laugh and play to see a lamb at school.

The wheels on the bus go round and round
round and round
round and round
the wheels on the bus go round and round
all through the town.
The wipers on the bus go swish swish swish
swish swish swish
swish swish swish
the wipers on the bus go swish swish swish
all through the town.
The driver on the bus says move on back
move on back
move on back
the driver on the bus says move on back
all through the town
`)

var changedFile = []byte(`Berry had a little cow
her fleece was white as snow.
Everywhere that mary went her lamb was sure to go.
It followed her to the factory one day
which was against the rule.
It made the workers laugh and play to see a cow at the factory.

The wheels on the train go round and round
round and round
round and round
the wheels on the train go round and round
all through the town.
The cow catcher on the train goes chunk chunk chunk
chunk chunk chunk
chunk chunk chunk
the cow catcher on the train goes chunk chunk chunk
all through the town.
The driver on the train says move on back
move on back
move on back
the driver on the train says move on back
all through the town
`)


func TestSigSerializeDeserialize(t *testing.T) {
    sig := NewSigFile(11, baseFile, 8);
    var sigDisk bytes.Buffer
    err := sig.Serialize(&sigDisk)
    if err != nil {
       panic(err)
    }
    firstAttempt := hex.EncodeToString(sigDisk.Bytes())
    sig2, serr := DeserializeSigFileView(sigDisk.Bytes())
    if serr != nil {
       panic(serr)
    }
    var sigDisk2 bytes.Buffer
    err = sig2.Serialize(&sigDisk2)
    if err != nil {
       panic(err)
    }
    secondAttempt := hex.EncodeToString(sigDisk2.Bytes())
    if firstAttempt != secondAttempt {
       panic(secondAttempt+ "\nmust ==\n" + firstAttempt)
    }
}


func TestSigDeltaPatch(t *testing.T) {
    sig := NewSigFile(11, baseFile, 8);
    var sigDisk bytes.Buffer
    err := sig.Serialize(&sigDisk)
    if err != nil {
       panic(err)
    }
    var patchOut bytes.Buffer
    patchWriter,perr := NewRsyncPatchWriter(sigDisk.Bytes(), &patchOut)
    if perr != nil {
        panic(perr)
    }
    _, err = patchWriter.Write(changedFile)
    if err != nil {
        panic(err)
    }
    err = patchWriter.Close()
    if err != nil {
       panic(err)
    }
    var finalOutput bytes.Buffer
    err = ApplyPatch(baseFile, patchOut.Bytes(), &finalOutput)
    if err != nil {
       panic(err)
    }
    fixedHex := hex.EncodeToString(changedFile)
    finalOutputHex := hex.EncodeToString(finalOutput.Bytes())
    if fixedHex != finalOutputHex {
       panic(finalOutputHex + "\nmust ==\n" + fixedHex)
    }
}
