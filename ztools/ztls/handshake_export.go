package ztls

import "encoding/binary"

type rsaExportParams struct {
	modulusLength          uint16
	rawModulus             []byte
	exponentLength         uint16
	rawExponent            []byte
	signatureHashAlgorithm uint16
	signatureLength        uint16
	rawSignature           []byte

	raw []byte
}

func (p *rsaExportParams) unmarshal(data []byte) bool {
	p.raw = data
	// Read out modulusLength
	if len(data) < 2 {
		return false
	}
	modulusLength := int(data[0])<<8 | int(data[1])
	if modulusLength < 0 || modulusLength > 65535 {
		return false
	}
	p.modulusLength = uint16(modulusLength)

	// Move forward
	data = data[2:]
	if len(data) < modulusLength {
		return false
	}
	// Pull out raw modulus
	p.rawModulus = data[0:modulusLength]
	data = data[modulusLength:]

	// Pull out exponent length
	if len(data) < 2 {
		return false
	}
	exponentLength := int(data[0])<<8 | int(data[1])
	if exponentLength < 0 || exponentLength > 65535 {
		return false
	}
	p.exponentLength = uint16(exponentLength)
	if exponentLength > 4 {
		return false
	}

	// Pull out exponent
	data = data[2:]
	if len(data) < exponentLength {
		return false
	}
	p.rawExponent = data[0:exponentLength]
	data = data[exponentLength:]

	// Pull out signature algorithm
	if len(data) < 2 {
		return false
	}
	algorithm := int(data[0])<<8 | int(data[1])
	if algorithm < 0 || algorithm > 65535 {
		return false
	}
	p.signatureHashAlgorithm = uint16(algorithm)
	data = data[2:]

	// Read signature length
	if len(data) < 2 {
		return false
	}
	sigLength := int(data[0])<<8 | int(data[1])
	if sigLength < 0 || sigLength > 65535 {
		return false
	}
	p.signatureLength = uint16(sigLength)
	data = data[2:]
	if len(data) < sigLength {
		return false
	}
	p.rawSignature = data[0:sigLength]
	return true
}

func (p *rsaExportParams) marshal() []byte {
	paramsLen := 2 + p.modulusLength + 2 + p.exponentLength + 2 + 2 + p.signatureLength
	out := make([]byte, paramsLen)
	buf := out
	binary.BigEndian.PutUint16(buf, p.modulusLength)
	buf = buf[2:]
	n := copy(buf, p.rawModulus)
	buf = buf[n:]
	binary.BigEndian.PutUint16(buf, p.exponentLength)
	buf = buf[2:]
	n = copy(buf, p.rawExponent)
	buf = buf[n:]
	binary.BigEndian.PutUint16(buf, p.signatureHashAlgorithm)
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, p.signatureLength)
	buf = buf[2:]
	n = copy(buf, p.rawSignature)
	return out
}
