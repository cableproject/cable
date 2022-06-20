package pfcpType

import (
	"encoding/binary"
	"fmt"
)

type PDUTEID struct {
	Pduteid uint32
}

func (u *PDUTEID) MarshalBinary() (data []byte, err error) {
	var idx uint16 = 0
	// Octet 5 to 8
	data = make([]byte, 4)
	binary.BigEndian.PutUint32(data[idx:], u.Pduteid)

	return data, nil
}

func (u *PDUTEID) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5 to 8
	if length < idx + 4 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	u.Pduteid = binary.LittleEndian.Uint32(data[idx:])
	idx = idx + 4

	if length != idx {
		fmt.Printf("%d",length)
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
