package pfcpType

import (
	"encoding/binary"
	"fmt"
)

type UPFDataT struct {
	UpfdatatValue uint64
}

func (u *UPFDataT) MarshalBinary() (data []byte, err error) {
	var idx uint16 = 0
	// Octet 5 to 8
	data = make([]byte, 8)
	binary.BigEndian.PutUint64(data[idx:], u.UpfdatatValue)

	return data, nil
}

func (u *UPFDataT) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5 to 8
	if length < idx + 8 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	u.UpfdatatValue = binary.LittleEndian.Uint64(data[idx:])
	idx = idx + 8

	if length != idx {
		fmt.Printf("%d",length)
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
