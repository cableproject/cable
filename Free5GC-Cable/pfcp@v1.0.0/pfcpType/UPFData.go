package pfcpType

import (
	"encoding/binary"
	"fmt"
)

type UPFData struct {
	UpfdataValue uint16
}

func (u *UPFData) MarshalBinary() (data []byte, err error) {
	var idx uint16 = 0
	// Octet 5 to 8
	data = make([]byte, 4)
	binary.BigEndian.PutUint16(data[idx:], u.UpfdataValue)

	return data, nil
}

func (u *UPFData) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5 to 8
	if length < idx + 4 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	u.UpfdataValue = binary.LittleEndian.Uint16(data[idx:])
	idx = idx + 4

	if length != idx {
		fmt.Printf("%d",length)
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
