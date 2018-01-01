/*
* Honeytrap Agent
* Copyright (C) 2016-2017 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package server

import (
	"encoding"
	"encoding/binary"
	"errors"
	"net"
)

type agentConnection struct {
	net.Conn
}

func (ac agentConnection) receive() (interface{}, error) {
	buff := make([]byte, 1)

	n, err := ac.Conn.Read(buff)
	if err != nil {
		return nil, err
	} else if n == 0 {
		return nil, errors.New("Could not read object")
	}

	type_ := int(buff[0])

	var o encoding.BinaryUnmarshaler

	switch type_ {
	case TypeHello:
		o = &Hello{}
	case TypePing:
		o = &Ping{}
	case TypeHandshake:
		o = &Handshake{}
	case TypeHandshakeResponse:
		o = &HandshakeResponse{}
	case TypeReadWrite:
		o = &ReadWrite{}
	case TypeEOF:
		o = &EOF{}
	}

	buff = make([]byte, 2)

	n, err = ac.Conn.Read(buff)
	if err != nil {
		return nil, err
	} else if n == 0 {
		return nil, errors.New("Could not read object")
	}

	size := binary.LittleEndian.Uint16(buff)

	buff = make([]byte, size)

	n, err = ac.Conn.Read(buff)
	if err != nil {
		return nil, err
	} else if n == 0 {
		return nil, errors.New("Could not read object")
	}

	if err := o.UnmarshalBinary(buff[:n]); err != nil {
		return nil, err
	}

	return o, nil
}

func (ac agentConnection) send(o encoding.BinaryMarshaler) error {
	// write type
	switch o.(type) {
	case Hello:
		_, err := ac.Conn.Write([]byte{uint8(TypeHello)})
		if err != nil {
			log.Errorf("Error occured writing Hello: %s", err.Error())
			return err
		}
	case Handshake:
		_, err := ac.Conn.Write([]byte{uint8(TypeHandshake)})
		if err != nil {
			log.Errorf("Error occured writing TypeHandshake: %s", err.Error())
			return err
		}
	case HandshakeResponse:
		_, err := ac.Conn.Write([]byte{uint8(TypeHandshakeResponse)})
		if err != nil {
			log.Errorf("Error occured writing TypeHandshakeResponse: %s", err.Error())
			return err
		}
	case ReadWrite:
		_, err := ac.Conn.Write([]byte{uint8(TypeReadWrite)})
		if err != nil {
			log.Errorf("Error occured writing TypeReadWrite: %s", err.Error())
			return err
		}
	case Ping:
		_, err := ac.Conn.Write([]byte{uint8(TypePing)})
		if err != nil {
			log.Errorf("Error occured writing TypePing: %s", err.Error())
			return err
		}
	case EOF:
		_, err := ac.Conn.Write([]byte{uint8(TypeEOF)})
		if err != nil {
			log.Errorf("Error occured writing TypeEOF: %s", err.Error())
			return err
		}
	}

	data, err := o.MarshalBinary()
	if err != nil {
		return err
	}

	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff[0:2], uint16(len(data)))

	if _, err := ac.Conn.Write(buff); err != nil {
		log.Errorf("Error occured writing data length: %s \n", err.Error())
		return err
	}

	if _, err := ac.Conn.Write(data); err != nil {
		log.Errorf("Error occured writing data: %s \n", err.Error())
		return err
	}

	return nil
}
