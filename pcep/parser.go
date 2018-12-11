package pcep

import (
	"bytes"
	"github.com/golang/glog"
)

// Parse received data into a pcep message (collection of objects)
func parseMessage(data []byte) (msg *PcepMsg, err error) {
	buf := bytes.NewBuffer(data)
	commonHeader := &CommonHeader{}
	if err = commonHeader.Parse(buf.Next(COMMON_HDR_LEN)); err != nil {
		return
	}
	glog.V(4).Infof("ParseMsg.Parse: Received message of len: %d, type: %s", commonHeader.MsgLen, MsgTypeToName[int(commonHeader.MsgType)])
	msg = NewPcepMsg(int(commonHeader.MsgType))
	// read contents of buffer and parse into objects until buffer is empty.
	for buf.Len() > 0 {
		objHeader := &CommonObjectHeader{}
		if err = objHeader.Parse(buf.Next(COMMON_OBJECT_HDR_LEN)); err != nil {
			return
		}
		object := NewObjectByClass(int(objHeader.ObjectClass))
		if object == nil {
			glog.V(4).Infof("ParseMsg.Parse: Skip parsing unknown object type %d", int(objHeader.ObjectClass))
			buf.Next(int(objHeader.Length) - COMMON_OBJECT_HDR_LEN)
			continue
		}
		switch o := object.(type) {
		// EP Object requires info from the header for parsing
		case *EndPointsObject:
			o.Hdr = objHeader
		}
		if err = object.Parse(buf.Next(int(objHeader.Length) - COMMON_OBJECT_HDR_LEN)); err != nil {
			// we terminate parsing if any one object cant be parsed
			return
		}
		msg.ObjectList = append(msg.ObjectList, Object{ObjClass: int(objHeader.ObjectClass), Obj: object})
	}

	glog.V(4).Infof("ParseMsg.Parse: Parsed %d objects", len(msg.ObjectList))
	return
}

// build headers and serialize a pcep message
func SerializeMessage(msg *PcepMsg) []byte {
	buf := &bytes.Buffer{}
	var (
		totalObjLen int
		tmpBuf      []byte
	)
	// serialize all the objects first and then slap on a header with the total len
	for _, o := range msg.ObjectList {
		serializedObj := o.Obj.Serialize()
		objHdr := NewCommonObjectHeader(o.ObjClass, 1, len(serializedObj))
		tmpBuf = append(tmpBuf, objHdr.Serialize()...)
		tmpBuf = append(tmpBuf, serializedObj...)
		totalObjLen += int(objHdr.Length)
	}
	msgHdr := NewCommonHeader(msg.MsgType, totalObjLen)
	buf.Write(msgHdr.Serialize())
	buf.Write(tmpBuf)
	glog.V(4).Infof("SerializeMsg: Serialized %d objects, %d bytes for message: %s", len(msg.ObjectList), int(msgHdr.MsgLen), MsgTypeToName[int(msgHdr.MsgType)])
	return buf.Bytes()
}

// the split function for the Scanner. This splits incoming data on pcep-message boundaries
func SplitPcepMessage(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 || len(data) < COMMON_HDR_LEN {
		return 0, nil, nil
	}
	tmpHdr := &CommonHeader{}
	if err = tmpHdr.Parse(data[:COMMON_HDR_LEN]); err != nil {
		return 0, nil, nil
	}
	if len(data) < int(tmpHdr.MsgLen) {
		return 0, nil, nil
	}
	return int(tmpHdr.MsgLen), data[0:tmpHdr.MsgLen], nil
}
