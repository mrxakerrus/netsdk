package dvr

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/lunixbochs/struc"
	utils "github.com/mrxakerrus/netsdk/utils"
)

type DVR struct {
	IP           string
	SocketType   string
	Port         int
	Login        string
	Password     string
	HashPassword string
	Connection   net.Conn
	SessionID    string
	Count        int
	Mx           sync.Mutex
}

var CAPTURE_SIZE = [...]string{"D1", "HD1", "BCIF", "CIF", "QCIF", "VGA", "QVGA", "SVCD", "QQVGA", "ND1", "650TVL", "720P", "1_3M", "UXGA", "1080P", "WUXGA", "2_5M", "3M", "5M", "NR", "1080N", "4M", "6M", "8M", "12M", "4K", "V2_NR", "720N", "WSVGA", "NHD", "3M_N", "4M_N", "5M_N", "4K_N", "V3_NR"}

var QCODES = map[string]int{
	"AuthorityList":     1470,
	"Users":             1472,
	"Groups":            1474,
	"AddGroup":          1476,
	"ModifyGroup":       1478,
	"DelGroup":          1480,
	"AddUser":           1482,
	"ModifyUser":        1484,
	"DelUser":           1486,
	"ModifyPassword":    1488,
	"AlarmInfo":         1504,
	"AlarmSet":          1500,
	"ChannelTitle":      1046,
	"EncodeCapability":  1360,
	"General":           1042,
	"KeepAlive":         1006,
	"OPMachine":         1450,
	"OPMailTest":        1636,
	"OPMonitor":         1413,
	"OPNetKeyboard":     1550,
	"OPPTZControl":      1400,
	"OPSNAP":            1560,
	"OPSendFile":        0x5F2,
	"OPSystemUpgrade":   0x5F5,
	"OPTalk":            1434,
	"OPTimeQuery":       1452,
	"OPTimeSetting":     1450,
	"NetWork.NetCommon": 1042,
	"OPNetAlarm":        1506,
	"SystemFunction":    1360,
	"SystemInfo":        1020,
	"NetWork.NetNTP":    1042,
	"NetWork.NetDNS":    1042,
}

type Header struct {
	Start   int `struc:"little,int8"`
	Version int `struc:"little,int8"`
	Pad1    int `struc:"pad"`
	Pad2    int `struc:"pad"`
	Session int `struc:"little,int32"`
	Count   int `struc:"little,int32"`
	Pad3    int `struc:"pad"`
	Pad4    int `struc:"pad"`
	Msg     int `struc:"little,int16"`
	Len     int `struc:"little,int32"`
}

type HeaderMessage struct {
	Head    *Header
	Message []byte
}

type Login struct {
	EncryptType string `json:"EncryptType"`
	LoginType   string `json:"LoginType"`
	Password    string `json:"PassWord"`
	Username    string `json:"UserName"`
}

type Info struct {
	Name      string `json:"Name"`
	SessionID string `json:"SessionID"`
}

type SystemInfo struct {
	Name       string `json:"Name"`
	Ret        int    `json:"Ret"`
	SessionID  string `json:"SessionID"`
	SystemInfo struct {
		AlarmInChannel  int    `json:"AlarmInChannel"`
		AlarmOutChannel int    `json:"AlarmOutChannel"`
		AudioInChannel  int    `json:"AudioInChannel"`
		BuildTime       string `json:"BuildTime"`
		CombineSwitch   int    `json:"CombineSwitch"`
		DeviceRunTime   string `json:"DeviceRunTime"`
		DigChannel      int    `json:"DigChannel"`
		EncryptVersion  string `json:"EncryptVersion"`
		ExtraChannel    int    `json:"ExtraChannel"`
		HardWare        string `json:"HardWare"`
		HardWareVersion string `json:"HardWareVersion"`
		SerialNo        string `json:"SerialNo"`
		SoftWareVersion string `json:"SoftWareVersion"`
		TalkInChannel   int    `json:"TalkInChannel"`
		TalkOutChannel  int    `json:"TalkOutChannel"`
		UpdataTime      string `json:"UpdataTime"`
		UpdataType      string `json:"UpdataType"`
		VideoInChannel  int    `json:"VideoInChannel"`
		VideoOutChannel int    `json:"VideoOutChannel"`
	} `json:"SystemInfo"`
}

type AuthStruct struct {
	AliveInterval int    `json:"AliveInterval"`
	ChannelNum    int    `json:"ChannelNum"`
	DeviceType    string `json:"DeviceType "`
	ExtraChannel  int    `json:"ExtraChannel"`
	Ret           int    `json:"Ret"`
	SessionID     string `json:"SessionID"`
}

type EncodeCapability struct {
	EncodeCapability struct {
		ChannelMaxSetSync int `json:"ChannelMaxSetSync"`
		CombEncodeInfo    []struct {
			CompressionMask string `json:"CompressionMask"`
			Enable          bool   `json:"Enable"`
			HaveAudio       bool   `json:"HaveAudio"`
			ResolutionMask  string `json:"ResolutionMask"`
			StreamType      string `json:"StreamType"`
		} `json:"CombEncodeInfo"`
		Compression string `json:"Compression"`
		EncodeInfo  []struct {
			CompressionMask string `json:"CompressionMask"`
			Enable          bool   `json:"Enable"`
			HaveAudio       bool   `json:"HaveAudio"`
			ResolutionMask  string `json:"ResolutionMask"`
			StreamType      string `json:"StreamType"`
		} `json:"EncodeInfo"`
		ExImageSizePerChannel    []string   `json:"ExImageSizePerChannel"`
		ExImageSizePerChannelEx  [][]string `json:"ExImageSizePerChannelEx"`
		FourthStreamImageSize    []string   `json:"FourthStreamImageSize"`
		ImageSizePerChannel      []string   `json:"ImageSizePerChannel"`
		MaxBitrate               int        `json:"MaxBitrate"`
		MaxEncodePower           int        `json:"MaxEncodePower"`
		MaxEncodePowerPerChannel []string   `json:"MaxEncodePowerPerChannel"`
		ThirdStreamImageSize     []string   `json:"ThirdStreamImageSize"`
	} `json:"EncodeCapability"`
	Name      string `json:"Name"`
	Ret       int    `json:"Ret"`
	SessionID string `json:"SessionID"`
}

type NetworkDNS struct {
	Name          string `json:"Name"`
	NetWorkNetDNS struct {
		Address      string `json:"Address"`
		SpareAddress string `json:"SpareAddress"`
	} `json:"NetWork.NetDNS"`
	Ret       int    `json:"Ret"`
	SessionID string `json:"SessionID"`
}

type Snap struct {
	Name      string `json:"Name"`
	SessionID string `json:"SessionID"`
	OPSNAP    struct {
		Channel int `json:"Channel"`
	} `json:"OPSNAP"`
}

// Snapshot camera channel(0-main,1-sub(not work))
func (dvr *DVR) GetSnapshot(channel int, path string) error {
	snap := Snap{Name: "OPSNAP", SessionID: dvr.SessionID}
	snap.OPSNAP.Channel = channel
	snapMarshal, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	data, err := dvr.PrepareSend(QCODES["OPSNAP"], snapMarshal)
	if err != nil {
		return err
	}
	buff, err := dvr.Send(data)
	if err != nil {
		return err
	}
	err = os.WriteFile(path, []byte(buff), 0777)
	if err != nil {
		return err
	}
	return nil
}

// Get information by string code
func (dvr *DVR) GetCode(code string) (string, error) {
	info := Info{code, dvr.SessionID}
	infoMarshal, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	data, err := dvr.PrepareSend(QCODES[code], infoMarshal)
	if err != nil {
		return "", err
	}
	buff, err := dvr.Send(data)
	if err != nil {
		return "", err
	}
	return buff, nil
}

// TODO
func (dvr *DVR) GetInfo() (Info, error) {
	info := Info{"General", dvr.SessionID}
	infoMarshal, err := json.Marshal(info)
	if err != nil {
		return info, err
	}
	data, err := dvr.PrepareSend(QCODES["General"], infoMarshal)
	if err != nil {
		return info, err
	}
	buff, err := dvr.Send(data)
	if err != nil {
		return info, err
	}
	log.Println(buff)
	return info, err
}

// getSystemInfo return info camera
func (dvr *DVR) GetSystemInfo() (SystemInfo, error) {
	systeminfo := SystemInfo{}
	info := Info{"SystemInfo", dvr.SessionID}
	infoMarshal, err := json.Marshal(info)
	if err != nil {
		return systeminfo, err
	}
	data, err := dvr.PrepareSend(QCODES["SystemInfo"], infoMarshal)
	if err != nil {
		return systeminfo, err
	}
	buff, err := dvr.Send(data)
	if err != nil {
		return systeminfo, err
	}

	err = json.Unmarshal([]byte(buff), &systeminfo)
	if err != nil {
		return systeminfo, err
	}
	return systeminfo, nil
}

// Auth
func (dvr *DVR) Auth() (AuthStruct, error) {
	auth := AuthStruct{}
	login := Login{"MD5", "DVRIP-Web", dvr.HashPassword, dvr.Login}
	loginMarshal, err := json.Marshal(login)
	if err != nil {
		return auth, err
	}

	data, err := dvr.PrepareSend(1000, loginMarshal)
	if err != nil {
		return auth, err
	}
	buff, err := dvr.Send(data)
	if err != nil {
		return auth, err
	}

	err = json.Unmarshal([]byte(buff), &auth)
	if err != nil {
		return auth, err
	}
	dvr.SessionID = auth.SessionID
	return auth, nil
}

// TODO concat
func (dvr *DVR) CreateConnection() error {
	var err error
	dvr.Connection, err = net.Dial(dvr.SocketType, dvr.IP+":"+strconv.Itoa(dvr.Port))
	if err != nil {
		dvr.Connection = nil
		return err
	}
	return nil
}

func (dvr *DVR) PasswordHash() {
	passwordHash := ""
	buf := md5.Sum([]byte(dvr.Password))
	for i := 0; i < 8; i++ {
		var n int = (int(buf[2*i]) + int(buf[2*i+1])) % 0x3e
		if n > 9 {
			if n > 35 {
				n += 61
			} else {
				n += 55
			}
		} else {
			n += 0x30
		}
		passwordHash += string(rune(n))
	}
	dvr.HashPassword = passwordHash
}

func (dvr *DVR) PrepareSend(code int, json []byte) (*HeaderMessage, error) {
	output, err := strconv.ParseInt(utils.HexaNumberToInteger(dvr.SessionID), 16, 64)
	if err != nil {
		return nil, err
	}
	head := &Header{255, 0, 0, 0, int(output), dvr.Count, 0, 0, code, len(json) + 2}
	data := &HeaderMessage{head, json}
	dvr.Count++
	return data, nil
}

func (dvr *DVR) Send(header *HeaderMessage) (string, error) {
	dvr.Mx.Lock()
	var buf bytes.Buffer
	end := []byte{0x0a, 0x00}
	err := struc.Pack(&buf, &header.Head)
	if err != nil {
		return "", err
	}
	// log.Println("\n" + hex.Dump(buf.Bytes()))
	buf.Write(header.Message)
	buf.Write(end)

	dvr.Connection.Write(buf.Bytes())
	headerMessage := make([]byte, 20)
	n, err := dvr.Connection.Read(headerMessage)
	if err != nil {
		return "", err
	}
	if n < 20 {
		return "", errors.New("not enought headers length")
	}
	// get length package
	message, err := dvr.Parse(*bytes.NewBuffer(headerMessage))
	if err != nil {
		return "", err
	}
	totalLen := 0
	content := make([]byte, 0, message.Len)
	tmp := make([]byte, 256)
	for {
		n, err = dvr.Connection.Read(tmp)
		if err != nil {
			return "", err
		}
		totalLen += n
		content = append(content, tmp[:n]...)
		if totalLen == message.Len {
			break
		}
	}
	// log.Println(hex.Dump(content[:len(content)-2]))
	dvr.Mx.Unlock()
	return string(content[:len(content)-2]), nil
}

func (dvr *DVR) Parse(buf bytes.Buffer) (Header, error) {
	// log.Println("\n" + hex.Dump(buf.Bytes()))
	head := &Header{}
	err := struc.Unpack(&buf, head)
	if err != nil {
		return *head, err
	}
	return *head, nil
}
