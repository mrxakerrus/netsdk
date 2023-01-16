package main

import (
	"log"
	"os"
	"sync"

	"github.com/mrxakerrus/netsdk/entity/dvr"
)

// TODO make clean architecture entity
func main() {
	// TODO create constructor
	camera := dvr.DVR{IP: "10.195.2.25", SocketType: "tcp", Port: 34567, Login: "admin", Password: "tvmix333", HashPassword: "", Connection: nil, SessionID: "0x00000000", Count: 0, Mx: sync.Mutex{}}
	camera.PasswordHash()

	// Create connection socket
	err := camera.CreateConnection()
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}

	// Login struct
	err, login := camera.Auth()
	if err != nil {
		log.Println(err)
	}
	if login.Ret != 100 {
		log.Println("Invalid login or password")
		os.Exit(0)
	}
	log.Println(login)

	// SystemInfo
	err, info := camera.GetSystemInfo()
	if err != nil {
		log.Println(err)
	}
	log.Println(info)

	//Get INFO
	//camera.getInfo()

	//get by QCODE
	//log.Println(camera.getCode("Users"))

	//get by QCODE
	// err, enc := camera.getCode("EncodeCapability")
	// encode := EncodeCapability{}
	// err = json.Unmarshal([]byte(enc), &encode)
	// log.Println(encode.EncodeCapability.ImageSizePerChannel)

	// // Get 0 stream and quality access
	// output, err := strconv.ParseInt(hexaNumberToInteger(encode.EncodeCapability.ImageSizePerChannel[0]), 16, 64)
	// if err != nil {
	// 	log.Println(err)
	// }
	// binaryFill := Reverse(zfill(strconv.FormatInt(output, 2), "0", 32))
	// for i := 0; i < len(binaryFill); i++ {
	// 	if string(binaryFill[i]) == "1" {
	// 		log.Println(i, CAPTURE_SIZE[i])
	// 	}
	// }

	// err, enc = camera.getCode("NetWork.NetNTP")
	// log.Println(enc)

	// // DNS
	// dns := NetworkDNS{}
	// err, enc = camera.getCode("NetWork.NetDNS")
	// err = json.Unmarshal([]byte(enc), &dns)
	// log.Println(convertip(dns.NetWorkNetDNS.Address))

	err = camera.GetSnapshot(0, "./snap4.jpg")
	if err != nil {
		log.Println(err)
	}

}
