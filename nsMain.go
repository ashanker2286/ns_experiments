package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netns"
	"net"
	"runtime"
	"time"
)

var origns1 netns.NsHandle
var newns netns.NsHandle

func foo(namespace, ifName string) *pcap.Handle {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	origns1, _ = netns.Get()
	fmt.Println("===Orig NsHandle: ", origns1, origns1.String())
	defer origns1.Close()

	newns, _ = netns.GetFromName(namespace)
	fmt.Println("===1 NsHandle: ", newns, newns.String())
	netns.Set(newns)
	defer newns.Close()

	pcapHdl, err := pcap.OpenLive(ifName, 65549, false, time.Duration(1)*time.Second)
	if err != nil {
		fmt.Println("Pcap OpenLive failed")
		netns.Set(origns1)
		return nil
	}
	netns.Set(origns1)
	return pcapHdl
}

func recvPkt(hdl *pcap.Handle) {
	origns, _ := netns.Get()
	fmt.Println("1===Orig NsHandle: ", origns, origns.String())
	fmt.Println(" Ret value:", origns, origns1, origns.Equal(origns1))
	fmt.Println("1 Ret value:", origns, newns, origns.Equal(newns))
	origns.Close()
	src := gopacket.NewPacketSource(hdl, hdl.LinkType())
	in := src.Packets()
	for {
		select {
		case packet, ok := <-in:
			if ok {
				fmt.Println("Recv packet", packet)
			} else {
				fmt.Println("No packet")
			}
		}
	}
	return
}

func sendArpReq(srcIp, destIp string, ifName, namespace string) {
	macAddr := "00:e0:ec:31:34:04"
	pcapHdl := foo(namespace, ifName)
	if pcapHdl == nil {
		fmt.Println("Invalid Pcap Hdl")
		return
	}
	defer pcapHdl.Close()
	srcIpAddr := (net.ParseIP(srcIp)).To4()
	if srcIpAddr == nil {
		fmt.Println("Corrupted destination ip :  ", srcIp)
		return
	}

	destIpAddr := (net.ParseIP(destIp)).To4()
	if destIpAddr == nil {
		fmt.Println("Corrupted destination ip :  ", destIp)
		return
	}

	myMacAddr, _ := net.ParseMAC(macAddr)
	if myMacAddr == nil {
		fmt.Println("corrupted my mac : ", macAddr)
		return
	}
	arp_layer := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   myMacAddr,
		SourceProtAddress: srcIpAddr,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	eth_layer := layers.Ethernet{
		SrcMAC:       myMacAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	arp_layer.DstProtAddress = destIpAddr
	gopacket.SerializeLayers(buffer, options, &eth_layer, &arp_layer)

	if err := pcapHdl.WritePacketData(buffer.Bytes()); err != nil {
		fmt.Println("Error writing data to packet buffer for l3Intf:")
		return
	}
	return
}

func main() {
	origns, _ := netns.Get()
	fmt.Println("2===Orig NsHandle: ", origns, origns.String())
	pcapHdl := foo("foo", "fpPort2")
	if pcapHdl == nil {
		fmt.Println("Pcap Handle is nil")
		return
	}
	go recvPkt(pcapHdl)
	for {
		time.Sleep(time.Duration(10) * time.Second)
		sendArpReq("21.1.10.1", "21.1.10.2", "fpPort2", "foo")
	}
}
