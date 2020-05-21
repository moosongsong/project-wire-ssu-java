package com.ssusoft.WireSSU;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class PacketData {
	   private int num; // 0 부터 시작
	   private PcapPacket packet;
	   private byte[] packetByteArray;
	   private String srcIp;
	   private String dstIp;
	   private String cityName;
	   private double latitude;
	   private double longitude;
	   
	   Ethernet eth = new Ethernet();
	   Ip4 ip = new Ip4(); 
	   Tcp tcp = new Tcp(); 
	   Payload payload = new Payload(); 
	   
	   public PacketData(PcapPacket packet) {
	      this.packet = packet;
	      packetByteArray = packet.getByteArray(0, packet.size());
	      
	      packet.hasHeader(eth);
	      packet.hasHeader(ip);
	      packet.hasHeader(tcp);
	      packet.hasHeader(payload);
	      
	      srcIp = FormatUtils.ip(ip.source());
	      dstIp = FormatUtils.ip(ip.destination());
	      
	   }
	   
	   void setNum(int num){
	      this.num = num;
	   }
	   
	   int getNum() {
	      return num;
	   }
	   
	   String getNumtoString() {
		      return Integer.toString(num);
		   }
	   
	   String getSrcIp() {
	      return srcIp;
	   }
	   
	   String getDstIp() {
	      return dstIp;
	   }
	   
	   void setCityName(String cityName) {
		   this.cityName = cityName;
	   }
	   
	   String getCityName() {
		   return cityName;
	   }
	   
	   void setLatitude(double latitude) {
		   this.latitude = latitude;
	   }
	   
	   double getLatitude() {
		   return latitude;
	   }
	   
	   void setLongitude(double longitude) {
		   this.longitude = longitude;
	   }
	   
	   double getLongitude() {
		   return longitude;
	   }
	   
	   void sshowAll() {
	         //System.out.println("\n-----------------------------------------------------");
	         MyDialog.textfeild.append("Packet No."+ num +"\n");
	         
	         MyDialog.textfeild.append("[Ethernet]\n");
	         MyDialog.textfeild.append("Destination: " + FormatUtils.mac(eth.destination())+"\n");
	         MyDialog.textfeild.append("Source: " + FormatUtils.mac(eth.source())+"\n");
	         MyDialog.textfeild.append("Type: "+ eth.typeDescription()+"\n");
	          
	         MyDialog.textfeild.append("[IP]");
	         MyDialog.textfeild.append("Version: " + ip.version()+"\n");
	         MyDialog.textfeild.append("Header Length: "+ ip.getHeaderLength()+"\n");
	         MyDialog.textfeild.append("Type of Service(TOS): " + ip.tos() + " - " + tosMean(ip.tos())+"\n");
	         MyDialog.textfeild.append("Total Length: "+ ip.length()+"\n");
	         MyDialog.textfeild.append("Identification: " + parseIdentification()+"\n"); // Fragment identifier - 결합할 때 원래의 데이터를 실별하기 위해 사용
		      sshowFragmentFlags(parseFragmentFlags());
		     MyDialog.textfeild.append("Time to live: " + ip.ttl()+"\n");
		     MyDialog.textfeild.append("Protocol: "+ protocolMean(parseProtocol()) + parseProtocol()+"\n");
		     MyDialog.textfeild.append("Header Checksum: "+ parseHeaderChecksum()+"\n");
		     MyDialog.textfeild.append("Destination: " + FormatUtils.ip(ip.destination())+"\n");
		     MyDialog.textfeild.append("Source: " + FormatUtils.ip(ip.source())+"\n");
		     MyDialog.textfeild.append("City: " + cityName+"\n");
		     MyDialog.textfeild.append("Latitude: " + latitude+"\n");
		     MyDialog.textfeild.append("Longitude: " + longitude+"\n");
		      
		     MyDialog.textfeild.append("[TCP]"+"\n");
		     MyDialog.textfeild.append("Source Port: "+ tcp.source()+"\n");
		     MyDialog.textfeild.append("Destination Port: "+ tcp.destination()+"\n");
		     MyDialog.textfeild.append("Sequence number: "+ tcp.seq()+"\n");
		     MyDialog.textfeild.append("Acknowledgment number: "+ tcp.ack()+"\n");
		     MyDialog.textfeild.append("Header Length: "+ tcp.getHeaderLength()+"bytes \n");
		      sshowControlFlags(parseControlFlags());
		     MyDialog.textfeild.append("Window size: "+ tcp.window()+"\n");
		     MyDialog.textfeild.append(packet.toHexdump()+"\n\n");
		     
	   }
	   
	   
	   void showAll() {
	      //System.out.println("\n-----------------------------------------------------");
	      System.out.printf("Packet No.%d\n\n", num);
	      
	      System.out.println("[Ethernet]");
	      System.out.printf("Destination: %s\n", FormatUtils.mac(eth.destination()));
	      System.out.printf("Source: %s\n", FormatUtils.mac(eth.source()));
	      System.out.printf("Type: %s\n\n", eth.typeDescription());
	      
	      System.out.println("[IP]");
	      System.out.printf("Version: %d\n", ip.version());
	      System.out.printf("Header Length: %d\n", ip.getHeaderLength());
	      System.out.printf("Type of Service(TOS): %d - %s\n", ip.tos(), tosMean(ip.tos()));
	      System.out.printf("Total Length: %d\n", ip.length());
	      System.out.printf("Identification: 0x%04x\n", parseIdentification()); // Fragment identifier - 결합할 때 원래의 데이터를 실별하기 위해 사용
	      showFragmentFlags(parseFragmentFlags());
	      System.out.printf("Time to live: %d\n", ip.ttl());
	      System.out.printf("Protocol: %s (0x%02x)\n", protocolMean(parseProtocol()), parseProtocol());
	      System.out.printf("Header Checksum: 0x%04x\n", parseHeaderChecksum());
	      System.out.printf("Destination: %s\n", FormatUtils.ip(ip.destination()));
	      System.out.printf("Source: %s\n\n", FormatUtils.ip(ip.source()));
	      System.out.printf("City: %s\n", cityName);
	      System.out.printf("Latitude: %f\n", latitude);
	      System.out.printf("Longitude: %f\n", longitude);
	      
	      System.out.println("[TCP]");
	      System.out.printf("Source Port: %d\n", tcp.source());
	      System.out.printf("Destination Port: %d\n", tcp.destination());
	      System.out.printf("Sequence number: %d\n", tcp.seq());
	      System.out.printf("Acknowledgment number: %d\n", tcp.ack());
	      System.out.printf("Header Length: %d bytes\n", tcp.getHeaderLength());
	      showControlFlags(parseControlFlags());
	      System.out.printf("Window size: %d\n\n", tcp.window());
	      System.out.print(packet.toHexdump()+"\n\n\n");
	   }
	   
	   String tosMean(int tos) {
		   switch(tos) {
		   case 0 :
			   return "Normal";
		   case 1 :
			   return "Minimize Cost";
		   case 2 :
			   return "Maximize Reiability";
		   case 4 :
			   return "Maximize Throughput";
		   case 8 :
			   return "Minimize Delay";
		   case 15 :
			   return "Maximize Security";
		   default :
			   return "Not Flag Data";	   
		   }
	   }
	   
	   int parseIdentification() {
		   byte[] b = new byte[2];
		   System.arraycopy(packetByteArray, 18, b, 0, 2);
		   
		   return byteArrayToInt(b);
	   }
	   
	   int parseProtocol() {
		   byte[] b = new byte[1];
		   System.arraycopy(packetByteArray, 23, b, 0, 1);
		   
		   return byteArrayToInt(b);
	   }
	   
	   String protocolMean(int ptc) {
		   switch(ptc) {
		   case 1 :
			   return "ICMP";
		   case 6 :
			   return "TCP";
		   case 8 :
			   return "EGP";
		   case 17 :
			   return "UDP";
		   case 88 :
			   return "IGRP";
		   case 89 :
			   return "OSPF";
		   default :
			   return "Not Protocol Data";
		   }
	   }
	   
	   int parseHeaderChecksum() {
		   byte[] b = new byte[2];
		   System.arraycopy(packetByteArray, 24, b, 0, 2);
		   
		   return byteArrayToInt(b);
	   }
	   
	   byte parseControlFlags() {
		   byte[] b = new byte[2];
		   System.arraycopy(packetByteArray, 46, b, 0, 2);
		   
		   return (byte)byteArrayToInt(b); 
	   }
	   
	   void sshowControlFlags(byte controlFlags) {
		   byte b;
		   controlFlags &= 0b000011111;
		   MyDialog.textfeild.append("Flags: " + controlFlags+"\n");
		   
		   b = (byte) 0b111000000000;
		   if((controlFlags & b) == b) { // 왜 계속 set이 나오는지 모르겠음
			   MyDialog.textfeild.append("----------Reserved: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Reserved: Not set\n");
		   }
		   b = (byte) 0b100000000;
		   if((controlFlags & b) == b) { // 왜 계속 set이 나오는지 모르겠음
			   MyDialog.textfeild.append("----------Nonce: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Nonce: Not set\n");
		   }
		   b = (byte) 0b10000000;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Congestion Window Reduced(CWR): Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Congestion Window Reduced(CWR): Not set\n");
		   }
		   b = (byte) 0b1000000;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------ECN-Echo: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-ECN-Echo: Not set\n");
		   }
		   b = (byte) 0b100000;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Urgent: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Urgent: Not set\n");
		   }
		   b = (byte) 0b10000;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Acknowledgment: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Acknowledgment: Not set\n");
		   }
		   b = (byte) 0b1000;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Push: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Push: Not set\n");
		   }
		   b = (byte) 0b100;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Reset: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Reset: Not set\n");
		   }
		   b = (byte) 0b10;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Syn: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Syn: Not set\n");
		   }
		   b = (byte) 0b1;
		   if((controlFlags & b) == b) {
			   MyDialog.textfeild.append("----------Fin: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Fin: Not set\n");
		   }
	   }
	   
	   void showControlFlags(byte controlFlags) {
		   byte b;
		   controlFlags &= 0b000011111;
		   System.out.printf("Flags: 0x%03x\n", controlFlags);
		   
		   b = (byte) 0b111000000000;
		   if((controlFlags & b) == b) { // 왜 계속 set이 나오는지 모르겠음
			   System.out.println("----------Reserved: Set");
		   }
		   else {
			   System.out.println("-Reserved: Not set");
		   }
		   b = (byte) 0b100000000;
		   if((controlFlags & b) == b) { // 왜 계속 set이 나오는지 모르겠음
			   System.out.println("----------Nonce: Set");
		   }
		   else {
			   System.out.println("-Nonce: Not set");
		   }
		   b = (byte) 0b10000000;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Congestion Window Reduced(CWR): Set");
		   }
		   else {
			   System.out.println("-Congestion Window Reduced(CWR): Not set");
		   }
		   b = (byte) 0b1000000;
		   if((controlFlags & b) == b) {
			   System.out.println("----------ECN-Echo: Set");
		   }
		   else {
			   System.out.println("-ECN-Echo: Not set");
		   }
		   b = (byte) 0b100000;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Urgent: Set");
		   }
		   else {
			   System.out.println("-Urgent: Not set");
		   }
		   b = (byte) 0b10000;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Acknowledgment: Set");
		   }
		   else {
			   System.out.println("-Acknowledgment: Not set");
		   }
		   b = (byte) 0b1000;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Push: Set");
		   }
		   else {
			   System.out.println("-Push: Not set");
		   }
		   b = (byte) 0b100;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Reset: Set");
		   }
		   else {
			   System.out.println("-Reset: Not set");
		   }
		   b = (byte) 0b10;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Syn: Set");
		   }
		   else {
			   System.out.println("-Syn: Not set");
		   }
		   b = (byte) 0b1;
		   if((controlFlags & b) == b) {
			   System.out.println("----------Fin: Set");
		   }
		   else {
			   System.out.println("-Fin: Not set");
		   }
	   }
	   
	   byte parseFragmentFlags() {
		   byte[] b = new byte[2];
		   System.arraycopy(packetByteArray, 20, b, 0, 2);
		   
		   return (byte)byteArrayToInt(b); 
	   }
	   
	   void sshowFragmentFlags(byte fragmentFlags) { // 나중에 고칠 예청
		   byte b;
		   MyDialog.textfeild.append("Flags: " + fragmentFlags+"\n");
		   
		   b = (byte) 0b1000000000000000;
		   if((fragmentFlags & b) == b) { 
			   MyDialog.textfeild.append("----------Reserved bit: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-Reserved bit: Not set\n");
		   }
		   b = (byte) 0b100000000000000;
		   if((fragmentFlags & b) == b) { 
			   MyDialog.textfeild.append("----------Don't fragment: Set\n");
		   }
		   else {
			   System.out.println("-Don't fragment: Not set\n");
		   }
		   b = (byte) 0b10000000000000;
		   if((fragmentFlags & b) == b) { 
			   MyDialog.textfeild.append("----------More fragments: Set\n");
		   }
		   else {
			   MyDialog.textfeild.append("-More fragments: Not set\n");
		   }
		   int temp = fragmentFlags & 0b1111111111111;
		   MyDialog.textfeild.append("-Fragment offset: " + temp+"\n");
	   }
	   
	   void showFragmentFlags(byte fragmentFlags) { // 나중에 고칠 예청
		   byte b;
		   System.out.printf("Flags: 0x%03x\n", fragmentFlags);
		   
		   b = (byte) 0b1000000000000000;
		   if((fragmentFlags & b) == b) { 
			   System.out.println("----------Reserved bit: Set");
		   }
		   else {
			   System.out.println("-Reserved bit: Not set");
		   }
		   b = (byte) 0b100000000000000;
		   if((fragmentFlags & b) == b) { 
			   System.out.println("----------Don't fragment: Set");
		   }
		   else {
			   System.out.println("-Don't fragment: Not set");
		   }
		   b = (byte) 0b10000000000000;
		   if((fragmentFlags & b) == b) { 
			   System.out.println("----------More fragments: Set");
		   }
		   else {
			   System.out.println("-More fragments: Not set");
		   }
		   System.out.printf("-Fragment offset: %d\n", fragmentFlags & 0b1111111111111);
	   }
	   
	   static String byteArrayToHex(byte[] a) {
	      StringBuilder sb = new StringBuilder();
	      for(final byte b: a)
	         sb.append(String.format("%02x ", b&0xff));
	      return sb.toString();
	   }
	   
	   private static int byteArrayToInt(byte[] bytes) {
			final int size = Integer.SIZE / 8;
			ByteBuffer buff = ByteBuffer.allocate(size);
			final byte[] newBytes = new byte[size];
			for (int i = 0; i < size; i++) {
				if (i + bytes.length < size) {
					newBytes[i] = (byte) 0x00;
				} else {
					newBytes[i] = bytes[i + bytes.length - size];
				}
			}
			buff = ByteBuffer.wrap(newBytes);
			buff.order(ByteOrder.BIG_ENDIAN); // Endian에 맞게 세팅
			return buff.getInt();
		}

	}