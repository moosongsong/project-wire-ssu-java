package com.ssusoft.WireSSU;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;

public class PacketSniffing implements Runnable {
	   public static HashMap<String, LinkedList<PacketData>> whichIp = new HashMap<String, LinkedList<PacketData>>();
	   public static String myIp;
	   Pcap pcap; 
	   int i;
	   
	   void setLocation(String ip, PacketData pd) throws IOException, GeoIp2Exception {
		   String ipad = ip;
		   String dbLocation = "D:\\DevelopeTools\\GeoIp\\MaxMind database\\GeoLite2-City.mmdb";
		   
		   File database = new File(dbLocation);
		   DatabaseReader dbReader = new DatabaseReader.Builder(database).build();
		   
		   
		   InetAddress ipAddress = InetAddress.getByName(ip);
		   CityResponse response = dbReader.city(ipAddress);
		   
		   String cityName = response.getCity().getName();
		   pd.setCityName(cityName);
		   double latitude = response.getLocation().getLatitude();
		   pd.setLatitude(latitude);
		   double longitude = response.getLocation().getLongitude();
		   pd.setLongitude(longitude);   
	   }

	   public void run() {
		   ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>(); 
	       StringBuilder errbuf = new StringBuilder();
	       
	       int r = Pcap.findAllDevs(allDevs, errbuf); // 1st인자: Pcap으로 접근 가능한 네트워크 디바이스, 2nd인자: 에러처리 
	       
	       if(r == Pcap.NOT_OK || allDevs.isEmpty()) { // Pcap이 동작하지 않거나 접근 가능한 네트워크 디바이스가 없을 경우 에러처리
	         System.out.println("네트워크 장치 찾기 실패." + errbuf.toString());
	          return;
	       }
	       
	       PcapIf device = allDevs.get(3);   
	       
	       myIp = (String) device.getAddresses().toString().subSequence(14, 28);
	       myIp = myIp.split("]")[0];
	       
	       System.out.println("My Ip: "+myIp);
	       
	       int snaplen = 64 *1024; // 65536bytes 만큼 패킷을 캡쳐
	       int flags = Pcap.MODE_PROMISCUOUS; // promiscuous모드로 설정
	       int timeout = 3*1000; // time out을 30초로 설정
	       pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf); // 패킷 캡쳐 활성화
	       
	       if(pcap == null) {
	          System.out.printf("Network Device Access Failed. Error: " + errbuf.toString());
	          return;
	       }
	                
	       Ethernet eth = new Ethernet(); // 2계층 이더넷 맥 주소 객체 생성
	       Ip4 ip = new Ip4(); // 3계층 IP 주소 객체 생성
	       Tcp tcp = new Tcp(); // 4계층 TCP 주소 객체 생성
//	       Payload payload = new Payload(); // 페이로드 객체 생성
	       PcapHeader header = new PcapHeader(JMemory.POINTER); // 캡쳐한 패킷의 헤더 값 객체 생성
	       JBuffer buf = new JBuffer(JMemory.POINTER); // 패킷 관련 버퍼 생성
	       
	       int id = JRegistry.mapDLTToId(pcap.datalink()); // pcap의 datalink유형을 jNetPcap의 프로토콜 ID에 맴핑
	       
	       while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) { // 에러가 발생하지 앟는 한 계속해서 다음 패킷을 입력 받음
	         
	          PcapPacket packet = new PcapPacket(header, buf);
	          
	          packet.scan(id); // 새로운 패킷을 스캔하여 포함된 header를 찾음
	          
	          if(packet.hasHeader(eth) && packet.hasHeader(ip) && packet.hasHeader(tcp)) { // eht, ip, tcp 로 제한
	             PacketData pd = new PacketData(packet);
	             
	             try {
					setLocation(getOtherIp(pd), pd);
				} catch (IOException | GeoIp2Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	             
	             pd.setNum(savePacketData(pd)); // PacketData의 num을 설정하고, LinkedList에 PacketData를 저장
	          }   
	       }
	       pcap.close();
	   }
	   
	   int savePacketData(PacketData pd) { // 패킷을 LinkedList에 저장
	      String otherIp = getOtherIp(pd);
	      double xpoint, ypoint;
	      if(!whichIp.containsKey(otherIp)) { // 처음 만난 Ip 노드 생성 -> 정상작동
	    	  
//	    		  System.out.println(otherIp+"와 처음 만남!!**********************");
	    			 
		          whichIp.put(otherIp, new LinkedList<PacketData>());
		          whichIp.get(otherIp).add(0, pd);
		         // whichIp.get(otherIp).get(0).showAll();
		         
		          // TODO: 점 찍기!!
		          i++;
		          xpoint = whichIp.get(otherIp).get(0).getLongitude();
		          xpoint = xpoint*MainFrame.xpic;
		          ypoint = whichIp.get(otherIp).get(0).getLatitude();
		          ypoint = ypoint*MainFrame.ypic;
		          
//		          if(xpoint == null || ypoint == null)
		          
		          if(xpoint < -30 * MainFrame.xpic ) {
		        	  xpoint += 1024;
		          } else {
		        	  xpoint += MainFrame.bc;
		          }
		          
		          ypoint = MainFrame.jd - ypoint;
		          
		          MainFrame.makeButton(MainFrame.panel, (int)xpoint,
		                (int)ypoint, otherIp, true);

		         
		          return 0;
	    	  
	       } 
	      else {
	          int num = whichIp.get(otherIp).size();
	          pd.setNum(num);
//	          System.out.println(otherIp+"와 "+num+"번째 만남!!****************");
	          whichIp.get(otherIp).add(num, pd);
	         
	          //whichIp.get(otherIp).get(num).showAll();
	         
	          return num;
	      }
	   }
	   
	   String getOtherIp(PacketData pd) { // 패킷을 주고받는 상대방의 Ip 추출
		   if(myIp.equals(pd.getSrcIp())) {
	    	  return pd.getDstIp();
	      }
	      else {
	    	  return pd.getSrcIp();   
	      }
	   }
	}