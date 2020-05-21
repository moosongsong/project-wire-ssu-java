package com.ssusoft.WireSSU;

import javax.swing.JFrame;

public class Main extends JFrame {
	public static Runnable ps = new PacketSniffing();
	public static Thread pst = null;
	
   public static void main(String [] args) {
       MainFrame fm = new  MainFrame();     
   }
}

