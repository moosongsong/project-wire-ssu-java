package com.ssusoft.WireSSU;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class MenuActionListener implements ActionListener {
	public void actionPerformed(ActionEvent e) {
		String cmd = e.getActionCommand();
		switch(cmd) {
			case "Start" :
				Main.pst = new Thread(Main.ps);
				Main.pst.setDaemon(true);
				Main.pst.start();
				break;
			case "Stop" :
				Main.pst.stop(); break; 
				
//				Main.pst.interrupt(); // interrupt를 사용하고 싶었으나 정지가 되지 않음
//				try {
//					Main.pst.sleep(500);
//				} catch (InterruptedException ie) {
//					ie.printStackTrace();
//				}
//				break;
				
//				Main.pst = null; // 무송이가 알려준 null로 바꾸는 방법도 해 보았으나 정지가 되지 않음
//				break;
			case "Exit" :
				System.exit(1);
			default :
				break;
		}
	}
}