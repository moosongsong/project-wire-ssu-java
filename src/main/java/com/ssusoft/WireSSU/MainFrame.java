package com.ssusoft.WireSSU;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;

public class MainFrame extends JFrame {
	   
	public static int sizeX, sizeY;//윈도우 가로, 세로
	   public static int xpos, ypos; //윈도우 x, y 위치
	   private static ImageIcon icon = null; //배경 지도
	   public static JPanel panel;
	   public static double bc, jd;
	   public static double xpic = 1024/360;
	   public static double ypic = 536/180;
	   
	   MainFrame(){
	     Dimension dim = Toolkit.getDefaultToolkit().getScreenSize(); //화면 크기 구하기
//	      sizeX = (int)(dim.getWidth()*2/3);   //화면 가로크기 정하기
//	      sizeY = (int)(dim.getHeight()*2/3);   //화면 세로크기 정하기
	      sizeX = 1024;
	      sizeY = 536;
	      bc = xpic*30;
	      jd = (sizeY)/2;
	      xpos = (int)(dim.getWidth()/10);   //화면 x위치 정하기
	      ypos = (int)(dim.getHeight()/10);   //화면 y위치 정하기
	      
	    		  
	      setTitle("WireSSU");//윈도우 이름
	      setSize(sizeX,sizeY);//사이즈 설정
	      setLocation(xpos, ypos);//위치 설정
	      setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);//닫기 누르면 종료
	      
	      icon =new ImageIcon("D:\\Haeri_Data\\2019 1학기\\SoftwareProject\\worldmap2.jpg"); //지도 사진 가져오기
	      
	      panel =new JPanel() {
	         public void paintComponent(Graphics g) {
	             g.drawImage(icon.getImage(), 0, 0, sizeX, (sizeY-65), null);   //이미지 크기 정하기
	             setOpaque(false);
	             super.paintComponent(g);
	            }
	      };
	      
	      panel.setLayout(null);
	      panel.setBackground(new Color(255,217,236));
	      
	      CreateMenu cm = new CreateMenu();
		  setJMenuBar(cm.mb);
		  
//	      makeButton(panel, xpos*2, ypos*4, "me", true);//true 일 경우 빨간색
//	      makeButton(panel, xpos*3, ypos*3, "me", false);//false 일 경우 분홍색
	      
	      this.add(panel);
	      setResizable(false);//윈도우 창 크기 조절 막기
	      setVisible(true);//화면에 띄우기
	   }
      
	   public static void makeButton(JPanel panel, int x, int y, final String s, boolean bool) {
		      ImageIcon imgc = null;
		      if(bool==true) {
		         imgc = new ImageIcon("D:\\Haeri_Data\\2019 1학기\\SoftwareProject\\reddot.png");
		      }
		      
		      Image img = imgc.getImage();
		      Image img2 = img.getScaledInstance(20, 20, java.awt.Image.SCALE_SMOOTH);
		      ImageIcon imgc2 = new ImageIcon(img2);
		      
		      JButton button = new JButton(imgc2);
		      
		      button.setLocation(x, y);
		      button.setSize(10, 10);
		      button.setBorderPainted(false);
		      button.setContentAreaFilled(false);
		      panel.add(button);
		      panel.repaint();
		      
		   
		      button.addActionListener(new ActionListener() {
		               public void actionPerformed(ActionEvent e) {
		            	   MyDialog dialog;
		            	   JFrame jFrame = null;
		            	   dialog = new MyDialog(jFrame, s);
		            	   
		            	   Thread mdthread = null;
		            	   mdthread = new Thread(dialog);
		            	   mdthread.start();
		                   dialog.setVisible(true); // 다이얼로그를 출력하고 작동시킨다.
		               }
		           });
		   }
}