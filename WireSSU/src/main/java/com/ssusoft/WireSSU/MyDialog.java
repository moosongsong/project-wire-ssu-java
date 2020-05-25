package com.ssusoft.WireSSU;

import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Iterator;
import java.util.Vector;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.WindowConstants;
import javax.swing.table.DefaultTableModel;

public class MyDialog extends JDialog implements Runnable {
	   JTable listTable;   
	   static JTextArea textfeild;
	   JScrollPane listscroll, textscroll;
	   JPanel listPanel;
	   Vector<String> userColumn = new Vector<String>();
	    DefaultTableModel model;
	    Vector<String> userRow;
	    int lin = 0;
	    private String title;
	    
	    public MyDialog(JFrame frame, final String title) { //title == 소통ip
	        super(frame,"Packet analysis", true);
	        this.title = title;
	        setBounds(100,100,1000,800);   //Dialog size(x위치, y위치, 넓이, 높이)
	        setResizable(true);   //사용자가 크기 조절 가능한 지 설정
	        
	        userColumn.addElement("seq");
	        userColumn.addElement("source IP");
	        userColumn.addElement("destination IP");   //칼럼 정하기
	        
	        model = new DefaultTableModel(userColumn,0) {
	            public boolean isCellEditable(int i, int c) {
	               return false;
	            }
	        }; //테이블 모델 생성(table내용 편집 안되게 설정)
	        listTable = new JTable(model);   //테이블 생성
	        listTable.getTableHeader().setReorderingAllowed(false);   //컬럼 이동 불가
	        listscroll = new JScrollPane(listTable);   //테이블 스크롤바 생성
	        
	        listPanel = new JPanel();   //패널생성
	        listPanel.setLayout(new GridLayout(2,1));   //패널 레이아웃 설정
	        
	        textfeild = new JTextArea();
	        textfeild.setEditable(false);
	        textscroll = new JScrollPane(textfeild);   //텍스트필드 스크롤바 설정
	        
	        listPanel.add(listscroll);   //패널에 스크롤바테이블 붙이기
	        listPanel.add(textscroll);   //패널에 텍스트필드 붙이기
	        add(listPanel);   //패널 frame에 붙이기
	        
	        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);   //x눌렀을 때 종료
	        listTable.addMouseListener(new MouseAdapter() {
	           public void mouseClicked(MouseEvent me) {
	              int row = listTable.getSelectedRow();
	              
	              textfeild.setText(null);
	               textfeild.append(row+"번이 선택되었습니다.\n");
	               PacketSniffing.whichIp.get(title).get(row).sshowAll();
	           }
	        });
	        
	    }
	     
	    public void run() {
	    	Iterator<PacketData> lia = PacketSniffing.whichIp.get(title).listIterator();
	        
//	        tablelist에 linkedlist띄우기
	        while(true) {
	        	if ( lia.hasNext() == true ) {
	 	           userRow = new Vector<String>();
	 	           PacketData point = lia.next();
	 	           
	 	           userRow.addElement(PacketSniffing.whichIp.get(title).get(lin).getNumtoString());
	 	           userRow.addElement(PacketSniffing.whichIp.get(title).get(lin).getSrcIp());
	 	           userRow.addElement(PacketSniffing.whichIp.get(title).get(lin).getDstIp());
	 	           
	 	           model.addRow(userRow);
	 	           lin++;
	 	        }
	        	else {
	        		
	        	}
	        }
	    	
	    }
	    
	}