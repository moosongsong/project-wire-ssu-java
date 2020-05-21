package com.ssusoft.WireSSU;

import java.awt.Color;
import java.awt.Font;

import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;

public class CreateMenu {
	JMenuBar mb = new JMenuBar();
	
	public CreateMenu() {
		JMenu mn = new JMenu("System");
		mb.setBackground(new Color(240, 240, 240));
		Font f = new Font("Dialog", Font.PLAIN, 18);
		mn.setFont(f);
		
		JMenuItem[] mni = new JMenuItem[3];
		String[] title = {"Start", "Stop", "Exit"};
		Font ff = new Font("Dialog", Font.PLAIN, 16);
		
		MenuActionListener listener = new MenuActionListener();
		for(int i = 0; i < mni.length; i++) {
			mni[i] = new JMenuItem(title[i]);
			mni[i].setFont(ff);
			mni[i].addActionListener(listener);
			mn.add(mni[i]);
			if(i < 2) mn.addSeparator();
		}
		
		mb.add(mn);
	}
}