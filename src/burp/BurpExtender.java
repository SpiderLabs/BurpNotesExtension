/*
 *	Burp Notes Extension - A plugin for Burp Suite that adds text documents and spreadsheets.
 *	Austin Lane<alane@trustwave.com>
 *	Copyright (C) 2013 Trustwave Holdings, Inc.
 *	
 *	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *	
 *	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import com.trustwave.burp.NotesExtensionOperations;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionStateListener;
import burp.ITab;

public class BurpExtender implements IBurpExtender, ITab, ActionListener, IExtensionStateListener, IContextMenuFactory
{
	private NotesExtensionOperations ops;

    public final String TAB_NAME = "Notes";
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks Callbacks)
    {
    	//Set up our extension operations
    	this.ops = new NotesExtensionOperations(Callbacks);
        
        //name our extension
        ops.callbacks.setExtensionName("Burp Notes Extension");

        //Our main and error output
        ops.stdout = new PrintWriter(ops.callbacks.getStdout(), true);
        ops.errout = new PrintWriter(ops.callbacks.getStderr(), true);

        // register ourselves as an extension state listener
        ops.callbacks.registerExtensionStateListener(this);
        
        //register to produce options for the context menu
        ops.callbacks.registerContextMenuFactory(this);
        
        //Keep track of our documents and types
        ops.tabTypes = new HashMap<String, String>();
        
        SwingUtilities.invokeLater(new Runnable(){
        	@Override
        	public void run(){
        		//Create our initial UI components
        		ops.tabbedPane = new JTabbedPane();
        		JPanel panel = new JPanel(new BorderLayout());
                //Tab Management
                ops.tabList = new JComboBox();
                ops.tabList.addItem("Choose...");
                ops.btnSaveTabAsTemplate = new JButton("Export Tab");
                ops.btnSaveTabAsTemplate.setActionCommand(NotesExtensionOperations.COMMAND_SAVE_TAB_AS_TEMPLATE);
                ops.btnSaveTabAsTemplate.addActionListener(BurpExtender.this); 
                ops.btnRemoveTab = new JButton("Remove Tab");
                ops.btnRemoveTab.setActionCommand(NotesExtensionOperations.COMMAND_REMOVE_TAB);
                ops.btnRemoveTab.addActionListener(BurpExtender.this); 

        		//Add the save,load, and document buttons
                ops.btnAddText = new JButton("New Text");
                ops.btnAddText.setActionCommand(NotesExtensionOperations.COMMAND_ADD_TEXT);
                ops.btnAddText.addActionListener(BurpExtender.this);
                ops.btnAddSpreadsheet = new JButton("New Spreadsheet");
                ops.btnAddSpreadsheet.setActionCommand(NotesExtensionOperations.COMMAND_ADD_SPREADSHEET);
                ops.btnAddSpreadsheet.addActionListener(BurpExtender.this);
                ops.btnImportText = new JButton("Import Text");
                ops.btnImportText.setActionCommand(NotesExtensionOperations.COMMAND_IMPORT_TEXT);
                ops.btnImportText.addActionListener(BurpExtender.this);
                ops.btnImportSpreadsheet = new JButton("Import Spreadsheet");
                ops.btnImportSpreadsheet.setActionCommand(NotesExtensionOperations.COMMAND_IMPORT_SPREADSHEET);
                ops.btnImportSpreadsheet.addActionListener(BurpExtender.this);
                ops.btnSaveNotes = new JButton("Save Notes");
                ops.btnSaveNotes.setActionCommand(NotesExtensionOperations.COMMAND_SAVE_NOTES);
                ops.btnSaveNotes.addActionListener(BurpExtender.this);
                ops.btnLoadNotes = new JButton("Load Notes");
                ops.btnLoadNotes.setActionCommand(NotesExtensionOperations.COMMAND_LOAD_NOTES);
                ops.btnLoadNotes.addActionListener(BurpExtender.this);

                //Make our panel with a grid layout for arranging the buttons
                JPanel topPanel = new JPanel();
                topPanel.add(ops.tabList);
                topPanel.add(ops.btnSaveTabAsTemplate);
                topPanel.add(ops.btnRemoveTab);
                topPanel.setPreferredSize(new Dimension(500,100));
                panel.add(topPanel, BorderLayout.PAGE_START);
                JPanel spaceLeft = new JPanel();
                spaceLeft.setPreferredSize(new Dimension(300,200));
                panel.add(spaceLeft, BorderLayout.LINE_START);
                JPanel buttonPanel = new JPanel(new GridLayout(3,2));
                buttonPanel.add(ops.btnSaveNotes);
                buttonPanel.add(ops.btnLoadNotes);
                buttonPanel.add(ops.btnAddText);
                buttonPanel.add(ops.btnAddSpreadsheet);
                buttonPanel.add(ops.btnImportText);
                buttonPanel.add(ops.btnImportSpreadsheet);
                buttonPanel.setPreferredSize(new Dimension(150,150));
                panel.add(buttonPanel, BorderLayout.CENTER);
                JPanel spaceRight = new JPanel();
                spaceRight.setPreferredSize(new Dimension(300,200));
                panel.add(spaceRight, BorderLayout.LINE_END);
                JPanel spaceBottom = new JPanel();
                spaceBottom.setPreferredSize(new Dimension(500,250));
                panel.add(spaceBottom, BorderLayout.PAGE_END);
        		ops.tabbedPane.addTab("Main", panel);
        		ops.callbacks.customizeUiComponent(ops.tabbedPane);
                
                //Add our tab to the suite
                ops.callbacks.addSuiteTab(BurpExtender.this);
        	}
        });
    }

	@Override
	public String getTabCaption() {
		return TAB_NAME;
	}

	@Override
	public Component getUiComponent() {
		return ops.tabbedPane;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String cmd = e.getActionCommand();
		ops.ParseAction(cmd);
		
	}

	@Override
	public void extensionUnloaded() {
		//Unloading extension, prompt user to save data if they have any tabs
		if(ops.tabbedPane.getTabCount() > 1){
			Object[] options = {"Yes", "No"};
			int n = JOptionPane.showOptionDialog(ops.tabbedPane, "Would you like to save your notes?", "Notes Tab", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
			if(n == JOptionPane.YES_OPTION){
				ops.SaveNotes();
			}
		}
        ops.stdout.println("Extension was unloaded");
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		return ops.CreateMenuItems(invocation, this);
	}
}

