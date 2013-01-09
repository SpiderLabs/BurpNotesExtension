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
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

import javax.swing.JButton;
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
    private JButton btnAddText, btnAddSpreadsheet, btnLoadNotes, btnSaveNotes;

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
        		JPanel panel = new JPanel();
        		//Add the save,load, and document buttons
                btnAddText = new JButton("Add Text");
                btnAddText.setActionCommand(NotesExtensionOperations.COMMAND_ADD_TEXT);
                btnAddText.addActionListener(BurpExtender.this);
                btnAddSpreadsheet = new JButton("Add Spreadsheet");
                btnAddSpreadsheet.setActionCommand(NotesExtensionOperations.COMMAND_ADD_SPREADSHEET);
                btnAddSpreadsheet.addActionListener(BurpExtender.this);
                btnSaveNotes = new JButton("Save Notes");
                btnSaveNotes.setActionCommand(NotesExtensionOperations.COMMAND_SAVE_NOTES);
                btnSaveNotes.addActionListener(BurpExtender.this);
                btnLoadNotes = new JButton("Load Notes");
                btnLoadNotes.setActionCommand(NotesExtensionOperations.COMMAND_LOAD_NOTES);
                btnLoadNotes.addActionListener(BurpExtender.this);

                //Make our panel with a grid layout for arranging the buttons
                panel.setLayout(new GridLayout(3, 3));
                panel.add(btnSaveNotes);
                panel.add(btnLoadNotes);
                panel.add(btnAddText);
                panel.add(btnAddSpreadsheet);
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
			int n = JOptionPane.showOptionDialog(getUiComponent(), "Would you like to save your notes?", "Notes Tab", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
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

