# -*- coding: utf-8 -*-
# search for # Default payloads to change default payloads
import threading
import binascii
import json
import re
import base64
import codecs
import traceback
import os
import time
from collections import OrderedDict
from copy import deepcopy
from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JLabel, JTabbedPane, JToolBar, JMenuItem, JOptionPane, JSpinner, SpinnerNumberModel, JComboBox, ButtonGroup, JRadioButton,
    SwingUtilities, JFileChooser, JSplitPane, JTable, JScrollPane, JTextField, JCheckBox, DefaultCellEditor, BorderFactory, BoxLayout, Box,
    SwingConstants, JToggleButton, JPopupMenu, ImageIcon, ListSelectionModel, JTextArea, JList, UIManager, OverlayLayout, JProgressBar, JEditorPane
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import ( BorderLayout, Dimension, FlowLayout, Color, Cursor, Dimension, Rectangle, Robot, Graphics2D, Graphics, Font, CardLayout,
    GridBagLayout, GridBagConstraints, Insets, Component, GridLayout
)
from java.awt.event import MouseAdapter, ActionListener, MouseEvent, FocusAdapter, KeyAdapter, KeyEvent, ComponentAdapter
from java.util import ArrayList
from javax.swing.event import ChangeListener
from java.lang import Boolean, Integer
from java.io import File
from javax.imageio import ImageIO
from java.net import URL

### ---------bac
# Global per-host BAC config storage
BAC_HOST_CONFIGS = {}
LAST_EXPORT_DIR_KEY = "last-export-directory"
LAST_POC_EXPORT_DIR_KEY = "last-poc-export-directory"
LAST_BAC_ROLE_DIR_KEY = "last-bac-role-directory"
LAST_PAYLOAD_STATE = {}

def extract_json_keys_recursive(data, path="", keys=None):
    if keys is None:
        keys = []
    
    if isinstance(data, dict):
        if not data and path and path not in keys:
            keys.append(path)
        else:
            for k, v in data.items():
                new_path = (path + "." + k) if path else k
                extract_json_keys_recursive(v, new_path, keys)
    elif isinstance(data, list):
        if not data and path and path not in keys:
            keys.append(path)
        else:
            for i, item in enumerate(data):
                new_path = path + "[%d]" % i
                extract_json_keys_recursive(item, new_path, keys)
    else:
        if path and path not in keys:
            keys.append(path)
            
    return keys

def set_nested_value(obj, path, value):
    # Split into names and bracket indices separately, e.g.
    # "contextUrns[0].inner[2]" -> ['contextUrns', '[0]', 'inner', '[2]']
    tokens = re.findall(r'[^.\[\]]+|\[\d+\]', path)

    def set_recursively(container, idx, val):
        if idx >= len(tokens):
            return

        tok = tokens[idx]
        is_last = (idx == len(tokens) - 1)

        if tok.startswith('['):  # list index like [0]
            i = int(tok[1:-1])
            # Ensure container is a list
            if not isinstance(container, list):
                # If it's None, convert to list; otherwise assume structure is valid JSON
                raise TypeError("Expected list while setting %s in path %s" % (tok, path))
            # Grow list if needed
            while len(container) <= i:
                container.append(None)
            if is_last:
                container[i] = val
            else:
                # Ensure next level exists
                if container[i] is None:
                    # Decide next node type based on next token
                    nxt = tokens[idx + 1]
                    container[i] = [] if nxt.startswith('[') else {}
                set_recursively(container[i], idx + 1, val)
        else:
            # dict key
            if not isinstance(container, dict):
                raise TypeError("Expected dict while setting %s in path %s" % (tok, path))
            if is_last:
                container[tok] = val
            else:
                if tok not in container or container[tok] is None:
                    nxt = tokens[idx + 1]
                    container[tok] = [] if nxt.startswith('[') else {}
                set_recursively(container[tok], idx + 1, val)

    set_recursively(obj, 0, value)
    return obj



def coerce_json_value(payload):
    """
    Mini type-hinting syntax for users:
      - If it starts with '='  -> parse the rest with json.loads (raw JSON literal)
      - If it starts with 'json:' or 'raw:' -> parse the rest with json.loads (raw)
      - If it starts with 'str:' -> force string (strip the prefix)
      - Otherwise -> keep original string (current behavior)
    """
    p = payload.strip()
    if p.startswith('='):
        return json.loads(p[1:].strip())
    if p.lower().startswith('json:') or p.lower().startswith('raw:'):
        return json.loads(p.split(':', 1)[1].strip())
    if p.lower().startswith('str:'):
        return p.split(':', 1)[1]
    return payload


def to_pairs(l):
    if not l:
        return []
    if isinstance(l[0], (list, tuple)) and len(l[0]) == 2:
        return l
    return [(v, True) for v in l]

def save_setting(callbacks, key, value):
    # Try to use project-specific setting if available
    if hasattr(callbacks, "saveProjectSetting"):
        try:
            callbacks.saveProjectSetting(key, value)
            return
        except Exception:
            pass
    # Fallback to extension-wide
    callbacks.saveExtensionSetting(key, value)

def load_setting(callbacks, key):
    # Try to use project-specific setting if available
    if hasattr(callbacks, "loadProjectSetting"):
        try:
            v = callbacks.loadProjectSetting(key)
            return v
        except Exception:
            pass
    # Fallback to extension-wide
    return callbacks.loadExtensionSetting(key)

# Helper to serialize to Burp project file (use in BurpExtender)
def save_bac_configs(callbacks):
    try:
        save_setting(callbacks, "bac-host-configs", json.dumps(BAC_HOST_CONFIGS))
    except Exception as e:
        print("[-] Error saving BAC configs:", e)


def load_bac_configs(callbacks):
    global BAC_HOST_CONFIGS
    try:
        raw = load_setting(callbacks, "bac-host-configs")
        if raw:
            BAC_HOST_CONFIGS = json.loads(raw)
    except Exception as e:
        print("[-] Error loading BAC configs:", e)


### ------------------- Table Models ----------------------
class BooleanColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if bool(value):
            comp.setForeground(Color(0, 153, 0))  # green
        else:
            comp.setForeground(Color(204, 0, 0))  # red
        return comp

class ListBoolTableModel(AbstractTableModel):
    def __init__(self, title, items):
        self.title = title
        self.rows = []
        for x in items:
            if isinstance(x, (list, tuple)) and len(x) == 2:
                self.rows.append([x[0], Boolean(x[1])])
            else:
                self.rows.append([x, Boolean(True)])

    def getRowCount(self): return len(self.rows)
    def getColumnCount(self): return 2
    def getColumnName(self, col): return [self.title, "Enabled"][col]
    def getValueAt(self, row, col): return self.rows[row][col]  # 0=payload, 1=enabled
    def setValueAt(self, value, row, col):
        if col == 1:
            if isinstance(value, bool): 
                value = Boolean(value)
            elif isinstance(value, str): 
                value = Boolean(value.lower() == "true")
            self.rows[row][col] = value
            self.fireTableCellUpdated(row, col)
            # Crucial: Immediately update global state after checkbox change
            if hasattr(self, 'parent_panel') and hasattr(self.parent_panel, 'refresh_global_payload_state'):
                self.parent_panel.refresh_global_payload_state()
    def isCellEditable(self, row, col): return col == 1
    def getColumnClass(self, col): return Boolean.TYPE if col == 1 else str

    def addItem(self, item, enabled=True):
        self.rows.append([item, Boolean(enabled)])
        self.fireTableDataChanged()
    def removeItems(self, row_indices):
        for row in sorted(row_indices, reverse=True):
            if 0 <= row < len(self.rows):
                del self.rows[row]
        self.fireTableDataChanged()
    def get_enabled(self): return [x[0] for x in self.rows if x[1] is True or x[1] == Boolean(True)]

class ListBoolTablePanel(JPanel):
    def __init__(self, label, items, editable=True, default_items=None):
        JPanel.__init__(self)
        self.setLayout(BorderLayout())
        self.default_items = default_items

        # Create a horizontal panel for label (left) and checkbox (right)
        header_panel = JPanel()
        # from java.awt import FlowLayout
        header_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        header_panel.add(JLabel(label))
        header_panel.add(Box.createHorizontalStrut(10))  # Optional: for spacing
        self.master_toggle = JCheckBox("Enable all", True, actionPerformed=self.toggle_all)
        header_panel.add(self.master_toggle)

        if editable and self.default_items is not None:
            self.reset_btn = JButton("Reset", actionPerformed=self.reset_to_default)
            header_panel.add(Box.createHorizontalStrut(5))
            header_panel.add(self.reset_btn)

        self.add(header_panel, BorderLayout.NORTH)

        self.model = ListBoolTableModel(label, items)
        self.model.parent_panel = self
        self.table = JTable(self.model)
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.getColumnModel().getColumn(1).setCellRenderer(BooleanColorRenderer())
        self.table.getColumnModel().getColumn(1).setCellEditor(DefaultCellEditor(JCheckBox()))
        self.add(JScrollPane(self.table), BorderLayout.CENTER)

        if editable:
            ctrl = JPanel()
            self.new_item = JTextField(18)
            self.add_btn = JButton("+", actionPerformed=self.add_item)
            self.add_btn.setPreferredSize(Dimension(32, 24))
            self.add_btn.setMaximumSize(Dimension(32, 24))
            self.add_btn.setMinimumSize(Dimension(24, 24))

            self.bulk_add_btn = JButton("Bulk", actionPerformed=self.bulk_add_items)
            self.bulk_add_btn.setPreferredSize(Dimension(56, 24))
            self.bulk_add_btn.setMaximumSize(Dimension(56, 24))
            self.bulk_add_btn.setMinimumSize(Dimension(36, 24))

            self.remove_btn = JButton("-", actionPerformed=self.remove_item)
            self.remove_btn.setPreferredSize(Dimension(32, 24))
            self.remove_btn.setMaximumSize(Dimension(32, 24))
            self.remove_btn.setMinimumSize(Dimension(24, 24))

            ctrl.add(self.new_item)
            ctrl.add(self.add_btn)
            ctrl.add(self.remove_btn)
            ctrl.add(self.bulk_add_btn)
            self.add(ctrl, BorderLayout.SOUTH)
        else:
            self.new_item = None
            self.add_btn = None
            self.remove_btn = None
    def refresh_global_payload_state(self):
        # Only update if this is a payloads panel (not a param panel)
        if hasattr(self, 'is_payloads_panel') and self.is_payloads_panel and hasattr(self, 'parent_payload_panel'):
            parent = self.parent_payload_panel
            url_rows = [(str(r[0]), bool(r[1]) if len(r)>1 else True) for r in parent.url_payloads_panel.model.rows]
            body_rows = [(str(r[0]), bool(r[1]) if len(r)>1 else True) for r in parent.body_payloads_panel.model.rows]
            global LAST_PAYLOAD_STATE
            LAST_PAYLOAD_STATE["url_payloads"] = url_rows
            LAST_PAYLOAD_STATE["body_payloads"] = body_rows
            try:
                if hasattr(self, 'parent_payload_panel') and hasattr(self.parent_payload_panel, 'callbacks'):
                    self.parent_payload_panel.callbacks.saveExtensionSetting(
                        "last_payload_state",
                        json.dumps(LAST_PAYLOAD_STATE)
                    )
            except Exception:
                pass

    def toggle_all(self, event):
        checked = self.master_toggle.isSelected()
        for row in self.model.rows:
            row[1] = Boolean(checked)
        self.model.fireTableDataChanged()
    
    def sync_payload_globals(self):
        if hasattr(self, 'is_payloads_panel') and self.is_payloads_panel:
            url_state = [(str(r[0]), bool(r[1]) if len(r) > 1 else True) for r in self.model.rows] if self.payload_type == "url" else []
            body_state = [(str(r[0]), bool(r[1]) if len(r) > 1 else True) for r in self.model.rows] if self.payload_type == "body" else []
            update_last_payload_state(url_state, body_state)

    def add_item(self, event):
        if self.new_item:
            val = self.new_item.getText()
            if val and val not in [r[0] for r in self.model.rows]:
                self.model.addItem(val)
                self.new_item.setText("")
        self.refresh_global_payload_state()
        

    def remove_item(self, event):
        selected_rows = self.table.getSelectedRows()
        if selected_rows is not None and len(selected_rows) > 0:
            self.model.removeItems(selected_rows)
        self.refresh_global_payload_state()
        

    def get_enabled(self):
        return self.model.get_enabled()
    
    def bulk_add_items(self, event):
        area = JTextArea(6, 30)
        scroll = JScrollPane(area)
        prompt = "Paste payloads (comma or newline separated):"
        res = JOptionPane.showConfirmDialog(self, scroll, prompt, JOptionPane.OK_CANCEL_OPTION)
        if res == JOptionPane.OK_OPTION:
            text = area.getText()
            items = []
            # Support both comma and newlines as separator
            # Split by newline first, then by comma
            for line in text.split('\n'):
                for part in line.split(','):
                    part = part.strip()
                    if part:
                        items.append(part)
            # Avoid duplicates
            existing = set([r[0] for r in self.model.rows])
            for item in items:
                if item not in existing:
                    self.model.addItem(item)
                    existing.add(item)
        self.refresh_global_payload_state()
        
    def reset_to_default(self, event):
        if self.default_items is not None:
            # Rebuild the model's data from the default list
            self.model.rows = [[item, Boolean(True)] for item in self.default_items]
            self.model.fireTableDataChanged()
            # Ensure the UI reflects the new state
            self.master_toggle.setSelected(True)
            self.refresh_global_payload_state()
                        
    

class PayloadSidePanel(JPanel):
    def __init__(self, url_params, url_payloads, body_params, body_payloads, default_url_payloads=None, default_body_payloads=None):
        JPanel.__init__(self)
        # import javax.swing  # for BoxLayout
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Param Probe"),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        # Set editable=False for parameter tables, editable=True for payload tables
        self.url_params_panel = ListBoolTablePanel("URL Parameters", url_params, editable=False)
        # Ensure payloads are always list of (value, enabled)
        self.url_payloads_panel = ListBoolTablePanel("URL Payloads", to_pairs(url_payloads), editable=True, default_items=default_url_payloads)
        self.body_params_panel = ListBoolTablePanel("Body Parameters", body_params, editable=False)
        self.body_payloads_panel = ListBoolTablePanel("Body Payloads", to_pairs(body_payloads), editable=True, default_items=default_body_payloads)
        self.add(self.url_params_panel)
        self.add(self.url_payloads_panel)
        self.add(self.body_params_panel)
        self.add(self.body_payloads_panel)
        self.url_payloads_panel.parent_payload_panel = self
        self.body_payloads_panel.parent_payload_panel = self
        self.url_payloads_panel.is_payloads_panel = True
        self.url_payloads_panel.payload_type = "url"
        self.body_payloads_panel.is_payloads_panel = True
        self.body_payloads_panel.payload_type = "body"
    def get_url_params(self): return self.url_params_panel.get_enabled()
    def get_url_payloads(self): return self.url_payloads_panel.get_enabled()
    def get_body_params(self): return self.body_params_panel.get_enabled()
    def get_body_payloads(self): return self.body_payloads_panel.get_enabled()
    def save_global_payload_state(self):
        global LAST_PAYLOAD_STATE
        # Store (payload, enabled) tuples for both
        url_rows = [(str(r[0]), bool(r[1]) if len(r) > 1 else True) for r in self.url_payloads_panel.model.rows]
        body_rows = [(str(r[0]), bool(r[1]) if len(r) > 1 else True) for r in self.body_payloads_panel.model.rows]
        LAST_PAYLOAD_STATE["url_payloads"] = url_rows
        LAST_PAYLOAD_STATE["body_payloads"] = body_rows
    

### ------------------ BAC tab ----------------------------
class BACCheckPanel(JPanel):
    def __init__(self, host, req_headers, on_save_callback=None, callbacks=None, single_check_handler=None):
        JPanel.__init__(self)
        self.host = host
        self.single_check_handler = single_check_handler
        self.req_headers = req_headers
        self.on_save_callback = on_save_callback
        self.callbacks = callbacks
        self.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Role Probe"),
            BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ))
        self.setLayout(BorderLayout())
        self.setMinimumSize(Dimension(450, 500))  # Optimal minimum size for full functionality
        self.role_data = []
        self.role_tabs = JTabbedPane(JTabbedPane.TOP)
        self.role_tabs.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT)  # Changed to WRAP for grid format
        self.role_tabs.setTabPlacement(JTabbedPane.TOP)
        self.role_tabs.setMinimumSize(Dimension(450, 200))  # Match panel minimum width
        
        # --- Top panel: compact left-aligned strip -------------------------------
        top_panel = JPanel(BorderLayout())

        left_strip = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))  # hug the left, zero gaps

        # Move buttons: glued together
        self.move_left_btn  = JButton("<")
        self.move_right_btn = JButton(">")

        for b in (self.move_left_btn, self.move_right_btn):
            b.setPreferredSize(Dimension(30, 28))
            b.setMinimumSize(Dimension(30, 28))
            b.setFocusable(False)
            b.setFont(Font("Dialog", Font.BOLD, 13))
            b.setMargin(Insets(0, 0, 0, 0))

        self.move_left_btn.setToolTipText("Move selected role left")
        self.move_left_btn.addActionListener(self.move_selected_left)
        self.move_right_btn.setToolTipText("Move selected role right")
        self.move_right_btn.addActionListener(self.move_selected_right)

        left_strip.add(self.move_left_btn)
        left_strip.add(self.move_right_btn)

        # Small gap, then Enable all
        left_strip.add(Box.createHorizontalStrut(8))
        self.enable_all_checkbox = JCheckBox("Enable all", True, actionPerformed=self.toggle_all_roles)
        left_strip.add(self.enable_all_checkbox)

        # Bigger Export / Import buttons
        self.export_bac_btn = JButton(u"\u21EA", actionPerformed=self.export_bac_roles)  # ⇪
        self.export_bac_btn.setToolTipText("Export roles")
        self.export_bac_btn.setMargin(Insets(0, 0, 0, 0))
        # bigger glyph without changing the family (safer across LAFs)
        self.export_bac_btn.setFont(self.export_bac_btn.getFont().deriveFont(20.0))
        # if glyph is missing, try: self.export_bac_btn.setFont(Font("Segoe UI Symbol", Font.PLAIN, 20))
        self.export_bac_btn.setPreferredSize(Dimension(30, 30))
        self.export_bac_btn.setMinimumSize(Dimension(30, 30))
        self.export_bac_btn.setMaximumSize(Dimension(30, 30))

        self.import_bac_btn = JButton(u"\u2B73", actionPerformed=self.import_bac_roles)  # ⭳
        self.import_bac_btn.setToolTipText("Import roles")
        self.import_bac_btn.setMargin(Insets(0, 0, 0, 0))
        self.import_bac_btn.setFont(self.import_bac_btn.getFont().deriveFont(20.0))
        # if glyph is missing, try: self.import_bac_btn.setFont(Font("Segoe UI Symbol", Font.PLAIN, 20))
        self.import_bac_btn.setPreferredSize(Dimension(30, 30))
        self.import_bac_btn.setMinimumSize(Dimension(30, 30))
        self.import_bac_btn.setMaximumSize(Dimension(30, 30))

        for b in (self.export_bac_btn, self.import_bac_btn):
            b.setMargin(Insets(0, 0, 0, 0))
            b.setPreferredSize(Dimension(30, 30))
            b.setMinimumSize(Dimension(30, 30))
            b.setMaximumSize(Dimension(30, 30))
            b.setHorizontalAlignment(SwingConstants.CENTER)
            b.setVerticalAlignment(SwingConstants.CENTER)

        left_strip.add(Box.createHorizontalStrut(10))
        left_strip.add(self.export_bac_btn)
        left_strip.add(Box.createHorizontalStrut(6))
        left_strip.add(self.import_bac_btn)
        # Delete Roles button (Unicode trash, text-style)
        self.delete_bac_btn = JButton(u"\u232B", actionPerformed=self.delete_bac_roles)  # ⌫
        self.delete_bac_btn.setToolTipText("Delete roles")
        self.delete_bac_btn.setMargin(Insets(0, 0, 0, 0))
        self.delete_bac_btn.setPreferredSize(Dimension(30, 30))
        self.delete_bac_btn.setMinimumSize(Dimension(30, 30))


        left_strip.add(Box.createHorizontalStrut(6))
        left_strip.add(self.delete_bac_btn)

        top_panel.add(left_strip, BorderLayout.WEST)
        self.add(top_panel, BorderLayout.NORTH)
        self.add(self.role_tabs, BorderLayout.CENTER)

        # 1. Load existing roles for this host from BAC_HOST_CONFIGS (if any)
        config = BAC_HOST_CONFIGS.get(self.host)
        if config and "roles" in config and config["roles"]:
            for role_cfg in config["roles"]:
                self._add_role_tab_internal(role_cfg.get("label", None), role_cfg)
            self.save_state()
        # Always add plus tab last
        self.ensure_single_plus_tab()
        self.role_tabs.addChangeListener(self.on_tab_change)
        self.update_move_buttons_state()
        
        # Add component listener to handle resizing and force proper layout
        
        _parent = self  # capture the BACCheckPanel instance

        class ResizeListener(ComponentAdapter):
            def componentResized(self, event):
                try:
                    _parent.role_tabs.revalidate()
                    _parent.role_tabs.repaint()
                    top_panel.revalidate()
                    top_panel.repaint()
                except Exception:
                    # Don't crash if components aren't ready during import/restore
                    pass

        self.addComponentListener(ResizeListener())
        SwingUtilities.invokeLater(lambda: self.refresh_layout())

    def refresh_layout(self):
        try:
            # First pass
            self.revalidate(); self.repaint()
            if hasattr(self, "role_tabs"):
                self.role_tabs.revalidate(); self.role_tabs.repaint()
            # Second pass (helps stubborn LAFs)
            SwingUtilities.invokeLater(lambda: (
                self.revalidate(), self.repaint(),
                hasattr(self, "role_tabs") and self.role_tabs.revalidate(),
                hasattr(self, "role_tabs") and self.role_tabs.repaint()
            ))
        except Exception:
            pass

    def update_move_buttons_state(self):
        idx = self.role_tabs.getSelectedIndex()
        count = self.role_tabs.getTabCount() - 1  # Exclude plus tab
        self.move_left_btn.setEnabled(idx > 0 and idx < count)
        self.move_right_btn.setEnabled(idx >= 0 and idx < count - 1)

    def on_tab_change(self, event):
        idx = self.role_tabs.getSelectedIndex()
        count = self.role_tabs.getTabCount() - 1  # Exclude plus tab
        self.update_move_buttons_state()
        # If "+" tab clicked, add a new role
        if idx == self.role_tabs.getTabCount() - 1:
            pass

    def move_selected_left(self, event):
        idx = self.role_tabs.getSelectedIndex()
        count = self.role_tabs.getTabCount() - 1  # Exclude plus tab
        if idx > 0 and idx < count:
            self.move_role_tab(idx, idx - 1)
            self.role_tabs.setSelectedIndex(idx - 1)
            self.update_move_buttons_state()

    def move_selected_right(self, event):
        idx = self.role_tabs.getSelectedIndex()
        count = self.role_tabs.getTabCount() - 1  # Exclude plus tab
        if idx >= 0 and idx < count - 1:
            self.move_role_tab(idx, idx + 1)
            self.role_tabs.setSelectedIndex(idx + 1)
            self.update_move_buttons_state()

    def move_role_tab(self, from_idx, to_idx):
        count = self.role_tabs.getTabCount() - 1  # Exclude plus tab
        if from_idx == to_idx or from_idx < 0 or to_idx < 0 or from_idx >= count or to_idx >= count:
            return
        # Swap role_data
        self.role_data[from_idx], self.role_data[to_idx] = self.role_data[to_idx], self.role_data[from_idx]
        self.save_state()
        self.rebuild_role_tabs_from_data()

    def rebuild_role_tabs_from_data(self):
        # Remove all real tabs (except plus tab)
        plus_idx = self.role_tabs.getTabCount() - 1
        # Remove from last real tab to first
        for i in range(plus_idx - 1, -1, -1):
            self.role_tabs.remove(i)
        # Re-add all tabs from role_data
        for idx, role_cfg in enumerate(self.role_data):
            role_label = role_cfg.get("label", "Role %d" % (idx + 1))
            panel = self.make_role_panel(role_cfg, idx)
            self.role_tabs.insertTab(role_label, None, panel, None, idx)
            self.role_tabs.setTabComponentAt(idx, ClosableTabComponent(self.role_tabs, panel, role_label, self, role_idx=idx))
        # Ensure plus tab is last
        self.ensure_single_plus_tab()
        self.role_tabs.setSelectedIndex(0 if self.role_data else self.role_tabs.getTabCount() - 1)
        self.update_move_buttons_state()

    def ensure_single_plus_tab(self):
        # Remove any existing plus tab
        for i in range(self.role_tabs.getTabCount() - 1, -1, -1):
            if self.role_tabs.getTitleAt(i) == "":
                self.role_tabs.remove(i)
        self.add_plus_tab()

    def export_bac_roles(self, event):
        try:
            if not self.role_data:
                JOptionPane.showMessageDialog(self, "No BAC roles to export.")
                return
            # --- Step 1: build a panel of checkboxes with Select All ---
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            select_all = JCheckBox(" Select All", True)
            panel.add(select_all)
            checks = []
            role_names = [role.get("label", "Role #%d" % (i+1)) for i, role in enumerate(self.role_data)]
            for i, name in enumerate(role_names):
                cb = JCheckBox(" " + name, True)
                checks.append(cb)
                panel.add(cb)
            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)
            select_all.addActionListener(toggle_all)
            scroll = JScrollPane(panel)
            scroll.setPreferredSize(Dimension(300, min((len(checks) + 1) * 30, 300)))
            res = JOptionPane.showConfirmDialog(self, scroll, "Select BAC roles to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected_indices = [i for i, cb in enumerate(checks) if cb.isSelected()]
            if not selected_indices:
                JOptionPane.showMessageDialog(self, "No roles selected.")
                return
            export_list = [self.role_data[idx] for idx in selected_indices]
            last_dir = load_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY) if self.callbacks else None
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setDialogTitle("Export BAC Roles As")
            chooser.setSelectedFile(File("bac_roles_%s.json" % self.host.replace(':', '_')))
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                if self.callbacks:
                    save_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY, os.path.dirname(out_path))
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(export_list, f, indent=2)
                JOptionPane.showMessageDialog(self, "Exported %d BAC roles to:\n%s" % (len(export_list), out_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error exporting BAC roles:\n" + str(e) + "\n" + traceback.format_exc())

    def import_bac_roles(self, event):
        try:
            last_dir = load_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY) if self.callbacks else None
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Import BAC Roles (.json)")
            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                in_path = file.getAbsolutePath()
                if self.callbacks:
                    save_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY, os.path.dirname(in_path))
                with codecs.open(in_path, "r", encoding="utf-8") as f:
                    imported = json.load(f)
                if isinstance(imported, dict):
                    imported = [imported]
                if not imported:
                    JOptionPane.showMessageDialog(self, "No BAC roles found in file.")
                    return
                
                # --- Build a panel of checkboxes with Select All ---
                panel = JPanel()
                panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
                select_all = JCheckBox(" Select All", True)
                panel.add(select_all)
                checks = []
                role_names = [role.get("label", "Role #%d" % (i+1)) for i, role in enumerate(imported)]
                for i, name in enumerate(role_names):
                    cb = JCheckBox(" " + name, True)
                    checks.append(cb)
                    panel.add(cb)

                def toggle_all(evt=None):
                    state = select_all.isSelected()
                    for cb in checks:
                        cb.setSelected(state)

                select_all.addActionListener(toggle_all)

                scroll = JScrollPane(panel)
                scroll.setPreferredSize(Dimension(300, min((len(checks) + 1) * 30, 300)))
                res = JOptionPane.showConfirmDialog(self, scroll, "Select BAC roles to import", JOptionPane.OK_CANCEL_OPTION)
                if res != JOptionPane.OK_OPTION:
                    return

                selected_indices = [i for i, cb in enumerate(checks) if cb.isSelected()]
                if not selected_indices:
                    JOptionPane.showMessageDialog(self, "No roles selected.")
                    return

                # Insert imported roles before the plus tab
                plus_idx = self.role_tabs.getTabCount() - 1
                for offset, idx in enumerate(selected_indices):
                    role_cfg = imported[idx]
                    self._add_role_tab_internal(role_cfg.get("label", None), role_cfg)
                self.save_state()
                self.ensure_single_plus_tab()
                JOptionPane.showMessageDialog(self, "Imported %d BAC roles." % len(selected_indices))
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error importing BAC roles:\n" + str(e) + "\n" + traceback.format_exc())

    def delete_bac_roles(self, event):
        try:
            if not self.role_data:
                JOptionPane.showMessageDialog(self, "No roles to delete.")
                return

            # Build a confirmation panel with ALL roles (enabled pre-checked, disabled shown unticked)
            container = JPanel()
            container.setLayout(BoxLayout(container, BoxLayout.Y_AXIS))
            container.setAlignmentX(JPanel.LEFT_ALIGNMENT)

            # Proper HTML message
            msg = JEditorPane("text/html",
                            "<html><b>Reminder:</b> Consider exporting roles before deleting."
                            "<br>Select the roles you want to delete, then click <b>OK</b>.</html>")
            msg.setEditable(False)
            msg.setOpaque(False)
            msg.setAlignmentX(JEditorPane.LEFT_ALIGNMENT)
            container.add(msg)
            container.add(Box.createVerticalStrut(6))

            # Select All checkbox reflects initial state (all enabled?)
            all_enabled_initial = all(r.get("enabled", True) for r in self.role_data)
            select_all = JCheckBox(" Select All", all_enabled_initial)
            select_all.setAlignmentX(JCheckBox.LEFT_ALIGNMENT)
            select_all.setHorizontalAlignment(SwingConstants.LEFT)  # ensure left text alignment
            container.add(select_all)

            # Create one checkbox per role (pre-select enabled, show disabled unticked)
            checks = []
            idx_map = []  # map from checkbox index -> real role index
            count_real_tabs = len(self.role_data)
            for i in range(count_real_tabs):
                # Prefer the tab title; fallback to stored label
                try:
                    name = self.role_tabs.getTitleAt(i)
                except:
                    name = None
                if not name:
                    name = self.role_data[i].get("label", "Role #%d" % (i + 1))

                preselect = bool(self.role_data[i].get("enabled", True))
                cb = JCheckBox(" " + name, preselect)
                cb.setAlignmentX(JCheckBox.LEFT_ALIGNMENT)
                cb.setHorizontalAlignment(SwingConstants.LEFT)  # ensure left text alignment
                checks.append(cb)
                idx_map.append(i)
                container.add(cb)

            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)
            select_all.addActionListener(toggle_all)

            # Wrap in a WEST-anchored panel so content hugs the left inside the dialog/scrollpane
            outer = JPanel(BorderLayout())
            outer.add(container, BorderLayout.WEST)

            scroll = JScrollPane(outer)
            scroll.setPreferredSize(Dimension(380, min((len(checks) + 3) * 30, 380)))

            res = JOptionPane.showConfirmDialog(self, scroll, "Delete Roles", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return

            # Roles actually selected for deletion
            to_delete_real_indices = [idx_map[j] for j, cb in enumerate(checks) if cb.isSelected()]
            if not to_delete_real_indices:
                JOptionPane.showMessageDialog(self, "No roles selected for deletion.")
                return

            # Final confirmation with proper HTML list
            names = []
            for i in to_delete_real_indices:
                try:
                    nm = self.role_tabs.getTitleAt(i)
                except:
                    nm = None
                if not nm:
                    nm = self.role_data[i].get("label", "Role #%d" % (i + 1))
                names.append(nm)

            confirm_html = "<html>You are about to delete <b>%d</b> role(s):<br><br>%s<br><br>This cannot be undone. Continue?</html>" % (
                len(to_delete_real_indices),
                "<br>".join("&nbsp;&nbsp;&bull; " + n for n in names)
            )
            confirm = JEditorPane("text/html", confirm_html)
            confirm.setEditable(False)
            confirm.setOpaque(False)

            res2 = JOptionPane.showConfirmDialog(self, confirm, "Confirm Deletion", JOptionPane.OK_CANCEL_OPTION)
            if res2 != JOptionPane.OK_OPTION:
                return

            # Delete from role_data (delete highest index first to avoid shifting)
            for i in sorted(to_delete_real_indices, reverse=True):
                if 0 <= i < len(self.role_data):
                    del self.role_data[i]

            # Persist + rebuild UI
            self.save_state()
            self.rebuild_role_tabs_from_data()
            self.ensure_single_plus_tab()
            self.update_move_buttons_state()

            JOptionPane.showMessageDialog(self, "Deleted %d role(s)." % len(to_delete_real_indices))

        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error deleting roles:\n" + str(e) + "\n" + traceback.format_exc())


    def _add_role_tab_internal(self, label=None, config=None):
        # Used for initial load - appends at end before "+" tab
        plus_idx = self.role_tabs.getTabCount()  # always last
        role_label = label or "Role %d" % (len(self.role_data) + 1)
        role_cfg = config if config else {
            "label": role_label,
            "headers": [{"header": "", "value": ""}],
            "extra_enabled": False,
            "extra_name": "",
            "extra_value": "",
            "force": False
        }
        panel = self.make_role_panel(role_cfg, len(self.role_data))
        # Insert at plus_idx (which is at end, since only "+" at this point on init)
        self.role_tabs.insertTab(role_label, None, panel, None, plus_idx)
        self.role_tabs.setTabComponentAt(plus_idx, ClosableTabComponent(self.role_tabs, panel, role_label, self, role_idx=plus_idx))
        # Ensure enabled state is set
        if "enabled" not in role_cfg:
            role_cfg["enabled"] = True
        self.role_data.insert(plus_idx, role_cfg)
        self.role_tabs.setSelectedIndex(plus_idx)
        self.save_state()

    def add_role_tab(self, label=None, config=None):
        # Used when "+" clicked - appends to end before "+" tab, always matches role_data order!
        plus_idx = self.role_tabs.getTabCount() - 1
        role_label = label or "Role %d" % (len(self.role_data) + 1)
        role_cfg = config if config else {
            "label": role_label,
            "headers": [{"header": "", "value": ""}],
            "extra_enabled": False,
            "extra_name": "",
            "extra_value": "",
            "force": False
        }
        panel = self.make_role_panel(role_cfg, len(self.role_data))
        self.role_tabs.insertTab(role_label, None, panel, None, plus_idx)
        self.role_tabs.setTabComponentAt(plus_idx, ClosableTabComponent(self.role_tabs, panel, role_label, self, role_idx=plus_idx))
        self.role_data.append(role_cfg)
        self.role_tabs.setSelectedIndex(plus_idx)
        self.save_state()

    def save_state(self):
        BAC_HOST_CONFIGS[self.host] = {"roles": list(self.role_data)}
        if hasattr(self, "on_save_callback") and self.on_save_callback:
            self.on_save_callback(self.host)

    def make_role_panel(self, role_cfg, role_idx):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        # List to hold each header row panel
        role_cfg.setdefault("headers", [])

        headers_container = JPanel()
        headers_container.setLayout(BoxLayout(headers_container, BoxLayout.Y_AXIS))

        wrapper = JPanel(BorderLayout())
        wrapper.add(headers_container, BorderLayout.NORTH)

        headers_scroll = JScrollPane(wrapper)
        headers_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        headers_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        # Increased default size for better visibility
        headers_scroll.setPreferredSize(Dimension(400, 250))
        headers_scroll.setMinimumSize(Dimension(300, 200))
        headers_scroll.setMaximumSize(Dimension(800, 400))
        panel.add(headers_scroll)

        # --- Add header row logic with improved wrapping and left alignment ---
        def add_header_row(header_val=None):
            default_font = Font("Dialog", Font.PLAIN, 12)

            # Main row panel using GridBagLayout for better control
            row = JPanel()
            row.setLayout(GridBagLayout())
            row.setAlignmentX(Component.LEFT_ALIGNMENT)
            row.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2))

            gbc = GridBagConstraints()
            gbc.insets = Insets(2, 2, 2, 2)
            gbc.anchor = GridBagConstraints.WEST
            gbc.fill = GridBagConstraints.HORIZONTAL

            # Header selection - row 0
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.weightx = 0.0
            header_label = JLabel("Header:")
            header_label.setFont(default_font)
            row.add(header_label, gbc)

            gbc.gridx = 1
            gbc.weightx = 0.7
            available_headers = list(self.req_headers)
            combo = JComboBox(available_headers)
            combo.setEditable(True)
            combo.setPreferredSize(Dimension(180, 24))
            combo.setMinimumSize(Dimension(150, 24))
            combo.setFont(default_font)
            if header_val and "header" in header_val and header_val["header"]:
                combo.setSelectedItem(header_val["header"])
            row.add(combo, gbc)

            gbc.gridx = 2
            gbc.weightx = 0.0
            gbc.fill = GridBagConstraints.NONE
            del_btn = JButton(u"\u232B")  # ⌫
            del_btn.setToolTipText("Delete this header")
            del_btn.setMargin(Insets(0, 0, 0, 0))
            del_btn.setPreferredSize(Dimension(26, 26))
            del_btn.setMinimumSize(Dimension(26, 26))
            del_btn.setMaximumSize(Dimension(26, 26))
            row.add(del_btn, gbc)


            # Value input - row 1
            gbc.gridx = 0
            gbc.gridy = 1
            gbc.weightx = 0.0
            value_label = JLabel("Value:")
            value_label.setFont(default_font)
            row.add(value_label, gbc)

            gbc.gridx = 1
            gbc.weightx = 0.7
            gbc.fill = GridBagConstraints.BOTH
            value = header_val["value"] if header_val and "value" in header_val else ""
            val_field = JTextArea(value, 2, 25)
            val_field.setFont(default_font)
            val_field.setLineWrap(True)
            val_field.setWrapStyleWord(True)

            val_scroll = JScrollPane(val_field)
            val_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            val_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
            val_scroll.setPreferredSize(Dimension(250, 50))
            val_scroll.setMinimumSize(Dimension(200, 40))
            row.add(val_scroll, gbc)

            gbc.gridx = 2
            gbc.weightx = 0.0
            gbc.fill = GridBagConstraints.NONE
            edit_btn = JButton(u"\u270E")  # ✎
            edit_btn.setToolTipText("Edit header value")
            edit_btn.setMargin(Insets(0, 0, 0, 0))
            edit_btn.setPreferredSize(Dimension(26, 26))
            edit_btn.setMinimumSize(Dimension(26, 26))
            edit_btn.setMaximumSize(Dimension(26, 26))
            row.add(edit_btn, gbc)

            def open_editor_popup(evt=None):
                popup_area = JTextArea(val_field.getText(), 10, 60)
                popup_area.setLineWrap(True)
                popup_area.setWrapStyleWord(True)
                scroll_pane = JScrollPane(popup_area)
                
                res = JOptionPane.showConfirmDialog(
                    panel,
                    scroll_pane,
                    "Edit Header Value",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE
                )
                
                if res == JOptionPane.OK_OPTION:
                    new_text = popup_area.getText()
                    val_field.setText(new_text)

            edit_btn.addActionListener(open_editor_popup)

            # Listeners for saving
            def on_combo_change(evt=None):
                idx = None
                for i, (p, _, _) in enumerate(header_rows):
                    if p == row:
                        idx = i
                        break
                if idx is not None:
                    role_cfg["headers"][idx]["header"] = str(combo.getSelectedItem())
                if self.on_save_callback:
                    self.on_save_callback(self.host)

            def on_val_change(evt=None):
                idx = None
                for i, (p, _, _) in enumerate(header_rows):
                    if p == row:
                        idx = i
                        break
                if idx is not None:
                    role_cfg["headers"][idx]["value"] = val_field.getText()
                if self.on_save_callback:
                    self.on_save_callback(self.host)

            combo.addActionListener(on_combo_change)
            val_field.addCaretListener(lambda evt: on_val_change())

            class EnterKeyListener(KeyAdapter):
                def keyPressed(self, event):
                    if event.getKeyCode() == KeyEvent.VK_ENTER:
                        if event.isShiftDown():
                            val_field.insert("\n", val_field.getCaretPosition())
                        else:
                            on_val_change()
                            combo.requestFocusInWindow()
                            event.consume()

            val_field.addKeyListener(EnterKeyListener())

            def delete_row(evt=None):
                idx = None
                for i, (p, _, _) in enumerate(header_rows):
                    if p == row:
                        idx = i
                        break
                if idx is not None:
                    headers_container.remove(row)
                    header_rows.pop(idx)
                    role_cfg["headers"].pop(idx)
                    headers_container.revalidate()
                    headers_container.repaint()
                    if self.on_save_callback:
                        self.on_save_callback(self.host)

            del_btn.addActionListener(delete_row)

            headers_container.add(row)
            header_rows.append((row, combo, val_field))
            if header_val is None:
                role_cfg["headers"].append({"header": str(combo.getSelectedItem()), "value": val_field.getText()})
            headers_container.revalidate()
            headers_container.repaint()

        header_rows = []

        # Add existing headers
        for header_val in role_cfg.get("headers", []):
            add_header_row(header_val)

        # Add header button aligned to the left without vertical stretching
        add_header_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        add_header_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))

        add_header_btn = JButton("Add header", actionPerformed=lambda evt: add_header_row())
        add_header_btn.setPreferredSize(Dimension(120, 28))
        add_header_btn.setMinimumSize(Dimension(120, 28))
        add_header_btn.setMaximumSize(Dimension(120, 28))  # Prevent vertical growth
        add_header_btn.setMargin(Insets(2, 10, 2, 10))

        add_header_panel.add(add_header_btn)
        panel.add(add_header_panel)

        # --- Extra header section: all rows hug the left edge -----------------------
        extra_panel = JPanel()
        extra_panel.setLayout(BoxLayout(extra_panel, BoxLayout.Y_AXIS))
        extra_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))

        # Row 0: checkbox
        extra_toggle_row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        extra_toggle_row.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        extra_toggle = JCheckBox("Add extra header")
        extra_toggle.setSelected(role_cfg.get("extra_enabled", False))
        extra_toggle_row.add(extra_toggle)
        extra_panel.add(extra_toggle_row)

        # Row 1: header name
        extra_name_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        extra_name_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        extra_name_label = JLabel("Header name:")
        extra_name_panel.add(extra_name_label)
        extra_name = JTextField(role_cfg.get("extra_name", ""), 15)
        extra_name.setPreferredSize(Dimension(150, 24))
        extra_name.setMinimumSize(Dimension(150, 24))
        extra_name.setMaximumSize(Dimension(150, 24))  # prevent vertical growth
        extra_name_panel.add(extra_name)
        extra_panel.add(extra_name_panel)

        # Row 2: value
        extra_val_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        extra_val_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        extra_val_label = JLabel("Value:")
        extra_val_panel.add(extra_val_label)
        extra_val = JTextField(role_cfg.get("extra_value", ""), 20)
        extra_val.setPreferredSize(Dimension(200, 24))
        extra_val.setMinimumSize(Dimension(200, 24))
        extra_val.setMaximumSize(Dimension(200, 24))   # prevent vertical growth
        extra_val_panel.add(extra_val)
        extra_panel.add(extra_val_panel)

        panel.add(extra_panel)

        def update_extra_fields():
            show = extra_toggle.isSelected()
            extra_name_panel.setVisible(show)
            extra_val_panel.setVisible(show)
            role_cfg["extra_enabled"] = show
            if self.on_save_callback:
                self.on_save_callback(self.host)
            # refresh layout
            extra_panel.revalidate(); extra_panel.repaint()
            panel.revalidate(); panel.repaint()

        extra_toggle.addActionListener(lambda evt: update_extra_fields())
        update_extra_fields()

        def on_extra_name_change(evt=None):
            role_cfg["extra_name"] = extra_name.getText()
            if self.on_save_callback:
                self.on_save_callback(self.host)

        def on_extra_val_change(evt=None):
            role_cfg["extra_value"] = extra_val.getText()
            if self.on_save_callback:
                self.on_save_callback(self.host)

        extra_name.addActionListener(on_extra_name_change)
        extra_val.addActionListener(on_extra_val_change)
        extra_name.addCaretListener(lambda evt: on_extra_name_change())
        extra_val.addCaretListener(lambda evt: on_extra_val_change())

        # --- Force toggle row (per-role) ---
        force_row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        force_chk = JCheckBox("Force (add missing headers)")
        force_chk.setSelected(role_cfg.get("force", False))
        force_row.add(force_chk)
        panel.add(force_row)

        def on_force_toggle(evt=None):
            role_cfg["force"] = force_chk.isSelected()
            if self.on_save_callback:
                self.on_save_callback(self.host)

        force_chk.addActionListener(lambda evt: on_force_toggle())
        # Action row aligned to the left without vertical stretching
        action_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        action_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))

        check_btn = JButton("Check this role")
        check_btn.setPreferredSize(Dimension(130, 28))  # same as Export Roles
        check_btn.setMinimumSize(Dimension(130, 28))
        check_btn.setMaximumSize(Dimension(130, 28))    # <-- prevents vertical growth
        check_btn.setMargin(Insets(2, 10, 2, 10))

        action_panel.add(check_btn)

        def run_single_role(evt=None):
            try:
                # Determine current role index dynamically (works even after reordering)
                idx = self.role_tabs.indexOfComponent(panel)
                plus_idx = self.role_tabs.getTabCount() - 1
                if idx >= 0 and idx < plus_idx and self.single_check_handler:
                    self.single_check_handler(idx)
            except Exception as e:
                JOptionPane.showMessageDialog(panel, "Error: " + str(e))

        check_btn.addActionListener(lambda e: run_single_role())
        
        panel.add(action_panel)

        return panel
    
    def add_plus_tab(self):
        btn = JButton("+")
        btn.setPreferredSize(Dimension(32, 24))
        btn.setFocusable(False)
        btn.setToolTipText("Add new role")
        class PlusListener(ActionListener):
            def actionPerformed(listener_self, e):
                self.add_role_tab()
                self.save_state()
        btn.addActionListener(PlusListener())
        plus_panel = JPanel()
        idx = self.role_tabs.getTabCount()
        self.role_tabs.addTab("", plus_panel)
        self.role_tabs.setTabComponentAt(idx, btn)

    def toggle_all_roles(self, event):
        checked = self.enable_all_checkbox.isSelected()
        for idx, role in enumerate(self.role_data):
            role["enabled"] = checked
            # Update the checkbox in the tab component if present
            tab_comp = self.role_tabs.getTabComponentAt(idx)
            if hasattr(tab_comp, "set_checkbox_state"):
                tab_comp.set_checkbox_state(checked)
        self.save_state()
                         
### ------------------- Fuzzer Tab Main ----------------------

# class MessageHistoryEntry(object):
#     def __init__(self, req_bytes, resp_bytes, param_name=None, payload=None):
#         self.req_bytes = req_bytes
#         self.resp_bytes = resp_bytes
#         self.param_name = param_name
#         self.payload = payload
#         self.highlight = None  # (start, end)

class FuzzerPOCTab(JPanel, IMessageEditorController):
    def __init__(self, helpers, callbacks, base_message, save_tabs_state_callback, parent_extender=None):
            
        JPanel.__init__(self)
        self.helpers = helpers
        self.callbacks = callbacks
        self.base_message = base_message
        self.setLayout(BorderLayout())
        self.save_tabs_state_callback = save_tabs_state_callback
        self.has_been_shown_once = False

        # --- Toolbar ---
        toolbar = JToolBar()
        toolbar.setFloatable(False)

        # Match role tab arrow button size
        nav_button_size = Dimension(30, 28)

        self.access_check_btn = JButton("Access Check", actionPerformed=self.bac_check)
        self.send_btn = JButton("Send")
        self.attack_btn = JButton("Attack")

        # Previous dropdown ▼
        self.prev_dropdown = JButton(u"\u25BC")
        self.prev_dropdown.setFocusable(False)
        self.prev_dropdown.addActionListener(lambda e: self.show_history_dropdown(False))

        # Previous <
        self.prev_btn = JButton("<")

        # Status label
        self.status_lbl = JLabel(" 0/0 ")
        self.status_lbl.setHorizontalAlignment(JLabel.CENTER)
        self.status_lbl.setPreferredSize(Dimension(60, 24))
        self.status_lbl.setMaximumSize(Dimension(60, 24))
        self.status_lbl.setMinimumSize(Dimension(60, 24))

        # Next >
        self.next_btn = JButton(">")

        # Next dropdown ▼
        self.next_dropdown = JButton(u"\u25BC")
        self.next_dropdown.setFocusable(False)
        self.next_dropdown.addActionListener(lambda e: self.show_history_dropdown(True))

        # Apply consistent styling to all nav buttons
        for b in (self.prev_btn, self.next_btn, self.prev_dropdown, self.next_dropdown):
            b.setPreferredSize(nav_button_size)
            b.setMinimumSize(nav_button_size)
            b.setMaximumSize(nav_button_size)
            b.setFocusable(False)
            b.setFont(Font("Dialog", Font.BOLD, 13))
            b.setMargin(Insets(0, 0, 0, 0))
            b.setHorizontalAlignment(SwingConstants.CENTER)
            b.setVerticalAlignment(SwingConstants.CENTER)

        nav_panel = JPanel()
        nav_panel.setLayout(BoxLayout(nav_panel, BoxLayout.X_AXIS))
        nav_panel.add(self.prev_dropdown)
        nav_panel.add(self.prev_btn)
        nav_panel.add(self.status_lbl)
        nav_panel.add(self.next_btn)
        nav_panel.add(self.next_dropdown)

        button_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        button_row.add(self.access_check_btn)
        button_row.add(self.send_btn)
        button_row.add(self.attack_btn)
        button_row.add(Box.createHorizontalStrut(15))  # spacer
        button_row.add(nav_panel)

        toolbar.add(button_row)
        # Wrap toolbar (left) + status square (right)
        self.status_indicator = StatusIndicator(20)  # default enabled

        topbar = JPanel(BorderLayout())
        topbar.add(toolbar, BorderLayout.WEST)

        right_top = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 2))
        # --- Progress UI + run guard ---
        self._run_in_flight = False
        self._progress_total = 0
        self._progress_done = 0

        self.progress = JProgressBar()
        self.progress.setVisible(False)
        self.progress.setStringPainted(True)   # show "x / y"
        self.progress.setIndeterminate(False)

        right_top.add(self.progress)
        right_top.add(self.status_indicator)
        topbar.add(right_top, BorderLayout.EAST)

        self.add(topbar, BorderLayout.NORTH)

        self.req_editor = callbacks.createMessageEditor(self, True)
        self.resp_editor = callbacks.createMessageEditor(self, False)

        # --- Bottom Panel (Save, Export, Screenshot) ---
        # Icon-only Save button (uses built-in Swing floppy icon)
        self.save_btn = JButton("", actionPerformed=self.on_save_state)
        icon = UIManager.getIcon("FileView.floppyDriveIcon")  # built-in LAF icon
        if icon is not None:
            self.save_btn.setIcon(icon)
            self.save_btn.setToolTipText("Save state")
            self.save_btn.setPreferredSize(Dimension(30, 30))
        else:
            # Fallback if the LAF doesn't provide the icon
            self.save_btn.setText("Save State")
        
        self.export_all_btn = JButton("Export Results", actionPerformed=self.exportAllTabs)
        self.merge_all_btn = JButton("Merge Results", actionPerformed=self.mergeAllTabs)
        left_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        left_panel.add(self.save_btn)
        left_panel.add(self.export_all_btn)
        left_panel.add(self.merge_all_btn)
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(left_panel, BorderLayout.WEST)

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.screenshot_btn = JButton(u"\U0001F4F7", actionPerformed=self.takeScreenshot)  # 📷
        self.screenshot_btn.setToolTipText("Take screenshot")
        self.screenshot_btn.setMargin(Insets(0, 0, 0, 0))
        self.screenshot_btn.setFont(self.screenshot_btn.getFont().deriveFont(20.0))  # bump icon size
        self.screenshot_btn.setPreferredSize(Dimension(30, 30))
        self.screenshot_btn.setMinimumSize(Dimension(30, 30))
        self.screenshot_btn.setMaximumSize(Dimension(30, 30))
        self.export_tabs_btn = JButton("Export Tabs", actionPerformed=self.exportTabsForImport)
        self.merge_export_tabs_btn = JButton("Merge Export", actionPerformed=(lambda e: self.parent_extender.mergeExportTabsForImport(e)))
        self.import_tabs_btn = JButton("Import Tabs", actionPerformed=self.importTabsFromFile)

        btn_panel.add(self.export_tabs_btn)
        btn_panel.add(self.merge_export_tabs_btn)
        btn_panel.add(self.import_tabs_btn)
        btn_panel.add(self.screenshot_btn)
        right_container = JPanel(BorderLayout())
        right_container.add(btn_panel, BorderLayout.WEST)

        self.metrics_lbl = JLabel(" ")  # will show: "295 bytes | 11 ms"
        self.metrics_lbl.setHorizontalAlignment(SwingConstants.RIGHT)
        self.metrics_lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 8))
        right_container.add(self.metrics_lbl, BorderLayout.EAST)

        bottom_panel.add(right_container, BorderLayout.EAST)
        self.add(bottom_panel, BorderLayout.SOUTH)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.req_editor.getComponent(), self.resp_editor.getComponent())
        main_split.setResizeWeight(0.5)
        main_split.setDividerLocation(400)
        main_split.setOneTouchExpandable(True)
        self.main_split = main_split

        # -- Prepare Param Probe and Role Probe panels --
        if base_message is not None:
            req_bytes = base_message.getRequest()
        else:
            req_bytes = bytearray()
        url_params, default_url_payloads, body_params, default_body_payloads = self.extract_sidepanel_lists(req_bytes)

        url_payloads_state = LAST_PAYLOAD_STATE.get("url_payloads")
        body_payloads_state = LAST_PAYLOAD_STATE.get("body_payloads")

        self.payload_panel = PayloadSidePanel(
            url_params,
            to_pairs(url_payloads_state) if url_payloads_state is not None else to_pairs(default_url_payloads),
            body_params,
            to_pairs(body_payloads_state) if body_payloads_state is not None else to_pairs(default_body_payloads),
            default_url_payloads=default_url_payloads,
            default_body_payloads=default_body_payloads
        )
        headers = []
        if req_bytes:
            req_str = self.helpers.bytesToString(req_bytes)
            for line in req_str.split('\r\n'):
                if ':' in line:
                    hname = line.split(':', 1)[0].strip()
                    if hname and hname.lower() not in ("get", "post", "put", "delete", "patch"):
                        headers.append(hname)
        host = None
        service = self.base_message.getHttpService() if self.base_message else self.guess_service_from_request(req_bytes)
        if service:
            host = service.getHost()
        else:
            host = "default"

        if not headers:
            self.bac_panel = JPanel()
            self.bac_panel.add(JLabel("NO HEADERS FOUND. Load or send a real request."))
        else:
            try:
                self.bac_panel = BACCheckPanel(host, headers, on_save_callback=lambda host: save_bac_configs(self.callbacks), callbacks=self.callbacks, single_check_handler=lambda idx: self.bac_check_single(idx))
            except Exception as e:
                print("DEBUG: BACCheckPanel creation failed:", str(e))
                traceback.print_exc()
                self.bac_panel = JPanel()
                self.bac_panel.add(JLabel("BACCheckPanel failed to load."))

        self.bac_scroll_panel = JScrollPane(self.bac_panel)
        self.bac_scroll_panel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        self.card_panel = JPanel(CardLayout())
        self.card_panel.add(self.payload_panel, "Param Probe")
        self.card_panel.add(self.bac_scroll_panel, "Role Probe")

        self.tab_button_panel = JPanel()
        self.tab_button_panel.setLayout(BoxLayout(self.tab_button_panel, BoxLayout.Y_AXIS))

        self.sidebar_width_expanded = 400
        self.sidebar_width_collapsed = 36

        def on_tab_click(tab_name):
            if self.current_tab == tab_name and not self.tab_collapsed:
                self.card_panel.setVisible(False)
                self.right_panel.setPreferredSize(Dimension(self.sidebar_width_collapsed, self.right_panel.getHeight()))
                self.tab_collapsed = True
            else:
                self.card_panel.setVisible(True)
                self.right_panel.setPreferredSize(Dimension(self.sidebar_width_expanded, self.right_panel.getHeight()))
                self.tab_collapsed = False
                self.current_tab = tab_name
                layout = self.card_panel.getLayout()
                layout.show(self.card_panel, tab_name)

            self.inspector_btn.set_selected(self.current_tab == "Param Probe" and not self.tab_collapsed)
            self.bac_btn.set_selected(self.current_tab == "Role Probe" and not self.tab_collapsed)
            self.right_panel.revalidate()
            self.resize_sidebar()
                    
        self.inspector_btn = StackedVerticalTabButton("Param Probe", selected=True, on_click=lambda: on_tab_click("Param Probe"))
        self.bac_btn = StackedVerticalTabButton("Role Probe", selected=False, on_click=lambda: on_tab_click("Role Probe"))
        self.tab_button_panel.removeAll()
        self.tab_button_panel.add(self.inspector_btn)
        self.tab_button_panel.add(self.bac_btn)
        self.tab_button_panel.setMaximumSize(Dimension(40, 240))

        self.sidebar_width_collapsed = self.tab_button_panel.getPreferredSize().width + 5

        self.right_panel = JPanel(BorderLayout())
        self.right_panel.add(self.card_panel, BorderLayout.CENTER)
        self.right_panel.add(self.tab_button_panel, BorderLayout.EAST)
        
        main_split.setMinimumSize(Dimension(600, 400))
        self.outer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, main_split, self.right_panel)
        self.outer_split.setOneTouchExpandable(True)
        self.outer_split.setResizeWeight(1.0)
        self.add(self.outer_split, BorderLayout.CENTER)

        self.history = []
        self.current_idx = -1
        self.req_editor.setMessage(req_bytes, True)
        self.resp_editor.setMessage(bytearray(), False)

        self.send_btn.addActionListener(self.send_request)
        self.attack_btn.addActionListener(self.attack)
        self.prev_btn.addActionListener(self.go_prev)
        self.next_btn.addActionListener(self.go_next)
        self.update_status()
        self.parent_extender = parent_extender
        SwingUtilities.invokeLater(lambda: self.force_layout())

    def force_layout(self):
        try:
            # Nudge the Role Probe panel if present
            if hasattr(self, "bac_panel") and hasattr(self.bac_panel, "refresh_layout"):
                self.bac_panel.refresh_layout()

            # Nudge our containers
            if hasattr(self, "card_panel"):
                self.card_panel.revalidate(); self.card_panel.repaint()
            if hasattr(self, "right_panel"):
                self.right_panel.revalidate(); self.right_panel.repaint()
            if hasattr(self, "outer_split"):
                self.outer_split.revalidate(); self.outer_split.repaint()

            # One more pass on the next tick to catch late size changes
            SwingUtilities.invokeLater(lambda: (
                hasattr(self, "card_panel") and self.card_panel.revalidate(),
                hasattr(self, "card_panel") and self.card_panel.repaint(),
                hasattr(self, "right_panel") and self.right_panel.revalidate(),
                hasattr(self, "right_panel") and self.right_panel.repaint(),
                hasattr(self, "outer_split") and self.outer_split.revalidate(),
                hasattr(self, "outer_split") and self.outer_split.repaint(),
                self.resize_sidebar()
            ))
        except Exception:
            pass

    def reset_ui_state(self):
        # Method to set the side panel to its default (collapsed) state.
        # This can be called on init and when a tab becomes visible.
        def do_reset():
            self.tab_collapsed = True
            self.current_tab = "Param Probe"
            self.card_panel.setVisible(False)
            self.right_panel.setPreferredSize(Dimension(self.sidebar_width_collapsed, self.right_panel.getHeight()))
            self.inspector_btn.set_selected(False) # No tabs are "selected" when collapsed
            self.bac_btn.set_selected(False)
            self.resize_sidebar()

        # Defer to ensure the component hierarchy is ready before calculating sizes.
        SwingUtilities.invokeLater(do_reset)

    def on_gaining_visibility(self):
        # Called by the tab listener when this tab is selected.
        # This is the best place to initialize the UI state for tabs
        # that were created in the background (e.g., on restore).
        if not self.has_been_shown_once:
            self.reset_ui_state()
            self.has_been_shown_once = True
        else:
            # For subsequent views, just ensure layout is correct
            self.resize_sidebar()
        # After the tab becomes visible, force a clean layout so JTabbedPane wraps correctly
        SwingUtilities.invokeLater(lambda: self.force_layout())

    # --- The rest of your FuzzerPOCTab methods are unchanged ---
    # on_save_state, get_bytes_as_text, exportResults, mergeResults, exportAllTabs, mergeAllTabs, etc...

    def _begin_run(self, total_steps, label="Working…"):
        if self._run_in_flight:
            return False
        self._run_in_flight = True
        self._progress_total = max(1, int(total_steps))
        self._progress_done = 0
        def ui():
            # lock buttons
            self.attack_btn.setEnabled(False)
            self.access_check_btn.setEnabled(False)
            self.send_btn.setEnabled(False)
            # prime progress bar
            self.progress.setMinimum(0)
            self.progress.setMaximum(self._progress_total)
            self.progress.setValue(0)
            self.progress.setString("%s 0 / %d" % (label, self._progress_total))
            self.progress.setIndeterminate(False)  # set True if you prefer pulsing
            self.progress.setVisible(True)
            # wait cursor (nice to have)
            try:
                self.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR))
            except:
                pass
        SwingUtilities.invokeLater(ui)
        return True

    def _tick(self):
        if not self._run_in_flight:
            return
        self._progress_done += 1
        done = min(self._progress_done, self._progress_total)
        def ui():
            self.progress.setValue(done)
            self.progress.setString("%d / %d" % (done, self._progress_total))
        SwingUtilities.invokeLater(ui)

    def _end_run(self):
        if not self._run_in_flight:
            return
        self._run_in_flight = False
        def ui():
            self.progress.setVisible(False)
            self.attack_btn.setEnabled(True)
            self.access_check_btn.setEnabled(True)
            self.send_btn.setEnabled(True)
            try:
                self.setCursor(Cursor.getDefaultCursor())
            except:
                pass
        SwingUtilities.invokeLater(ui)


    def on_save_state(self, event):
        if self.save_tabs_state_callback:
            self.save_tabs_state_callback()

    def get_bytes_as_text(self, b):
        if b is None:
            return ""
        try:
            if hasattr(b, "tostring"):  # Jython bytearray
                return b.tostring().decode('utf-8')
            elif isinstance(b, bytes):
                return b.decode('utf-8')
            elif isinstance(b, str):
                # In Python3/Jython, may be unicode already
                return b
            else:
                return str(b)
        except Exception:
            return "<<Non-UTF8 content, omitted>>"

    def exportAllTabs(self, event):
        try:
            # --- Step 1: build a list of candidate tabs ---
            if not (hasattr(self, "parent_extender") and self.parent_extender):
                JOptionPane.showMessageDialog(self, "No tabs to export.")
                return
            tabs = self.parent_extender.tabs
            count = tabs.getTabCount() - 1  # exclude '+'
            if count <= 0:
                JOptionPane.showMessageDialog(self, "No tabs to export.")
                return

            # --- Step 2: build a panel of checkboxes with a "Select All" ---
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            select_all = JCheckBox(" Select All", True)
            panel.add(select_all)
            checks = []
            for i in range(count):
                title = tabs.getTitleAt(i)
                cb = JCheckBox(" " + title, True)
                checks.append(cb)
                panel.add(cb)

            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)
            select_all.addActionListener(toggle_all)

            scroll = JScrollPane(panel)
            scroll.setPreferredSize(Dimension(300, min((count + 1) * 30, 300)))

            res = JOptionPane.showConfirmDialog(self, scroll, "Select tabs to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return

            selected = [i for i, cb in enumerate(checks) if cb.isSelected()]
            if not selected:
                JOptionPane.showMessageDialog(self, "No tabs selected.")
                return

            # --- Step 3: file chooser ---
            project_name = "all_fuzz_results"
            try:
                p = self.callbacks.getProjectFile()
                if p:
                    project_name = os.path.splitext(os.path.basename(p))[0]
            except:
                pass
            default_file = File(project_name + ".txt")
            LAST_EXPORT_DIR_KEY = "last-export-directory"
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setSelectedFile(default_file)
            chooser.setDialogTitle("Export Selected Fuzz Results As")
            if chooser.showSaveDialog(None) != JFileChooser.APPROVE_OPTION:
                return

            out_path = chooser.getSelectedFile().getAbsolutePath()
            if not out_path.endswith(".txt"):
                out_path += ".txt"
            save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

            # ensure unique filename
            def get_nonconflicting(fp):
                base, ext = os.path.splitext(fp)
                n = 1
                new_fp = fp
                while os.path.exists(new_fp):
                    new_fp = "%s(%d)%s" % (base, n, ext)
                    n += 1
                return new_fp
            out_path = get_nonconflicting(out_path)

            # --- Step 4: collect only the selected tabs ---
            selected_tabs = []
            for i in selected:
                panel_i = tabs.getComponentAt(i)
                name = tabs.getTitleAt(i)
                if hasattr(panel_i, "history"):
                    selected_tabs.append((name, panel_i))

            # --- Step 5: write them out ---
            MAX_RESPONSE_LENGTH = 10000
            def safe_truncate(t, m):
                if not t: return ""
                return t if len(t) <= m else t[:m] + u"\n--------- Truncated ---------\n"

            with codecs.open(out_path, "w", encoding="utf-8") as f:
                for tab_name, panel_i in selected_tabs:
                    req_bytes = panel_i.req_editor.getMessage()
                    req_str = self.helpers.bytesToString(req_bytes)
                    svc = panel_i.getHttpService()
                    if svc:
                        ana = self.helpers.analyzeRequest(svc, req_bytes)
                        method = ana.getMethod()
                        url = ana.getUrl()
                        full = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                        api_line = method + " " + full
                        body = req_str[ana.getBodyOffset():].strip()
                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(u"API: %s%s\n\n" % (api_line, ("\n\n" + body) if body else ""))
                    else:
                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(req_str.split('\r\n', 1)[0] + "\n\n")

                    for idx, entry in enumerate(panel_i.history):
                        r = self.get_bytes_as_text(entry.req_bytes)
                        s = self.get_bytes_as_text(entry.resp_bytes)
                        s = safe_truncate(s, MAX_RESPONSE_LENGTH)
                        p_name = entry.param_name or ""
                        p_val  = entry.payload    or ""

                        f.write(u"---- Attack #%d ----\n" % (idx + 1))
                        f.write(u"Param/Role: %s\n" % p_name)
                        f.write(u"Value: %s\n\n"   % p_val)
                        f.write(u"Request:\n%s\n\n"  % r)
                        f.write(u"Response:\n%s\n"   % s)
                        f.write(u"-------------------\n\n")

            JOptionPane.showMessageDialog(self, "Exported %d tab(s) to:\n%s" % (len(selected_tabs), out_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error exporting results:\n%s\n%s" % (e, traceback.format_exc()))

    def mergeAllTabs(self, event):
        try:
            if not (hasattr(self, "parent_extender") and self.parent_extender):
                JOptionPane.showMessageDialog(self, "No tabs to merge.")
                return
            tabs = self.parent_extender.tabs
            count = tabs.getTabCount() - 1  # exclude '+'
            if count <= 0:
                JOptionPane.showMessageDialog(self, "No tabs to merge.")
                return
            # --- Step 1: build a panel of checkboxes with Select All ---
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            select_all = JCheckBox(" Select All", True)
            panel.add(select_all)
            checks = []
            for i in range(count):
                title = tabs.getTitleAt(i)
                cb = JCheckBox(" " + title, True)
                checks.append(cb)
                panel.add(cb)
            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)
            select_all.addActionListener(toggle_all)
            scroll = JScrollPane(panel)
            scroll.setPreferredSize(Dimension(300, min((count + 1) * 30, 300)))
            res = JOptionPane.showConfirmDialog(self, scroll, "Select tabs to merge", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected = [i for i, cb in enumerate(checks) if cb.isSelected()]
            if not selected:
                JOptionPane.showMessageDialog(self, "No tabs selected.")
                return
            # --- Step 2: file chooser ---
            LAST_EXPORT_DIR_KEY = "last-export-directory"
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setDialogTitle("Append Selected Fuzz Results To (Choose a .txt file)")
            if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
                return
            out_path = chooser.getSelectedFile().getAbsolutePath()
            if not out_path.endswith(".txt"):
                out_path += ".txt"
            save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))
            # --- Step 3: collect only the selected tabs ---
            selected_tabs = []
            for i in selected:
                panel_i = tabs.getComponentAt(i)
                name = tabs.getTitleAt(i)
                if hasattr(panel_i, "history"):
                    selected_tabs.append((name, panel_i))
            # --- Step 4: append them ---
            MAX_RESPONSE_LENGTH = 10000
            def safe_truncate(t, m):
                if not t: return ""
                return t if len(t) <= m else t[:m] + u"\n--------- Truncated ---------\n"
            with codecs.open(out_path, "a", encoding="utf-8") as f:
                for tab_name, panel_i in selected_tabs:
                    req_bytes = panel_i.req_editor.getMessage()
                    req_str = self.helpers.bytesToString(req_bytes)
                    svc = panel_i.getHttpService()
                    if svc:
                        ana = self.helpers.analyzeRequest(svc, req_bytes)
                        method = ana.getMethod()
                        url = ana.getUrl()
                        full = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                        api_line = method + " " + full
                        body = req_str[ana.getBodyOffset():].strip()
                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(u"API: %s%s\n\n" % (api_line, ("\n\n" + body) if body else ""))
                    else:
                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(req_str.split('\r\n', 1)[0] + "\n\n")
                    for idx, entry in enumerate(panel_i.history):
                        r = self.get_bytes_as_text(entry.req_bytes)
                        s = self.get_bytes_as_text(entry.resp_bytes)
                        s = safe_truncate(s, MAX_RESPONSE_LENGTH)
                        p_name = entry.param_name or ""
                        p_val  = entry.payload    or ""
                        f.write(u"---- Attack #%d ----\n" % (idx + 1))
                        f.write(u"Param/Role: %s\n" % p_name)
                        f.write(u"Value: %s\n\n"   % p_val)
                        f.write(u"Request:\n%s\n\n"  % r)
                        f.write(u"Response:\n%s\n"   % s)
                        f.write(u"-------------------\n\n")
            JOptionPane.showMessageDialog(self, "Merged %d tab(s) into:\n%s" % (len(selected_tabs), out_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error merging results:\n%s\n%s" % (e, traceback.format_exc()))

    def exportTabsForImport(self, event):
        try:
            if not (hasattr(self, "parent_extender") and self.parent_extender):
                JOptionPane.showMessageDialog(self, "Cannot export: parent component not found.")
                return
            tabs = self.parent_extender.tabs
            count = tabs.getTabCount() - 1  # Exclude '+'
            if count <= 0:
                JOptionPane.showMessageDialog(self, "No tabs to export.")
                return
            # --- Step 1: build a panel of checkboxes with Select All ---
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            select_all = JCheckBox(" Select All", True)
            panel.add(select_all)
            checks = []
            tab_titles = [tabs.getTitleAt(i) for i in range(count)]
            for i, title in enumerate(tab_titles):
                cb = JCheckBox(" " + title, True)
                checks.append(cb)
                panel.add(cb)
            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)
            select_all.addActionListener(toggle_all)
            scroll = JScrollPane(panel)
            scroll.setPreferredSize(Dimension(300, min((count + 1) * 30, 300)))
            res = JOptionPane.showConfirmDialog(self, scroll, "Select tabs to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected_indices = [i for i, cb in enumerate(checks) if cb.isSelected()]
            if not selected_indices:
                JOptionPane.showMessageDialog(self, "No tabs selected.")
                return
            export_list = []
            for idx in selected_indices:
                panel_i = tabs.getComponentAt(idx)
                if hasattr(panel_i, "serialize"):
                    tab_data = panel_i.serialize()
                    tab_data["tab_name"] = tabs.getTitleAt(idx)
                    export_list.append(tab_data)
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setDialogTitle("Export Tabs (for Import)")
            chooser.setSelectedFile(File("paramfuzzer_tabs.json"))
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(export_list, f, indent=2)
                JOptionPane.showMessageDialog(self, "Exported %d tabs for import:\n%s" % (len(export_list), out_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error exporting tabs:\n" + str(e) + "\n" + traceback.format_exc())

    def importTabsFromFile(self, event):
        try:
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setDialogTitle("Import Tabs (.json)")

            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                in_path = file.getAbsolutePath()
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(in_path))

                with codecs.open(in_path, "r", encoding="utf-8") as f:
                    imported = json.load(f)

                if isinstance(imported, dict):
                    imported = [imported]
                if not imported:
                    JOptionPane.showMessageDialog(self, "No tabs found in file.")
                    return

                tab_names = [tab.get("tab_name", "Tab #%d" % (i+1)) for i, tab in enumerate(imported)]

                # --- Build checkbox panel with Select All ---
                panel = JPanel()
                panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
                select_all = JCheckBox(" Select All", True)
                panel.add(select_all)
                checks = []

                for name in tab_names:
                    cb = JCheckBox(" " + name, True)
                    checks.append(cb)
                    panel.add(cb)

                def toggle_all(evt=None):
                    state = select_all.isSelected()
                    for cb in checks:
                        cb.setSelected(state)

                select_all.addActionListener(toggle_all)

                scroll = JScrollPane(panel)
                scroll.setPreferredSize(Dimension(300, min((len(checks) + 1) * 30, 300)))
                res = JOptionPane.showConfirmDialog(self, scroll, "Select tabs to import", JOptionPane.OK_CANCEL_OPTION)
                if res != JOptionPane.OK_OPTION:
                    return

                selected_indices = [i for i, cb in enumerate(checks) if cb.isSelected()]
                if not selected_indices:
                    JOptionPane.showMessageDialog(self, "No tabs selected.")
                    return

                count = 0
                for idx in selected_indices:
                    tab_data = imported[idx]
                    if hasattr(self, "parent_extender") and self.parent_extender and hasattr(self.parent_extender, "add_fuzzer_tab_with_state"):
                        self.parent_extender.add_fuzzer_tab_with_state(tab_data)
                        count += 1

                JOptionPane.showMessageDialog(self, "Imported %d tabs." % count)
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error importing tabs:\n" + str(e) + "\n" + traceback.format_exc())


    def serialize(self):
        # Save base request
        if self.base_message is not None:
            req_bytes = self.base_message.getRequest()
        else:
            req_bytes = self.req_editor.getMessage()
        # Save all request/response pairs in history
        entries = []
        for entry in self.history:
            entries.append({
                "req": base64.b64encode(entry.req_bytes).decode("ascii"),
                "resp": base64.b64encode(entry.resp_bytes or b"").decode("ascii"),
                "param_name": entry.param_name,
                "payload": entry.payload,
                "kind": getattr(entry, "kind", None)
            })
        # Save all current payloads
        url_payloads = [(row[0], bool(row[1])) for row in self.payload_panel.url_payloads_panel.model.rows]
        body_payloads = [(row[0], bool(row[1])) for row in self.payload_panel.body_payloads_panel.model.rows]
        # Save HTTP service info
        service = self.getHttpService()
        service_data = None
        if service:
            service_data = {
                "host": service.getHost(),
                "port": service.getPort(),
                "protocol": service.getProtocol()
            }
        # Save BAC tab data (roles)
        bac_roles = []
        if hasattr(self, "bac_panel") and hasattr(self.bac_panel, "role_data"):
            for role in self.bac_panel.role_data:
                # Deep copy to avoid mutation
                bac_roles.append({
                    "label": role.get("label", ""),
                    "headers": list(role.get("headers", [])),
                    "extra_enabled": role.get("extra_enabled", False),
                    "extra_name": role.get("extra_name", ""),
                    "extra_value": role.get("extra_value", ""),
                    "force": role.get("force", False)
                })
        # Save the tab name (if available)
        tab_name = None
        # (We'll set this when recreating the tab.)
        return {
            "req": base64.b64encode(req_bytes).decode("ascii"),
            "entries": entries,
            "url_payloads": url_payloads,
            "body_payloads": body_payloads,
            "service": service_data,
            "tab_name": tab_name,
            "bac_roles": bac_roles
        }

    @staticmethod
    def deserialize(data, helpers, callbacks, save_tabs_state_callback=None, parent_extender=None):
        # Dummy base_message with correct request and HTTP service
        class DummyBaseMessage(object):
            def __init__(self, req_bytes, service):
                self._req_bytes = req_bytes
                self._service = service
            def getRequest(self):
                return self._req_bytes
            def getHttpService(self):
                return self._service

        req_bytes = base64.b64decode(data["req"])
        service = None
        if "service" in data and data["service"]:
            s = data["service"]
            service = helpers.buildHttpService(s["host"], int(s["port"]), s["protocol"])

        base_message = DummyBaseMessage(req_bytes, service)
        obj = FuzzerPOCTab(helpers, callbacks, base_message=base_message, save_tabs_state_callback=save_tabs_state_callback, parent_extender=parent_extender)

        # Restore base request into editor
        obj.req_editor.setMessage(req_bytes, True)

        # Restore payload lists
        url_params, default_url_payloads, body_params, default_body_payloads = obj.extract_sidepanel_lists(req_bytes)
        obj.payload_panel = PayloadSidePanel(
            url_params,
            to_pairs(data.get("url_payloads", [])),
            body_params,
            to_pairs(data.get("body_payloads", [])),
            default_url_payloads=default_url_payloads,
            default_body_payloads=default_body_payloads
        )

        # Restore BAC tab (headers from request)
        restored_service = service if service else obj.guess_service_from_request(req_bytes)
        if restored_service:
            host = restored_service.getHost()
        else:
            host = "default"
        headers = []
        req_str = helpers.bytesToString(req_bytes)
        for line in req_str.split('\r\n'):
            if ':' in line:
                hname = line.split(':', 1)[0].strip()
                if hname and hname.lower() not in ("get", "post", "put", "delete", "patch"):
                    headers.append(hname)
        if not headers:
            obj.bac_panel = JPanel()
            obj.bac_panel.add(JLabel("NO HEADERS FOUND. Load or send a real request."))
        else:
            try:
                obj.bac_panel = BACCheckPanel(host, headers, on_save_callback=lambda host: save_bac_configs(callbacks), callbacks=callbacks, single_check_handler=lambda idx: obj.bac_check_single(idx))
                # Restore BAC roles if present
                if "bac_roles" in data and hasattr(obj.bac_panel, "role_data"):
                    obj.bac_panel.role_data = []
                    obj.bac_panel.role_tabs.removeAll()
                    for role_cfg in data["bac_roles"]:
                        if not isinstance(role_cfg, dict):
                            print("[-] Skipping invalid BAC role (not a dict):", role_cfg)
                            continue
                        obj.bac_panel._add_role_tab_internal(role_cfg.get("label", None), role_cfg)
                    obj.bac_panel.save_state()
                # Always ensure plus tab is present after restore
                if hasattr(obj.bac_panel, "ensure_single_plus_tab"):
                    obj.bac_panel.ensure_single_plus_tab()
            except Exception as e:
                print("DEBUG: BACCheckPanel creation failed:", str(e))
                # import traceback
                traceback.print_exc()
                obj.bac_panel = JPanel()
                obj.bac_panel.add(JLabel("BACCheckPanel failed to load."))

        # Set up card layout: remove and re-add the panels (if needed)
        obj.card_panel.removeAll()
        obj.card_panel.add(obj.payload_panel, "Param Probe")
        obj.card_panel.add(obj.bac_panel, "Role Probe")

        # Always show Param Probe tab/card on restore
        layout = obj.card_panel.getLayout()
        layout.show(obj.card_panel, "Param Probe")
        obj.current_tab = "Param Probe"
        obj.tab_collapsed = False

        # Restore attack history (infer 'kind' for older saves)
        obj.history = []

        # Collect role labels for inference (from restored BAC role tabs)
        role_labels = set()
        try:
            if hasattr(obj, "bac_panel") and hasattr(obj.bac_panel, "role_data"):
                for r in obj.bac_panel.role_data:
                    name = r.get("label")
                    if name:
                        role_labels.add(name)
        except:
            pass

        for entry in data.get("entries", []):
            param_name = entry.get("param_name")
            payload    = entry.get("payload")
            kind       = entry.get("kind")  # may be None in older saves

            if kind is None:
                # Heuristics for old history:
                # - If param_name matches a role tab label -> 'role'
                # - Else if there is a param_name or payload -> 'attack'
                # - Else -> 'send'
                if param_name in role_labels:
                    kind = "role"
                elif (param_name is not None) or (payload is not None):
                    kind = "attack"
                else:
                    kind = "send"

            e = MessageHistoryEntry(
                base64.b64decode(entry["req"]),
                base64.b64decode(entry["resp"]),
                param_name,
                payload,
                kind=kind
            )
            obj.history.append(e)

        # --- THIS IS THE KEY FIX: show correct counter right after reload ---
        if obj.history:
            obj.current_idx = len(obj.history) - 1
            obj.show_entry(obj.current_idx)
            # Force update counter label in case show_entry doesn't do it
            if hasattr(obj, "update_history_status"):
                obj.update_history_status()
        else:
            obj.current_idx = -1
            if hasattr(obj, "update_history_status"):
                obj.update_history_status()

        return obj

    def extract_sidepanel_lists(self, req_bytes):
        req_str = self.helpers.bytesToString(req_bytes)
        url_params = []
        body_params = []
        # --- Parse params from Burp's analysis ---
        service = self.base_message.getHttpService() if self.base_message else self.guess_service_from_request(req_bytes)
        analyzed = self.helpers.analyzeRequest(service, req_bytes) if service else None
        if analyzed:
            for p in analyzed.getParameters():
                if p.getType() == 0 and p.getName() not in url_params:
                    url_params.append(p.getName())
                # For JSON, we'll get params from our own parser
                if p.getType() == 1 and "content-type: application/json" not in req_str.lower():
                    if p.getName() not in body_params:
                        body_params.append(p.getName())

            # --- Try to parse JSON keys from body as body params ---
                        # --- Try to parse JSON keys from the body if it looks like JSON ---
            body_offset = analyzed.getBodyOffset()
            body = req_str[body_offset:]
            body_strip = body.strip()
            if body_strip.startswith("{") or body_strip.startswith("["):
                try:
                    # Remove BOM if present
                    bom = codecs.BOM_UTF8.decode('utf-8')
                    if body_strip.startswith(bom):
                        body_strip = body_strip[len(bom):]

                    j = json.loads(body_strip, strict=False)
                    for key in extract_json_keys_recursive(j):
                        if key not in body_params:
                            body_params.append(key)
                except Exception:
                    # if it's not valid JSON, we'll just skip parsing
                    pass
        # Default payloads
        url_payloads = ["null", "*", "' OR 1=1 --", "<script>alert(1)</script>"]
        body_payloads = ["=null", "*", "' OR 1=1 --", "<img src=x onerror=alert(1)>"]
        return url_params, url_payloads, body_params, body_payloads

    # IMessageEditorController methods
    def getHttpService(self):
        return self.base_message.getHttpService() if self.base_message else None
    def getRequest(self):
        return self.req_editor.getMessage()
    def getResponse(self):
        return self.resp_editor.getMessage()

    def send_request(self, event):
        def worker():
            try:
                # grab whatever the user has in the editor
                req_bytes = self.req_editor.getMessage()

                if self.base_message is not None:
                    service = self.base_message.getHttpService()
                else:
                    service = self.guess_service_from_request(req_bytes)
                    if not service:
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self,
                            "No HTTP service found.\nUse context menu to send a real request, or paste a valid request including Host: header."))
                        return
                # ─── NEW: rebuild the request so Content-Length is correct ───
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                headers = list(analyzed.getHeaders())
                body_offset = analyzed.getBodyOffset()
                body = req_bytes[body_offset:]
                headers = [h for h in headers if not h.lower().startswith("content-length")]
                headers.append("Content-Length: %d" % len(body))
                req_bytes = self.helpers.buildHttpMessage(headers, body)

                # now send
                t0 = time.time()
                resp = self.callbacks.makeHttpRequest(service, req_bytes)
                dt_ms = int(round((time.time() - t0) * 1000))
                resp_bytes = resp.getResponse()
                size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                entry = MessageHistoryEntry(req_bytes, resp_bytes, resp_time_ms=dt_ms, resp_size_bytes=size, kind="send")
                self.history.append(entry)
                self.current_idx = len(self.history) - 1
                
                def do_ui_update():
                    self.show_entry(self.current_idx)
                    # Immediately refresh the status square for this new entry
                    try:
                        self.update_status_indicator_from_entry(self.history[self.current_idx])
                    except:
                        pass
                    # Defer the resize call to run *after* any UI events from show_entry have completed.
                    self.resize_sidebar()
                SwingUtilities.invokeLater(do_ui_update)

                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()
                # --- Update side panel if user pasted a new request
                url_params, url_payloads, body_params, body_payloads = self.extract_sidepanel_lists(req_bytes)
                self.update_payload_panel(url_params, url_payloads, body_params, body_payloads)
            except Exception as e:
                # import traceback
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Error sending request:\n" + str(e) + "\n" + traceback.format_exc()))
        threading.Thread(target=worker).start()

    def attack(self, event):
        if self._run_in_flight:
            return
        def worker():
            try:
                req_bytes = self.req_editor.getMessage()
                req_str = self.helpers.bytesToString(req_bytes)
                if self.base_message is not None:
                    service = self.base_message.getHttpService()
                else:
                    service = self.guess_service_from_request(req_bytes)
                    if not service:
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "No HTTP service found.\nUse context menu to send a real request, or paste a valid request including Host: header."))
                        return
                # ─── NEW: rebuild the request so Content-Length is correct ───
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                headers = list(analyzed.getHeaders())
                body_offset = analyzed.getBodyOffset()
                body = req_bytes[body_offset:]
                headers = [h for h in headers if not h.lower().startswith("content-length")]
                headers.append("Content-Length: %d" % len(body))
                req_bytes = self.helpers.buildHttpMessage(headers, body)
                req_str = self.helpers.bytesToString(req_bytes)
                if self.base_message is not None:
                    service = self.base_message.getHttpService()
                else:
                    service = self.guess_service_from_request(req_bytes)
                    if not service:
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "No HTTP service found.\nUse context menu to send a real request, or paste a valid request including Host: header."))
                        return
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                params = analyzed.getParameters()
                # --- Use params and payloads from side panel
                url_params = self.payload_panel.get_url_params()
                url_payloads = self.payload_panel.get_url_payloads()
                body_params = self.payload_panel.get_body_params()
                body_payloads = self.payload_panel.get_body_payloads()
                param_types = {}
                for p in params:
                    if p.getType() in (0, 1):
                        param_types[p.getName()] = p.getType()
                history = []

                # Check for JSON body - detect JSON by content, not just content-type
                headers_str, body_str = req_str.split("\r\n\r\n", 1) if "\r\n\r\n" in req_str else (req_str, "")
                content_type = ""
                for header in headers_str.split("\r\n"):
                    if header.lower().startswith("content-type:"):
                        content_type = header.lower()
                        break
                
                # Check if body is JSON regardless of content-type
                is_json_body = False
                try:
                    if body_str.strip():
                        json.loads(body_str.strip())
                        is_json_body = True
                except:
                    is_json_body = False
                
                # Use JSON handling if either content-type says JSON OR body is valid JSON
                is_json = (("application/json" in content_type) or 
                        (is_json_body and body_str.strip().startswith(("{", "["))))
                # --- Progress start ---
                total = len(url_params) * len(url_payloads)
                total += len(body_params) * len(body_payloads)  # body fuzzing count
                if not self._begin_run(total, label="Attack"):
                    return

                # --- Attack URL params (type 0) ---
                for pname in url_params:
                    for payload in url_payloads:
                        mod_req_bytes = req_bytes
                        for p in params:
                            if p.getName() == pname and p.getType() == 0:
                                mod_req_bytes = self.helpers.removeParameter(mod_req_bytes, p)
                        new_param = self.helpers.buildParameter(pname, payload, 0)
                        mod_req_bytes = self.helpers.addParameter(mod_req_bytes, new_param)
                        # Rebuild Content-Length
                        analyzed_mod = self.helpers.analyzeRequest(service, mod_req_bytes)
                        headers_mod = list(analyzed_mod.getHeaders())
                        body_offset_mod = analyzed_mod.getBodyOffset()
                        body_mod = mod_req_bytes[body_offset_mod:]
                        headers_mod = [h for h in headers_mod if not h.lower().startswith("content-length")]
                        headers_mod.append("Content-Length: %d" % len(body_mod))
                        mod_req_bytes = self.helpers.buildHttpMessage(headers_mod, body_mod)
                        t0 = time.time()
                        resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                        dt_ms = int(round((time.time() - t0) * 1000))
                        resp_bytes = resp.getResponse()
                        size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                        mark = self.find_param_offset(self.helpers.bytesToString(mod_req_bytes), pname, payload)
                        entry = MessageHistoryEntry(mod_req_bytes, resp_bytes, param_name=pname, payload=payload,
                                                    resp_time_ms=dt_ms, resp_size_bytes=size, kind="attack")
                        entry.highlight = mark
                        history.append(entry)
                        self._tick()

                # --- Attack body/form params (type 1) ---
                # Only skip body param attacks if it's JSON (we handle JSON separately)
                if not is_json:
                    # Process body parameters
                    for pname in body_params:
                        for payload in body_payloads:
                            mod_req_bytes = req_bytes
                            found_existing_param = False
                            
                            # Remove existing parameter if it exists
                            for p in params:
                                if p.getName() == pname and p.getType() == 1:
                                    mod_req_bytes = self.helpers.removeParameter(mod_req_bytes, p)
                                    found_existing_param = True
                            
                            # For text/plain content, we might need to handle body parameters differently
                            # Check if this is a text/plain request
                            if "text/plain" in content_type:
                                # For text/plain, manually modify the body content
                                analyzed_temp = self.helpers.analyzeRequest(service, mod_req_bytes)
                                body_offset_temp = analyzed_temp.getBodyOffset()
                                current_body = self.helpers.bytesToString(mod_req_bytes[body_offset_temp:])
                                
                                # Try to replace parameter in body text
                                # This is a simple approach - you might need to customize based on your body format
                                if pname in current_body:
                                    # Replace existing parameter value
                                    import re
                                    # Pattern to match parameter=value or parameter:value or just parameter value
                                    patterns = [
                                        r'(' + re.escape(pname) + r'=)[^&\s\n]*',
                                        r'(' + re.escape(pname) + r':)[^,\s\n]*',
                                        r'(' + re.escape(pname) + r'\s+)[^\s\n]*'
                                    ]
                                    
                                    modified_body = current_body
                                    for pattern in patterns:
                                        if re.search(pattern, current_body):
                                            modified_body = re.sub(pattern, r'\1' + payload, current_body)
                                            break
                                    
                                    if modified_body != current_body:
                                        # Reconstruct the request with modified body
                                        headers_temp = list(analyzed_temp.getHeaders())
                                        headers_temp = [h for h in headers_temp if not h.lower().startswith("content-length")]
                                        headers_temp.append("Content-Length: %d" % len(modified_body))
                                        mod_req_bytes = self.helpers.buildHttpMessage(headers_temp, self.helpers.stringToBytes(modified_body))
                                        found_existing_param = True
                                else:
                                    # Add parameter to body if it doesn't exist
                                    if current_body:
                                        # Add parameter at the end of body with appropriate separator
                                        if current_body.endswith('\n'):
                                            modified_body = current_body + pname + '=' + payload
                                        else:
                                            modified_body = current_body + '\n' + pname + '=' + payload
                                    else:
                                        modified_body = pname + '=' + payload
                                    
                                    headers_temp = list(analyzed_temp.getHeaders())
                                    headers_temp = [h for h in headers_temp if not h.lower().startswith("content-length")]
                                    headers_temp.append("Content-Length: %d" % len(modified_body))
                                    mod_req_bytes = self.helpers.buildHttpMessage(headers_temp, self.helpers.stringToBytes(modified_body))
                                    found_existing_param = True
                            else:
                                # For other content types, use Burp's parameter handling
                                new_param = self.helpers.buildParameter(pname, payload, 1)
                                mod_req_bytes = self.helpers.addParameter(mod_req_bytes, new_param)
                                found_existing_param = True
                            
                            # Rebuild Content-Length one more time to ensure it's correct
                            analyzed_mod = self.helpers.analyzeRequest(service, mod_req_bytes)
                            headers_mod = list(analyzed_mod.getHeaders())
                            body_offset_mod = analyzed_mod.getBodyOffset()
                            body_mod = mod_req_bytes[body_offset_mod:]
                            headers_mod = [h for h in headers_mod if not h.lower().startswith("content-length")]
                            headers_mod.append("Content-Length: %d" % len(body_mod))
                            mod_req_bytes = self.helpers.buildHttpMessage(headers_mod, body_mod)
                            
                            # Only send request if we actually modified something or found a parameter
                            if found_existing_param or mod_req_bytes != req_bytes:
                                t0 = time.time()
                                resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                                dt_ms = int(round((time.time() - t0) * 1000))
                                resp_bytes = resp.getResponse()
                                size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                                mark = self.find_param_offset(self.helpers.bytesToString(mod_req_bytes), pname, payload)
                                entry = MessageHistoryEntry(mod_req_bytes, resp_bytes, param_name=pname, payload=payload,
                                                            resp_time_ms=dt_ms, resp_size_bytes=size, kind="attack")
                                entry.highlight = mark
                                history.append(entry)
                                self._tick()

                # --- Attack JSON body keys if body is JSON ---
                if is_json:
                    try:
                        jbody = json.loads(body_str, strict=False)
                        if isinstance(jbody, (dict, list)):
                            for key_path in body_params:
                                for payload in body_payloads:
                                    jbody_mod = deepcopy(jbody)
                                    try:
                                        val = coerce_json_value(payload)
                                        set_nested_value(jbody_mod, key_path, val)
                                        body_mod = json.dumps(jbody_mod)
                                        req_mod = headers_str + "\r\n\r\n" + body_mod
                                        mod_req_bytes = self.helpers.stringToBytes(req_mod)
                                        # Rebuild Content-Length
                                        analyzed_mod = self.helpers.analyzeRequest(service, mod_req_bytes)
                                        headers_mod = list(analyzed_mod.getHeaders())
                                        body_offset_mod = analyzed_mod.getBodyOffset()
                                        body_mod_bytes = mod_req_bytes[body_offset_mod:]
                                        headers_mod = [h for h in headers_mod if not h.lower().startswith("content-length")]
                                        headers_mod.append("Content-Length: %d" % len(body_mod_bytes))
                                        mod_req_bytes = self.helpers.buildHttpMessage(headers_mod, body_mod_bytes)
                                        t0 = time.time()
                                        resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                                        dt_ms = int(round((time.time() - t0) * 1000))
                                        resp_bytes = resp.getResponse()
                                        size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                                        entry = MessageHistoryEntry(mod_req_bytes, resp_bytes, param_name=key_path, payload=payload,
                                                                    resp_time_ms=dt_ms, resp_size_bytes=size, kind="attack")

                                        history.append(entry)
                                        self._tick()
                                    except (KeyError, IndexError, TypeError):
                                        pass
                    except Exception:
                        pass

                self.history += history
                
                def do_ui_update():
                    if history:
                        self.current_idx = len(self.history) - len(history)
                        self.show_entry(self.current_idx)
                        try:
                            self.update_status_indicator_from_entry(self.history[self.current_idx])
                        except:
                            pass
                    else:
                        # Should still update status if no requests were sent
                        self.update_status()
                    # Defer the resize call to run *after* any UI events from show_entry/update_status
                    self.resize_sidebar()
                SwingUtilities.invokeLater(do_ui_update)

                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()
            except Exception as e:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Attack Error:\n" + str(e) + "\n" + traceback.format_exc()))
            finally:
                self._end_run()
        threading.Thread(target=worker).start()
        
    def bac_check(self, event):
        if self._run_in_flight:
            return
        def worker():
            try:
                req_bytes = self.req_editor.getMessage()
                req_str = self.helpers.bytesToString(req_bytes)
                service = self.base_message.getHttpService() if self.base_message else self.guess_service_from_request(req_bytes)

                # Rebuild request for accurate Content-Length
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                headers = list(analyzed.getHeaders())
                body_offset = analyzed.getBodyOffset()
                body = req_bytes[body_offset:]
                headers = [h for h in headers if not h.lower().startswith("content-length")]
                headers.append("Content-Length: %d" % len(body))
                req_bytes = self.helpers.buildHttpMessage(headers, body)
                req_str = self.helpers.bytesToString(req_bytes)

                # Parse headers
                header_lines, body = (req_str.split('\r\n\r\n', 1) + [""])[:2]
                base_headers = header_lines.split('\r\n')
                history = []
                # Count how many roles are enabled (and not the '+' tab)
                enabled_roles = 0
                for idx, role in enumerate(list(self.bac_panel.role_data)):
                    if idx < self.bac_panel.role_tabs.getTabCount() - 1 and role.get("enabled", True):
                        enabled_roles += 1

                if not self._begin_run(enabled_roles, label="Access Check"):
                    return

                for idx, role in enumerate(list(self.bac_panel.role_data)):
                    if idx >= self.bac_panel.role_tabs.getTabCount() - 1 or not role.get("enabled", True):
                        continue

                    # Build map of headers to override
                    role_headers = {
                        h['header'].strip().lower(): h['value']
                        for h in role.get('headers', []) if h.get('header')
                    }

                    request_line = base_headers[0]
                    rest_headers = base_headers[1:]

                    changed_headers = []
                    unchanged_headers = []
                    used_headers = set()

                    for h in rest_headers:
                        if ':' in h:
                            hname, hval = h.split(':', 1)
                            hname_stripped = hname.strip()
                            hname_lc = hname_stripped.lower()
                            if hname_lc in role_headers:
                                changed_headers.append("%s: %s" % (hname_stripped, role_headers[hname_lc]))
                                used_headers.add(hname_lc)
                            else:
                                unchanged_headers.append(h)
                        else:
                            unchanged_headers.append(h)

                    # Add any new headers from role not originally present (only if Force is enabled)
                    if role.get("force", False):
                        for hname_lc, hval in role_headers.items():
                            if hname_lc not in used_headers:
                                changed_headers.append("%s: %s" % (hname_lc, hval))

                    # Add extra header after changed ones
                    if role.get('extra_enabled') and role.get('extra_name'):
                        extra_name = role.get('extra_name').strip()
                        extra_value = role.get('extra_value', '')
                        extra_name_lc = extra_name.lower()
                        unchanged_headers = [
                            h for h in unchanged_headers
                            if not (':' in h and h.split(':', 1)[0].strip().lower() == extra_name_lc)
                        ]
                        changed_headers.append("%s: %s" % (extra_name, extra_value))

                    # Final assembly
                    modified_headers = [request_line] + changed_headers + unchanged_headers
                    new_req_str = "\r\n".join(modified_headers) + "\r\n\r\n" + body
                    mod_req_bytes = self.helpers.stringToBytes(new_req_str)

                    t0 = time.time()
                    resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                    dt_ms = int(round((time.time() - t0) * 1000))
                    resp_bytes = resp.getResponse()
                    size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                    entry = MessageHistoryEntry(
                        mod_req_bytes,
                        resp_bytes,
                        param_name=role['label'],
                        payload="; ".join(["%s=%s" % (h.get('header', ''), h.get('value', '')) for h in role.get('headers', [])]),
                        resp_time_ms=dt_ms,
                        resp_size_bytes=size,
                        kind="role"
                    )
                    history.append(entry)
                    self._tick()

                self.history += history

                def do_ui_update():
                    if history:
                        self.current_idx = len(self.history) - len(history)
                        self.show_entry(self.current_idx)
                        try:
                            self.update_status_indicator_from_entry(self.history[self.current_idx])
                        except:
                            pass
                    else:
                        self.update_status()
                    self.resize_sidebar()

                SwingUtilities.invokeLater(do_ui_update)

                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()

            except Exception as e:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Role Probe Error:\n" + str(e) + "\n" + traceback.format_exc()))
            finally:
                self._end_run()
        threading.Thread(target=worker).start()

    def bac_check_single(self, role_idx):
        def worker():
            try:
                req_bytes = self.req_editor.getMessage()
                service = self.base_message.getHttpService() if self.base_message else self.guess_service_from_request(req_bytes)

                # Rebuild request for accurate Content-Length
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                headers = list(analyzed.getHeaders())
                body_offset = analyzed.getBodyOffset()
                body = req_bytes[body_offset:]
                headers = [h for h in headers if not h.lower().startswith("content-length")]
                headers.append("Content-Length: %d" % len(body))
                req_bytes = self.helpers.buildHttpMessage(headers, body)
                req_str = self.helpers.bytesToString(req_bytes)

                # Split headers/body
                header_lines, body_part = (req_str.split('\r\n\r\n', 1) + [""])[:2]
                base_headers = header_lines.split('\r\n')

                # Validate role_idx against current tabs (exclude +)
                if not hasattr(self, "bac_panel") or not hasattr(self.bac_panel, "role_tabs"):
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Role UI not ready."))
                    return

                plus_idx = self.bac_panel.role_tabs.getTabCount() - 1
                if role_idx < 0 or role_idx >= plus_idx or role_idx >= len(self.bac_panel.role_data):
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Invalid role index."))
                    return

                role = self.bac_panel.role_data[role_idx]
                if not role.get("enabled", True):
                    # still allow single check even if globally disabled (that’s the point)
                    pass

                # Build header map to override
                role_headers = {
                    h['header'].strip().lower(): h['value']
                    for h in role.get('headers', []) if h.get('header')
                }

                request_line = base_headers[0]
                rest_headers = base_headers[1:]

                changed_headers, unchanged_headers, used = [], [], set()
                for h in rest_headers:
                    if ':' in h:
                        hn, hv = h.split(':', 1)
                        hn_stripped = hn.strip()
                        hn_lc = hn_stripped.lower()
                        if hn_lc in role_headers:
                            changed_headers.append("%s: %s" % (hn_stripped, role_headers[hn_lc]))
                            used.add(hn_lc)
                        else:
                            unchanged_headers.append(h)
                    else:
                        unchanged_headers.append(h)

                # Add headers present only in role (only if Force is enabled)
                if role.get("force", False):
                    for hn_lc, hval in role_headers.items():
                        if hn_lc not in used:
                            changed_headers.append("%s: %s" % (hn_lc, hval))

                # Extra header support
                if role.get('extra_enabled') and role.get('extra_name'):
                    ename = role.get('extra_name', '').strip()
                    eval_ = role.get('extra_value', '')
                    ename_lc = ename.lower()
                    unchanged_headers = [
                        h for h in unchanged_headers
                        if not (':' in h and h.split(':', 1)[0].strip().lower() == ename_lc)
                    ]
                    changed_headers.append("%s: %s" % (ename, eval_))

                # Final request
                modified_headers = [request_line] + changed_headers + unchanged_headers
                new_req_str = "\r\n".join(modified_headers) + "\r\n\r\n" + body_part
                mod_req_bytes = self.helpers.stringToBytes(new_req_str)

                t0 = time.time()
                resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                dt_ms = int(round((time.time() - t0) * 1000))
                resp_bytes = resp.getResponse()
                size = 0 if resp_bytes is None else len(bytearray(resp_bytes))

                entry = MessageHistoryEntry(
                    mod_req_bytes,
                    resp_bytes,
                    param_name=role.get('label', 'Role'),
                    payload="; ".join(["%s=%s" % (h.get('header', ''), h.get('value', '')) for h in role.get('headers', [])]),
                    resp_time_ms=dt_ms,
                    resp_size_bytes=size,
                    kind="role"
                )

                self.history.append(entry)
                self.current_idx = len(self.history) - 1

                SwingUtilities.invokeLater(lambda: (
                    self.show_entry(self.current_idx),
                    # Immediately refresh the status square
                    self.update_status_indicator_from_entry(self.history[self.current_idx]),
                    self.resize_sidebar()
                ))
                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()

            except Exception as e:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Role Probe (single) Error:\n" + str(e) + "\n" + traceback.format_exc()))
        threading.Thread(target=worker).start()


    def _save_table_state(self):
        # Save the current enabled/disabled state and custom payloads
        state = {}
        if hasattr(self, 'payload_panel'):
            pp = self.payload_panel
            # Save parameter/payload values and enableds
            def get_state(panel):
                try:
                    # Returns list of tuples: (value, enabled)
                    return [(row[0], bool(row[1])) for row in panel.model.rows]
                except Exception:
                    return []
            state['url_params'] = get_state(pp.url_params_panel)
            state['url_payloads'] = get_state(pp.url_payloads_panel)
            state['body_params'] = get_state(pp.body_params_panel)
            state['body_payloads'] = get_state(pp.body_payloads_panel)
        return state

    def _restore_table_state(self, state):
        # After you create self.payload_panel, restore the values
        def set_state(panel, entries):
            for i, (val, enabled) in enumerate(entries):
                try:
                    panel.model.setValueAt(enabled, i, 1)
                except Exception:
                    pass

        pp = self.payload_panel
        if not pp: return
        set_state(pp.url_params_panel, state.get('url_params', []))
        set_state(pp.url_payloads_panel, state.get('url_payloads', []))
        set_state(pp.body_params_panel, state.get('body_params', []))
        set_state(pp.body_payloads_panel, state.get('body_payloads', []))

    def update_payload_panel(self, url_params, url_payloads, body_params, body_payloads):
        if not hasattr(self, "inspector_tabs"):
            # print("DEBUG: inspector_tabs not defined yet, skipping update_payload_panel")
            return
    # --- 1. Save previous state as value->enabled mapping
        def get_state(panel):
            try:
                return dict((str(row[0]), bool(row[1])) for row in panel.model.rows)
            except Exception:
                return {}

        old_state = {}
        if hasattr(self, "payload_panel"):
            pp = self.payload_panel
            old_state["url_params"] = get_state(pp.url_params_panel)
            old_state["url_payloads"] = get_state(pp.url_payloads_panel)
            old_state["body_params"] = get_state(pp.body_params_panel)
            old_state["body_payloads"] = get_state(pp.body_payloads_panel)
        else:
            old_state = {"url_params": {}, "url_payloads": {}, "body_params": {}, "body_payloads": {}}

        # --- 2. Recreate the panels as before
        new_payload_panel = PayloadSidePanel(url_params, url_payloads, body_params, body_payloads)

        # --- 3. Restore enabled/disabled state by value
        def restore(panel, state_map):
            for i in range(panel.model.getRowCount()):
                val = str(panel.model.getValueAt(i, 0))
                if val in state_map:
                    panel.model.setValueAt(state_map[val], i, 1)

        restore(new_payload_panel.url_params_panel, old_state["url_params"])
        restore(new_payload_panel.url_payloads_panel, old_state["url_payloads"])
        restore(new_payload_panel.body_params_panel, old_state["body_params"])
        restore(new_payload_panel.body_payloads_panel, old_state["body_payloads"])

        # --- 4. Swap in the new panel in the Param Probe sub-tab (index 0)
        self.inspector_tabs.setComponentAt(0, new_payload_panel)
        self.payload_panel = new_payload_panel


    def go_prev(self, event):
        if self.history and self.current_idx > 0:
            self.current_idx -= 1
            self.show_entry(self.current_idx)
            self.update_status()
    def go_next(self, event):
        if self.history and self.current_idx < len(self.history) - 1:
            self.current_idx += 1
            self.show_entry(self.current_idx)
            self.update_status()
    def show_entry(self, idx):
        entry = self.history[idx]
        self.req_editor.setMessage(entry.req_bytes, True)
        try:
            if hasattr(self.req_editor, "setHighlight"):
                if hasattr(entry, "highlight") and entry.highlight:
                    self.req_editor.setHighlight(entry.highlight[0], entry.highlight[1])
                else:
                    self.req_editor.setHighlight(-1, -1)
        except:
            pass

        if entry.resp_bytes is None:
            self.resp_editor.setMessage(bytearray(), False)
            if hasattr(self, "metrics_lbl"):
                self.metrics_lbl.setText(" ")
        else:
            self.resp_editor.setMessage(entry.resp_bytes, False)
            if hasattr(self, "metrics_lbl"):
                size = entry.resp_size_bytes if entry.resp_size_bytes is not None else len(bytearray(entry.resp_bytes))
                ms = entry.resp_time_ms if entry.resp_time_ms is not None else 0
                self.metrics_lbl.setText("%d bytes | %d ms" % (size, ms))

        # Update status square from the selected entry
        self.update_status_indicator_from_entry(entry)
        self.update_status()

    def update_status_indicator_from_entry(self, entry):
        try:
            if entry is None or entry.resp_bytes is None:
                # Unknown/empty
                SwingUtilities.invokeLater(lambda: self.status_indicator.setStatus(None, False))
                return
            resp_bytes = entry.resp_bytes
            info = self.helpers.analyzeResponse(resp_bytes)
            code = info.getStatusCode()
            body_off = info.getBodyOffset()
            has_body = False
            try:
                raw = bytearray(resp_bytes)
                if body_off is not None and body_off >= 0 and body_off < len(raw):
                    # consider body present only if there is non-whitespace after the offset
                    tail = self.helpers.bytesToString(raw[body_off:])
                    has_body = bool(tail) and bool(tail.strip())
            except:
                pass
            SwingUtilities.invokeLater(lambda: self.status_indicator.setStatus(code, has_body))
        except:
            SwingUtilities.invokeLater(lambda: self.status_indicator.setStatus(None, False))
        
    def show_history_dropdown(self, is_forward=True):
        popup = JPopupMenu()
        entries = self.history
        curr = self.current_idx
        if not entries:
            return

        indices = range(curr + 1, len(entries)) if is_forward else range(curr - 1, -1, -1)
        for i in indices:
            entry = entries[i]
            label = "%d. %s" % (i + 1, self.summarize_entry(entry))
            item = JMenuItem(label)
            item.addActionListener(lambda evt, idx=i: self.jump_to_history(idx))
            popup.add(item)

        btn = self.next_btn if is_forward else self.prev_btn
        popup.show(btn, 0, btn.getHeight())

    def summarize_entry(self, entry):
        # Prefer human-friendly labels based on what kind of action it was
        try:
            # ATTACK: show "param = value"
            if getattr(entry, "kind", None) == "attack" and entry.param_name:
                val = entry.payload if entry.payload is not None else ""
                # keep labels short
                if isinstance(val, str):
                    if len(val) > 80:
                        val = val[:77] + "..."
                return u"%s = %s" % (entry.param_name, val)

            # ROLE/BAC: show "Role: <role tab name>"
            if getattr(entry, "kind", None) == "role":
                label = entry.param_name or "Role"
                return u"Role: %s" % label

            # SEND (or unknown): show API URL like Repeater
            analyzed = self.helpers.analyzeRequest(self.getHttpService(), entry.req_bytes)
            url = analyzed.getUrl().toString()
            return url
        except:
            return "(invalid)"


    def jump_to_history(self, idx):
        self.current_idx = idx
        self.show_entry(idx)
        self.update_status()
    
    def update_status(self):
        total = len(self.history)
        idx = self.current_idx + 1 if self.current_idx >= 0 else 0
        self.status_lbl.setText(" %d/%d " % (idx, total))

    def find_param_offset(self, req_str, param, value):
        try:
            pattern = r'(%s=)' % re.escape(param)
            matches = list(re.finditer(pattern, req_str))
            for m in matches:
                val_start = m.end()
                if req_str[val_start:val_start+len(value)] == value:
                    start = val_start
                    end = val_start + len(value)
                    return (start, end)
            return None
        except Exception as e:
            return None

    def find_json_key_offset(self, body, key, payload):
        try:
            patt = r'("%s"\s*:\s*)"(.*?)"' % re.escape(key)
            for m in re.finditer(patt, body):
                val = m.group(2)
                if val == payload:
                    val_start = m.start(2)
                    return (val_start, val_start+len(payload))
            patt2 = r"('%s'\s*:\s*)'(.*?)'" % re.escape(key)
            for m in re.finditer(patt2, body):
                val = m.group(2)
                if val == payload:
                    val_start = m.start(2)
                    return (val_start, val_start+len(payload))
            return None
        except:
            return None

    def guess_service_from_request(self, req_bytes):
        try:
            req_str = self.helpers.bytesToString(req_bytes)
            host = None
            port = 80
            protocol = "http"
            for line in req_str.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    if ":" in host:
                        host, port_str = host.split(":", 1)
                        port = int(port_str)
                    break
            if req_str.startswith("CONNECT ") or ":443" in req_str:
                protocol = "https"
                port = 443
            if host:
                return self.helpers.buildHttpService(host, port, protocol)
            return None
        except:
            return None

    def takeScreenshot(self, event):
        try:
            
            # Unique key for screenshots
            LAST_SCREENSHOT_DIR_KEY = "last-screenshot-directory"

            # Capture only the main_split: request and response editor window
            split = self.main_split
            loc = split.getLocationOnScreen()
            size = split.getSize()
            rect = Rectangle(loc.x, loc.y, size.width, size.height)
            robot = Robot()
            image = robot.createScreenCapture(rect)
            req_bytes = self.req_editor.getMessage()
            req_str = self.helpers.bytesToString(req_bytes)
            path = "poc_screenshot"
            m = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?]+)", req_str)
            if m:
                path = m.group(1).replace("/", "_").strip("_")
            default_file = File(path + ".png")

            # --- Remember last-used screenshot folder ---
            last_dir = load_setting(self.callbacks, LAST_SCREENSHOT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()

            chooser.setSelectedFile(default_file)
            chooser.setDialogTitle("Save Screenshot As")
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                save_path = file.getAbsolutePath()
                if not save_path.endswith(".png"):
                    save_path += ".png"

                # Save directory for next time
                save_setting(self.callbacks, LAST_SCREENSHOT_DIR_KEY, os.path.dirname(save_path))

                ImageIO.write(image, "png", File(save_path))
        except Exception as e:
            print("[-] Screenshot failed:", str(e))

    def resize_sidebar(self):
        def do_resize():
            if not self.right_panel.isShowing():
                return
            desired_width = self.sidebar_width_expanded if not self.tab_collapsed else self.sidebar_width_collapsed
            divider_location = self.outer_split.getWidth() - desired_width
            # Sanity check to avoid invalid divider locations
            if divider_location >= 0 and divider_location < self.outer_split.getWidth():
                self.outer_split.setDividerLocation(divider_location)
        # Always run on the EDT
        SwingUtilities.invokeLater(do_resize)

    

### You may add your ClosableTabComponent, PlusTabComponent, and BurpExtender skeleton below as before ###

# ---------- Tab Decorators ----------
class ClosableTabComponent(JPanel):
    def __init__(self, tabs, tab_panel, title, bac_parent=None, role_idx=None):
        JPanel.__init__(self)
        self.tabs = tabs
        self.tab_panel = tab_panel
        self.bac_parent = bac_parent   # Use this instead of .parent!
        self.setOpaque(False)
        self.setLayout(FlowLayout(FlowLayout.LEFT, 0, 0))
        self.role_idx = role_idx
        self.enable_checkbox = None
        # --- Enable/disable checkbox for BAC roles, now on the left ---
        if self.bac_parent is not None and role_idx is not None:
            self.enable_checkbox = JCheckBox()
            enabled = True
            try:
                enabled = bool(self.bac_parent.role_data[role_idx].get("enabled", True))
            except Exception:
                pass
            self.enable_checkbox.setSelected(enabled)
            self.enable_checkbox.setToolTipText("Enable/disable this role for Access Check")
            self.enable_checkbox.addActionListener(self.on_checkbox_toggle)
            self.add(self.enable_checkbox)
        self.label = JLabel(title)
        self.add(self.label)
        self.close_button = JButton("x")
        self.close_button.setPreferredSize(Dimension(16, 16))  # Good hitbox
        self.close_button.setFocusable(False)
        self.close_button.setToolTipText("Close tab")
        self.close_button.setBorderPainted(True)  # Draw border!
        self.close_button.setContentAreaFilled(False)
        self.close_button.setOpaque(True)
        self.close_button.setBackground(Color(240,240,240))  # or a color matching your theme
        self.close_button.setBorder(BorderFactory.createLineBorder(Color(200,200,200)))  # Draw visible box
        class CloseListener(ActionListener):
            def actionPerformed(listener_self, e):
                idx = self.tabs.indexOfComponent(self.tab_panel)
                plus_idx = self.tabs.getTabCount() - 1
                if idx != -1 and idx < plus_idx:
                    self.tabs.remove(idx)
                    if self.bac_parent and hasattr(self.bac_parent, 'role_data'):
                        if idx < len(self.bac_parent.role_data):
                            del self.bac_parent.role_data[idx]
                            self.bac_parent.save_state()
        self.close_button.addActionListener(CloseListener())
        self.add(self.close_button)
        # Mouse listener for switching/renaming
        self.addMouseListener(self.TabMouseListener(self))
        self.close_button.addMouseListener(self.IgnoreTabSwitchListener())
    def set_checkbox_state(self, checked):
        if self.enable_checkbox is not None:
            self.enable_checkbox.setSelected(checked)
    def setTitle(self, title):
        self.label.setText(title)
    class TabMouseListener(MouseAdapter):
        def __init__(self, parent):
            MouseAdapter.__init__(self)
            self.parent = parent
        def mouseClicked(self, evt):
            idx = self.parent.tabs.indexOfComponent(self.parent.tab_panel)
            if idx == -1:
                return
            if evt.getSource() == self.parent:
                self.parent.tabs.setSelectedIndex(idx)
                # Double-click = rename dialog
                if evt.getClickCount() == 2:
                    name = JOptionPane.showInputDialog(self.parent, "Rename tab:", self.parent.label.getText())
                    if name:
                        self.parent.label.setText(name)
                        self.parent.tabs.setTitleAt(idx, name)
                        # For BACCheckPanel, also update label in role_data
                        if self.parent.bac_parent and hasattr(self.parent.bac_parent, 'role_data'):
                            if idx < len(self.parent.bac_parent.role_data):
                                self.parent.bac_parent.role_data[idx]["label"] = name
                                self.save_state()
    class IgnoreTabSwitchListener(MouseAdapter):
        def mouseClicked(self, evt):
            evt.consume()
    def on_checkbox_toggle(self, event):
        # Update the enabled state in role_data
        if self.bac_parent is not None and self.role_idx is not None:
            try:
                self.bac_parent.role_data[self.role_idx]["enabled"] = self.enable_checkbox.isSelected()
                self.bac_parent.save_state()
            except Exception:
                pass

class PlusTabComponent(JPanel):
    def __init__(self, tabs, extender):
        JPanel.__init__(self)
        self.tabs = tabs
        self.extender = extender
        self.setLayout(FlowLayout(FlowLayout.LEFT, 0, 0))
        plus_btn = JButton("+")
        plus_btn.setPreferredSize(Dimension(32, 24))
        plus_btn.setFocusable(False)
        plus_btn.setToolTipText("Add empty fuzzer tab")
        class PlusListener(ActionListener):
            def actionPerformed(listener_self, e):
                self.extender.add_fuzzer_tab()
        plus_btn.addActionListener(PlusListener())
        self.add(plus_btn)

# ---------- Custom Vertical Button ----------
# from javax.swing import JToggleButton
# from java.awt import Graphics2D
# ---------- Small clickable status square ----------
class StatusIndicator(JPanel):
    def __init__(self, size=20):
        JPanel.__init__(self)
        self.setLayout(OverlayLayout(self))  # overlay children
        self.setPreferredSize(Dimension(size, size))
        self.setMinimumSize(Dimension(size, size))
        self.setMaximumSize(Dimension(size, size))
        self.setBorder(BorderFactory.createLineBorder(Color(0,0,0)))
        self.setToolTipText("Response status indicator (click to toggle)")

        # state
        self.enabled_flag = True
        self.base_color = Color(192,192,192)
        self.show_tri = False  # tri-color flag enabled?
        self.tri_top = self.base_color
        self.tri_mid = Color(0,0,0)
        self.tri_bot = self.base_color

        # Single-color panel (default)
        self.single_panel = JPanel()
        self.single_panel.setOpaque(True)
        self.single_panel.setBackground(self.base_color)

        # Tri-color panel (top/base, mid/black, bottom/base)
        self.tri_panel = JPanel(GridLayout(3, 1, 0, 0))
        self.tri_panel.setOpaque(True)
        self.tri_top_panel = JPanel();  self.tri_top_panel.setOpaque(True)
        self.tri_mid_panel = JPanel();  self.tri_mid_panel.setOpaque(True)
        self.tri_bot_panel = JPanel();  self.tri_bot_panel.setOpaque(True)
        self.tri_panel.add(self.tri_top_panel)
        self.tri_panel.add(self.tri_mid_panel)
        self.tri_panel.add(self.tri_bot_panel)
        self.tri_panel.setVisible(False)  # hidden until needed

        # Disabled overlay (shows an X)
        self.disabled_lbl = JLabel(u"\u2715", SwingConstants.CENTER)  # ✕
        self.disabled_lbl.setAlignmentX(0.5)
        self.disabled_lbl.setAlignmentY(0.5)
        self.disabled_lbl.setOpaque(False)
        self.disabled_lbl.setFont(Font("Dialog", Font.BOLD, 12))
        self.disabled_lbl.setForeground(Color(0,0,0))
        self.disabled_lbl.setVisible(False)

        # Add in z-order: background(s) first, overlay last
        self.add(self.single_panel)
        self.add(self.tri_panel)
        self.add(self.disabled_lbl)

        # Make children fill the box so they’re visible
        maxHuge = Dimension(10000, 10000)
        self.single_panel.setMaximumSize(maxHuge)
        self.tri_panel.setMaximumSize(maxHuge)
        self.tri_top_panel.setMaximumSize(maxHuge)
        self.tri_mid_panel.setMaximumSize(maxHuge)
        self.tri_bot_panel.setMaximumSize(maxHuge)
        self.disabled_lbl.setMaximumSize(maxHuge)
        self.disabled_lbl.setHorizontalAlignment(SwingConstants.CENTER)
        self.disabled_lbl.setVerticalAlignment(SwingConstants.CENTER)

        # click anywhere toggles enabled/disabled
        class Clicker(MouseAdapter):
            def mouseClicked(listener_self, e):
                self.setEnabledFlag(not self.enabled_flag)
        self.addMouseListener(Clicker())
        self.single_panel.addMouseListener(Clicker())
        self.tri_panel.addMouseListener(Clicker())
        self.tri_top_panel.addMouseListener(Clicker())
        self.tri_mid_panel.addMouseListener(Clicker())
        self.tri_bot_panel.addMouseListener(Clicker())
        self.disabled_lbl.addMouseListener(Clicker())

    def setEnabledFlag(self, enabled):
        self.enabled_flag = bool(enabled)
        # when disabled, show gray single panel + X; hide tri
        if self.enabled_flag:
            if self.show_tri:
                self.tri_panel.setVisible(True)
                self.single_panel.setVisible(False)
            else:
                self.tri_panel.setVisible(False)
                self.single_panel.setVisible(True)
            self.single_panel.setBackground(self.base_color)
            self.disabled_lbl.setVisible(False)
        else:
            self.tri_panel.setVisible(False)
            self.single_panel.setVisible(True)
            self.single_panel.setBackground(Color(180,180,180))
            self.disabled_lbl.setVisible(True)
        self.revalidate()
        self.repaint()

    def setStatus(self, status_code=None, has_body=False):
        """
        Colors:
          1xx -> WHITE
          2xx -> GREEN
          3xx -> BLUE
          4xx -> YELLOW
          5xx -> RED
        For 3xx/4xx/5xx + body -> show tri-color flag: base / black / base
        """
        try:
            code = int(status_code) if status_code is not None else None
        except:
            code = None

        if code is None:
            self.base_color = Color(192,192,192)  # unknown
            self.show_tri = False
        else:
            cat = code // 100
            if   cat == 1: self.base_color = Color(255, 255, 255)   # WHITE (changed per request)
            elif cat == 2: self.base_color = Color( 15, 157,  88)   # GREEN
            elif cat == 3: self.base_color = Color( 66, 133, 244)   # BLUE  (changed per request)
            elif cat == 4: self.base_color = Color(251, 188,   5)   # YELLOW
            elif cat == 5: self.base_color = Color(219,  68,  55)   # RED
            else:          self.base_color = Color(160,160,160)

            self.show_tri = (cat in (3,4,5)) and bool(has_body)

        # Apply colors to the panels
        self.tri_top = self.base_color
        self.tri_mid = Color(0,0,0)
        self.tri_bot = self.base_color
        self.tri_top_panel.setBackground(self.tri_top)
        self.tri_mid_panel.setBackground(self.tri_mid)
        self.tri_bot_panel.setBackground(self.tri_bot)

        if self.enabled_flag:
            # show tri if requested; else single with base color
            if self.show_tri:
                self.tri_panel.setVisible(True)
                self.single_panel.setVisible(False)
            else:
                self.tri_panel.setVisible(False)
                self.single_panel.setVisible(True)
                self.single_panel.setBackground(self.base_color)
            self.disabled_lbl.setVisible(False)
        else:
            # disabled view
            self.tri_panel.setVisible(False)
            self.single_panel.setVisible(True)
            self.single_panel.setBackground(Color(180,180,180))
            self.disabled_lbl.setVisible(True)

        self.revalidate()
        self.repaint()

class StackedVerticalTabButton(JPanel):
    def __init__(self, text, selected=False, on_click=None):
        JPanel.__init__(self)
        self.text = text
        self.on_click = on_click
        self.selected = selected
        self.rollover = False
        self.labels = []

        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self.setOpaque(True)

        # Set consistent sizing
        self.setPreferredSize(Dimension(32, 260))
        self.setMaximumSize(Dimension(32, 260))
        self.setMinimumSize(Dimension(32, 250))

        self.add(Box.createVerticalGlue())
        # Create vertical label using stacked JLabels
        for c in text:
            lbl = JLabel(c)
            lbl.setAlignmentX(0.5)
            lbl.setHorizontalAlignment(JLabel.CENTER)
            self.add(Box.createVerticalStrut(2))
            self.add(lbl)
            self.labels.append(lbl)
        self.add(Box.createVerticalGlue())

        # Apply visual style
        self.apply_style()

        # Add mouse listener for click + hover effect
        self.addMouseListener(self.TabClickListener(self))

    def set_selected(self, selected):
        self.selected = selected
        self.apply_style()

    def apply_style(self):
    # Theme-aware values from UIManager
        bg_default  = UIManager.getColor("Panel.background") or UIManager.getColor("TabbedPane.background")
        bg_hover    = UIManager.getColor("TabbedPane.hoverColor") or UIManager.getColor("TabbedPane.selected") or bg_default
        fg_default  = UIManager.getColor("Label.foreground")
        border_color = UIManager.getColor("Separator.foreground") or Color.GRAY

        if self.selected or self.rollover:
            self.setBackground(bg_hover)
            self.setBorder(BorderFactory.createLineBorder(border_color, 1))  # same border for both
        else:
            self.setBackground(bg_default)
            self.setBorder(BorderFactory.createLineBorder(border_color, 1))

        for lbl in self.labels:
            lbl.setForeground(fg_default)


    class TabClickListener(MouseAdapter):
        def __init__(self, parent):
            self.parent = parent

        def mouseClicked(self, event):
            if self.parent.on_click:
                self.parent.on_click()

        def mouseEntered(self, event):
            self.parent.rollover = True
            self.parent.apply_style()

        def mouseExited(self, event):
            self.parent.rollover = False
            self.parent.apply_style()
            
def update_last_payload_state(url_payloads_state, body_payloads_state):
    global LAST_PAYLOAD_STATE
    LAST_PAYLOAD_STATE["url_payloads"] = list(url_payloads_state)
    LAST_PAYLOAD_STATE["body_payloads"] = list(body_payloads_state)

class MessageHistoryEntry(object):
    def __init__(self, req_bytes, resp_bytes, param_name=None, payload=None, resp_time_ms=None, resp_size_bytes=None, kind=None):
        self.req_bytes = req_bytes
        self.resp_bytes = resp_bytes
        self.param_name = param_name
        self.payload = payload
        self.highlight = None  # (start, end)
        self.resp_time_ms = resp_time_ms
        self.resp_size_bytes = resp_size_bytes
        self.kind = kind  # "send", "attack", or "role"
# ---------- Main BurpExtender ----------
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        load_bac_configs(callbacks)
        callbacks.setExtensionName("Role-Parameter_Fuzzer")
        # callbacks._parent_extender = self

        self.tabs = JTabbedPane()
        self.tabs.addChangeListener(self.on_tab_switched)
        
        # The main panel for the extension
        self.main_panel = JPanel(BorderLayout())
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        self.add_plus_tab()
        saved = load_setting(self._callbacks, "param-fuzzer-tabs")
        if saved:
            try:
                tab_datas = json.loads(saved)
                for tab_data in tab_datas:
                    self.add_fuzzer_tab_with_state(tab_data)
                # After restoring all tabs, set LAST_PAYLOAD_STATE to the last tab's payloads/status
                if self.tabs.getTabCount() > 1:  # Exclude '+'
                    last_idx = self.tabs.getTabCount() - 2
                    last_panel = self.tabs.getComponentAt(last_idx)
                    if hasattr(last_panel, "payload_panel"):
                        url_payloads = [(row[0], bool(row[1])) for row in last_panel.payload_panel.url_payloads_panel.model.rows]
                        body_payloads = [(row[0], bool(row[1])) for row in last_panel.payload_panel.body_payloads_panel.model.rows]
                        global LAST_PAYLOAD_STATE
                        LAST_PAYLOAD_STATE["url_payloads"] = url_payloads
                        LAST_PAYLOAD_STATE["body_payloads"] = body_payloads
                        try:
                            self._callbacks.saveExtensionSetting("last_payload_state", json.dumps(LAST_PAYLOAD_STATE))
                        except Exception:
                            pass
            except Exception as e:
                print("[-] Error restoring tabs:", str(e))
        else:
            saved_state = load_setting(self._callbacks, "last_payload_state")
            if saved_state:
                try:
                    global LAST_PAYLOAD_STATE
                    LAST_PAYLOAD_STATE = json.loads(saved_state)
                except Exception as e:
                    print("[-] Error loading LAST_PAYLOAD_STATE:", e)

    def on_tab_switched(self, event):
        # When a tab is switched, save the payload state from the *previous* tab.
        selected_component = self.tabs.getSelectedComponent()
        if hasattr(selected_component, "payload_panel"):
            panel = selected_component
            url_panel = panel.payload_panel.url_payloads_panel
            body_panel = panel.payload_panel.body_payloads_panel
            
            # Flush pending edits
            if url_panel.table.isEditing():
                url_panel.table.getCellEditor().stopCellEditing()
            if body_panel.table.isEditing():
                body_panel.table.getCellEditor().stopCellEditing()

            url_payloads = [(row[0], bool(row[1])) for row in url_panel.model.rows]
            body_payloads = [(row[0], bool(row[1])) for row in body_panel.model.rows]

            global LAST_PAYLOAD_STATE
            LAST_PAYLOAD_STATE["url_payloads"] = url_payloads
            LAST_PAYLOAD_STATE["body_payloads"] = body_payloads
            try:
                self._callbacks.saveExtensionSetting("last_payload_state", json.dumps(LAST_PAYLOAD_STATE))
            except Exception:
                pass
        
        # Also, notify the newly selected tab that it's visible.
        if hasattr(selected_component, "on_gaining_visibility"):
            selected_component.on_gaining_visibility()
        # One more repaint to settle wrapping for newly created tabs
        if hasattr(selected_component, "force_layout"):
            SwingUtilities.invokeLater(lambda: selected_component.force_layout())

    def add_plus_tab(self):
        panel = JPanel()
        panel.setPreferredSize(Dimension(40, 40))
        self.tabs.addTab("+", panel)
        idx = self.tabs.indexOfComponent(panel)
        self.tabs.setTabComponentAt(idx, PlusTabComponent(self.tabs, self))

    def add_fuzzer_tab(self, base_message=None):
        tab_count = self.tabs.getTabCount()
        tab_name = "Tab #%d" % tab_count
        
        # This logic is now handled by on_tab_switched, but we can leave it as a fallback.
        if tab_count > 1:
            last_panel = self.tabs.getComponentAt(tab_count - 2)
            if hasattr(last_panel, "payload_panel"):
                url_panel = last_panel.payload_panel.url_payloads_panel
                body_panel = last_panel.payload_panel.body_payloads_panel

                # Fetch latest state
                url_payloads = [(row[0], bool(row[1])) for row in url_panel.model.rows]
                body_payloads = [(row[0], bool(row[1])) for row in body_panel.model.rows]

                global LAST_PAYLOAD_STATE
                LAST_PAYLOAD_STATE["url_payloads"] = url_payloads
                LAST_PAYLOAD_STATE["body_payloads"] = body_payloads
                try:
                    self._callbacks.saveExtensionSetting("last_payload_state", json.dumps(LAST_PAYLOAD_STATE))
                except Exception:
                    pass

        tab_panel = FuzzerPOCTab(self._helpers, self._callbacks, base_message, self.save_all_tabs_state, parent_extender=self)
        insert_at = self.tabs.getTabCount() - 1
        self.tabs.insertTab(tab_name, None, tab_panel, None, insert_at)
        self.tabs.setTabComponentAt(insert_at, ClosableTabComponent(self.tabs, tab_panel, tab_name))
        self.tabs.setSelectedComponent(tab_panel)
        # For new tabs, explicitly call the visibility function to set initial state
        tab_panel.on_gaining_visibility()
        self.save_all_tabs_state()

    def getTabCaption(self):
        return "Role-Param Fuzzer"

    def getUiComponent(self):
        return self.main_panel

    def createMenuItems(self, invocation):
        items = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages and len(messages) == 1:
            def add_tab_action(event):
                SwingUtilities.invokeLater(lambda: self.add_fuzzer_tab(messages[0]))
            items.add(JMenuItem("Send to RP Fuzzer", actionPerformed=add_tab_action))
        return items

    def extensionUnloaded(self):
        self.save_all_tabs_state()
        save_bac_configs(self._callbacks)

    def save_all_tabs_state(self, event=None):
        all_tabs = []
        for i in range(self.tabs.getTabCount() - 1):  # Exclude '+' tab
            panel = self.tabs.getComponentAt(i)
            if hasattr(panel, "serialize"):
                tab_data = panel.serialize()
                tab_name = self.tabs.getTitleAt(i)
                tab_data["tab_name"] = tab_name
                all_tabs.append(tab_data)
        save_setting(self._callbacks, "param-fuzzer-tabs", json.dumps(all_tabs))
        save_bac_configs(self._callbacks)

    def add_fuzzer_tab_with_state(self, tab_data):
        tab_panel = FuzzerPOCTab.deserialize(
            tab_data, self._helpers, self._callbacks, self.save_all_tabs_state, parent_extender=self
        )
        insert_at = self.tabs.getTabCount() - 1
        tab_name = tab_data.get("tab_name", "Tab #%d" % (insert_at + 1))
        self.tabs.insertTab(tab_name, None, tab_panel, None, insert_at)
        self.tabs.setTabComponentAt(insert_at, ClosableTabComponent(self.tabs, tab_panel, tab_name))
        self.tabs.setSelectedComponent(tab_panel)
        self.save_all_tabs_state()

    def mergeExportTabsForImport(self, event):
        try:
            tabs = self.tabs
            tab_titles = []
            for i in range(tabs.getTabCount() - 1):  # Exclude '+' tab
                tab_titles.append(tabs.getTitleAt(i))
            if not tab_titles:
                JOptionPane.showMessageDialog(self.main_panel, "No tabs to export.")
                return

            # --- Build checkbox panel with Select All ---
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            select_all = JCheckBox(" Select All", True)
            panel.add(select_all)
            checks = []
            for title in tab_titles:
                cb = JCheckBox(" " + title, True)
                checks.append(cb)
                panel.add(cb)

            def toggle_all(evt=None):
                state = select_all.isSelected()
                for cb in checks:
                    cb.setSelected(state)

            select_all.addActionListener(toggle_all)

            scroll = JScrollPane(panel)
            scroll.setPreferredSize(Dimension(300, min((len(checks) + 1) * 30, 300)))
            res = JOptionPane.showConfirmDialog(self.main_panel, scroll, "Select tabs to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return

            selected_indices = [i for i, cb in enumerate(checks) if cb.isSelected()]
            if not selected_indices:
                JOptionPane.showMessageDialog(self.main_panel, "No tabs selected.")
                return

            export_list = []
            for idx in selected_indices:
                panel = tabs.getComponentAt(idx)
                if hasattr(panel, "serialize"):
                    tab_data = panel.serialize()
                    tab_data["tab_name"] = tabs.getTitleAt(idx)
                    export_list.append(tab_data)

            last_dir = load_setting(self._callbacks, LAST_EXPORT_DIR_KEY)
            chooser = JFileChooser(last_dir) if last_dir and os.path.isdir(last_dir) else JFileChooser()
            chooser.setDialogTitle("Merge Export Tabs (to .json)")
            chooser.setSelectedFile(File("paramfuzzer_tabs.json"))

            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                save_setting(self._callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Load existing content if any
                merged = []
                if os.path.exists(out_path):
                    try:
                        with codecs.open(out_path, "r", encoding="utf-8") as f:
                            existing = json.load(f)
                        if isinstance(existing, dict):
                            existing = [existing]
                        if isinstance(existing, list):
                            merged.extend(existing)
                    except Exception:
                        pass  # Ignore errors in reading existing file

                # Append selected tabs
                merged.extend(export_list)

                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(merged, f, indent=2)

                JOptionPane.showMessageDialog(self.main_panel, "Merged %d tabs into:\n%s" % (len(export_list), out_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self.main_panel, "Error merging export tabs:\n" + str(e) + "\n" + traceback.format_exc())




# search for # Default payloads to change default payloads
