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
from collections import OrderedDict
from copy import deepcopy
from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JLabel, JTabbedPane, JToolBar, JMenuItem, JOptionPane, JSpinner, SpinnerNumberModel, JComboBox, ButtonGroup, JRadioButton,
    SwingUtilities, JFileChooser, JSplitPane, JTable, JScrollPane, JTextField, JCheckBox, DefaultCellEditor, BorderFactory, BoxLayout, Box,
    SwingConstants, JToggleButton, JPopupMenu, ImageIcon, ListSelectionModel, JTextArea, JList
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import ( BorderLayout, Dimension, FlowLayout, Color, Cursor, Dimension, Rectangle, Robot, Graphics2D, Graphics, Font, CardLayout,
    GridBagLayout, GridBagConstraints, Insets, Component
)
from java.awt.event import MouseAdapter, ActionListener, MouseEvent, FocusAdapter, KeyAdapter, KeyEvent
from java.util import ArrayList
from javax.swing.event import ChangeListener
from java.lang import Boolean
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
    keys = re.findall(r'\[\d+\]|[^.]+', path)
    def set_recursively(sub_obj, sub_keys, val):
        if not sub_keys:
            return
        current_key = sub_keys[0]
        remaining_keys = sub_keys[1:]
        if current_key.startswith('['):
            idx = int(current_key.strip('[]'))
            if not remaining_keys:
                sub_obj[idx] = val
            else:
                set_recursively(sub_obj[idx], remaining_keys, val)
        else:
            if not remaining_keys:
                sub_obj[current_key] = val
            else:
                set_recursively(sub_obj[current_key], remaining_keys, val)
    set_recursively(obj, keys, value)
    return obj

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
            BorderFactory.createTitledBorder("Inspector"),
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
    def __init__(self, host, req_headers, on_save_callback=None, callbacks=None):
        JPanel.__init__(self)
        self.host = host
        self.req_headers = req_headers
        self.on_save_callback = on_save_callback
        self.callbacks = callbacks
        self.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("BAC Check"),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ))
        self.setLayout(BorderLayout())
        self.role_data = []
        self.role_tabs = JTabbedPane(JTabbedPane.TOP)
        self.role_tabs.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT)
        self.add(self.role_tabs, BorderLayout.CENTER)

        # --- Export/Import BAC Roles buttons ---
        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.export_bac_btn = JButton("Export BAC Roles", actionPerformed=self.export_bac_roles)
        self.import_bac_btn = JButton("Import BAC Roles", actionPerformed=self.import_bac_roles)
        btn_panel.add(self.export_bac_btn)
        btn_panel.add(self.import_bac_btn)
        self.add(btn_panel, BorderLayout.NORTH)

        # 1. Load existing roles for this host from BAC_HOST_CONFIGS (if any)
        config = BAC_HOST_CONFIGS.get(self.host)
        if config and "roles" in config and config["roles"]:
            for role_cfg in config["roles"]:
                self._add_role_tab_internal(role_cfg.get("label", None), role_cfg)
            self.save_state()
        # Always add plus tab last
        self.ensure_single_plus_tab()
        self.role_tabs.addChangeListener(self.on_tab_change)

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
            # Show selection dialog
            role_names = [role.get("label", "Role #%d" % (i+1)) for i, role in enumerate(self.role_data)]
            # from javax.swing import JList
            jlist = JList(role_names)
            jlist.setSelectionInterval(0, len(role_names)-1)  # Pre-select all
            jlist.setVisibleRowCount(min(8, len(role_names)))
            res = JOptionPane.showConfirmDialog(self, JScrollPane(jlist), "Select BAC roles to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected_indices = jlist.getSelectedIndices()
            if len(selected_indices) == 0:
                JOptionPane.showMessageDialog(self, "No roles selected.")
                return
            export_list = [self.role_data[idx] for idx in selected_indices]
            last_dir = load_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY) if self.callbacks else None
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Export BAC Roles As")
            chooser.setSelectedFile(File("bac_roles_%s.json" % self.host.replace(':', '_')))
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                if self.callbacks:
                    save_setting(self.callbacks, LAST_BAC_ROLE_DIR_KEY, os.path.dirname(out_path))
                # import codecs, json
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(export_list, f, indent=2)
                JOptionPane.showMessageDialog(self, "Exported %d BAC roles to:\n%s" % (len(export_list), out_path))
        except Exception as e:
            # import traceback
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
                # import codecs, json
                with codecs.open(in_path, "r", encoding="utf-8") as f:
                    imported = json.load(f)
                if isinstance(imported, dict):
                    imported = [imported]
                if not imported:
                    JOptionPane.showMessageDialog(self, "No BAC roles found in file.")
                    return
                # Show selection dialog
                role_names = [role.get("label", "Role #%d" % (i+1)) for i, role in enumerate(imported)]
                # from javax.swing import JList
                jlist = JList(role_names)
                jlist.setSelectionInterval(0, len(role_names)-1)  # Pre-select all
                jlist.setVisibleRowCount(min(8, len(role_names)))
                res = JOptionPane.showConfirmDialog(self, JScrollPane(jlist), "Select BAC roles to import", JOptionPane.OK_CANCEL_OPTION)
                if res != JOptionPane.OK_OPTION:
                    return
                selected_indices = jlist.getSelectedIndices()
                if len(selected_indices) == 0:
                    JOptionPane.showMessageDialog(self, "No roles selected.")
                    return
                count = 0
                # Insert imported roles before the plus tab
                plus_idx = self.role_tabs.getTabCount() - 1
                for offset, idx in enumerate(selected_indices):
                    role_cfg = imported[idx]
                    # Insert at plus_idx + offset (so they appear before the plus tab)
                    self._add_role_tab_internal(role_cfg.get("label", None), role_cfg)
                self.save_state()
                self.ensure_single_plus_tab()  # Ensure plus tab is always present and unique
                JOptionPane.showMessageDialog(self, "Imported %d BAC roles." % len(selected_indices))
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error importing BAC roles:\n" + str(e) + "\n" + traceback.format_exc())

    def _add_role_tab_internal(self, label=None, config=None):
        # Used for initial load - appends at end before "+" tab
        plus_idx = self.role_tabs.getTabCount()  # always last
        role_label = label or "Role %d" % (len(self.role_data) + 1)
        role_cfg = config if config else {
            "label": role_label,
            "headers": [{"header": "", "value": ""}],
            "extra_enabled": False,
            "extra_name": "",
            "extra_value": ""
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
            "extra_value": ""
        }
        panel = self.make_role_panel(role_cfg, len(self.role_data))
        self.role_tabs.insertTab(role_label, None, panel, None, plus_idx)
        self.role_tabs.setTabComponentAt(plus_idx, ClosableTabComponent(self.role_tabs, panel, role_label, self))
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
        # Remove or reduce the preferred size, and add a sensible max size
        headers_scroll.setPreferredSize(Dimension(200, 150))  # Or even remove this line for fully dynamic sizing
        headers_scroll.setMaximumSize(Dimension(600, 200))    # Prevent it from overflowing screen
        panel.add(headers_scroll)

        # --- Add header row logic ---
        def add_header_row(header_val=None):

            default_font = Font("Dialog", Font.PLAIN, 12)

            # The row panel stacks two horizontal panels vertically
            row = JPanel()
            row.setLayout(BoxLayout(row, BoxLayout.Y_AXIS))
            row.setAlignmentX(Component.LEFT_ALIGNMENT)

            # Top line: Header + dropdown + delete
            top_line = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
            top_line.setAlignmentX(Component.LEFT_ALIGNMENT)

            header_label = JLabel("Header:")
            header_label.setFont(default_font)

            available_headers = list(self.req_headers)
            combo = JComboBox(available_headers)
            combo.setEditable(True)
            combo.setPreferredSize(Dimension(130, 24))
            combo.setFont(default_font)
            if header_val and "header" in header_val and header_val["header"]:
                combo.setSelectedItem(header_val["header"])

            del_btn = JButton("Delete")
            del_btn.setFont(default_font)

            top_line.add(header_label)
            top_line.add(combo)
            top_line.add(del_btn)

            # Bottom line: Value + value field
            value_label = JLabel("Value:")
            value_label.setFont(default_font)

            value = header_val["value"] if header_val and "value" in header_val else ""
            val_field = JTextArea(value, 1, 18)
            val_field.setFont(default_font)
            val_field.setLineWrap(True)
            val_field.setWrapStyleWord(True)
            val_field.setPreferredSize(Dimension(150, 24))
            val_field.setMinimumSize(Dimension(80, 24))
            val_field.setMaximumSize(Dimension(400, 40))
            val_field.setAlignmentX(Component.LEFT_ALIGNMENT)

            bottom_line = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
            bottom_line.setAlignmentX(Component.LEFT_ALIGNMENT)
            bottom_line.add(value_label)
            bottom_line.add(val_field)

            edit_btn = JButton("Edit")
            edit_btn.setFont(default_font)
            bottom_line.add(edit_btn)

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
                    # The existing CaretListener on val_field will handle saving the state.
            
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

            row.add(top_line)
            row.add(bottom_line)

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

        # Add header button
        add_header_btn = JButton("Add header", actionPerformed=lambda evt: add_header_row())
        add_header_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        add_header_panel.add(add_header_btn)
        panel.add(add_header_panel)

        # --- Extra header toggle and fields (unchanged) ---
        extra_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        extra_toggle = JCheckBox("Add extra header")
        extra_toggle.setSelected(role_cfg.get("extra_enabled", False))
        extra_row.add(extra_toggle)
        extra_name = JTextField(role_cfg.get("extra_name", ""), 12)
        extra_val = JTextField(role_cfg.get("extra_value", ""), 18)
        extra_row.add(JLabel("Header name:"))
        extra_row.add(extra_name)
        extra_row.add(JLabel("Value:"))
        extra_row.add(extra_val)
        panel.add(extra_row)

        def update_extra_fields():
            show = extra_toggle.isSelected()
            extra_name.setVisible(show)
            extra_val.setVisible(show)
            role_cfg["extra_enabled"] = show
            if self.on_save_callback:
                self.on_save_callback(self.host)
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

    def on_tab_change(self, event):
        idx = self.role_tabs.getSelectedIndex()
        # If "+" tab clicked, add a new role
        if idx == self.role_tabs.getTabCount() - 1:
            pass


### ------------------- Fuzzer Tab Main ----------------------

class MessageHistoryEntry(object):
    def __init__(self, req_bytes, resp_bytes, param_name=None, payload=None):
        self.req_bytes = req_bytes
        self.resp_bytes = resp_bytes
        self.param_name = param_name
        self.payload = payload
        self.highlight = None  # (start, end)

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

        nav_button_size = Dimension(28, 24)
        self.access_check_btn = JButton("Access Check", actionPerformed=self.bac_check)
        self.send_btn = JButton("Send")
        self.attack_btn = JButton("Attack")

        self.prev_btn = JButton("<")
        self.prev_btn.setPreferredSize(nav_button_size)
        self.prev_btn.setMaximumSize(nav_button_size)
        self.prev_btn.setMinimumSize(nav_button_size)

        self.prev_dropdown = JButton("^")
        self.prev_dropdown.setPreferredSize(nav_button_size)
        self.prev_dropdown.setMaximumSize(nav_button_size)
        self.prev_dropdown.setMinimumSize(nav_button_size)
        self.prev_dropdown.setFocusable(False)
        self.prev_dropdown.setMargin(Insets(0, 0, 0, 0))
        self.prev_dropdown.addActionListener(lambda e: self.show_history_dropdown(False))

        self.status_lbl = JLabel(" 0/0 ")
        self.status_lbl.setHorizontalAlignment(JLabel.CENTER)
        self.status_lbl.setPreferredSize(Dimension(40, 24))
        self.status_lbl.setMaximumSize(Dimension(40, 24))
        self.status_lbl.setMinimumSize(Dimension(40, 24))

        self.next_btn = JButton(">")
        self.next_btn.setPreferredSize(nav_button_size)
        self.next_btn.setMaximumSize(nav_button_size)
        self.next_btn.setMinimumSize(nav_button_size)

        self.next_dropdown = JButton("^")
        self.next_dropdown.setPreferredSize(nav_button_size)
        self.next_dropdown.setMaximumSize(nav_button_size)
        self.next_dropdown.setMinimumSize(nav_button_size)
        self.next_dropdown.setFocusable(False)
        self.next_dropdown.setMargin(Insets(0, 0, 0, 0))
        self.next_dropdown.addActionListener(lambda e: self.show_history_dropdown(True))

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
        self.add(toolbar, BorderLayout.NORTH)

        self.req_editor = callbacks.createMessageEditor(self, True)
        self.resp_editor = callbacks.createMessageEditor(self, False)

        # --- Bottom Panel (Save, Export, Screenshot) ---
        self.save_btn = JButton("Save State", actionPerformed=self.on_save_state)
        self.export_all_btn = JButton("Export All Results", actionPerformed=self.exportAllTabs)
        self.merge_all_btn = JButton("Merge All Results", actionPerformed=self.mergeAllTabs)
        left_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        left_panel.add(self.save_btn)
        left_panel.add(self.export_all_btn)
        left_panel.add(self.merge_all_btn)
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(left_panel, BorderLayout.WEST)

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        self.merge_btn = JButton("Merge Results", actionPerformed=self.mergeResults)
        self.export_btn = JButton("Export Results", actionPerformed=self.exportResults)
        self.screenshot_btn = JButton("Take Screenshot", actionPerformed=self.takeScreenshot)
        self.export_tabs_btn = JButton("Export Tabs", actionPerformed=self.exportTabsForImport)
        self.merge_export_tabs_btn = JButton("Merge Export", actionPerformed=(lambda e: self.parent_extender.mergeExportTabsForImport(e)))
        self.import_tabs_btn = JButton("Import Tabs", actionPerformed=self.importTabsFromFile)
        btn_panel.add(self.export_tabs_btn)
        btn_panel.add(self.merge_export_tabs_btn)
        btn_panel.add(self.import_tabs_btn)
        btn_panel.add(self.merge_btn)
        btn_panel.add(self.export_btn)
        btn_panel.add(self.screenshot_btn)
        bottom_panel.add(btn_panel, BorderLayout.EAST)
        self.add(bottom_panel, BorderLayout.SOUTH)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.req_editor.getComponent(), self.resp_editor.getComponent())
        main_split.setResizeWeight(0.5)
        main_split.setDividerLocation(400)
        main_split.setOneTouchExpandable(True)
        self.main_split = main_split

        # -- Prepare Inspector and BAC Check panels --
        if base_message is not None:
            req_bytes = base_message.getRequest()
        else:
            req_bytes = bytearray()
        url_params, default_url_payloads, body_params, default_body_payloads = self.extract_sidepanel_lists(req_bytes)

        # If a payload state was saved from a previous tab, use it directly.
        # Otherwise, this is the first tab, so use the default payload lists.
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
                self.bac_panel = BACCheckPanel(host, headers)
            except Exception as e:
                print("DEBUG: BACCheckPanel creation failed:", str(e))
                # import traceback
                traceback.print_exc()
                self.bac_panel = JPanel()
                self.bac_panel.add(JLabel("BACCheckPanel failed to load."))

        self.bac_scroll_panel = JScrollPane(self.bac_panel)
        self.bac_scroll_panel.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        # --- Custom vertical tab bar with CardLayout ---
        self.card_panel = JPanel(CardLayout())
        self.card_panel.add(self.payload_panel, "Inspector")
        self.card_panel.add(self.bac_scroll_panel, "BAC Check")

        self.tab_button_panel = JPanel()
        self.tab_button_panel.setLayout(BoxLayout(self.tab_button_panel, BoxLayout.Y_AXIS))

        # Store sidebar widths for consistent resizing
        self.sidebar_width_expanded = 400
        self.sidebar_width_collapsed = 36 # Default, will be updated

        def on_tab_click(tab_name):
            # If clicking the active, expanded tab, collapse it.
            if self.current_tab == tab_name and not self.tab_collapsed:
                self.card_panel.setVisible(False)
                self.right_panel.setPreferredSize(Dimension(self.sidebar_width_collapsed, self.right_panel.getHeight()))
                self.tab_collapsed = True
            # Otherwise, expand the panel and show the clicked tab.
            else:
                self.card_panel.setVisible(True)
                self.right_panel.setPreferredSize(Dimension(self.sidebar_width_expanded, self.right_panel.getHeight()))
                self.tab_collapsed = False
                
                self.current_tab = tab_name
                layout = self.card_panel.getLayout()
                layout.show(self.card_panel, tab_name)

            self.inspector_btn.set_selected(self.current_tab == "Inspector" and not self.tab_collapsed)
            self.bac_btn.set_selected(self.current_tab == "BAC Check" and not self.tab_collapsed)
            
            # Re-layout the components with the new sizes
            self.right_panel.revalidate()
            self.resize_sidebar()
                
        self.inspector_btn = StackedVerticalTabButton("Inspector", selected=True, on_click=lambda: on_tab_click("Inspector"))
        self.bac_btn = StackedVerticalTabButton("BAC Check", selected=False, on_click=lambda: on_tab_click("BAC Check"))
        self.tab_button_panel.removeAll()
        self.tab_button_panel.add(self.inspector_btn)
        self.tab_button_panel.add(self.bac_btn)
        self.tab_button_panel.setMaximumSize(Dimension(40, 240))

        # After adding buttons, get their actual width for the collapsed state
        self.sidebar_width_collapsed = self.tab_button_panel.getPreferredSize().width + 5 # Padding

        # Set up the panels
        self.right_panel = JPanel(BorderLayout())
        self.right_panel.add(self.card_panel, BorderLayout.CENTER)
        self.right_panel.add(self.tab_button_panel, BorderLayout.EAST)
        
        main_split.setMinimumSize(Dimension(600, 400))
        self.outer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, main_split, self.right_panel)
        self.outer_split.setOneTouchExpandable(True)
        self.outer_split.setResizeWeight(1.0) # Pin the right component's size
        self.add(self.outer_split, BorderLayout.CENTER)

        # The UI state will be reset when the tab is first made visible.
        # This is handled by on_gaining_visibility().

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

    def reset_ui_state(self):
        # Method to set the side panel to its default (collapsed) state.
        # This can be called on init and when a tab becomes visible.
        def do_reset():
            self.tab_collapsed = True
            self.current_tab = "Inspector"
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

    # --- The rest of your FuzzerPOCTab methods are unchanged ---
    # on_save_state, get_bytes_as_text, exportResults, mergeResults, exportAllTabs, mergeAllTabs, etc...

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

    def exportResults(self, event):
        try:

            # Unique key for last export directory
            LAST_EXPORT_DIR_KEY = "last-export-directory"

            req_bytes = self.req_editor.getMessage()
            req_str = self.helpers.bytesToString(req_bytes)
            path = "fuzz_results"
            m = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?]+)", req_str)
            if m:
                path = m.group(1).replace("/", "_").strip("_")
            default_file = File(path + ".txt")

            # --- Remember last used export folder ---
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()

            chooser.setSelectedFile(default_file)
            chooser.setDialogTitle("Save Fuzz Results As")
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".txt"):
                    out_path += ".txt"

                # --- Begin fix: find a non-conflicting filename ---
                def get_nonconflicting_filename(filepath):
                    base, ext = os.path.splitext(filepath)
                    counter = 1
                    new_filepath = filepath
                    while os.path.exists(new_filepath):
                        new_filepath = "%s(%d)%s" % (base, counter, ext)
                        counter += 1
                    return new_filepath
                out_path = get_nonconflicting_filename(out_path)
                # --- End fix ---

                # Save directory for next time
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Build API line as before
                service = self.getHttpService()
                api_string = ""
                if service:
                    analyzed = self.helpers.analyzeRequest(service, req_bytes)
                    method = analyzed.getMethod()
                    url = analyzed.getUrl()
                    full_url = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                    request_line = "%s %s" % (method, full_url)
                    body_offset = analyzed.getBodyOffset()
                    body = req_str[body_offset:]
                    if body.strip():
                        api_string = request_line + "\n\n" + body.strip()
                    else:
                        api_string = request_line
                else:
                    api_string = req_str.split('\r\n', 1)[0]

                MAX_RESPONSE_LENGTH = 10000
                def safe_truncate(text, maxlen):
                    if text is None:
                        return ""
                    if len(text) > maxlen:
                        return text[:maxlen] + u"\n--------- Truncated ---------\n"
                    return text

                # import codecs
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    f.write(u"API: %s\n\n" % api_string)
                    for idx, entry in enumerate(self.history):
                        req_text = self.get_bytes_as_text(entry.req_bytes)
                        resp_text = self.get_bytes_as_text(entry.resp_bytes)
                        resp_text = safe_truncate(resp_text, MAX_RESPONSE_LENGTH)
                        param = getattr(entry, "param_name", "") or ""
                        value = getattr(entry, "payload", "") or ""

                        f.write(u"---- Attack #%d ----\n" % (idx + 1))
                        f.write(u"Param/Role: %s\n" % param)
                        f.write(u"Value: %s\n\n" % value)
                        f.write(u"Request:\n%s\n\n" % req_text)
                        f.write(u"Response:\n%s\n" % resp_text)
                        f.write(u"-------------------\n\n")
                JOptionPane.showMessageDialog(self, "Exported fuzz results to:\n" + out_path)
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error exporting results:\n" + str(e) + "\n" + traceback.format_exc())

    def mergeResults(self, event):
        try:

            # Unique key for last export directory
            LAST_EXPORT_DIR_KEY = "last-export-directory"

            req_bytes = self.req_editor.getMessage()
            req_str = self.helpers.bytesToString(req_bytes)
            path = "fuzz_results"
            m = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s?]+)", req_str)
            if m:
                path = m.group(1).replace("/", "_").strip("_")
            default_file = File(path + ".txt")

            # --- Remember last used export folder ---
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()

            chooser.setSelectedFile(default_file)
            chooser.setDialogTitle("Append Fuzz Results To (Choose a .txt file)")
            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".txt"):
                    out_path += ".txt"

                # Save directory for next time
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Build API line as before
                service = self.getHttpService()
                api_string = ""
                if service:
                    analyzed = self.helpers.analyzeRequest(service, req_bytes)
                    method = analyzed.getMethod()
                    url = analyzed.getUrl()
                    full_url = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                    request_line = "%s %s" % (method, full_url)
                    body_offset = analyzed.getBodyOffset()
                    body = req_str[body_offset:]
                    if body.strip():
                        api_string = request_line + "\n\n" + body.strip()
                    else:
                        api_string = request_line
                else:
                    api_string = req_str.split('\r\n', 1)[0]

                MAX_RESPONSE_LENGTH = 10000
                def safe_truncate(text, maxlen):
                    if text is None:
                        return ""
                    if len(text) > maxlen:
                        return text[:maxlen] + u"\n--------- Truncated ---------\n"
                    return text

                # import codecs
                with codecs.open(out_path, "a", encoding="utf-8") as f:  # 'a' for append
                    tab_name = "This Tab"
                    if hasattr(self, "parent_extender") and self.parent_extender:
                        tab_name = self.parent_extender.tabs.getTitleAt(
                            self.parent_extender.tabs.indexOfComponent(self)
                        )
                    f.write(u"\n\nMERGED FUZZ RESULTS: %s\n" % tab_name)
                    f.write(u"API: %s\n\n" % api_string)
                    for idx, entry in enumerate(self.history):
                        req_text = self.get_bytes_as_text(entry.req_bytes)
                        resp_text = self.get_bytes_as_text(entry.resp_bytes)
                        resp_text = safe_truncate(resp_text, MAX_RESPONSE_LENGTH)
                        param = getattr(entry, "param_name", "") or ""
                        value = getattr(entry, "payload", "") or ""

                        f.write(u"---- Attack #%d ----\n" % (idx + 1))
                        f.write(u"Param/Role: %s\n" % param)
                        f.write(u"Value: %s\n\n" % value)
                        f.write(u"Request:\n%s\n\n" % req_text)
                        f.write(u"Response:\n%s\n" % resp_text)
                        f.write(u"-------------------\n\n")
                JOptionPane.showMessageDialog(self, "Merged fuzz results into:\n" + out_path)
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error merging results:\n" + str(e) + "\n" + traceback.format_exc())

    def exportAllTabs(self, event):
        try:
            # import os
            # import codecs

            # Try to get Burp project name
            project_name = "all_fuzz_results"
            try:
                project_path = self.callbacks.getProjectFile()
                if project_path:
                    project_name = os.path.splitext(os.path.basename(project_path))[0]
            except Exception:
                pass

            # Use project name for filename, else fallback
            default_file = File(project_name + ".txt")
            LAST_EXPORT_DIR_KEY = "last-export-directory"
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            

            chooser.setSelectedFile(default_file)
            chooser.setDialogTitle("Export ALL Fuzz Results As")
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".txt"):
                    out_path += ".txt"
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Ensure unique filename
                def get_nonconflicting_filename(filepath):
                    base, ext = os.path.splitext(filepath)
                    counter = 1
                    new_filepath = filepath
                    while os.path.exists(new_filepath):
                        new_filepath = "%s(%d)%s" % (base, counter, ext)
                        counter += 1
                    return new_filepath
                out_path = get_nonconflicting_filename(out_path)

                # Get all tab results
                all_tabs = []
                if hasattr(self, "parent_extender") and self.parent_extender:
                    tabs = self.parent_extender.tabs
                    for i in range(tabs.getTabCount() - 1):  # Exclude '+'
                        panel = tabs.getComponentAt(i)
                        tab_name = tabs.getTitleAt(i)
                        if hasattr(panel, "history"):
                            all_tabs.append((tab_name, panel))

                MAX_RESPONSE_LENGTH = 10000
                def safe_truncate(text, maxlen):
                    if text is None:
                        return ""
                    if len(text) > maxlen:
                        return text[:maxlen] + u"\n--------- Truncated ---------\n"
                    return text

                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    for tab_idx, (tab_name, panel) in enumerate(all_tabs):
                        req_bytes = panel.req_editor.getMessage()
                        req_str = self.helpers.bytesToString(req_bytes)
                        service = panel.getHttpService()
                        api_string = ""
                        if service:
                            analyzed = self.helpers.analyzeRequest(service, req_bytes)
                            method = analyzed.getMethod()
                            url = analyzed.getUrl()
                            full_url = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                            request_line = "%s %s" % (method, full_url)
                            body_offset = analyzed.getBodyOffset()
                            body = req_str[body_offset:]
                            if body.strip():
                                api_string = request_line + "\n\n" + body.strip()
                            else:
                                api_string = request_line
                        else:
                            api_string = req_str.split('\r\n', 1)[0]

                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(u"API: %s\n\n" % api_string)
                        for idx, entry in enumerate(panel.history):
                            req_text = self.get_bytes_as_text(entry.req_bytes)
                            resp_text = self.get_bytes_as_text(entry.resp_bytes)
                            resp_text = safe_truncate(resp_text, MAX_RESPONSE_LENGTH)
                            param = getattr(entry, "param_name", "") or ""
                            value = getattr(entry, "payload", "") or ""

                            f.write(u"---- Attack #%d ----\n" % (idx + 1))
                            f.write(u"Param/Role: %s\n" % param)
                            f.write(u"Value: %s\n\n" % value)
                            f.write(u"Request:\n%s\n\n" % req_text)
                            f.write(u"Response:\n%s\n" % resp_text)
                            f.write(u"-------------------\n\n")
                JOptionPane.showMessageDialog(self, "Exported all fuzz results to:\n" + out_path)
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error exporting all results:\n" + str(e) + "\n" + traceback.format_exc())

    def mergeAllTabs(self, event):
        try:

            # --- Remember last used export folder ---
            LAST_EXPORT_DIR_KEY = "last-export-directory"
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Append ALL Fuzz Results To (Choose a .txt file)")

            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".txt"):
                    out_path += ".txt"

                # Save directory for next time
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Get all tab results
                all_tabs = []
                if hasattr(self, "parent_extender") and self.parent_extender:
                    tabs = self.parent_extender.tabs
                    for i in range(tabs.getTabCount() - 1):  # Exclude '+'
                        panel = tabs.getComponentAt(i)
                        tab_name = tabs.getTitleAt(i)
                        if hasattr(panel, "history"):
                            all_tabs.append((tab_name, panel))

                MAX_RESPONSE_LENGTH = 10000
                def safe_truncate(text, maxlen):
                    if text is None:
                        return ""
                    if len(text) > maxlen:
                        return text[:maxlen] + u"\n--------- Truncated ---------\n"
                    return text

                with codecs.open(out_path, "a", encoding="utf-8") as f:
                    for tab_name, panel in all_tabs:
                        req_bytes = panel.req_editor.getMessage()
                        req_str = self.helpers.bytesToString(req_bytes)
                        service = panel.getHttpService()
                        api_string = ""
                        if service:
                            analyzed = self.helpers.analyzeRequest(service, req_bytes)
                            method = analyzed.getMethod()
                            url = analyzed.getUrl()
                            full_url = "%s://%s%s" % (url.getProtocol(), url.getHost(), url.getFile())
                            request_line = "%s %s" % (method, full_url)
                            body_offset = analyzed.getBodyOffset()
                            body = req_str[body_offset:]
                            if body.strip():
                                api_string = request_line + "\n\n" + body.strip()
                            else:
                                api_string = request_line
                        else:
                            api_string = req_str.split('\r\n', 1)[0]

                        f.write(u"\n====== %s ======\n" % tab_name)
                        f.write(u"API: %s\n\n" % api_string)
                        for idx, entry in enumerate(panel.history):
                            req_text = self.get_bytes_as_text(entry.req_bytes)
                            resp_text = self.get_bytes_as_text(entry.resp_bytes)
                            resp_text = safe_truncate(resp_text, MAX_RESPONSE_LENGTH)
                            param = getattr(entry, "param_name", "") or ""
                            value = getattr(entry, "payload", "") or ""

                            f.write(u"---- Attack #%d ----\n" % (idx + 1))
                            f.write(u"Param/Role: %s\n" % param)
                            f.write(u"Value: %s\n\n" % value)
                            f.write(u"Request:\n%s\n\n" % req_text)
                            f.write(u"Response:\n%s\n" % resp_text)
                            f.write(u"-------------------\n\n")
                JOptionPane.showMessageDialog(self, "Merged all fuzz results into:\n" + out_path)
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error merging all results:\n" + str(e) + "\n" + traceback.format_exc())

    def exportTabsForImport(self, event):
        try:
            if not (hasattr(self, "parent_extender") and self.parent_extender):
                JOptionPane.showMessageDialog(self, "Cannot export: parent component not found.")
                return
            # Get tab titles for selection
            tabs = self.parent_extender.tabs
            tab_titles = []
            for i in range(tabs.getTabCount() - 1):  # Exclude '+'
                tab_titles.append(tabs.getTitleAt(i))
            if not tab_titles:
                JOptionPane.showMessageDialog(self, "No tabs to export.")
                return

            # from javax.swing import JList
            jlist = JList(tab_titles)
            jlist.setSelectionInterval(0, 0)  # Pre-select first
            jlist.setVisibleRowCount(min(8, len(tab_titles)))
            res = JOptionPane.showConfirmDialog(self, JScrollPane(jlist), "Select tabs to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected_indices = jlist.getSelectedIndices()
            if len(selected_indices) == 0:
                JOptionPane.showMessageDialog(self, "No tabs selected.")
                return

            export_list = []
            for idx in selected_indices:
                panel = tabs.getComponentAt(idx)
                if hasattr(panel, "serialize"):
                    tab_data = panel.serialize()
                    tab_data["tab_name"] = tabs.getTitleAt(idx)
                    export_list.append(tab_data)

            # Use last export dir if available
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Export Tabs (for Import)")
            chooser.setSelectedFile(File("paramfuzzer_tabs.json"))
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                # Save directory for next time
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(export_list, f, indent=2)
                JOptionPane.showMessageDialog(self, "Exported %d tabs for import:\n%s" % (len(export_list), out_path))
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self, "Error exporting tabs:\n" + str(e) + "\n" + traceback.format_exc())

    def importTabsFromFile(self, event):
        try:
            last_dir = load_setting(self.callbacks, LAST_EXPORT_DIR_KEY)
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Import Tabs (.json)")
            if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                in_path = file.getAbsolutePath()
                # Save directory for next time
                save_setting(self.callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(in_path))
                with codecs.open(in_path, "r", encoding="utf-8") as f:
                    imported = json.load(f)
                # Support both single tab and list of tabs
                if isinstance(imported, dict):
                    imported = [imported]
                if not imported:
                    JOptionPane.showMessageDialog(self, "No tabs found in file.")
                    return
                # Show selection dialog
                tab_names = [tab.get("tab_name", "Tab #%d" % (i+1)) for i, tab in enumerate(imported)]
                # from javax.swing import JList
                jlist = JList(tab_names)
                jlist.setSelectionInterval(0, len(tab_names)-1)  # Pre-select all
                jlist.setVisibleRowCount(min(8, len(tab_names)))
                res = JOptionPane.showConfirmDialog(self, JScrollPane(jlist), "Select tabs to import", JOptionPane.OK_CANCEL_OPTION)
                if res != JOptionPane.OK_OPTION:
                    return
                selected_indices = jlist.getSelectedIndices()
                if len(selected_indices) == 0:
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
            # import traceback
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
                "payload": entry.payload
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
                    "extra_value": role.get("extra_value", "")
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
                obj.bac_panel = BACCheckPanel(host, headers, callbacks=callbacks)
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
        obj.card_panel.add(obj.payload_panel, "Inspector")
        obj.card_panel.add(obj.bac_panel, "BAC Check")

        # Always show Inspector tab/card on restore
        layout = obj.card_panel.getLayout()
        layout.show(obj.card_panel, "Inspector")
        obj.current_tab = "Inspector"
        obj.tab_collapsed = False

        # Restore attack history
        obj.history = []
        for entry in data.get("entries", []):
            e = MessageHistoryEntry(
                base64.b64decode(entry["req"]),
                base64.b64decode(entry["resp"]),
                entry.get("param_name"),
                entry.get("payload")
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
        url_payloads = ["NULL", "*", "' OR 1=1 --", "<script>alert(1)</script>"]
        body_payloads = ["NULL", "*", "' OR 1=1 --", "<img src=x onerror=alert(1)>"]
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
                req_bytes = self.req_editor.getMessage()
                if self.base_message is not None:
                    service = self.base_message.getHttpService()
                else:
                    service = self.guess_service_from_request(req_bytes)
                    if not service:
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "No HTTP service found.\nUse context menu to send a real request, or paste a valid request including Host: header."))
                        return
                resp = self.callbacks.makeHttpRequest(service, req_bytes)
                resp_bytes = resp.getResponse()
                entry = MessageHistoryEntry(req_bytes, resp_bytes)
                self.history.append(entry)
                self.current_idx = len(self.history) - 1
                
                def do_ui_update():
                    self.show_entry(self.current_idx)
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

                # Check for JSON body
                headers, body = req_str.split("\r\n\r\n", 1) if "\r\n\r\n" in req_str else (req_str, "")
                is_json = "content-type: application/json" in headers.lower() and body.strip().startswith("{")

                # --- Attack URL params (type 0) ---
                for pname in url_params:
                    for payload in url_payloads:
                        mod_req_bytes = bytearray(req_bytes)
                        for p in params:
                            if p.getName() == pname and p.getType() == 0:
                                mod_req_bytes = self.helpers.removeParameter(mod_req_bytes, p)
                        new_param = self.helpers.buildParameter(pname, payload, 0)
                        mod_req_bytes = self.helpers.addParameter(mod_req_bytes, new_param)
                        resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                        mark = self.find_param_offset(self.helpers.bytesToString(mod_req_bytes), pname, payload)
                        entry = MessageHistoryEntry(mod_req_bytes, resp.getResponse(), param_name=pname, payload=payload)
                        entry.highlight = mark
                        history.append(entry)

                # --- Attack body/form params (type 1) ---
                # Only run if NOT JSON (fixes duplicate issue)
                if not is_json:
                    for pname in body_params:
                        for payload in body_payloads:
                            mod_req_bytes = bytearray(req_bytes)
                            found = False
                            for p in params:
                                if p.getName() == pname and p.getType() == 1:
                                    mod_req_bytes = self.helpers.removeParameter(mod_req_bytes, p)
                                    found = True
                            new_param = self.helpers.buildParameter(pname, payload, 1)
                            mod_req_bytes = self.helpers.addParameter(mod_req_bytes, new_param)
                            if found or mod_req_bytes != req_bytes:
                                resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                                mark = self.find_param_offset(self.helpers.bytesToString(mod_req_bytes), pname, payload)
                                entry = MessageHistoryEntry(mod_req_bytes, resp.getResponse(), param_name=pname, payload=payload)
                                entry.highlight = mark
                                history.append(entry)

                # --- Attack JSON body keys if Content-Type is JSON ---
                if is_json:
                    try:
                        jbody = json.loads(body, strict=False)
                        if isinstance(jbody, (dict, list)):
                            for key_path in body_params:
                                for payload in body_payloads:
                                    jbody_mod = deepcopy(jbody)
                                    try:
                                        set_nested_value(jbody_mod, key_path, payload)
                                        body_mod = json.dumps(jbody_mod)
                                        req_mod = headers + "\r\n\r\n" + body_mod
                                        mod_req_bytes = self.helpers.stringToBytes(req_mod)
                                        resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                                        entry = MessageHistoryEntry(mod_req_bytes, resp.getResponse(), param_name=key_path, payload=payload)
                                        history.append(entry)
                                    except (KeyError, IndexError, TypeError):
                                        pass
                    except Exception:
                        pass

                self.history += history
                
                def do_ui_update():
                    if history:
                        self.current_idx = len(self.history) - len(history)
                        self.show_entry(self.current_idx)
                    else:
                        # Should still update status if no requests were sent
                        self.update_status()
                    # Defer the resize call to run *after* any UI events from show_entry/update_status
                    self.resize_sidebar()
                SwingUtilities.invokeLater(do_ui_update)

                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()
            except Exception as e:
                # import traceback
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "Attack Error:\n" + str(e) + "\n" + traceback.format_exc()))
        threading.Thread(target=worker).start()

    def bac_check(self, event):
        def worker():
            try:
                req_bytes = self.req_editor.getMessage()
                req_str = self.helpers.bytesToString(req_bytes)
                service = self.base_message.getHttpService() if self.base_message else self.guess_service_from_request(req_bytes)
                analyzed = self.helpers.analyzeRequest(service, req_bytes)
                body = ""
                if "\r\n\r\n" in req_str:
                    headers_part, body = req_str.split('\r\n\r\n', 1)
                    header_lines = headers_part.split('\r\n')
                else:
                    header_lines = req_str.split('\r\n')
                base_headers = []
                for line in header_lines:
                    base_headers.append(line)
                history = []
                # Only use roles that are currently in role_data, have a corresponding tab, and are enabled
                for idx, role in enumerate(list(self.bac_panel.role_data)):
                    if idx >= self.bac_panel.role_tabs.getTabCount() - 1:
                        continue  # Skip if not a real role tab
                    if not role.get("enabled", True):
                        continue  # Skip if not enabled
                    modified_headers = []
                    used_headers = set()
                    # Build a header name -> value map for this role
                    role_headers = {h['header'].strip().lower(): h['value'] for h in role.get('headers', []) if h.get('header')}
                    for h in base_headers:
                        hname = h.split(":", 1)[0].strip() if ":" in h else ""
                        if hname.lower() in role_headers:
                            modified_headers.append("%s: %s" % (hname, role_headers[hname.lower()]))
                            used_headers.add(hname.lower())
                        else:
                            modified_headers.append(h)
                    # Add per-role extra header if enabled
                    if role.get('extra_enabled') and role.get('extra_name'):
                        extra_name = role.get('extra_name').strip()
                        extra_value = role.get('extra_value', '')
                        extra_found = False
                        for idx2, h in enumerate(modified_headers):
                            if ':' in h and h.split(':', 1)[0].strip().lower() == extra_name.lower():
                                modified_headers[idx2] = "%s: %s" % (extra_name, extra_value)
                                extra_found = True
                                break
                        if not extra_found:
                            insert_idx = 1
                            for i, h in enumerate(modified_headers):
                                if ':' in h and h.split(':', 1)[0].strip().lower() in used_headers:
                                    insert_idx = i + 1
                                    break
                            modified_headers.insert(insert_idx, "%s: %s" % (extra_name, extra_value))
                    # Build request
                    new_req_str = "\r\n".join(modified_headers) + "\r\n\r\n" + body
                    mod_req_bytes = self.helpers.stringToBytes(new_req_str)
                    resp = self.callbacks.makeHttpRequest(service, mod_req_bytes)
                    entry = MessageHistoryEntry(
                        mod_req_bytes,
                        resp.getResponse(),
                        param_name=role['label'],
                        payload="; ".join(["%s=%s" % (h.get('header', ''), h.get('value', '')) for h in role.get('headers', [])])
                    )
                    history.append(entry)
                self.history += history
                
                def do_ui_update():
                    if history:
                        self.current_idx = len(self.history) - len(history)
                        self.show_entry(self.current_idx)
                    else:
                        self.update_status()
                    # Defer the resize call to run *after* any UI events from show_entry/update_status
                    self.resize_sidebar()
                SwingUtilities.invokeLater(do_ui_update)

                if self.save_tabs_state_callback:
                    self.save_tabs_state_callback()
            except Exception as e:
                # import traceback
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(self, "BAC Check Error:\n" + str(e) + "\n" + traceback.format_exc()))
        # import threading
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

        # --- 4. Swap in the new panel in the Inspector sub-tab (index 0)
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
        else:
            self.resp_editor.setMessage(entry.resp_bytes, False)
        # --- FIX: Always update the status label! ---
        self.update_status()
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
        try:
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
        self.label = JLabel(title)
        self.add(self.label)
        # Add enable/disable checkbox for selective access check (only for BAC roles)
        self.role_idx = role_idx
        self.enable_checkbox = None
        if self.bac_parent is not None and role_idx is not None:
            self.enable_checkbox = JCheckBox()
            # Default to enabled unless specified in role_data
            enabled = True
            try:
                enabled = bool(self.bac_parent.role_data[role_idx].get("enabled", True))
            except Exception:
                pass
            self.enable_checkbox.setSelected(enabled)
            self.enable_checkbox.setToolTipText("Enable/disable this role for Access Check")
            self.enable_checkbox.addActionListener(self.on_checkbox_toggle)
            self.add(self.enable_checkbox)
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


            # DO NOT add a new tab here, even if this was the last one.
            # After this, if the only tab left is "+", that's correct!

                    # If NO tabs left except "+", add a single blank role tab
        self.close_button.addActionListener(CloseListener())
        self.add(self.close_button)
        # Mouse listener for switching/renaming
        self.addMouseListener(self.TabMouseListener(self))
        self.close_button.addMouseListener(self.IgnoreTabSwitchListener())

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

class StackedVerticalTabButton(JPanel):
    def __init__(self, text, selected=False, on_click=None):
        JPanel.__init__(self)
        self.text = text
        self.on_click = on_click
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.labels = []
        button_width = 24
        button_height = 180
        for c in text:
            lbl = JLabel(c)
            lbl.setForeground(Color.BLACK)
            lbl.setAlignmentX(0.5)
            lbl.setHorizontalAlignment(JLabel.CENTER)
            self.add(Box.createVerticalStrut(2))
            self.add(lbl)
            self.labels.append(lbl)
        # Use system default background (no more orange)
        self.setBackground(None)
        self.setPreferredSize(Dimension(button_width, button_height))
        self.setMaximumSize(Dimension(button_width, button_height))
        self.setMinimumSize(Dimension(button_width, button_height))
        self.setBorder(BorderFactory.createEmptyBorder())
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self.selected = selected
        self.addMouseListener(self.TabClickListener(self))
        self.update_highlight()
    def set_selected(self, selected):
        self.selected = selected
        self.update_highlight()
        self.repaint()
    def update_highlight(self):
        # This will underline the selected tab label by making it blue
        for lbl in self.labels:
            if self.selected:
                lbl.setForeground(Color(0, 120, 215))  # Burp blue (or Windows accent blue)
            else:
                lbl.setForeground(Color.BLACK)
    class TabClickListener(MouseAdapter):
        def __init__(self, parent):
            MouseAdapter.__init__(self)
            self.parent = parent
        def mouseClicked(self, event):
            if self.parent.on_click:
                self.parent.on_click()

def update_last_payload_state(url_payloads_state, body_payloads_state):
    global LAST_PAYLOAD_STATE
    LAST_PAYLOAD_STATE["url_payloads"] = list(url_payloads_state)
    LAST_PAYLOAD_STATE["body_payloads"] = list(body_payloads_state)
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
            for i in range(tabs.getTabCount() - 1):  # Exclude '+'
                tab_titles.append(tabs.getTitleAt(i))
            if not tab_titles:
                JOptionPane.showMessageDialog(self.main_panel, "No tabs to export.")
                return

            from javax.swing import JList
            jlist = JList(tab_titles)
            jlist.setSelectionInterval(0, 0)  # Pre-select first
            jlist.setVisibleRowCount(min(8, len(tab_titles)))
            res = JOptionPane.showConfirmDialog(self.main_panel, JScrollPane(jlist), "Select tabs to export", JOptionPane.OK_CANCEL_OPTION)
            if res != JOptionPane.OK_OPTION:
                return
            selected_indices = jlist.getSelectedIndices()
            if len(selected_indices) == 0:
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
            if last_dir and os.path.isdir(last_dir):
                chooser = JFileChooser(last_dir)
            else:
                chooser = JFileChooser()
            chooser.setDialogTitle("Merge Export Tabs (to .json)")
            chooser.setSelectedFile(File("paramfuzzer_tabs.json"))
            if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                file = chooser.getSelectedFile()
                out_path = file.getAbsolutePath()
                if not out_path.endswith(".json"):
                    out_path += ".json"
                save_setting(self._callbacks, LAST_EXPORT_DIR_KEY, os.path.dirname(out_path))

                # Load existing file if present
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
                        pass
                # Append new tabs
                merged.extend(export_list)
                with codecs.open(out_path, "w", encoding="utf-8") as f:
                    json.dump(merged, f, indent=2)
                JOptionPane.showMessageDialog(self.main_panel, "Merged %d tabs into:\n%s" % (len(export_list), out_path))
        except Exception as e:
            # import traceback
            JOptionPane.showMessageDialog(self.main_panel, "Error merging export tabs:\n" + str(e) + "\n" + traceback.format_exc())



# search for # Default payloads to change default payloads
