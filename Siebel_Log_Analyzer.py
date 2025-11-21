import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
from datetime import datetime
import json

# Try to import PIL for better image export, but provide fallback
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# SECURITY: Disable network access completely
import sys

# --- LICENSE CHECK (runs on import) ---
import base64
from tkinter import messagebox

def tcs_check_license():
    import os
    from datetime import datetime

    key_path = os.path.join(os.path.dirname(__file__), "license.key")
    if not os.path.exists(key_path):
        messagebox.showerror("License Error",
                             "License key missing.\nPlease contact vendor for a new key.")
        return False
    try:
        with open(key_path, "r") as f:
            encoded = f.read().strip()
        decoded = base64.b64decode(encoded).decode("utf-8", errors="strict")
        parts = decoded.split("|")
        # Expected: "SIEBEL-LOG-ANALYZER-TCS-TOOL-LICENSE-VALIDITY|YYYY-MM-DD"
        if len(parts) != 2 or parts[0] != "SIEBEL-LOG-ANALYZER-TCS-TOOL-LICENSE-VALIDITY":
            raise ValueError("Invalid key format")

        expiry = datetime.strptime(parts[1], "%Y-%m-%d").date()
        today = datetime.now().date()
        if today > expiry:
            messagebox.showerror("License Expired",
                                 f"This license expired on {expiry}.\nPlease request a renewal.")
            return False
        return True
    except Exception as e:
        messagebox.showerror("License Error", f"Invalid license: {e}")
        return False

if not tcs_check_license():
    # Stop import -> app won’t run if license check fails
    raise SystemExit(1)
# --- END LICENSE CHECK ---


# Block network-related modules from being imported
BLOCKED_MODULES = [
    'urllib2', 'urllib3', 'requests', 'http', 'https',
    'httplib', 'httplib2', 'ftplib', 'smtplib', 'telnetlib', 'poplib',
    'imaplib', 'nntplib', 'socketserver', 'xmlrpc', 'webbrowser'
]


class TCSNetworkBlocker:
    """TCS Security module to prevent network access"""
    def __init__(self):
        self.original_import = __builtins__.__import__
        __builtins__.__import__ = self._secure_import
    
    def _secure_import(self, name, *args, **kwargs):
        # Block any network-related imports
        for blocked in BLOCKED_MODULES:
            if name.startswith(blocked):
                raise ImportError(f"Network module '{name}' is blocked for security reasons")
        return self.original_import(name, *args, **kwargs)

# Initialize network blocking
_tcs_network_blocker = TCSNetworkBlocker()

# SECURITY: Additional runtime network blocking
def _block_socket_creation(*args, **kwargs):
    """Block any attempt to create network sockets"""
    raise PermissionError("Network access is disabled for security reasons")

# Block socket creation at runtime if socket module is already imported
try:
    import socket
    socket.socket = _block_socket_creation
    socket.create_connection = _block_socket_creation
except ImportError:
    pass  # Socket module not available, which is good

# Helper functions - optimized for performance
def tcs_find_nth_index(s, char, n):
    """Find the nth occurrence of char in string s - optimized version"""
    if n <= 0:
        raise ValueError("Index must be greater than 0")
    
    offset = -1
    for _ in range(n):
        offset = s.find(char, offset + 1)
        if offset == -1:
            return -1
    return offset

def tcs_safe_substring(s, start, length=None):
    """Extract substring safely with bounds checking - optimized version"""
    if not s or start < 0 or start >= len(s):
        return ''
    
    if length is None:
        result = s[start:]
    else:
        end = min(start + length, len(s))
        result = s[start:end]
    
    # Clean the result: remove newlines, tabs, and extra spaces
    result = result.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Replace multiple spaces with single space
    while '  ' in result:
        result = result.replace('  ', ' ')
    
    return result.strip()

# Helper function to clean single-line display data
def tcs_clean_single_line(text):
    """Clean text to ensure it displays as a single line"""
    if not text:
        return ''
    
    # Convert to string and remove all line break characters
    clean_text = str(text).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    
    # Replace multiple spaces with single space
    while '  ' in clean_text:
        clean_text = clean_text.replace('  ', ' ')
    
    return clean_text.strip()

# Main application class
class SiebelLogAnalyzer:
    def _apply_modern_theme(self):
        """Apply modern theme and styling to the application"""
        # Configure ttk styles for modern look
        style = ttk.Style()
        
        # Use a modern theme as base
        try:
            style.theme_use('clam')
        except:
            pass  # Fallback to default if clam not available
        
        # Configure progressbar style
        style.configure("Horizontal.TProgressbar", 
                       troughcolor='#ecf0f1',
                       background='#3498db',
                       bordercolor='#2980b9',
                       lightcolor='#3498db',
                       darkcolor='#2980b9')
        
    def __init__(self, root):
        self.root = root
        self.root.title("TCS Siebel Log Analyzer - Professional Edition")
        
        # Start in full screen mode
        self.root.state('zoomed')  # Windows full screen
        self.root.resizable(True, True)
        
        # Apply modern styling
        self._apply_modern_theme()
        
        self.filename = ""
        
        # SECURITY: Verify network blocking is active
        self._verify_network_security()
        
        # Initialize security flag for memory warnings
        self._memory_warning_shown = False
        
        # Cross-tab line highlighting
        self._selected_line_number = None
        self._all_text_widgets = []  # Will be populated after creating tabs

        # Create main frame with modern styling
        main_frame = tk.Frame(root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title bar with gradient-like effect
        title_frame = tk.Frame(main_frame, bg='#2c3e50', height=60)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, 
                              text="🔍 TCS Siebel Log Analyzer - Professional Edition",
                              font=("Segoe UI", 16, "bold"),
                              bg='#2c3e50', fg='white')
        title_label.pack(pady=15)

        # UI Elements with modern styling
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(pady=10)

        # Style for modern buttons
        button_style = {
            'font': ('Segoe UI', 10, 'bold'),
            'bg': '#3498db',
            'fg': 'white',
            'activebackground': '#2980b9',
            'activeforeground': 'white',
            'relief': tk.FLAT,
            'cursor': 'hand2',
            'borderwidth': 0,
            'padx': 20,
            'pady': 10
        }

        self.select_button = tk.Button(button_frame, text="📁 Select Log File", 
                                      command=self.select_file, **button_style)
        self.select_button.pack(side=tk.LEFT, padx=5)

        self.analyze_button = tk.Button(button_frame, text="⚡ Analyze Log", 
                                       command=self.analyze_log, **button_style)
        self.analyze_button.pack(side=tk.LEFT, padx=5)

        # Notepad++ button now uses same blue color as Analyze button
        self.notepad_button = tk.Button(button_frame, text="⚙️ Set Notepad++", 
                                       command=self.select_notepad_path, **button_style)
        self.notepad_button.pack(side=tk.LEFT, padx=5)

        # Progress bar with modern styling
        self.progress_frame = tk.Frame(main_frame, bg='#f0f0f0')
        self.progress_frame.pack(pady=10)
        
        # Create a styled frame for progress bar
        progress_container = tk.Frame(self.progress_frame, bg='white', relief=tk.SOLID, borderwidth=1)
        progress_container.pack(side=tk.LEFT, padx=5)
        
        self.progress_bar = ttk.Progressbar(progress_container, length=500, mode='determinate')
        self.progress_bar.pack(padx=2, pady=2)
        
        self.progress_label = tk.Label(self.progress_frame, text="Ready", 
                                      font=('Segoe UI', 10), fg="#27ae60", bg='#f0f0f0')
        self.progress_label.pack(side=tk.LEFT, padx=10)

        # Status label with modern styling
        self.status_label = tk.Label(main_frame, text="📂 No file selected", 
                                    font=('Segoe UI', 10), fg="#7f8c8d", bg='#f0f0f0')
        self.status_label.pack(pady=5)
        
        # Security status label with modern styling
        security_container = tk.Frame(main_frame, bg='#fff3cd', relief=tk.SOLID, borderwidth=1)
        security_container.pack(pady=5, padx=20, fill=tk.X)
        
        self.security_label = tk.Label(security_container, 
                                      text="🔒 NETWORK ACCESS DISABLED - Secure Mode Active", 
                                      fg="#856404", font=("Segoe UI", 9, "bold"), 
                                      bg="#fff3cd", pady=5)
        self.security_label.pack()

        # Create notebook for tabs with modern styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#f0f0f0', borderwidth=0)
        style.configure('TNotebook.Tab', 
                       font=('Segoe UI', 10, 'bold'),
                       padding=[20, 10],
                       background='#bdc3c7')
        style.map('TNotebook.Tab',
                 background=[('selected', '#3498db')],
                 foreground=[('selected', 'white'), ('!selected', '#2c3e50')])
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.create_tabs()

    def create_tabs(self):
        """Create individual tabs for different analysis results"""
        # Modern text widget styling
        text_style = {
            'wrap': tk.NONE,
            'font': ('Consolas', 10),
            'bg': '#ffffff',
            'fg': '#2c3e50',
            'insertbackground': '#3498db',
            'selectbackground': '#3498db',
            'selectforeground': 'white',
            'relief': tk.FLAT,
            'borderwidth': 0,
            'padx': 5,
            'pady': 5
        }
        
        # Event Context Tab (1st)
        self.event_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.event_frame, text="📋 Event Context")
        
        # Add search bar at top
        event_search_frame = ttk.Frame(self.event_frame)
        event_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(event_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.event_search_var = tk.StringVar()
        event_search_entry = ttk.Entry(event_search_frame, textvariable=self.event_search_var, width=15)
        event_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(event_search_frame, text="Go", command=lambda: self._search_line_number(self.event_text, self.event_search_var.get())).pack(side=tk.LEFT, padx=2)
        event_search_entry.bind("<Return>", lambda e: self._search_line_number(self.event_text, self.event_search_var.get()))
        
        # Create text widget with both scrollbars
        self.event_text = tk.Text(self.event_frame, **text_style)
        event_vsb = ttk.Scrollbar(self.event_frame, orient="vertical", command=self.event_text.yview)
        event_hsb = ttk.Scrollbar(self.event_frame, orient="horizontal", command=self.event_text.xview)
        self.event_text.configure(yscrollcommand=event_vsb.set, xscrollcommand=event_hsb.set)
        # Grid layout for scrollbars
        self.event_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        event_vsb.grid(row=1, column=1, sticky="ns")
        event_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.event_frame.grid_rowconfigure(1, weight=1)
        self.event_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.event_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.event_text))
        self.event_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.event_text))
        self.event_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.event_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.event_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.event_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.event_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.event_text))
        self.event_text.bind("<Control-a>", lambda e: self._select_all(self.event_text))

        # Workflow Tab (2nd)
        self.workflow_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.workflow_frame, text="🔄 Workflow")
        
        # Add search bar at top
        workflow_search_frame = ttk.Frame(self.workflow_frame)
        workflow_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(workflow_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.workflow_search_var = tk.StringVar()
        workflow_search_entry = ttk.Entry(workflow_search_frame, textvariable=self.workflow_search_var, width=15)
        workflow_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(workflow_search_frame, text="Go", command=lambda: self._search_line_number(self.workflow_text, self.workflow_search_var.get())).pack(side=tk.LEFT, padx=2)
        workflow_search_entry.bind("<Return>", lambda e: self._search_line_number(self.workflow_text, self.workflow_search_var.get()))
        
        # Create text widget with both scrollbars
        self.workflow_text = tk.Text(self.workflow_frame, **text_style)
        workflow_vsb = ttk.Scrollbar(self.workflow_frame, orient="vertical", command=self.workflow_text.yview)
        workflow_hsb = ttk.Scrollbar(self.workflow_frame, orient="horizontal", command=self.workflow_text.xview)
        self.workflow_text.configure(yscrollcommand=workflow_vsb.set, xscrollcommand=workflow_hsb.set)
        # Grid layout for scrollbars
        self.workflow_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        workflow_vsb.grid(row=1, column=1, sticky="ns")
        workflow_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.workflow_frame.grid_rowconfigure(1, weight=1)
        self.workflow_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.workflow_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.workflow_text))
        self.workflow_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.workflow_text))
        self.workflow_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.workflow_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.workflow_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.workflow_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.workflow_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.workflow_text))
        self.workflow_text.bind("<Control-a>", lambda e: self._select_all(self.workflow_text))

        # Business Service Tab (3rd - after Workflow)
        self.business_service_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.business_service_frame, text="� Business Service")
        
        # Add search bar at top
        bs_search_frame = ttk.Frame(self.business_service_frame)
        bs_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(bs_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.bs_search_var = tk.StringVar()
        bs_search_entry = ttk.Entry(bs_search_frame, textvariable=self.bs_search_var, width=15)
        bs_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(bs_search_frame, text="Go", command=lambda: self._search_line_number(self.business_service_text, self.bs_search_var.get())).pack(side=tk.LEFT, padx=2)
        bs_search_entry.bind("<Return>", lambda e: self._search_line_number(self.business_service_text, self.bs_search_var.get()))
        
        # Create treeview with scrollbars
        # Create text widget with both scrollbars
        self.business_service_text = tk.Text(self.business_service_frame, **text_style)
        business_service_vsb = ttk.Scrollbar(self.business_service_frame, orient="vertical", command=self.business_service_text.yview)
        business_service_hsb = ttk.Scrollbar(self.business_service_frame, orient="horizontal", command=self.business_service_text.xview)
        self.business_service_text.configure(yscrollcommand=business_service_vsb.set, xscrollcommand=business_service_hsb.set)
        # Grid layout for scrollbars
        self.business_service_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        business_service_vsb.grid(row=1, column=1, sticky="ns")
        business_service_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.business_service_frame.grid_rowconfigure(1, weight=1)
        self.business_service_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.business_service_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.business_service_text))
        self.business_service_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.business_service_text))
        self.business_service_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.business_service_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.business_service_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.business_service_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.business_service_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.business_service_text))
        self.business_service_text.bind("<Control-a>", lambda e: self._select_all(self.business_service_text))

        # Workflow Map Tab (4th - after Business Service)
        self.workflow_map_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.workflow_map_frame, text="🗺️ Workflow Map")
        
        # Add toolbar for workflow map actions
        wf_map_toolbar = ttk.Frame(self.workflow_map_frame)
        wf_map_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(wf_map_toolbar, text="🪟 Pop-Out Window", command=self.popout_workflow_map).pack(side=tk.LEFT, padx=2)
        ttk.Button(wf_map_toolbar, text="🔍 Zoom In", command=self.zoom_in_workflow_map).pack(side=tk.LEFT, padx=2)
        ttk.Button(wf_map_toolbar, text="🔍 Zoom Out", command=self.zoom_out_workflow_map).pack(side=tk.LEFT, padx=2)
        ttk.Button(wf_map_toolbar, text="🔄 Reset View", command=self.reset_workflow_map_zoom).pack(side=tk.LEFT, padx=2)
        ttk.Button(wf_map_toolbar, text="💾 Export as PNG", command=self.export_workflow_map_png).pack(side=tk.LEFT, padx=2)
        ttk.Button(wf_map_toolbar, text="🎨 Open in Paint", command=self.open_workflow_map_in_paint).pack(side=tk.LEFT, padx=2)
        
        # Create canvas with scrollbars for graphical workflow map
        canvas_container = ttk.Frame(self.workflow_map_frame)
        canvas_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create canvas for drawing workflow diagram
        self.workflow_map_canvas = tk.Canvas(canvas_container, bg="white", highlightthickness=1, highlightbackground="gray")
        self.workflow_map_zoom = 1.0  # Track zoom level
        
        # Add scrollbars
        wf_map_v_scroll = ttk.Scrollbar(canvas_container, orient="vertical", command=self.workflow_map_canvas.yview)
        wf_map_h_scroll = ttk.Scrollbar(canvas_container, orient="horizontal", command=self.workflow_map_canvas.xview)
        self.workflow_map_canvas.configure(yscrollcommand=wf_map_v_scroll.set, xscrollcommand=wf_map_h_scroll.set)
        
        # Pack canvas and scrollbars
        self.workflow_map_canvas.grid(row=0, column=0, sticky="nsew")
        wf_map_v_scroll.grid(row=0, column=1, sticky="ns")
        wf_map_h_scroll.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        canvas_container.grid_rowconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(0, weight=1)
        
        # Store workflow map data
        self.workflow_map_data = {}
        self.workflow_map_items_cache = []
        self.workflow_map_popout_window = None  # Track pop-out window

        # Errors Tab (5th)
        self.errors_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.errors_frame, text="⚠️ Errors")
        
        # Add search bar at top
        errors_search_frame = ttk.Frame(self.errors_frame)
        errors_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(errors_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.errors_search_var = tk.StringVar()
        errors_search_entry = ttk.Entry(errors_search_frame, textvariable=self.errors_search_var, width=15)
        errors_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(errors_search_frame, text="Go", command=lambda: self._search_line_number(self.errors_text, self.errors_search_var.get())).pack(side=tk.LEFT, padx=2)
        errors_search_entry.bind("<Return>", lambda e: self._search_line_number(self.errors_text, self.errors_search_var.get()))
        
        # Create text widget with both scrollbars
        self.errors_text = tk.Text(self.errors_frame, **text_style)
        errors_vsb = ttk.Scrollbar(self.errors_frame, orient="vertical", command=self.errors_text.yview)
        errors_hsb = ttk.Scrollbar(self.errors_frame, orient="horizontal", command=self.errors_text.xview)
        self.errors_text.configure(yscrollcommand=errors_vsb.set, xscrollcommand=errors_hsb.set)
        # Grid layout for scrollbars
        self.errors_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        errors_vsb.grid(row=1, column=1, sticky="ns")
        errors_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.errors_frame.grid_rowconfigure(1, weight=1)
        self.errors_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.errors_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.errors_text))
        self.errors_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.errors_text))
        self.errors_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.errors_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.errors_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.errors_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.errors_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.errors_text))
        self.errors_text.bind("<Control-a>", lambda e: self._select_all(self.errors_text))

        # SQL Execution Tab (4th)
        self.exec_sql_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.exec_sql_frame, text="💾 SQL Execution")
        
        # Add search bar at top
        sql_search_frame = ttk.Frame(self.exec_sql_frame)
        sql_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(sql_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.sql_search_var = tk.StringVar()
        sql_search_entry = ttk.Entry(sql_search_frame, textvariable=self.sql_search_var, width=15)
        sql_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(sql_search_frame, text="Go", command=lambda: self._search_line_number(self.exec_sql_text, self.sql_search_var.get())).pack(side=tk.LEFT, padx=2)
        sql_search_entry.bind("<Return>", lambda e: self._search_line_number(self.exec_sql_text, self.sql_search_var.get()))
        
        # Create text widget with both scrollbars
        self.exec_sql_text = tk.Text(self.exec_sql_frame, **text_style)
        exec_sql_vsb = ttk.Scrollbar(self.exec_sql_frame, orient="vertical", command=self.exec_sql_text.yview)
        exec_sql_hsb = ttk.Scrollbar(self.exec_sql_frame, orient="horizontal", command=self.exec_sql_text.xview)
        self.exec_sql_text.configure(yscrollcommand=exec_sql_vsb.set, xscrollcommand=exec_sql_hsb.set)
        # Grid layout for scrollbars
        self.exec_sql_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        exec_sql_vsb.grid(row=1, column=1, sticky="ns")
        exec_sql_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.exec_sql_frame.grid_rowconfigure(1, weight=1)
        self.exec_sql_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.exec_sql_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.exec_sql_text))
        self.exec_sql_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.exec_sql_text))
        self.exec_sql_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.exec_sql_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.exec_sql_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.exec_sql_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.exec_sql_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.exec_sql_text))
        self.exec_sql_text.bind("<Control-a>", lambda e: self._select_all(self.exec_sql_text))

        # Performance Tab (5th)
        self.perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_frame, text="⚡ Performance")
        
        # Add search bar at top
        perf_search_frame = ttk.Frame(self.perf_frame)
        perf_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(perf_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.perf_search_var = tk.StringVar()
        perf_search_entry = ttk.Entry(perf_search_frame, textvariable=self.perf_search_var, width=15)
        perf_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(perf_search_frame, text="Go", command=lambda: self._search_line_number(self.perf_text, self.perf_search_var.get())).pack(side=tk.LEFT, padx=2)
        perf_search_entry.bind("<Return>", lambda e: self._search_line_number(self.perf_text, self.perf_search_var.get()))
        
        # Create text widget with both scrollbars
        self.perf_text = tk.Text(self.perf_frame, **text_style)
        perf_vsb = ttk.Scrollbar(self.perf_frame, orient="vertical", command=self.perf_text.yview)
        perf_hsb = ttk.Scrollbar(self.perf_frame, orient="horizontal", command=self.perf_text.xview)
        self.perf_text.configure(yscrollcommand=perf_vsb.set, xscrollcommand=perf_hsb.set)
        # Grid layout for scrollbars
        self.perf_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        perf_vsb.grid(row=1, column=1, sticky="ns")
        perf_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.perf_frame.grid_rowconfigure(1, weight=1)
        self.perf_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.perf_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.perf_text))
        self.perf_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.perf_text))
        self.perf_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.perf_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.perf_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.perf_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.perf_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.perf_text))
        self.perf_text.bind("<Control-a>", lambda e: self._select_all(self.perf_text))

        # Task-Based UI Tab (6th)
        self.tbui_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tbui_frame, text="🎯 Task-Based UI")
        
        # Add search bar at top
        tbui_search_frame = ttk.Frame(self.tbui_frame)
        tbui_search_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Label(tbui_search_frame, text="🔍 Search Line Number:").pack(side=tk.LEFT, padx=5)
        self.tbui_search_var = tk.StringVar()
        tbui_search_entry = ttk.Entry(tbui_search_frame, textvariable=self.tbui_search_var, width=15)
        tbui_search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(tbui_search_frame, text="Go", command=lambda: self._search_line_number(self.tbui_text, self.tbui_search_var.get())).pack(side=tk.LEFT, padx=2)
        tbui_search_entry.bind("<Return>", lambda e: self._search_line_number(self.tbui_text, self.tbui_search_var.get()))
        
        # Create text widget with both scrollbars
        self.tbui_text = tk.Text(self.tbui_frame, **text_style)
        tbui_vsb = ttk.Scrollbar(self.tbui_frame, orient="vertical", command=self.tbui_text.yview)
        tbui_hsb = ttk.Scrollbar(self.tbui_frame, orient="horizontal", command=self.tbui_text.xview)
        self.tbui_text.configure(yscrollcommand=tbui_vsb.set, xscrollcommand=tbui_hsb.set)
        # Grid layout for scrollbars
        self.tbui_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        tbui_vsb.grid(row=1, column=1, sticky="ns")
        tbui_hsb.grid(row=2, column=0, sticky="ew", padx=5)
        self.tbui_frame.grid_rowconfigure(1, weight=1)
        self.tbui_frame.grid_columnconfigure(0, weight=1)
        # Bind events
        self.tbui_text.bind("<Double-Button-1>", lambda e: self._on_text_double_click(e, self.tbui_text))
        self.tbui_text.bind("<Button-3>", lambda e: self._show_context_menu(e, self.tbui_text))
        self.tbui_text.bind("<Prior>", lambda e: None)  # Page Up (allow default)
        self.tbui_text.bind("<Next>", lambda e: None)  # Page Down (allow default)
        self.tbui_text.bind("<Up>", lambda e: None)  # Up arrow (allow default)
        self.tbui_text.bind("<Down>", lambda e: None)  # Down arrow (allow default)
        # Enable clipboard operations
        self.tbui_text.bind("<Control-c>", lambda e: self._copy_to_clipboard(self.tbui_text))
        self.tbui_text.bind("<Control-a>", lambda e: self._select_all(self.tbui_text))

        # SQL Tree View Tab (7th)
        self.sql_tree_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.sql_tree_frame, text="🌳 SQL Tree View")
        
        # Create treeview with scrollbars
        tree_container = ttk.Frame(self.sql_tree_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview
        self.sql_tree = ttk.Treeview(tree_container, columns=("exec_time", "line_num"), show="tree headings")
        
        # Define headings
        self.sql_tree.heading("#0", text="SQL ID / Query", anchor="w")
        self.sql_tree.heading("exec_time", text="Execution Time", anchor="center")
        self.sql_tree.heading("line_num", text="Line #", anchor="center")
        
        # Configure column widths
        self.sql_tree.column("#0", width=500, minwidth=300)
        self.sql_tree.column("exec_time", width=150, minwidth=100)
        self.sql_tree.column("line_num", width=80, minwidth=60)
        
        # Add scrollbars
        tree_v_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.sql_tree.yview)
        tree_h_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.sql_tree.xview)
        self.sql_tree.configure(yscrollcommand=tree_v_scroll.set, xscrollcommand=tree_h_scroll.set)
        
        # Pack treeview and scrollbars
        self.sql_tree.grid(row=0, column=0, sticky="nsew")
        tree_v_scroll.grid(row=0, column=1, sticky="ns")
        tree_h_scroll.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Bind events for navigation
        self.sql_tree.bind("<Double-Button-1>", lambda e: self._on_tree_double_click(e))
        self.sql_tree.bind("<Button-3>", lambda e: self._on_tree_right_click(e))

        # Notepad++ configuration
        self.notepad_path = ""
        self.load_notepad_config()
        
        # Store all text widgets for cross-tab highlighting
        self._all_text_widgets = [
            self.event_text, self.workflow_text, self.business_service_text, self.errors_text,
            self.exec_sql_text, self.perf_text, self.tbui_text
        ]
        
        # Configure highlight tag for all text widgets with higher priority
        for widget in self._all_text_widgets:
            widget.tag_configure("highlight", background="#FFFF99", foreground="black", 
                               relief=tk.RAISED, borderwidth=1)
            widget.tag_raise("highlight")  # Ensure highlight tag has highest priority
        
        # Bind tab change event to refresh highlights
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def select_file(self):
        self.filename = filedialog.askopenfilename(filetypes=[("Siebel Log", "*.log"), ("All Files", "*.*")])
        if self.filename:
            self.status_label.config(text=f"Selected: {os.path.basename(self.filename)}", fg="green")
            messagebox.showinfo("File Selected", f"Selected file: {self.filename}")
        else:
            self.status_label.config(text="No file selected", fg="gray")

    def _verify_network_security(self):
        """Verify that network access is properly blocked"""
        try:
            # Test 1: Try to import blocked modules
            blocked_test_modules = ['requests']
            for module in blocked_test_modules:
                try:
                    __import__(module)
                    # If we get here, the module was imported (bad)
                    messagebox.showwarning("Security Warning", 
                        f"Network module '{module}' is still accessible. Network blocking may not be complete.")
                except ImportError:
                    # Good - module is blocked
                    pass
            
            # Test 2: Verify socket blocking
            try:
                import socket
                try:
                    socket.socket()
                    messagebox.showwarning("Security Warning", 
                        "Socket creation is still possible. Network access may not be fully blocked.")
                except (PermissionError, Exception):
                    # Good - socket creation is blocked
                    pass
            except ImportError:
                # Good - socket module is not available
                pass
                
        except Exception as e:
            # Network verification failed, but continue
            pass

    def analyze_log(self):
        if not self.filename or not os.path.exists(self.filename):
            messagebox.showerror("Error", "No valid log file selected.")
            return

        # Disable analyze button and show progress
        self.analyze_button.config(state='disabled')
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Starting analysis...", fg="blue")
        self.root.update()

        # Initialize collections with better data structures
        exec_sql_items = []
        perf_items = []
        error_items = []
        evtcxt_items = []
        tbui_items = []
        wf_items = []
        business_service_items = []
        workflow_map_items = []
        
        # Security: Memory usage limits (DoS protection)
        MAX_ITEMS_PER_CATEGORY = 50000  # Limit to prevent memory exhaustion

        try:
            # Get file size for progress tracking and security check
            file_size = os.path.getsize(self.filename)
            
            # Security: Prevent processing of extremely large files (DoS protection)
            MAX_FILE_SIZE = 900 * 1024 * 1024  # 900 MB limit
            if file_size > MAX_FILE_SIZE:
                messagebox.showerror("File Too Large", 
                    f"File size ({file_size:,} bytes) exceeds maximum allowed size "
                    f"({MAX_FILE_SIZE:,} bytes). Please use a smaller log file.")
                return
            
            self.progress_label.config(text=f"File size: {file_size:,} bytes")
            self.root.update()

            # Use buffered reading for large files
            with open(self.filename, 'r', encoding='utf-8', errors='ignore', buffering=8192*4) as f:
                # Initialize state variables
                linecnt = 0
                bytes_read = 0
                isSQL = False
                isBind = False
                selectsql = False
                current_sql_id = bind_buffer = sql_buffer = previous_sql = table_name = process_definition_name = ""
                
                # Process file in chunks for better memory management
                chunk_size = 1000  # Process 1000 lines at a time
                lines_buffer = []
                
                # Read and process line by line instead of loading entire file
                for line in f:
                    linecnt += 1
                    bytes_read += len(line.encode('utf-8'))
                    lines_buffer.append(line.strip())
                    
                    # Process in batches and update progress
                    if len(lines_buffer) >= chunk_size:
                        self._tcs_process_lines_batch(lines_buffer, linecnt - len(lines_buffer) + 1,
                                                exec_sql_items, perf_items, error_items, 
                                                evtcxt_items, tbui_items, wf_items, business_service_items, workflow_map_items,
                                                isSQL, isBind, selectsql, current_sql_id, bind_buffer, sql_buffer, previous_sql, table_name, process_definition_name,
                                                MAX_ITEMS_PER_CATEGORY)
                        
                        # Update progress
                        progress = min(90, (bytes_read / file_size) * 90)  # Reserve 10% for UI updates
                        self.progress_bar['value'] = progress
                        self.progress_label.config(text=f"Processing... {linecnt:,} lines")
                        self.root.update()
                        lines_buffer.clear()
                
                # Process remaining lines
                if lines_buffer:
                    self._tcs_process_lines_batch(lines_buffer, linecnt - len(lines_buffer) + 1,
                                            exec_sql_items, perf_items, error_items, 
                                            evtcxt_items, tbui_items, wf_items, business_service_items, workflow_map_items,
                                            isSQL, isBind, selectsql, current_sql_id, bind_buffer, sql_buffer, previous_sql, table_name, process_definition_name,
                                            MAX_ITEMS_PER_CATEGORY)

            # Final processing with optimized line parsing
            self.progress_label.config(text="Final processing...")
            self.progress_bar['value'] = 95
            self.root.update()

            # Display results in respective tabs
            self.progress_label.config(text="Updating display...")
            
            self.tcs_display_results(exec_sql_items, perf_items, error_items, tbui_items, wf_items, evtcxt_items, business_service_items, workflow_map_items)
            
            # Complete
            self.progress_bar['value'] = 100
            self.progress_label.config(text=f"Analysis complete! Processed {linecnt:,} lines", fg="green")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.progress_label.config(text="Analysis failed!", fg="red")
        finally:
            # Re-enable analyze button
            self.analyze_button.config(state='normal')
    
    def _tcs_safe_add_item(self, items_list, item, max_items, category_name):
        """TCS: Safely add item to list with memory protection"""
        if len(items_list) >= max_items:
            if not hasattr(self, '_memory_warning_shown'):
                messagebox.showwarning("Memory Protection", 
                    f"Maximum number of {category_name} items ({max_items:,}) reached. "
                    f"Further items will be skipped to prevent memory exhaustion.")
                self._memory_warning_shown = True
            return False
        items_list.append(item)
        return True

    def _tcs_process_lines_batch(self, lines_batch, start_line_num, exec_sql_items, perf_items, error_items, 
                           evtcxt_items, tbui_items, wf_items, business_service_items, workflow_map_items, isSQL, isBind, selectsql, current_sql_id, bind_buffer, sql_buffer, previous_sql, table_name, process_definition_name, max_items):
        """Process a batch of lines for better performance"""

        for i, line in enumerate(lines_batch):
            linecnt = start_line_num + i

            # Optimize string operations with early exits
            if not line:  # Skip empty lines
                continue

            # Use more efficient string checking
            if "Bind variable" in line:
                isSQL = False
                isBind = True
                posColon = line.rfind(':')
                bind_value = tcs_safe_substring(line, posColon + 1) if posColon >= 0 else ''
                bind_buffer += bind_value + "\n"

            elif "SQL Statement" in line and isBind:
                # Extract date and execution time from the current line for SQL statements
                date_str = self._extract_date_from_line(line)

                # Extract execution time using regex
                import re
                exec_time = "N/A"
                seconds_match = re.search(r'(.{0,10})seconds', line.lower())
                if seconds_match:
                    timing_text = seconds_match.group(1).strip()
                    # Clean up the timing text to get just the number
                    timing_clean = re.search(r'(\d+\.?\d*)\s*$', timing_text)
                    if timing_clean:
                        exec_time = f"{timing_clean.group(1)} sec"

                self._tcs_safe_add_item(exec_sql_items, {
                    "ID": current_sql_id,
                    "Table": table_name,
                    "SQL": sql_buffer,
                    "Bind": bind_buffer,
                    "Line": linecnt,
                    "Date": date_str,
                    "ExecTime": exec_time
                }, max_items, "SQL execution")
                previous_sql = sql_buffer
                isBind = False
                sql_buffer = bind_buffer = current_sql_id = ""

            elif isSQL:
                sql_buffer += line + "\n"
                if selectsql and "WHERE" in line:
                    posDot = sql_buffer.rfind('.')
                    table_name = tcs_safe_substring(sql_buffer, posDot + 1) if posDot >= 0 else ''
                    posSpace = table_name.find(' ')
                    if posSpace >= 0:
                        table_name = table_name[:posSpace]
                elif not selectsql:
                    if "INSERT INTO SIEBEL." in line:
                        posDot = sql_buffer.rfind('.')
                        table_name = tcs_safe_substring(sql_buffer, posDot + 1) if posDot >= 0 else ''
                        posParen = table_name.find(" (")
                        if posParen >= 0:
                            table_name = table_name[:posParen]
                    elif "UPDATE SIEBEL." in line:
                        posDot = sql_buffer.rfind('.')
                        table_name = tcs_safe_substring(sql_buffer, posDot + 1) if posDot >= 0 else ''
                        posSet = table_name.find("SET")
                        if posSet >= 0:
                            table_name = table_name[:posSet]

            elif "SELECT statement with ID" in line or "INSERT/UPDATE statement with ID" in line:
                isSQL = True
                posColonID = line.rfind(':')
                current_sql_id = tcs_safe_substring(line, posColonID + 1) if posColonID >= 0 else ''
                selectsql = "SELECT statement with ID" in line

            elif "SQL Statement" in line:
                # Extract date and execution time from the current line for performance entries
                date_str = self._extract_date_from_line(line)

                # Extract execution time using regex
                import re
                exec_time = "N/A"
                seconds_match = re.search(r'(.{0,10})seconds', line.lower())
                if seconds_match:
                    timing_text = seconds_match.group(1).strip()
                    # Clean up the timing text to get just the number
                    timing_clean = re.search(r'(\d+\.?\d*)\s*$', timing_text)
                    if timing_clean:
                        exec_time = f"{timing_clean.group(1)} sec"

                num5 = line.rfind(":")
                num3 = line.find("SQL Statement")
                perf_statement_snippet = tcs_safe_substring(line, num3, num5 - num3) if num3 >= 0 and num5 > num3 else ''
                perf_extra_info = ''
                if num5 >= 0:
                    idxDot = line.find('.')
                    if idxDot > num5:
                        len_ = (idxDot + 4) - num5
                        if len_ > 0:
                            perf_extra_info = tcs_safe_substring(line, num5 + 1, len_)
                self._tcs_safe_add_item(perf_items, {
                    "Statement": perf_statement_snippet,
                    "Table": previous_sql,
                    "Extra": perf_extra_info,
                    "Line": linecnt,
                    "Date": date_str,
                    "ExecTime": exec_time
                }, max_items, "performance")

            elif "\tError" in line:
                num4 = line.find("SBL")
                if num4 > 0:
                    code_or_context = tcs_safe_substring(line, num4, 13)
                    description_or_details = tcs_safe_substring(line, num4 + 14)
                    num2 = tcs_find_nth_index(line, '\t', 4) + 1
                    timestamp_str = ''
                    if num2 > 0 and num2 + 19 <= len(line):
                        try:
                            dt = datetime.strptime(tcs_safe_substring(line, num2, 19), "%Y-%m-%d %H:%M:%S")
                            timestamp_str = dt.strftime("%d-%b-%y %H:%M:%S")
                        except:
                            pass
                    error_level = "ERROR" if "\tError" in line else "WARNING"
                    self._tcs_safe_add_item(error_items, {
                        "Date": timestamp_str,
                        "Type": error_level,
                        "Code": code_or_context,
                        "Description": description_or_details,
                        "Line": linecnt
                    }, max_items, "error")

            elif "Task engine requested to navigate to next step:" in line:
                num2 = tcs_find_nth_index(line, '\t', 4) + 1
                timestamp_str = ''
                if num2 > 0 and num2 + 19 <= len(line):
                    try:
                        dt = datetime.strptime(tcs_safe_substring(line, num2, 19), "%Y-%m-%d %H:%M:%S")
                        timestamp_str = dt.strftime("%d-%b-%y %H:%M:%S")
                    except:
                        pass
                num6 = line.find(": '") + 3
                num7 = line.rfind("'")
                task_name = tcs_safe_substring(line, num6, num7 - num6) if num6 >= 0 and num7 > num6 else ''
                self._tcs_safe_add_item(tbui_items, {
                    "Task": task_name,
                    "Date": timestamp_str,
                    "Line": linecnt
                }, max_items, "task-based UI")

            elif "Instantiating process definition" in line:
                num8 = line.find("'") + 1
                num9 = line.rfind("'")
                process_definition_name = tcs_safe_substring(line, num8, num9 - num8) if num8 >= 0 and num9 > num8 else ''

            elif "Instantiating step definition" in line:
                num2 = tcs_find_nth_index(line, '\t', 4) + 1
                timestamp_str = ''
                if num2 > 0 and num2 + 19 <= len(line):
                    try:
                        dt = datetime.strptime(tcs_safe_substring(line, num2, 19), "%Y-%m-%d %H:%M:%S")
                        timestamp_str = dt.strftime("%d-%b-%y %H:%M:%S")
                    except:
                        pass
                num8 = line.find("'") + 1
                num9 = line.rfind("'")
                step_definition_name = tcs_safe_substring(line, num8, num9 - num8) if num8 >= 0 and num9 > num8 else ''
                self._tcs_safe_add_item(wf_items, {
                    "Process": process_definition_name,
                    "Step": step_definition_name,
                    "Date": timestamp_str,
                    "Line": linecnt
                }, max_items, "workflow")

            elif "ObjMgrBusServiceLog" in line and "InvokeMethod" in line:
                # Parse Business Service InvokeMethod entries from ObjMgrBusServiceLog
                # Extract date from the line
                num2 = tcs_find_nth_index(line, '\t', 4) + 1
                timestamp_str = ''
                if num2 > 0 and num2 + 19 <= len(line):
                    try:
                        dt = datetime.strptime(tcs_safe_substring(line, num2, 19), "%Y-%m-%d %H:%M:%S")
                        timestamp_str = dt.strftime("%d-%b-%y %H:%M:%S")
                    except:
                        pass
                
                # Extract Business Service name similar to Event Context pattern
                # Look for "Business Service '" and extract text between quotes
                bs_name = ""
                method_name = ""
                
                # Find "Business Service '" pattern
                bs_idx = line.find("Business Service '")
                if bs_idx >= 0:
                    # Extract text after "Business Service '"
                    start_idx = bs_idx + len("Business Service '")
                    end_idx = line.find("'", start_idx)
                    if end_idx > start_idx:
                        bs_name = line[start_idx:end_idx].strip()
                
                # Extract method name (look for next quote pair after Business Service name)
                if end_idx > 0:
                    # Look for method name in quotes after the Business Service name
                    method_start = line.find("'", end_idx + 1)
                    if method_start >= 0:
                        method_end = line.find("'", method_start + 1)
                        if method_end > method_start:
                            method_name = line[method_start + 1:method_end].strip()
                
                # If Business Service name not found, try alternative pattern
                if not bs_name and "Service" in line:
                    # Try to extract from InvokeMethod context
                    invoke_idx = line.find("InvokeMethod")
                    if invoke_idx >= 0:
                        after_invoke = line[invoke_idx:]
                        if "'" in after_invoke:
                            first_quote = after_invoke.find("'")
                            second_quote = after_invoke.find("'", first_quote + 1)
                            if first_quote >= 0 and second_quote > first_quote:
                                bs_name = after_invoke[first_quote + 1:second_quote].strip()
                
                # Store Business Service entry
                self._tcs_safe_add_item(business_service_items, {
                    "BusinessService": bs_name if bs_name else "Unknown",
                    "Method": method_name if method_name else "InvokeMethod",
                    "Date": timestamp_str,
                    "Line": linecnt,
                    "Description": line  # Store full line for reference
                }, max_items, "Business Service")

            elif "PrcExec" in line and "PropSet" in line:
                # Parse PrcExec PropSet entries for workflow relationships
                # Extract parent and child workflow names
                parent_wf = ""
                child_wf = ""
                
                # Look for PropSet pattern to find child workflow
                if "PropSet" in line:
                    # Extract workflow names from the line
                    # Pattern: PrcExec ... PropSet: ... 
                    propset_idx = line.find("PropSet")
                    if propset_idx >= 0:
                        after_propset = line[propset_idx:]
                        # Look for workflow name in quotes or after specific keywords
                        if "'" in after_propset:
                            first_quote = after_propset.find("'")
                            second_quote = after_propset.find("'", first_quote + 1)
                            if first_quote >= 0 and second_quote > first_quote:
                                child_wf = after_propset[first_quote + 1:second_quote].strip()
                
                # Store the relationship for workflow map
                self._tcs_safe_add_item(workflow_map_items, {
                    "ParentWorkflow": parent_wf if parent_wf else "Unknown",
                    "ChildWorkflow": child_wf if child_wf else "Unknown",
                    "Type": "SubWorkflow",
                    "Line": linecnt,
                    "Description": line
                }, max_items, "Workflow Map")

            elif line.startswith("EventContext"):
                posEvt = line.find("EvtCtx")
                posTab2 = tcs_find_nth_index(line, '\t', 2)
                code_or_context = tcs_safe_substring(line, posEvt + 6, posTab2 - (posEvt + 6)) if posEvt >= 0 and posTab2 > posEvt + 6 else ''
                posLastTab = line.rfind('\t')
                description_or_details = tcs_safe_substring(line, posLastTab + 1) if posLastTab >= 0 else ''
                num2 = tcs_find_nth_index(line, '\t', 4) + 1
                timestamp_str = ''
                if num2 > 0 and num2 + 19 <= len(line):
                    try:
                        dt = datetime.strptime(tcs_safe_substring(line, num2, 19), "%Y-%m-%d %H:%M:%S")
                        timestamp_str = dt.strftime("%d-%b-%y %H:%M:%S")
                    except:
                        pass
                self._tcs_safe_add_item(evtcxt_items, {
                    "Context": code_or_context,
                    "Description": description_or_details,
                    "Date": timestamp_str,
                    "Line": linecnt
                }, max_items, "event context")

    def tcs_extract_date_from_line(self, line):
        """Extract date from log line if available"""
        try:
            # Try to find date pattern in the line
            num2 = tcs_find_nth_index(line, '\t', 4) + 1
            if num2 > 0 and num2 + 19 <= len(line):
                date_str = tcs_safe_substring(line, num2, 19)
                dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%d-%b-%y %H:%M:%S")
        except:
            pass
        return "N/A"

    def tcs_display_results(self, exec_sql_items, perf_items, error_items, tbui_items, wf_items, evtcxt_items, business_service_items, workflow_map_items):
        """TCS: Display analysis results in respective tabs with optimized rendering"""
        try:
            # Clear all tabs
            self.clear_all_tabs()
            
            # Use StringIO for efficient string building
            from io import StringIO
            
            # Display all records (removed the 10000 limit to show all data)
            # Each tab will show all items collected during analysis
            
            # SQL Execution Tab
            self._tcs_populate_tab_optimized(
                self.exec_sql_text,
                exec_sql_items,
                "SQL EXECUTION ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('ExecTime','N/A'))[:12]:>12} | "
                                f"{tcs_clean_single_line(str(item.get('ID','')) + ' - ' + str(item.get('Table','')))[:100]:<100}\n",
                None
            )

            # Performance Tab
            self._tcs_populate_tab_optimized(
                self.perf_text,
                perf_items,
                "PERFORMANCE ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('ExecTime','N/A'))[:12]:>12} | "
                                f"{tcs_clean_single_line(str(item.get('Statement','')) + ' - ' + str(item.get('Table','')))[:100]:<100}\n",
                None
            )

            # Errors Tab
            self._tcs_populate_tab_optimized(
                self.errors_text,
                error_items,
                "ERROR ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('Date','N/A'))[:19]:>19} | "
                                f"{tcs_clean_single_line(str(item.get('Type','')) + ': ' + str(item.get('Code','')) + ' - ' + str(item.get('Description','')))[:100]:<100}\n",
                None
            )

            # Task-Based UI Tab
            self._tcs_populate_tab_optimized(
                self.tbui_text,
                tbui_items,
                "TASK-BASED UI ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('Date','N/A'))[:19]:>19} | "
                                f"{tcs_clean_single_line(str(item.get('Task','')))[:100]:<100}\n",
                None
            )

            # Workflow Tab
            self._tcs_populate_tab_optimized(
                self.workflow_text,
                wf_items,
                "WORKFLOW ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('Date','N/A'))[:19]:>19} | "
                                f"{tcs_clean_single_line(str(item.get('Process','')) + ' -> ' + str(item.get('Step','')))[:100]:<100}\n",
                None
            )

            # Business Service Tab
            self._tcs_populate_tab_optimized(
                self.business_service_text,
                business_service_items,
                "BUSINESS SERVICE ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('Date','N/A'))[:19]:>19} | "
                                f"{tcs_clean_single_line(str(item.get('BusinessService','Unknown')) + ' -> ' + str(item.get('Method','InvokeMethod')))[:100]:<100}\n",
                None
            )
        

            # Event Context Tab
            self._tcs_populate_tab_optimized(
                self.event_text,
                evtcxt_items,
                "EVENT CONTEXT ANALYSIS",
                lambda item, i: f"{str(item.get('Line',''))[:8]:>8} | {str(item.get('Date','N/A'))[:19]:>19} | "
                                f"{tcs_clean_single_line(str(item.get('Context','')) + ': ' + str(item.get('Description','')))[:100]:<100}\n",
                None
            )

            
            # Populate Tree Views and Workflow Map
            self._tcs_populate_sql_tree_view(exec_sql_items)
            self._tcs_populate_workflow_map(workflow_map_items, wf_items, evtcxt_items)
        except Exception as e:
            messagebox.showerror("Display Error", f"Failed updating display:\n{e}")

    def _tcs_populate_tab_optimized(self, text_widget, items, title, format_func, max_items):
        from io import StringIO
        import traceback

        # Optional safety cap (avoid huge inserts causing TclError on some builds)
        HARD_CAP = 250_000  # show at most 250k rows per tab; tune as needed
        if max_items is None:
            display_count = min(len(items), HARD_CAP)
        else:
            display_count = min(len(items), max_items, HARD_CAP)

        content = StringIO()
        content.write(f"{title}\n{'='*80}\n\n")
        content.write(f"Total entries found: {len(items):,}\n")
        if len(items) > display_count:
            content.write(f"Displaying first {display_count:,} entries (file has {len(items):,} total)\n")
        else:
            content.write(f"Displaying all {display_count:,} entries\n")
        content.write("\n")

        content.write(f"{'Line':>8} | {'Date':>19} | {'Description (100 chars fixed width)':<100}\n")
        content.write(f"{'-'*8} | {'-'*19} | {'-'*100}\n")
        content.write("Double-click or Right-click on any line to open in Notepad++ at that line number\n\n")

        batch_size = 100
        try:
            for start_idx in range(0, display_count, batch_size):
                end_idx = min(start_idx + batch_size, display_count)
                for i in range(start_idx, end_idx):
                    try:
                        content.write(format_func(items[i], i + 1))
                    except Exception:
                        # Skip a bad row but keep going
                        continue

                if start_idx % (batch_size * 10) == 0:
                    self.root.update_idletasks()

            # Insert in chunks to avoid Tk large-insert crashes
            text_str = content.getvalue()
            CHUNK = 1_000_000  # 1 MB chunks
            for pos in range(0, len(text_str), CHUNK):
                text_widget.insert(tk.END, text_str[pos:pos+CHUNK])

        except Exception as e:
            # Log and surface a minimal message so the UI survives
            try:
                with open("sla_ui_errors.log", "a", encoding="utf-8") as logf:
                    logf.write("\n---- _tcs_populate_tab_optimized failure ----\n")
                    logf.write(traceback.format_exc())
            except:
                pass
            text_widget.insert(tk.END, f"\n[Render error] {e}\n")
        finally:
            content.close()


    def _populate_sql_tree_view(self, exec_sql_items):
        """Populate the SQL tree view with hierarchical SQL data"""
        
        # Clear existing items
        for item in self.sql_tree.get_children():
            self.sql_tree.delete(item)
        
        if not exec_sql_items:
            return
        
        # Efficiently read log file once and cache lines for timing extraction
        line_cache = {}
        if self.filename and os.path.exists(self.filename):
            try:
                # Collect all line numbers we need to read
                needed_lines = set()
                for item in exec_sql_items:
                    line_num = item.get('Line', '')
                    if str(line_num).isdigit():
                        needed_lines.add(int(line_num))
                
                # Read file once and cache only the lines we need
                if needed_lines:
                    with open(self.filename, 'r', encoding='utf-8', errors='ignore', buffering=8192*4) as f:
                        for current_line_num, line in enumerate(f, 1):
                            if current_line_num in needed_lines:
                                line_cache[current_line_num] = line
                                # Stop reading if we've found all needed lines
                                if len(line_cache) == len(needed_lines):
                                    break
            except Exception:
                line_cache = {}
        
        # Helper function to extract timing from cached line
        def extract_timing_from_cached_line(line_number):
            """Extract timing from cached line data"""
            if line_number not in line_cache:
                return "N/A"
            
            try:
                line = line_cache[line_number]
                # Look for 'seconds' keyword in the line
                import re
                seconds_match = re.search(r'(.{0,10})seconds', line.lower())
                if seconds_match:
                    timing_text = seconds_match.group(1).strip()
                    # Clean up the timing text to get just the number
                    timing_clean = re.search(r'(\d+\.?\d*)\s*$', timing_text)
                    if timing_clean:
                        return f"{timing_clean.group(1)} sec"
                return "N/A"
            except Exception:
                return "N/A"
        
        # Group SQL items by SQL ID
        sql_groups = {}
        for item in exec_sql_items:
            sql_id = item.get('ID', 'Unknown')
            if sql_id not in sql_groups:
                sql_groups[sql_id] = []
            sql_groups[sql_id].append(item)
        
        # Calculate execution times for each group and prepare for sorting
        sql_groups_with_timing = []
        for sql_id, sql_items in sql_groups.items():
            # Calculate total execution time for the group
            total_exec_time = 0
            line_numbers = []
            
            for sql_item in sql_items:
                line_num = sql_item.get('Line', '')
                line_numbers.append(str(line_num))
                
                # Extract timing from the cached log line
                if str(line_num).isdigit():
                    timing_str = extract_timing_from_cached_line(int(line_num))
                    if timing_str != "N/A" and "sec" in timing_str:
                        try:
                            # Extract numeric value from "X.XX sec" format
                            numeric_part = timing_str.replace(" sec", "").strip()
                            total_exec_time += float(numeric_part)
                        except ValueError:
                            pass
            
            # Store group info with timing for sorting
            sql_groups_with_timing.append((sql_id, sql_items, total_exec_time, line_numbers))
        
        # Sort by total execution time (descending - highest first)
        sql_groups_with_timing.sort(key=lambda x: x[2], reverse=True)
        
        # Add grouped items to tree in sorted order
        for sql_id, sql_items, total_exec_time, line_numbers in sql_groups_with_timing:
            # Format timing display for parent
            if total_exec_time > 0:
                exec_display = f"{total_exec_time:.3f} sec"
            else:
                exec_display = "N/A"
            
            # Insert parent node (SQL ID)
            parent_id = self.sql_tree.insert("", "end", 
                                           text=f"{sql_id} ({len(sql_items)} executions)",
                                           values=(exec_display, line_numbers[0] if line_numbers else ""))
            
            # Add child nodes for each execution (sort child nodes by individual timing too)
            child_items_with_timing = []
            for sql_item in sql_items:
                table_name = sql_item.get('Table', 'Unknown')
                line_num = sql_item.get('Line', '')
                date_time = sql_item.get('Date', 'N/A')
                
                # Extract individual timing from cached log line
                if str(line_num).isdigit():
                    individual_timing = extract_timing_from_cached_line(int(line_num))
                    # Extract numeric value for sorting
                    individual_time_value = 0
                    if individual_timing != "N/A" and "sec" in individual_timing:
                        try:
                            individual_time_value = float(individual_timing.replace(" sec", "").strip())
                        except ValueError:
                            pass
                else:
                    individual_timing = "N/A"
                    individual_time_value = 0
                
                child_items_with_timing.append((sql_item, table_name, line_num, date_time, individual_timing, individual_time_value))
            
            # Sort child items by individual timing (descending)
            child_items_with_timing.sort(key=lambda x: x[5], reverse=True)
            
            # Insert child nodes in sorted order
            for sql_item, table_name, line_num, date_time, individual_timing, _ in child_items_with_timing:
                # Create child node text with table and timestamp
                child_text = f"Table: {table_name[:30]} | {date_time[:19]}"
                
                self.sql_tree.insert(parent_id, "end",
                                   text=child_text,
                                   values=(individual_timing, str(line_num)))
            
            # Keep parent nodes collapsed by default for better overview
            # Users can expand individual nodes as needed
            # self.sql_tree.item(parent_id, open=True)

    def _populate_workflow_map(self, workflow_map_items, wf_items, evtcxt_items):
        """Populate the workflow map canvas with detailed graphical flow diagram"""
        
        # Store items for export functionality
        self.workflow_map_items_cache = wf_items
        
        # Clear canvas
        self.workflow_map_canvas.delete("all")
        
        if not wf_items:
            # Show message if no workflow data
            self.workflow_map_canvas.create_text(400, 200, text="No workflow data found in log file", 
                                                 font=("Arial", 14), fill="gray")
            return
        
        # Build detailed workflow hierarchy with line numbers and timestamps
        workflow_calls = []  # List of (parent_workflow, child_workflow, line_num, description)
        workflow_details = {}  # workflow_name -> {steps: [], lines: [], times: []}
        
        # Store for popup access
        self.workflow_map_items_dict = {}  # Will store complete workflow details for popup
        
        # Extract workflow-to-workflow calls from workflow_map_items
        if workflow_map_items:
            for map_item in workflow_map_items:
                parent = map_item.get('ParentWorkflow', 'Unknown')
                child = map_item.get('ChildWorkflow', 'Unknown')
                line_num = map_item.get('Line', '')
                desc = map_item.get('Description', '')
                
                # Only add if both parent and child are valid
                if parent != 'Unknown' and child != 'Unknown':
                    workflow_calls.append((parent, child, line_num, desc))
                    
                    # Ensure both parent and child are in workflow_details
                    # (even if they don't have steps yet)
                    if parent not in workflow_details:
                        workflow_details[parent] = {
                            'steps': [],
                            'lines': [],
                            'times': [],
                            'step_details': []
                        }
                    if child not in workflow_details:
                        workflow_details[child] = {
                            'steps': [],
                            'lines': [],
                            'times': [],
                            'step_details': []
                        }
        
        # Parse workflow items to extract workflow details (processes and steps)
        for idx, wf_item in enumerate(wf_items):
            process = wf_item.get('Process', 'Unknown')
            step = wf_item.get('Step', 'Unknown')
            line_num = wf_item.get('Line', '')
            time = wf_item.get('Time', '')
            
            # Initialize workflow details
            if process not in workflow_details:
                workflow_details[process] = {
                    'steps': [],
                    'lines': [],
                    'times': [],
                    'step_details': []
                }
            
            # Add step details
            step_info = f"{step} (Line {line_num})"
            if step_info not in workflow_details[process]['step_details']:
                workflow_details[process]['step_details'].append(step_info)
                workflow_details[process]['lines'].append(line_num)
                workflow_details[process]['times'].append(time)
        
        # Store workflow details for popup access
        self.workflow_map_items_dict = workflow_details.copy()
        
        # Layout configuration - Tree/Hierarchy style with card-based design
        x_start = 100
        y_start = 100
        card_width = 220  # Width of workflow cards
        card_height = 80  # Height of workflow cards
        x_spacing = 280  # Horizontal spacing between cards
        y_spacing = 120  # Vertical spacing between levels
        
        # Draw title with better styling
        self.workflow_map_canvas.create_text(x_start, 25, text="Siebel Workflow Hierarchy Map", 
                                             font=("Arial", 18, "bold"), anchor="w", fill="#1565C0")
        self.workflow_map_canvas.create_text(x_start, 50, text="Visual hierarchy showing workflow relationships and execution flow", 
                                             font=("Arial", 10), anchor="w", fill="#666")
        
        # Draw legend with card-style indicators
        legend_x = x_start
        legend_y = 70
        
        # Root workflow indicator
        self.workflow_map_canvas.create_rectangle(legend_x, legend_y, legend_x+35, legend_y+15, 
                                                  fill="#E8F5E9", outline="#4CAF50", width=2)
        self.workflow_map_canvas.create_text(legend_x+40, legend_y+7, text="Root Workflow", 
                                            font=("Arial", 9, "bold"), anchor="w", fill="#2E7D32")
        
        # Called workflow indicator
        self.workflow_map_canvas.create_rectangle(legend_x+160, legend_y, legend_x+195, legend_y+15, 
                                                  fill="#E3F2FD", outline="#2196F3", width=2)
        self.workflow_map_canvas.create_text(legend_x+200, legend_y+7, text="Called Workflow", 
                                            font=("Arial", 9, "bold"), anchor="w", fill="#1565C0")
        
        # Connection indicator
        self.workflow_map_canvas.create_line(legend_x+340, legend_y+7, legend_x+380, legend_y+7, 
                                            arrow=tk.LAST, fill="#F57C00", width=2, smooth=True)
        self.workflow_map_canvas.create_text(legend_x+385, legend_y+7, text="Calls", 
                                            font=("Arial", 9), anchor="w", fill="#E65100")
        
        # Add interaction hint
        self.workflow_map_canvas.create_text(legend_x+460, legend_y+7, text="💡 Tip: Double-click any workflow card to view all steps", 
                                            font=("Arial", 9, "italic"), anchor="w", fill="#666")
        
        # Build workflow hierarchy for tree-style layout
        workflow_levels = {}  # level -> [workflow_names]
        workflow_parents = {}  # child -> [parents]
        workflow_children = {}  # parent -> [children]
        
        # Build parent-child relationships
        for parent_wf, child_wf, line_num, desc in workflow_calls:
            if child_wf not in workflow_parents:
                workflow_parents[child_wf] = []
            if parent_wf not in workflow_parents[child_wf]:
                workflow_parents[child_wf].append(parent_wf)
            
            if parent_wf not in workflow_children:
                workflow_children[parent_wf] = []
            if child_wf not in workflow_children[parent_wf]:
                workflow_children[parent_wf].append(child_wf)
        
        # Assign workflows to levels (tree hierarchy)
        all_workflows = set(workflow_details.keys())
        assigned = set()
        current_level = 0
        
        # Level 0: Root workflows (no parents or entry points)
        root_workflows = [wf for wf in all_workflows if wf not in workflow_parents or len(workflow_parents[wf]) == 0]
        if root_workflows:
            workflow_levels[current_level] = root_workflows
            assigned.update(root_workflows)
            current_level += 1
        
        # Assign remaining workflows based on parent levels
        max_iterations = 10
        iteration = 0
        while len(assigned) < len(all_workflows) and iteration < max_iterations:
            level_workflows = []
            for wf in all_workflows:
                if wf not in assigned:
                    # Check if all parents are assigned
                    parents = workflow_parents.get(wf, [])
                    if not parents or all(p in assigned for p in parents):
                        level_workflows.append(wf)
            
            if level_workflows:
                workflow_levels[current_level] = level_workflows
                assigned.update(level_workflows)
                current_level += 1
            iteration += 1
        
        # Add any remaining unassigned workflows to final level
        remaining = all_workflows - assigned
        if remaining:
            workflow_levels[current_level] = list(remaining)
        
        workflow_positions = {}  # Track positions for drawing connections
        
        # Card ID counter for unique tags (avoid issues with special characters in workflow names)
        card_id_counter = 0
        workflow_card_mapping = {}  # Map card_id to workflow_name
        
        # Draw workflows as modern cards in tree hierarchy
        for level, workflows_in_level in sorted(workflow_levels.items()):
            level_y = y_start + (level * y_spacing)
            
            # Calculate horizontal positioning - distribute evenly
            num_workflows = len(workflows_in_level)
            if num_workflows == 1:
                # Single workflow - position based on parent if exists
                workflow_name = workflows_in_level[0]
                if workflow_name in workflow_parents and workflow_parents[workflow_name]:
                    # Center under parent
                    parent = workflow_parents[workflow_name][0]
                    if parent in workflow_positions:
                        wf_x = workflow_positions[parent]['center'][0]
                    else:
                        wf_x = x_start + 300
                else:
                    wf_x = x_start + 300
                workflow_positions_x = [(workflow_name, wf_x)]
            else:
                # Multiple workflows - spread horizontally
                workflow_positions_x = []
                for idx, wf in enumerate(workflows_in_level):
                    wf_x = x_start + (idx * x_spacing) + 150
                    workflow_positions_x.append((wf, wf_x))
            
            for workflow_name, wf_x in workflow_positions_x:
                wf_y = level_y
                details = workflow_details[workflow_name]
                
                # Generate unique card ID
                card_id = f"card_{card_id_counter}"
                workflow_card_mapping[card_id] = workflow_name
                card_id_counter += 1
                
                # Determine card style based on workflow type
                is_root = level == 0
                step_count = len(details['step_details'])
                
                # Calculate dynamic card height
                dynamic_height = card_height if step_count == 0 else min(card_height + (step_count * 4), 140)
                
                if is_root:
                    # Root workflow - green card with shadow effect
                    # Shadow
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2 + 3, wf_y + 3,
                        wf_x + card_width//2 + 3, wf_y + dynamic_height + 3,
                        fill="#BDBDBD", outline="", width=0
                    )
                    # Main card - add tag for clicking
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2, wf_y,
                        wf_x + card_width//2, wf_y + dynamic_height,
                        fill="#E8F5E9", outline="#4CAF50", width=3,
                        tags=card_id
                    )
                    # Header bar
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2, wf_y,
                        wf_x + card_width//2, wf_y + 25,
                        fill="#4CAF50", outline="", width=0,
                        tags=card_id
                    )
                    # Icon
                    self.workflow_map_canvas.create_text(
                        wf_x - card_width//2 + 15, wf_y + 12,
                        text="🟢", font=("Arial", 12), anchor="w",
                        tags=card_id
                    )
                    # Title
                    self.workflow_map_canvas.create_text(
                        wf_x, wf_y + 12,
                        text="ROOT WORKFLOW", 
                        font=("Arial", 8, "bold"), fill="white", anchor="center",
                        tags=card_id
                    )
                else:
                    # Called workflow - blue card with shadow
                    # Shadow
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2 + 3, wf_y + 3,
                        wf_x + card_width//2 + 3, wf_y + dynamic_height + 3,
                        fill="#BDBDBD", outline="", width=0
                    )
                    # Main card - add tag for clicking
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2, wf_y,
                        wf_x + card_width//2, wf_y + dynamic_height,
                        fill="#E3F2FD", outline="#2196F3", width=2,
                        tags=card_id
                    )
                    # Header bar
                    self.workflow_map_canvas.create_rectangle(
                        wf_x - card_width//2, wf_y,
                        wf_x + card_width//2, wf_y + 22,
                        fill="#2196F3", outline="", width=0,
                        tags=card_id
                    )
                    # Icon
                    self.workflow_map_canvas.create_text(
                        wf_x - card_width//2 + 12, wf_y + 11,
                        text="📋", font=("Arial", 10), anchor="w",
                        tags=card_id
                    )
                    # Level indicator
                    self.workflow_map_canvas.create_text(
                        wf_x + card_width//2 - 10, wf_y + 11,
                        text=f"L{level}", 
                        font=("Arial", 7, "bold"), fill="white", anchor="e",
                        tags=card_id
                    )
                
                # Workflow name (main content) - make it clickable
                workflow_text_id = self.workflow_map_canvas.create_text(
                    wf_x, wf_y + 40,
                    text=workflow_name[:28], 
                    font=("Arial", 10, "bold"), fill="#212121", width=card_width-20,
                    tags=card_id
                )
                
                # Create a closure to properly capture workflow_name
                def make_click_handler(wf_name):
                    return lambda event: self.show_workflow_steps_popup(wf_name)
                
                def make_enter_handler():
                    return lambda event: self.workflow_map_canvas.config(cursor="hand2")
                
                def make_leave_handler():
                    return lambda event: self.workflow_map_canvas.config(cursor="")
                
                # Bind double-click event to the card tag
                self.workflow_map_canvas.tag_bind(card_id, "<Double-Button-1>", 
                                                  make_click_handler(workflow_name))
                
                # Change cursor to hand when hovering over workflow card
                self.workflow_map_canvas.tag_bind(card_id, "<Enter>", 
                                                  make_enter_handler())
                self.workflow_map_canvas.tag_bind(card_id, "<Leave>", 
                                                  make_leave_handler())
                
                # Step count and details - also make them clickable
                if step_count > 0:
                    step_text_id = self.workflow_map_canvas.create_text(
                        wf_x, wf_y + 60,
                        text=f"📊 {step_count} step{'s' if step_count != 1 else ''}", 
                        font=("Arial", 9), fill="#555",
                        tags=card_id
                    )
                    # Line range
                    if details['lines']:
                        line_range = f"Lines {details['lines'][0]}-{details['lines'][-1]}" if len(details['lines']) > 1 else f"Line {details['lines'][0]}"
                        line_range_id = self.workflow_map_canvas.create_text(
                            wf_x, wf_y + 75,
                            text=line_range, 
                            font=("Arial", 8), fill="#777",
                            tags=card_id
                        )
                else:
                    ref_text_id = self.workflow_map_canvas.create_text(
                        wf_x, wf_y + 55,
                        text="(Referenced only)", 
                        font=("Arial", 9, "italic"), fill="#999",
                        tags=card_id
                    )
                
                # Store position for connections
                workflow_positions[workflow_name] = {
                    'center': (wf_x, wf_y + dynamic_height // 2),
                    'bottom': (wf_x, wf_y + dynamic_height),
                    'top': (wf_x, wf_y),
                    'left': (wf_x - card_width//2, wf_y + dynamic_height // 2),
                    'right': (wf_x + card_width//2, wf_y + dynamic_height // 2)
                }
        
        # Draw connection arrows with better styling
        for parent_wf, child_wf, line_num, desc in workflow_calls:
            if parent_wf in workflow_positions and child_wf in workflow_positions:
                parent_pos = workflow_positions[parent_wf]
                child_pos = workflow_positions[child_wf]
                
                # Get connection points (parent bottom to child top)
                x1, y1 = parent_pos['bottom']
                x2, y2 = child_pos['top']
                
                # Draw curved connecting line with gradient effect
                if abs(x1 - x2) < 30:  # Straight vertical line
                    # Draw main arrow
                    self.workflow_map_canvas.create_line(
                        x1, y1, x2, y2,
                        arrow=tk.LAST, fill="#F57C00", width=2, 
                        arrowshape=(10, 12, 4), smooth=True
                    )
                    
                    # Label position (offset to side)
                    label_x = x1 + 25
                    label_y = (y1 + y2) / 2
                else:
                    # Curved line for diverging workflows
                    mid_y = (y1 + y2) / 2
                    
                    # Draw smooth curved arrow
                    self.workflow_map_canvas.create_line(
                        x1, y1,
                        x1, mid_y,
                        x2, mid_y,
                        x2, y2,
                        arrow=tk.LAST, fill="#F57C00", width=2, 
                        smooth=True, arrowshape=(10, 12, 4)
                    )
                    
                    # Label position (on horizontal segment)
                    label_x = (x1 + x2) / 2
                    label_y = mid_y - 15
                
                # Add line number badge
                badge_text = f"Line {line_num}"
                
                # Badge background (rounded)
                self.workflow_map_canvas.create_oval(
                    label_x - 28, label_y - 10,
                    label_x - 18, label_y + 10,
                    fill="#FFF3E0", outline="#F57C00", width=1
                )
                self.workflow_map_canvas.create_rectangle(
                    label_x - 23, label_y - 10,
                    label_x + 23, label_y + 10,
                    fill="#FFF3E0", outline="", width=0
                )
                self.workflow_map_canvas.create_oval(
                    label_x + 18, label_y - 10,
                    label_x + 28, label_y + 10,
                    fill="#FFF3E0", outline="#F57C00", width=1
                )
                # Top and bottom edges
                self.workflow_map_canvas.create_line(
                    label_x - 23, label_y - 10,
                    label_x + 23, label_y - 10,
                    fill="#F57C00", width=1
                )
                self.workflow_map_canvas.create_line(
                    label_x - 23, label_y + 10,
                    label_x + 23, label_y + 10,
                    fill="#F57C00", width=1
                )
                
                # Badge text
                self.workflow_map_canvas.create_text(
                    label_x, label_y,
                    text=badge_text, 
                    font=("Arial", 7, "bold"), fill="#E65100"
                )
        
        # Update canvas scroll region to fit all content
        bbox = self.workflow_map_canvas.bbox("all")
        if bbox:
            # Add padding
            self.workflow_map_canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def show_workflow_steps_popup(self, workflow_name):
        """Show all steps for a workflow in a popup window"""
        # Find workflow details
        workflow_details = None
        for wf_name, details in self.workflow_map_items_dict.items():
            if wf_name == workflow_name:
                workflow_details = details
                break
        
        if not workflow_details:
            messagebox.showinfo("No Steps", f"No steps found for workflow: {workflow_name}")
            return
        
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"Workflow Steps - {workflow_name}")
        popup.geometry("900x600")
        
        # Header
        header_frame = ttk.Frame(popup)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(header_frame, text=f"🔍 Workflow: {workflow_name}", 
                 font=("Arial", 14, "bold")).pack(anchor="w")
        
        step_count = len(workflow_details.get('step_details', []))
        ttk.Label(header_frame, text=f"Total Steps: {step_count}", 
                 font=("Arial", 10)).pack(anchor="w")
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(popup)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set,
                             font=("Consolas", 9), bg="#F5F5F5")
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_widget.yview)
        
        # Configure tags for styling
        text_widget.tag_config("step_header", foreground="#1976D2", font=("Arial", 10, "bold"))
        text_widget.tag_config("line_num", foreground="#F57C00", font=("Consolas", 9, "bold"), underline=True)
        text_widget.tag_config("step_name", foreground="#2E7D32", font=("Consolas", 9))
        text_widget.tag_config("no_steps", foreground="#999", font=("Arial", 10, "italic"))
        text_widget.tag_config("clickable_step", foreground="#1565C0", font=("Arial", 10, "bold"), underline=True)
        
        # Configure cursor for clickable elements
        text_widget.tag_config("line_num_link", foreground="#F57C00", font=("Consolas", 9, "bold"), underline=True)
        
        # Display steps with clickable line numbers
        if step_count > 0:
            for idx, step_detail in enumerate(workflow_details['step_details'], 1):
                # Parse step detail
                if ' (Line ' in step_detail:
                    step_name = step_detail.split(' (Line')[0]
                    line_num = workflow_details['lines'][idx-1] if idx-1 < len(workflow_details['lines']) else 'N/A'
                else:
                    step_name = step_detail
                    line_num = workflow_details['lines'][idx-1] if idx-1 < len(workflow_details['lines']) else 'N/A'
                
                # Insert step header - make it clickable
                step_start = text_widget.index(tk.END)
                text_widget.insert(tk.END, f"Step {idx}:", "clickable_step")
                step_end = text_widget.index(tk.END)
                
                # Create tag for this specific step
                step_tag = f"step_{idx}_tag"
                text_widget.tag_add(step_tag, step_start, step_end)
                text_widget.tag_bind(step_tag, "<Button-1>", 
                                   lambda e, ln=line_num, p=popup: self.jump_to_line_in_workflow_tab(ln, p))
                text_widget.tag_bind(step_tag, "<Enter>", 
                                   lambda e: text_widget.config(cursor="hand2"))
                text_widget.tag_bind(step_tag, "<Leave>", 
                                   lambda e: text_widget.config(cursor=""))
                
                text_widget.insert(tk.END, "\n")
                text_widget.insert(tk.END, f"  Line: ", "")
                
                # Make line number clickable
                line_start = text_widget.index(tk.END)
                text_widget.insert(tk.END, f"{line_num}", "line_num_link")
                line_end = text_widget.index(tk.END)
                
                # Create tag for line number click
                line_tag = f"line_{idx}_tag"
                text_widget.tag_add(line_tag, line_start, line_end)
                text_widget.tag_bind(line_tag, "<Button-1>", 
                                   lambda e, ln=line_num, p=popup: self.jump_to_line_in_workflow_tab(ln, p))
                text_widget.tag_bind(line_tag, "<Enter>", 
                                   lambda e: text_widget.config(cursor="hand2"))
                text_widget.tag_bind(line_tag, "<Leave>", 
                                   lambda e: text_widget.config(cursor=""))
                
                text_widget.insert(tk.END, "\n")
                text_widget.insert(tk.END, f"  Name: ", "")
                text_widget.insert(tk.END, f"{step_name}\n", "step_name")
                text_widget.insert(tk.END, "\n")
        else:
            text_widget.insert(tk.END, "No steps found for this workflow.\n", "no_steps")
            text_widget.insert(tk.END, "This workflow may be referenced but not executed in the current log.", "no_steps")
        
        # Keep text widget editable so tag bindings work, but make it read-only via key bindings
        # Don't use text_widget.config(state=tk.DISABLED) as it prevents tag bindings
        def make_readonly(event):
            # Allow selection and copying, but prevent editing
            if event.keysym in ('c', 'C') and (event.state & 0x4):  # Ctrl+C
                return
            if event.keysym in ('a', 'A') and (event.state & 0x4):  # Ctrl+A
                return
            return "break"
        
        text_widget.bind("<Key>", make_readonly)
        
        # Button frame
        button_frame = ttk.Frame(popup)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="📋 Copy to Clipboard", 
                  command=lambda: self.copy_workflow_steps_to_clipboard(workflow_name, workflow_details)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="✖ Close", 
                  command=popup.destroy).pack(side=tk.RIGHT, padx=5)
    
    def copy_workflow_steps_to_clipboard(self, workflow_name, workflow_details):
        """Copy workflow steps to clipboard"""
        step_count = len(workflow_details.get('step_details', []))
        clipboard_text = f"Workflow: {workflow_name}\n"
        clipboard_text += f"Total Steps: {step_count}\n"
        clipboard_text += "="*60 + "\n\n"
        
        if step_count > 0:
            for idx, step_detail in enumerate(workflow_details['step_details'], 1):
                if ' (Line ' in step_detail:
                    step_name = step_detail.split(' (Line')[0]
                    line_num = workflow_details['lines'][idx-1] if idx-1 < len(workflow_details['lines']) else 'N/A'
                else:
                    step_name = step_detail
                    line_num = workflow_details['lines'][idx-1] if idx-1 < len(workflow_details['lines']) else 'N/A'
                
                clipboard_text += f"Step {idx}:\n"
                clipboard_text += f"  Line: {line_num}\n"
                clipboard_text += f"  Name: {step_name}\n\n"
        else:
            clipboard_text += "No steps found for this workflow.\n"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(clipboard_text)
        messagebox.showinfo("Copied", "Workflow steps copied to clipboard!")
    
    def jump_to_line_in_workflow_tab(self, line_num, popup_window):
        """Jump to a specific line number in the Workflow tab and close popup"""
        popup_window.destroy()
        
        # Switch to Workflow tab (index 1: 0=Event Context, 1=Workflow, 2=Business Service...)
        self.notebook.select(1)
        
        # Force focus to the workflow text widget
        self.workflow_text.focus_set()
        
        # Clear previous selection and highlights
        self.workflow_text.tag_remove("sel", "1.0", tk.END)
        self.workflow_text.tag_remove("highlight", "1.0", tk.END)
        
        # Configure highlight tag with bright yellow background
        self.workflow_text.tag_config("highlight", background="#FFFF00", foreground="#000000", font=("Consolas", 9, "bold"))
        
        # Search for the line number in the workflow text
        # The format in Workflow tab is: "6563846  | 2024-10-27 10:30:45 | Process -> Step"
        # Line number appears at the start of the line
        line_str = str(line_num).strip()
        start_pos = "1.0"
        found = False
        
        # Search for line number that appears at the beginning of a content line
        while True:
            start_pos = self.workflow_text.search(line_str, start_pos, tk.END, nocase=False)
            if not start_pos:
                break
            
            # Get the entire line content
            line_start = self.workflow_text.index(f"{start_pos} linestart")
            line_end = self.workflow_text.index(f"{start_pos} lineend")
            line_content = self.workflow_text.get(line_start, line_end).strip()
            
            # Check if this line starts with the line number followed by pipe separator
            # This ensures we're finding the actual data line, not header or other text
            if line_content.startswith(line_str) and ' | ' in line_content:
                # Found the correct line!
                
                # Highlight the entire line
                self.workflow_text.tag_add("highlight", line_start, line_end)
                self.workflow_text.tag_add("sel", line_start, line_end)
                
                # Calculate position to show context (5 lines above)
                try:
                    current_line_num = int(line_start.split('.')[0])
                    context_line = max(1, current_line_num - 5)
                    context_start = f"{context_line}.0"
                    self.workflow_text.see(context_start)
                except:
                    pass
                
                # Scroll to the highlighted line
                self.workflow_text.see(line_start)
                
                # Set cursor at the beginning of the line
                self.workflow_text.mark_set("insert", line_start)
                
                found = True
                break
            
            # Move to next occurrence
            start_pos = f"{start_pos}+1c"
        
        if not found:
            # Fallback: search more broadly for the line number
            start_pos = "1.0"
            start_pos = self.workflow_text.search(line_str, start_pos, tk.END)
            if start_pos:
                line_start = self.workflow_text.index(f"{start_pos} linestart")
                line_end = self.workflow_text.index(f"{start_pos} lineend")
                self.workflow_text.tag_add("highlight", line_start, line_end)
                self.workflow_text.tag_add("sel", line_start, line_end)
                
                # Show context
                try:
                    current_line_num = int(line_start.split('.')[0])
                    context_line = max(1, current_line_num - 5)
                    context_start = f"{context_line}.0"
                    self.workflow_text.see(context_start)
                except:
                    pass
                
                self.workflow_text.see(line_start)
                self.workflow_text.mark_set("insert", line_start)
                found = True
        
        if not found:
            messagebox.showwarning("Line Not Found", 
                                  f"Line number {line_num} could not be found in the Workflow tab.\n\n"
                                  f"Possible reasons:\n"
                                  f"- The workflow data may not be loaded yet\n"
                                  f"- The line might be in a different tab (Process/Business Service)\n"
                                  f"- Try searching manually using Ctrl+F")
    
    def zoom_in_workflow_map(self):
        """Zoom in the workflow map"""
        self.workflow_map_zoom *= 1.2
        self.workflow_map_canvas.scale("all", 0, 0, 1.2, 1.2)
        bbox = self.workflow_map_canvas.bbox("all")
        if bbox:
            self.workflow_map_canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def zoom_out_workflow_map(self):
        """Zoom out the workflow map"""
        self.workflow_map_zoom *= 0.8
        self.workflow_map_canvas.scale("all", 0, 0, 0.8, 0.8)
        bbox = self.workflow_map_canvas.bbox("all")
        if bbox:
            self.workflow_map_canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def reset_workflow_map_zoom(self):
        """Reset zoom to default"""
        if self.workflow_map_zoom != 1.0:
            scale_factor = 1.0 / self.workflow_map_zoom
            self.workflow_map_canvas.scale("all", 0, 0, scale_factor, scale_factor)
            self.workflow_map_zoom = 1.0
            bbox = self.workflow_map_canvas.bbox("all")
            if bbox:
                self.workflow_map_canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def popout_workflow_map(self):
        """Open workflow map in a separate pop-out window"""
        
        # Check if window already exists
        if self.workflow_map_popout_window and self.workflow_map_popout_window.winfo_exists():
            # Bring existing window to front
            self.workflow_map_popout_window.lift()
            self.workflow_map_popout_window.focus_force()
            return
        
        # Create new top-level window
        self.workflow_map_popout_window = tk.Toplevel(self.root)
        self.workflow_map_popout_window.title("Workflow Map - Siebel Log Analyzer")
        self.workflow_map_popout_window.geometry("1200x800")
        
        # Set window icon (same as main window if available)
        try:
            self.workflow_map_popout_window.iconbitmap(self.root.iconbitmap())
        except:
            pass
        
        # Create toolbar in pop-out window
        popout_toolbar = ttk.Frame(self.workflow_map_popout_window)
        popout_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(popout_toolbar, text="🔍 Zoom In", 
                  command=lambda: self.zoom_canvas(popout_canvas, popout_zoom_var, 1.2)).pack(side=tk.LEFT, padx=2)
        ttk.Button(popout_toolbar, text="🔍 Zoom Out", 
                  command=lambda: self.zoom_canvas(popout_canvas, popout_zoom_var, 0.8)).pack(side=tk.LEFT, padx=2)
        ttk.Button(popout_toolbar, text="🔄 Reset View", 
                  command=lambda: self.reset_canvas_zoom(popout_canvas, popout_zoom_var)).pack(side=tk.LEFT, padx=2)
        ttk.Button(popout_toolbar, text="💾 Export as PNG", 
                  command=lambda: self.export_canvas_as_png(popout_canvas)).pack(side=tk.LEFT, padx=2)
        ttk.Button(popout_toolbar, text="🎨 Open in Paint", 
                  command=lambda: self.open_canvas_in_paint(popout_canvas)).pack(side=tk.LEFT, padx=2)
        ttk.Button(popout_toolbar, text="🔄 Refresh", 
                  command=lambda: self.refresh_popout_canvas(popout_canvas)).pack(side=tk.LEFT, padx=2)
        
        # Create canvas container with scrollbars
        canvas_container = ttk.Frame(self.workflow_map_popout_window)
        canvas_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create canvas
        popout_canvas = tk.Canvas(canvas_container, bg="white", highlightthickness=1, highlightbackground="gray")
        popout_zoom_var = tk.DoubleVar(value=1.0)
        
        # Add scrollbars
        v_scroll = ttk.Scrollbar(canvas_container, orient="vertical", command=popout_canvas.yview)
        h_scroll = ttk.Scrollbar(canvas_container, orient="horizontal", command=popout_canvas.xview)
        popout_canvas.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Pack canvas and scrollbars
        popout_canvas.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        canvas_container.grid_rowconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(0, weight=1)
        
        # Copy workflow map content to pop-out canvas
        self.copy_canvas_content(self.workflow_map_canvas, popout_canvas)
        
        # Update scroll region
        bbox = popout_canvas.bbox("all")
        if bbox:
            popout_canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
        
        # Handle window close
        def on_close():
            self.workflow_map_popout_window.destroy()
            self.workflow_map_popout_window = None
        
        self.workflow_map_popout_window.protocol("WM_DELETE_WINDOW", on_close)
    
    def copy_canvas_content(self, source_canvas, target_canvas):
        """Copy all items from source canvas to target canvas"""
        # Get all items from source canvas
        items = source_canvas.find_all()
        
        for item in items:
            item_type = source_canvas.type(item)
            coords = source_canvas.coords(item)
            
            if item_type == "rectangle":
                options = {
                    'fill': source_canvas.itemcget(item, 'fill'),
                    'outline': source_canvas.itemcget(item, 'outline'),
                    'width': source_canvas.itemcget(item, 'width')
                }
                target_canvas.create_rectangle(*coords, **options)
                
            elif item_type == "text":
                options = {
                    'text': source_canvas.itemcget(item, 'text'),
                    'font': source_canvas.itemcget(item, 'font'),
                    'fill': source_canvas.itemcget(item, 'fill'),
                    'anchor': source_canvas.itemcget(item, 'anchor')
                }
                # Handle width if present
                try:
                    width = source_canvas.itemcget(item, 'width')
                    if width:
                        options['width'] = width
                except:
                    pass
                target_canvas.create_text(*coords, **options)
                
            elif item_type == "line":
                options = {
                    'fill': source_canvas.itemcget(item, 'fill'),
                    'width': source_canvas.itemcget(item, 'width')
                }
                # Handle arrow if present
                try:
                    arrow = source_canvas.itemcget(item, 'arrow')
                    if arrow:
                        options['arrow'] = arrow
                    arrowshape = source_canvas.itemcget(item, 'arrowshape')
                    if arrowshape:
                        options['arrowshape'] = arrowshape
                    smooth = source_canvas.itemcget(item, 'smooth')
                    if smooth:
                        options['smooth'] = smooth
                except:
                    pass
                target_canvas.create_line(*coords, **options)
                
            elif item_type == "oval":
                options = {
                    'fill': source_canvas.itemcget(item, 'fill'),
                    'outline': source_canvas.itemcget(item, 'outline'),
                    'width': source_canvas.itemcget(item, 'width')
                }
                target_canvas.create_oval(*coords, **options)
    
    def zoom_canvas(self, canvas, zoom_var, factor):
        """Zoom a canvas by a factor"""
        canvas.scale("all", 0, 0, factor, factor)
        zoom_var.set(zoom_var.get() * factor)
        bbox = canvas.bbox("all")
        if bbox:
            canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def reset_canvas_zoom(self, canvas, zoom_var):
        """Reset canvas zoom to 1.0"""
        current_zoom = zoom_var.get()
        if current_zoom != 1.0:
            scale_factor = 1.0 / current_zoom
            canvas.scale("all", 0, 0, scale_factor, scale_factor)
            zoom_var.set(1.0)
            bbox = canvas.bbox("all")
            if bbox:
                canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def refresh_popout_canvas(self, canvas):
        """Refresh the pop-out canvas with current workflow map data"""
        canvas.delete("all")
        self.copy_canvas_content(self.workflow_map_canvas, canvas)
        bbox = canvas.bbox("all")
        if bbox:
            canvas.configure(scrollregion=(bbox[0]-20, bbox[1]-20, bbox[2]+20, bbox[3]+20))
    
    def export_canvas_as_png(self, canvas):
        """Export a specific canvas as PNG"""
        if not PIL_AVAILABLE:
            messagebox.showwarning("Feature Unavailable", 
                                 "PNG export requires the Pillow library.\n\n"
                                 "Please install it using:\n"
                                 "pip install Pillow\n\n"
                                 "Using PostScript export as alternative...")
            self.export_canvas_as_ps(canvas)
            return
        
        try:
            # Ask user for save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
                initialfile=f"workflow_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            )
            
            if not file_path:
                return
            
            # Get canvas bounding box
            bbox = canvas.bbox("all")
            if not bbox:
                messagebox.showwarning("Export Error", "No content to export")
                return
            
            # Export using PostScript then convert (simplified approach)
            canvas.postscript(file=file_path.replace('.png', '.ps'), colormode='color',
                            x=bbox[0], y=bbox[1], width=bbox[2]-bbox[0], height=bbox[3]-bbox[1])
            
            messagebox.showinfo("Export", "Canvas exported as PostScript.\nPillow conversion not available.")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def export_canvas_as_ps(self, canvas):
        """Export a canvas as PostScript"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".ps",
                filetypes=[("PostScript", "*.ps"), ("EPS", "*.eps"), ("All Files", "*.*")],
                initialfile=f"workflow_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps"
            )
            
            if not file_path:
                return
            
            bbox = canvas.bbox("all")
            if not bbox:
                messagebox.showwarning("Export Error", "No content to export")
                return
            
            canvas.postscript(file=file_path, colormode='color',
                            x=bbox[0], y=bbox[1], width=bbox[2]-bbox[0], height=bbox[3]-bbox[1])
            
            messagebox.showinfo("Export Successful", f"Workflow map exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
    
    def open_canvas_in_paint(self, canvas):
        """Export canvas and open in MS Paint"""
        if not PIL_AVAILABLE:
            messagebox.showwarning("Feature Unavailable", 
                                 "Opening in Paint requires the Pillow library.\n\n"
                                 "Please install it using:\n"
                                 "pip install Pillow")
            return
        
        # Use the existing export functionality
        temp_path = os.path.join(os.path.expanduser("~"), "workflow_map_temp.ps")
        bbox = canvas.bbox("all")
        if bbox:
            canvas.postscript(file=temp_path, colormode='color',
                            x=bbox[0], y=bbox[1], width=bbox[2]-bbox[0], height=bbox[3]-bbox[1])
            messagebox.showinfo("Info", "PostScript file created. Pillow required for Paint integration.")
    
    def export_workflow_map_png(self):
        """Export workflow map as PNG image"""
        if not PIL_AVAILABLE:
            messagebox.showwarning("Feature Unavailable", 
                                 "PNG export requires the Pillow library.\n\n"
                                 "Please install it using:\n"
                                 "pip install Pillow\n\n"
                                 "Using PostScript export as alternative...")
            self.export_workflow_map_ps()
            return
        
        try:
            # Ask user for save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
                initialfile=f"workflow_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            )
            
            if not file_path:
                return
            
            # Get canvas bounding box
            bbox = self.workflow_map_canvas.bbox("all")
            if not bbox:
                messagebox.showwarning("Export Error", "No workflow map to export")
                return
            
            # Calculate image size
            width = int(bbox[2] - bbox[0] + 40)
            height = int(bbox[3] - bbox[1] + 40)
            
            # Create PIL image
            image = Image.new("RGB", (width, height), "white")
            draw = ImageDraw.Draw(image)
            
            # Try to use a nice font
            try:
                title_font = ImageFont.truetype("arial.ttf", 18)
                header_font = ImageFont.truetype("arial.ttf", 11)
                normal_font = ImageFont.truetype("arial.ttf", 8)
                small_font = ImageFont.truetype("arial.ttf", 7)
            except:
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
                small_font = ImageFont.load_default()
            
            # Draw workflow details
            offset_x = 20
            offset_y = 20
            
            # Title
            draw.text((offset_x, offset_y), "Siebel Workflow Call Hierarchy Map", 
                     fill="#1565C0", font=title_font)
            draw.text((offset_x, offset_y + 30), 
                     "Showing workflow processes, steps, and workflow-to-workflow call relationships",
                     fill="#555", font=small_font)
            
            # Draw legend
            legend_y = offset_y + 60
            
            draw.rectangle([offset_x, legend_y, offset_x+20, legend_y+15], fill="#FFF9C4", outline="#F57C00", width=2)
            draw.text((offset_x+25, legend_y+2), "Parent Workflow", fill="black", font=small_font)
            
            draw.rectangle([offset_x+160, legend_y, offset_x+180, legend_y+15], fill="#E8F5E9", outline="#388E3C", width=2)
            draw.text((offset_x+185, legend_y+2), "Called Workflow/Step", fill="black", font=small_font)
            
            # Render each canvas item
            current_y_pos = offset_y + 100
            
            # Get all workflow items from cache
            if hasattr(self, 'workflow_map_items_cache') and self.workflow_map_items_cache:
                workflow_details = {}
                for wf_item in self.workflow_map_items_cache:
                    process = wf_item.get('Process', 'Unknown')
                    step = wf_item.get('Step', 'Unknown')
                    line_num = wf_item.get('Line', '')
                    
                    if process not in workflow_details:
                        workflow_details[process] = []
                    
                    step_info = f"{step} (Line {line_num})"
                    if step_info not in workflow_details[process]:
                        workflow_details[process].append(step_info)
                
                # Draw each workflow
                box_width = 280
                box_height = 80
                step_height = 35
                
                for wf_name, steps in workflow_details.items():
                    wf_box_height = box_height + len(steps) * step_height
                    
                    # Draw workflow box
                    draw.rectangle(
                        [offset_x, current_y_pos, offset_x + box_width, current_y_pos + wf_box_height],
                        fill="#FFF9C4", outline="#F57C00", width=3
                    )
                    
                    # Workflow name
                    draw.text((offset_x + 10, current_y_pos + 10), 
                             f"Workflow: {wf_name[:35]}", fill="#E65100", font=header_font)
                    
                    # Draw separator
                    draw.line([offset_x + 5, current_y_pos + 35, offset_x + box_width - 5, current_y_pos + 35],
                             fill="#F57C00", width=1)
                    
                    # Draw steps
                    step_start_y = current_y_pos + 45
                    for idx, step_detail in enumerate(steps):
                        step_y = step_start_y + (idx * step_height)
                        
                        # Step number
                        draw.ellipse([offset_x + 10, step_y, offset_x + 22, step_y + 12],
                                    fill="#FF9800", outline="#E65100")
                        draw.text((offset_x + 13, step_y + 2), str(idx + 1), fill="white", font=small_font)
                        
                        # Step name
                        step_name = step_detail.split(' (Line')[0]
                        draw.text((offset_x + 28, step_y + 2), f"{step_name[:40]}", fill="#333", font=normal_font)
                        
                        # Line number
                        line_num = step_detail.split('Line ')[-1].rstrip(')')
                        draw.text((offset_x + box_width - 50, step_y + 2), f"L:{line_num}", fill="#666", font=small_font)
                    
                    current_y_pos += wf_box_height + 50
            
            # Save the image
            image.save(file_path, "PNG")
            messagebox.showinfo("Export Successful", f"Workflow map exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export workflow map:\n{str(e)}")
    
    def open_workflow_map_in_paint(self):
        """Export workflow map and open it in MS Paint"""
        if not PIL_AVAILABLE:
            messagebox.showwarning("Feature Unavailable", 
                                 "Opening in Paint requires the Pillow library.\n\n"
                                 "Please install it using:\n"
                                 "pip install Pillow\n\n"
                                 "You can use 'Export as PNG' after installation.")
            return
        
        try:
            # Create temporary file
            temp_path = os.path.join(os.path.expanduser("~"), "workflow_map_temp.png")
            
            # Get canvas bounding box
            bbox = self.workflow_map_canvas.bbox("all")
            if not bbox:
                messagebox.showwarning("Export Error", "No workflow map to export")
                return
            
            # Calculate image size
            width = int(bbox[2] - bbox[0] + 40)
            height = int(bbox[3] - bbox[1] + 40)
            
            # Create PIL image
            image = Image.new("RGB", (width, height), "white")
            draw = ImageDraw.Draw(image)
            
            # Try to use a nice font
            try:
                title_font = ImageFont.truetype("arial.ttf", 18)
                header_font = ImageFont.truetype("arial.ttf", 11)
                normal_font = ImageFont.truetype("arial.ttf", 8)
                small_font = ImageFont.truetype("arial.ttf", 7)
            except:
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
                small_font = ImageFont.load_default()
            
            # Draw workflow details (same as export)
            offset_x = 20
            offset_y = 20
            
            # Title
            draw.text((offset_x, offset_y), "Siebel Workflow Call Hierarchy Map", 
                     fill="#1565C0", font=title_font)
            draw.text((offset_x, offset_y + 30), 
                     "Showing workflow processes, steps, and workflow-to-workflow call relationships",
                     fill="#555", font=small_font)
            
            # Draw legend
            legend_y = offset_y + 60
            
            draw.rectangle([offset_x, legend_y, offset_x+20, legend_y+15], fill="#FFF9C4", outline="#F57C00", width=2)
            draw.text((offset_x+25, legend_y+2), "Parent Workflow", fill="black", font=small_font)
            
            draw.rectangle([offset_x+160, legend_y, offset_x+180, legend_y+15], fill="#E8F5E9", outline="#388E3C", width=2)
            draw.text((offset_x+185, legend_y+2), "Called Workflow/Step", fill="black", font=small_font)
            
            # Render workflow items
            current_y_pos = offset_y + 100
            
            if hasattr(self, 'workflow_map_items_cache') and self.workflow_map_items_cache:
                workflow_details = {}
                for wf_item in self.workflow_map_items_cache:
                    process = wf_item.get('Process', 'Unknown')
                    step = wf_item.get('Step', 'Unknown')
                    line_num = wf_item.get('Line', '')
                    
                    if process not in workflow_details:
                        workflow_details[process] = []
                    
                    step_info = f"{step} (Line {line_num})"
                    if step_info not in workflow_details[process]:
                        workflow_details[process].append(step_info)
                
                box_width = 280
                box_height = 80
                step_height = 35
                
                for wf_name, steps in workflow_details.items():
                    wf_box_height = box_height + len(steps) * step_height
                    
                    draw.rectangle(
                        [offset_x, current_y_pos, offset_x + box_width, current_y_pos + wf_box_height],
                        fill="#FFF9C4", outline="#F57C00", width=3
                    )
                    
                    draw.text((offset_x + 10, current_y_pos + 10), 
                             f"Workflow: {wf_name[:35]}", fill="#E65100", font=header_font)
                    
                    draw.line([offset_x + 5, current_y_pos + 35, offset_x + box_width - 5, current_y_pos + 35],
                             fill="#F57C00", width=1)
                    
                    step_start_y = current_y_pos + 45
                    for idx, step_detail in enumerate(steps):
                        step_y = step_start_y + (idx * step_height)
                        
                        draw.ellipse([offset_x + 10, step_y, offset_x + 22, step_y + 12],
                                    fill="#FF9800", outline="#E65100")
                        draw.text((offset_x + 13, step_y + 2), str(idx + 1), fill="white", font=small_font)
                        
                        step_name = step_detail.split(' (Line')[0]
                        draw.text((offset_x + 28, step_y + 2), f"{step_name[:40]}", fill="#333", font=normal_font)
                        
                        line_num = step_detail.split('Line ')[-1].rstrip(')')
                        draw.text((offset_x + box_width - 50, step_y + 2), f"L:{line_num}", fill="#666", font=small_font)
                    
                    current_y_pos += wf_box_height + 50
            
            # Save the image
            image.save(temp_path, "PNG")
            
            # Open in Paint
            os.startfile(temp_path, 'edit')
            messagebox.showinfo("Success", f"Workflow map opened in MS Paint!\nFile saved at: {temp_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in Paint:\n{str(e)}")
    
    def export_workflow_map_ps(self):
        """Export workflow map as PostScript file (fallback when PIL not available)"""
        try:
            # Ask user for save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".ps",
                filetypes=[("PostScript", "*.ps"), ("EPS", "*.eps"), ("All Files", "*.*")],
                initialfile=f"workflow_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps"
            )
            
            if not file_path:
                return
            
            # Get canvas bounding box
            bbox = self.workflow_map_canvas.bbox("all")
            if not bbox:
                messagebox.showwarning("Export Error", "No workflow map to export")
                return
            
            # Export canvas to PostScript
            self.workflow_map_canvas.postscript(file=file_path, colormode='color',
                                               x=bbox[0], y=bbox[1],
                                               width=bbox[2]-bbox[0], height=bbox[3]-bbox[1])
            
            messagebox.showinfo("Export Successful", 
                              f"Workflow map exported as PostScript to:\n{file_path}\n\n"
                              "Note: PostScript files can be converted to PNG/PDF using online tools\n"
                              "or install Pillow library for direct PNG export:\npip install Pillow")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export workflow map:\n{str(e)}")

    def clear_all_tabs(self):
        """Clear content from all tabs"""
        self.event_text.delete(1.0, tk.END)
        self.workflow_text.delete(1.0, tk.END)
        self.business_service_text.delete(1.0, tk.END)
        self.errors_text.delete(1.0, tk.END)
        self.exec_sql_text.delete(1.0, tk.END)
        self.perf_text.delete(1.0, tk.END)
        self.tbui_text.delete(1.0, tk.END)
        
        # Clear tree views
        for item in self.sql_tree.get_children():
            self.sql_tree.delete(item)
        
        # Clear workflow map canvas
        self.workflow_map_canvas.delete("all")

    def select_notepad_path(self):
        """Allow user to select Notepad++ installation path"""
        notepad_path = filedialog.askopenfilename(
            title="Select Notepad++ Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
            initialdir="C:\\Program Files\\Notepad++" if os.path.exists("C:\\Program Files\\Notepad++") else "C:\\"
        )
        
        if notepad_path and os.path.exists(notepad_path):
            self.notepad_path = notepad_path
            self.save_notepad_config()
            messagebox.showinfo("Notepad++ Path Set", f"Notepad++ path set to:\n{notepad_path}")
            
            # Update button text to show it's configured
            self.notepad_button.config(text="Notepad++ ✓")
        else:
            if notepad_path:  # User selected something but it doesn't exist
                messagebox.showerror("Invalid Path", "Selected file does not exist or is not accessible.")

    def load_notepad_config(self):
        """Load Notepad++ path from config file"""
        # Security: Validate config file location
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, "notepad_config.json")
            
            # Security: Ensure config file is in expected location
            if not config_file.startswith(script_dir):
                print("Security Error: Invalid config file path")
                return
                
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    try:
                        config = json.load(f)
                        # Security: Validate JSON structure
                        if not isinstance(config, dict):
                            print("Security Warning: Invalid config file structure")
                            return
                            
                        notepad_path = config.get('notepad_path', '')
                        
                        # Security: Validate the stored path
                        if notepad_path and isinstance(notepad_path, str) and os.path.exists(notepad_path):
                            # Security: Ensure it's actually a notepad++ executable
                            if notepad_path.lower().endswith(('notepad++.exe', 'notepad.exe')):
                                self.notepad_path = notepad_path
                                self.notepad_button.config(text="Notepad++ ✓")
                            else:
                                print("Security Warning: Invalid executable in config")
                                self.notepad_path = ""
                        else:
                            self.notepad_path = ""
                    except (json.JSONDecodeError, ValueError, TypeError) as e:
                        print(f"Security Warning: Invalid JSON in config file: {e}")
                        self.notepad_path = ""
            else:
                # Try to auto-detect common Notepad++ installation paths
                common_paths = [
                    "C:\\Program Files\\Notepad++\\notepad++.exe",
                    "C:\\Program Files (x86)\\Notepad++\\notepad++.exe",
                    os.path.expanduser("~\\AppData\\Local\\Notepad++\\notepad++.exe")
                ]
                
                for path in common_paths:
                    if os.path.exists(path):
                        self.notepad_path = path
                        self.save_notepad_config()
                        self.notepad_button.config(text="Notepad++ ✓")
                        break
        except Exception as e:
            print(f"Error loading Notepad++ config: {e}")

    def save_notepad_config(self):
        """Save Notepad++ path to config file"""
        # Security: Validate config directory and file path
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, "notepad_config.json")
            
            # Security: Ensure we're writing to the expected location
            if not config_file.startswith(script_dir):
                print("Security Error: Invalid config file path")
                return
                
            config = {'notepad_path': self.notepad_path}
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving Notepad++ config: {e}")

    def open_in_notepad(self, file_path, line_number=None):
        """Open file in Notepad++ at specific line number"""
        if not self.notepad_path or not os.path.exists(self.notepad_path):
            messagebox.showwarning("Notepad++ Not Found", 
                                 "Notepad++ path not set or invalid. Please use 'Set Notepad++' button to configure.")
            return

        # Security: Validate file_path exists and is readable
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("File Error", "File does not exist or is not accessible.")
            return
            
        # Security: Validate line_number is actually a number
        if line_number is not None:
            try:
                line_number = int(line_number)
                if line_number < 1:
                    line_number = 1
            except (ValueError, TypeError):
                line_number = None

        try:
            # Security: Use absolute paths and validate executable
            notepad_exe = os.path.abspath(self.notepad_path)
            target_file = os.path.abspath(file_path)
            
            # Security: Ensure notepad path is actually notepad++
            if not notepad_exe.lower().endswith(('notepad++.exe', 'notepad.exe')):
                messagebox.showerror("Security Error", "Invalid Notepad++ executable path.")
                return
            
            if line_number:
                # Open file at specific line number
                cmd = [notepad_exe, target_file, f"-n{line_number}"]
            else:
                # Just open the file
                cmd = [notepad_exe, target_file]
            
            import subprocess
            # Security: shell=False prevents shell injection
            subprocess.Popen(cmd, shell=False)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file in Notepad++: {str(e)}")
    
    def _highlight_line_across_tabs(self, line_number):
        """Highlight the nearest line in all tabs based on the selected line number"""
        if line_number is None:
            return
        
        self._selected_line_number = line_number
        
        # Clear previous highlights in all text widgets
        for widget in self._all_text_widgets:
            try:
                widget.tag_remove("highlight", "1.0", tk.END)
            except tk.TclError:
                pass  # Widget might not be ready yet
        
        # Highlight nearest line in each tab
        for widget in self._all_text_widgets:
            self._highlight_nearest_in_widget(widget, line_number)
    
    def _highlight_nearest_in_widget(self, widget, target_line):
        """Find and highlight the line closest to target_line in the given widget"""
        try:
            import re
            
            content = widget.get("1.0", tk.END)
            if not content or len(content) < 2:
                return  # Widget is empty
            
            lines = content.split('\n')
            
            closest_line_index = None
            min_distance = float('inf')
            
            # Search for lines with line numbers (format: "  12345 | ...")
            for idx, line in enumerate(lines):
                if not line.strip():
                    continue
                    
                match = re.match(r'\s*(\d+)\s*\|', line)
                if match:
                    line_num = int(match.group(1))
                    distance = abs(line_num - target_line)
                    
                    if distance < min_distance:
                        min_distance = distance
                        closest_line_index = idx
                    
                    # If exact match found, stop searching
                    if distance == 0:
                        break
            
            # Highlight the found line
            if closest_line_index is not None:
                # Convert to tkinter text index (line numbers are 1-based)
                start_pos = f"{closest_line_index + 1}.0"
                end_pos = f"{closest_line_index + 1}.end"
                
                # Add highlight tag
                widget.tag_add("highlight", start_pos, end_pos)
                
                # Ensure tag has proper configuration
                widget.tag_raise("highlight")
                
                # Scroll to make the highlighted line visible
                widget.see(start_pos)
                
                # Force update
                widget.update_idletasks()
                
        except Exception as e:
            # Silently fail if widget is not ready or has issues
            print(f"Highlight error: {e}")  # Debug only
    
    def _on_tab_changed(self, event):
        """Refresh highlights when switching tabs"""
        if self._selected_line_number is not None:
            # Small delay to ensure tab is fully switched before refreshing
            self.root.after(100, self._refresh_current_tab_highlight)
    
    def _refresh_current_tab_highlight(self):
        """Refresh highlight on the currently visible tab"""
        try:
            if self._selected_line_number is None:
                return
            
            # Determine which tab is active
            current_tab_id = self.notebook.select()
            tab_index = self.notebook.index(current_tab_id)
            
            # Map tab index to widget (skip SQL Tree View which is index 6)
            if tab_index < len(self._all_text_widgets):
                widget = self._all_text_widgets[tab_index]
                
                # Check if highlight exists, if not re-apply it
                if not widget.tag_ranges("highlight"):
                    self._highlight_nearest_in_widget(widget, self._selected_line_number)
                else:
                    # Ensure highlight is visible
                    try:
                        widget.see("highlight.first")
                    except tk.TclError:
                        pass
                        
                # Force widget update
                widget.update_idletasks()
        except Exception as e:
            print(f"Tab change refresh error: {e}")  # Debug only

    def _on_tree_double_click(self, event):
        """Handle double-click on tree view items - ONLY highlight, NO Notepad++"""
        # Identify the item at the click position (similar to right-click)
        item = self.sql_tree.identify_row(event.y)
        if item:
            # Select the item
            self.sql_tree.selection_set(item)
            self.sql_tree.focus(item)
            
            # Get line number from the item values
            values = self.sql_tree.item(item, "values")
            if values and len(values) >= 2:
                line_num = values[1]  # Line number is now in the 2nd column (index 1)
                if line_num and str(line_num).isdigit():
                    line_number = int(line_num)
                    
                    # ONLY highlight - DO NOT open Notepad++
                    self._highlight_line_across_tabs(line_number)

    def _on_tree_right_click(self, event):
        """Handle right-click on tree view items"""
        # Identify the item at the click position
        item = self.sql_tree.identify_row(event.y)
        
        if item:
            # Select the item
            self.sql_tree.selection_set(item)
            self.sql_tree.focus(item)
            
            # Get line number from the item values
            values = self.sql_tree.item(item, "values")
            
            if values and len(values) >= 2:
                line_num = values[1]  # Line number is now in the 2nd column (index 1)
                
                if line_num and str(line_num).isdigit():
                    line_number = int(line_num)
                    
                    # Highlight this line across all tabs
                    self._highlight_line_across_tabs(line_number)
                    
                    # Use the correct method and variable names
                    if self.filename:
                        self.open_in_notepad(self.filename, line_number)
                    else:
                        messagebox.showwarning("No File", "No log file selected.")

    def _search_line_number(self, text_widget, search_text):
        """Search for a line number in the text widget and highlight it"""
        if not search_text or not search_text.strip():
            messagebox.showinfo("Search", "Please enter a line number to search.")
            return
        
        try:
            line_num = int(search_text.strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid line number.")
            return
        
        # Clear previous highlights
        text_widget.tag_remove("search_highlight", "1.0", tk.END)
        text_widget.tag_remove("sel", "1.0", tk.END)
        
        # Configure highlight tag
        text_widget.tag_config("search_highlight", background="#FFFF00", foreground="#000000", font=("Consolas", 9, "bold"))
        
        # Search for the line number in the text
        line_str = str(line_num)
        start_pos = "1.0"
        found = False
        
        # Search for line number that appears at the beginning of a content line
        while True:
            start_pos = text_widget.search(line_str, start_pos, tk.END, nocase=False)
            if not start_pos:
                break
            
            # Get the entire line content
            line_start = text_widget.index(f"{start_pos} linestart")
            line_end = text_widget.index(f"{start_pos} lineend")
            line_content = text_widget.get(line_start, line_end).strip()
            
            # Check if this line starts with the line number followed by pipe separator
            # This ensures we're finding the actual data line, not header or other text
            if line_content.startswith(line_str) and ' | ' in line_content:
                # Found the correct line!
                
                # Highlight the entire line
                text_widget.tag_add("search_highlight", line_start, line_end)
                text_widget.tag_add("sel", line_start, line_end)
                
                # Calculate position to show context (5 lines above)
                try:
                    current_line_num = int(line_start.split('.')[0])
                    context_line = max(1, current_line_num - 5)
                    context_start = f"{context_line}.0"
                    text_widget.see(context_start)
                except:
                    pass
                
                # Scroll to the highlighted line
                text_widget.see(line_start)
                
                # Set cursor at the beginning of the line
                text_widget.mark_set("insert", line_start)
                text_widget.focus_set()
                
                found = True
                break
            
            # Move to next occurrence
            start_pos = f"{start_pos}+1c"
        
        if not found:
            # Fallback: search more broadly for the line number
            start_pos = "1.0"
            start_pos = text_widget.search(line_str, start_pos, tk.END)
            if start_pos:
                line_start = text_widget.index(f"{start_pos} linestart")
                line_end = text_widget.index(f"{start_pos} lineend")
                text_widget.tag_add("search_highlight", line_start, line_end)
                text_widget.tag_add("sel", line_start, line_end)
                
                # Show context
                try:
                    current_line_num = int(line_start.split('.')[0])
                    context_line = max(1, current_line_num - 5)
                    context_start = f"{context_line}.0"
                    text_widget.see(context_start)
                except:
                    pass
                
                text_widget.see(line_start)
                text_widget.mark_set("insert", line_start)
                text_widget.focus_set()
                found = True
        
        if not found:
            messagebox.showwarning("Not Found", 
                                  f"Line number {line_num} not found in this tab.\n\n"
                                  f"The line might be in a different tab or not present in the log file.")

    def _copy_to_clipboard(self, text_widget):
        """Copy selected text to clipboard"""
        try:
            # Check if there's a selection
            if text_widget.tag_ranges("sel"):
                selected_text = text_widget.get("sel.first", "sel.last")
                self.root.clipboard_clear()
                self.root.clipboard_append(selected_text)
                return "break"  # Prevent default behavior
        except tk.TclError:
            pass
        return None

    def _select_all(self, text_widget):
        """Select all text in the widget"""
        try:
            text_widget.tag_remove("sel", "1.0", tk.END)
            text_widget.tag_add("sel", "1.0", tk.END)
            text_widget.mark_set("insert", "1.0")
            text_widget.see("insert")
            return "break"  # Prevent default behavior
        except tk.TclError:
            pass
        return None

    def _on_text_double_click(self, event, text_widget):
        """Handle double-click on text widget to highlight line across all tabs (NO Notepad++)"""
        try:
            # Get the current line where user double-clicked
            current_pos = text_widget.index(tk.INSERT)
            line_start = text_widget.index(f"{current_pos} linestart")
            line_end = text_widget.index(f"{current_pos} lineend")
            line_content = text_widget.get(line_start, line_end)
            
            # Extract line number from the beginning of the line (first column)
            import re
            match = re.match(r'\s*(\d+)\s*\|', line_content)
            if match:
                line_number = int(match.group(1))
                
                print(f"Double-click detected: Line {line_number}")  # Debug
                
                # ONLY highlight - DO NOT open Notepad++
                self._highlight_line_across_tabs(line_number)
                
                # Force UI update
                self.root.update_idletasks()
            else:
                messagebox.showinfo("Info", "No line number found. Double-click on a line with log data.")
                
        except Exception as e:
            print(f"Double-click error: {e}")  # Debug

    def _show_context_menu(self, event, text_widget):
        """Show context menu on right-click with option to open in Notepad++"""
        try:
            # Get the position where user right-clicked
            click_pos = text_widget.index(f"@{event.x},{event.y}")
            line_start = text_widget.index(f"{click_pos} linestart")
            line_end = text_widget.index(f"{click_pos} lineend")
            line_content = text_widget.get(line_start, line_end)
            
            # Extract line number from the beginning of the line (first column)
            import re
            match = re.match(r'\s*(\d+)\s*\|', line_content)
            if match:
                line_number = int(match.group(1))
                
                print(f"Right-click detected: Line {line_number}")  # Debug
                
                # Highlight this line across all tabs
                self._highlight_line_across_tabs(line_number)
                
                # Force UI update
                self.root.update_idletasks()
                
                # Create context menu
                context_menu = tk.Menu(self.root, tearoff=0)
                context_menu.add_command(
                    label="📝 Open in Notepad++",
                    command=lambda: self._open_line_in_notepad(line_number)
                )
                context_menu.add_separator()
                context_menu.add_command(label="❌ Cancel", command=context_menu.destroy)
                
                # Show menu at mouse position
                context_menu.tk_popup(event.x_root, event.y_root)
            else:
                messagebox.showinfo("Info", "No line number found. Right-click on a line with log data.")
        except Exception as e:
            print(f"Context menu error: {e}")  # Debug

    def _open_line_in_notepad(self, line_number):
        """Open the log file in Notepad++ at the specified line number"""
        if self.filename:
            self.open_in_notepad(self.filename, line_number)
        else:
            messagebox.showwarning("No File", "No log file selected.")

    def _open_current_line_in_notepad(self, text_widget):
        """Open current line in Notepad++ using Ctrl+Shift+A"""
        try:
            # Get current cursor position
            current_pos = text_widget.index(tk.INSERT)
            line_start = text_widget.index(f"{current_pos} linestart")
            line_end = text_widget.index(f"{current_pos} lineend")
            line_content = text_widget.get(line_start, line_end)
            
            # Extract line number
            import re
            match = re.match(r'\s*(\d+)\s*\|', line_content)
            if match:
                line_number = int(match.group(1))
                self._open_line_in_notepad(line_number)
            else:
                messagebox.showinfo("Info", "No line number found at cursor position.")
        except Exception as e:
            print(f"Keyboard shortcut error: {e}")

    def _page_up(self, text_widget):
        """Handle Page Up key - scroll up one page"""
        try:
            text_widget.yview_scroll(-1, "pages")
            return "break"  # Prevent default behavior
        except Exception as e:
            print(f"Page Up error: {e}")

    def _page_down(self, text_widget):
        """Handle Page Down key - scroll down one page"""
        try:
            text_widget.yview_scroll(1, "pages")
            return "break"  # Prevent default behavior
        except Exception as e:
            print(f"Page Down error: {e}")

    def _on_text_right_click(self, event, text_widget):
        """Legacy handler - redirects to context menu"""
        self._show_context_menu(event, text_widget)

# Run the application
if __name__ == "__main__":
    # SECURITY: Final network blocking verification
    print("🔒 SECURITY: Network access is DISABLED for this application")
    
    # Verify network blocking is active
    network_blocked = True
    try:
        # Test import blocking
        import urllib
        network_blocked = False
        print("⚠️  WARNING: Network module import blocking failed")
    except ImportError:
        print("✅ Network module imports are blocked")
    
    try:
        # Test socket blocking
        import socket
        socket.socket()
        network_blocked = False
        print("⚠️  WARNING: Socket creation blocking failed")
    except (ImportError, PermissionError, Exception):
        print("✅ Socket creation is blocked")
    
    if network_blocked:
        print("🛡️  SECURITY: All network access successfully disabled")
    else:
        print("⚠️  SECURITY WARNING: Network blocking may be incomplete")
    
    try:
        root = tk.Tk()
        root.geometry("1000x800")  # Set explicit window size
        root.minsize(800, 600)     # Set minimum size
        root.state('normal')       # Ensure window is visible
        root.lift()               # Bring window to front
        root.attributes('-topmost', True)  # Make window topmost temporarily
        root.after(1000, lambda: root.attributes('-topmost', False))  # Remove topmost after 1 second
        
        app = SiebelLogAnalyzer(root)
        print("Siebel Log Analyzer GUI is starting...")
        root.mainloop()
    except Exception as e:
        print(f"Error starting GUI: {e}")
        import traceback
        traceback.print_exc()
