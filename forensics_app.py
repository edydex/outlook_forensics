import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import json
import os
from datetime import datetime
import pytz
import subprocess
import csv
import email
import shutil
import re
import zipfile
import tempfile
from pathlib import Path
import threading
from collections import defaultdict, Counter
import platform

class BreachAnalysisApp(tk.Tk):
    """
    Combined application for Microsoft Purview Audit Log analysis and PST Email extraction.
    Provides a tabbed interface for comprehensive breach investigation workflows.
    """
    def __init__(self):
        super().__init__()
        self.title("Breach Analysis Toolkit - Audit Logs & Email Extraction")
        self.geometry("1400x900")
        self.minsize(1000, 700)
        
        # Define consistent color scheme
        self.colors = {
            'background': '#F5F5F5',      # Very light gray background
            'text': '#333333',            # Dark gray text
            'border': '#CCCCCC',          # Medium-light gray borders
            'primary': '#607D8B',         # Blue-gray primary accent
            'secondary': '#5CB85C',       # Professional green secondary
            'selected': '#607D8B',        # Primary color for selections
            'white': '#FFFFFF'            # Pure white for input fields
        }
        
        # Shared data between tabs
        self.shared_data = {
            'compromised_emails': [],
            'suspicious_ips': [],
            'output_directory': tk.StringVar(),
            'investigation_notes': tk.StringVar()
        }
        
        self.setup_styles()
        self.create_main_interface()
    
    def setup_styles(self):
        """Configure consistent styling throughout the application."""
        # Configure root window
        self.configure(bg=self.colors['background'])
        
        # Create and configure ttk styles
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure main application styles
        self.style.configure('TFrame', background=self.colors['background'])
        self.style.configure('TLabel', background=self.colors['background'], foreground=self.colors['text'])
        self.style.configure('TLabelframe', background=self.colors['background'], foreground=self.colors['text'])
        self.style.configure('TLabelframe.Label', background=self.colors['background'], foreground=self.colors['text'])
        
        # Configure button styles
        self.style.configure('TButton',
            background=self.colors['primary'],
            foreground='white',
            borderwidth=1,
            relief='solid',
            focuscolor='none')
        self.style.map('TButton',
            background=[('active', self.colors['selected']),
                       ('pressed', self.colors['selected'])])
        
        # Configure secondary button style
        self.style.configure('Secondary.TButton',
            background=self.colors['secondary'],
            foreground='white',
            borderwidth=1,
            relief='solid',
            focuscolor='none')
        self.style.map('Secondary.TButton',
            background=[('active', self.colors['secondary']),
                       ('pressed', self.colors['secondary'])])
        
        # Configure entry and combobox styles
        self.style.configure('TEntry',
            background=self.colors['white'],
            foreground=self.colors['text'],
            borderwidth=1,
            relief='solid',
            insertcolor=self.colors['text'])
        
        self.style.configure('TCombobox',
            background=self.colors['white'],
            foreground=self.colors['text'],
            borderwidth=1,
            relief='solid')
        
        # Configure notebook styles
        self.style.configure('TNotebook', background=self.colors['background'])
        self.style.configure('TNotebook.Tab',
            background=self.colors['primary'],  # Inactive tabs darker
            foreground='white',
            padding=[8, 4])  # Smaller padding for inactive tabs
        self.style.map('TNotebook.Tab',
            background=[('selected', self.colors['background']),  # Selected tabs lighter
                       ('active', self.colors['border'])],
            foreground=[('selected', self.colors['text']),  # Selected tabs dark text
                       ('active', self.colors['text'])],
            padding=[('selected', [12, 6]),  # Selected tabs larger padding
                    ('active', [10, 5])])
        
        # Configure treeview styles
        self.style.configure("Treeview.Heading",
            font=("Inter", 10, "bold"),
            background=self.colors['background'],
            foreground=self.colors['text'],
            relief='solid',
            borderwidth=1)
        
        self.style.configure("Treeview",
            font=("Inter", 9),
            rowheight=25,
            background=self.colors['white'],
            foreground=self.colors['text'])
        
        self.style.map("Treeview",
            background=[('selected', self.colors['selected'])],
            foreground=[('selected', 'white')])
        
        # Special style for sync entries
        self.style.configure("Sync.Treeview", background="#FFEEEE")
        
        # Configure scrollbar styles
        self.style.configure('TScrollbar',
            background=self.colors['background'],
            troughcolor=self.colors['border'],
            borderwidth=0,
            arrowcolor=self.colors['text'])
    
    def create_main_interface(self):
        """Create the main tabbed interface."""
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tab frames
        self.audit_tab = ttk.Frame(self.notebook)
        self.email_tab = ttk.Frame(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.audit_tab, text="📊 Audit Log Analysis")
        self.notebook.add(self.email_tab, text="📧 Email Extraction & Scanning")
        
        # Initialize tab contents
        self.audit_viewer = AuditLogViewer(self.audit_tab, self.shared_data, self.colors, self.style)
        self.email_extractor = PSTExtractorApp(self.email_tab, self.shared_data, self.colors, self.style)
        
        # Create shared controls at the bottom
        self.create_shared_controls()
    
    def create_shared_controls(self):
        """Create shared controls and status bar."""
        shared_frame = ttk.Frame(self)
        shared_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Output directory selection (shared between tabs)
        ttk.Label(shared_frame, text="Investigation Output Directory:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Entry(shared_frame, textvariable=self.shared_data['output_directory'], width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(shared_frame, text="Browse", command=self.browse_output_directory).pack(side=tk.LEFT, padx=5)
        
        # Quick actions frame
        actions_frame = ttk.Frame(shared_frame)
        actions_frame.pack(side=tk.RIGHT, padx=(20, 0))
        
        # Status indicator
        self.status_label = ttk.Label(actions_frame, text="Ready", foreground=self.colors['secondary'])
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
        # Help button
        ttk.Button(actions_frame, text="Help", command=self.show_help).pack(side=tk.RIGHT, padx=5)
    
    def show_help(self):
        """Show help dialog for the application."""
        help_text = (
            "=== BREACH ANALYSIS TOOLKIT - HELP ===\n\n"
            "⚡️ HTML EXPORTS ARE THE MAIN WAY TO VIEW, SORT, AND SHARE RESULTS!\n"
            "• After filtering or extracting data, always use the 'Export to HTML' buttons to generate interactive reports.\n"
            "• HTML reports provide sortable tables, detailed timelines, keyword match breakdowns, and clickable details.\n"
            "• Use these HTML files for refining, sharing, and presenting your investigation findings.\n\n"
            "This application combines two tools for investigating email security breaches.\n\n"
            "📊 AUDIT LOG ANALYSIS TAB:\n"
            "• Load Microsoft Purview audit log CSV files\n"
            "• Filter by IP addresses, dates, and other criteria\n"
            "• View detailed audit events in an interactive table\n"
            "• Export filtered results to HTML reports (recommended for sorting and reviewing)\n"
            "• Extract email addresses and send to Email Extraction tab\n\n"
            "📧 EMAIL EXTRACTION & SCANNING TAB:\n"
            "• Extract emails from PST files using readpst\n"
            "• Scan extracted emails for specific keywords\n"
            "• Import compromised email addresses from Audit tab\n"
            "• Generate detailed analysis reports\n"
            "• Export results in HTML format for best viewing and sharing\n\n"
            "WORKFLOW:\n"
            "1. Start with Audit Log Analysis to identify suspicious activities\n"
            "2. Use \"Send Identified Emails to Extraction Tab\" button\n"
            "3. Switch to Email Extraction tab to analyze PST files\n"
            "4. Use \"Import from Audit Tab\" to load compromised emails\n"
            "5. Generate comprehensive HTML reports for your investigation\n\n"
            "TIPS:\n"
            "• Set a shared investigation output directory for all files\n"
            "• Use timezone settings to analyze logs in local time\n"
            "• Cross-reference IP addresses between both tools\n"
            "• Always export results in HTML format for professional, interactive reports\n"
        )
        
        help_window = tk.Toplevel(self)
        help_window.title("Breach Analysis Toolkit - Help")
        help_window.geometry("600x500")
        help_window.resizable(True, True)
        help_window.configure(bg=self.colors['background'])
        
        text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, padx=10, pady=10,
                                               bg=self.colors['white'], fg=self.colors['text'])
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state='disabled')
        
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=10)
    
    def browse_output_directory(self):
        """Browse for shared output directory."""
        directory = filedialog.askdirectory(title="Select Investigation Output Directory")
        if directory:
            self.shared_data['output_directory'].set(directory)
    
    def update_status(self, message, color=None):
        """Update the status label."""
        if color is None:
            color = self.colors['text']
        elif color == "green":
            color = self.colors['secondary']
        elif color == "red":
            color = "#D32F2F"  # Red for errors
        self.status_label.config(text=message, foreground=color)
        self.update_idletasks()

class AuditLogViewer:
    """
    Microsoft Purview Audit Log viewer component for the tabbed interface.
    """
    def __init__(self, parent_frame, shared_data, colors, style):
        self.parent = parent_frame
        self.shared_data = shared_data
        self.colors = colors
        self.style = style
        
        self.df = None # The DataFrame currently displayed in the Treeview
        self.original_df = None # Stores the initial loaded and processed DataFrame
        self.cell_data_map = {} # Maps (Treeview_item_id, column_name) to original_df_index for tooltips
        
        # Timezone settings
        self.selected_timezone = tk.StringVar(value="UTC")
        self.display_local_time = tk.BooleanVar(value=False)

        self.create_widgets()

    def create_widgets(self):
        """
        Creates all the GUI elements for the audit log viewer.
        """
        # --- Control Frame ---
        control_frame = ttk.Frame(self.parent, padding="10")
        control_frame.pack(pady=10, padx=10, fill=tk.X)

        self.load_button = ttk.Button(control_frame, text="Load CSV File", command=self.load_csv)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Timezone Frame
        timezone_frame = ttk.Frame(self.parent, padding="10")
        timezone_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Label(timezone_frame, text="Timezone:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Get common timezones
        common_timezones = [
            'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
            'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo',
            'Asia/Shanghai', 'Australia/Sydney', 'America/New_York',
            'America/Chicago', 'America/Denver', 'America/Los_Angeles'
        ]
        
        self.timezone_combo = ttk.Combobox(timezone_frame, textvariable=self.selected_timezone, 
                                          values=common_timezones, width=20, state="readonly")
        self.timezone_combo.pack(side=tk.LEFT, padx=5)
        self.timezone_combo.bind('<<ComboboxSelected>>', self.on_timezone_change)

        self.toggle_timezone_checkbox = ttk.Checkbutton(
            timezone_frame, 
            text="Display Local Time", 
            variable=self.display_local_time,
            command=self.toggle_timezone_display
        )
        self.toggle_timezone_checkbox.pack(side=tk.LEFT, padx=(20, 5))

        # IP Filter
        ttk.Label(control_frame, text="Filter by IP:").pack(side=tk.LEFT, padx=(20, 5))
        self.ip_filter_entry = ttk.Entry(control_frame, width=20, font=("Inter", 10))
        self.ip_filter_entry.pack(side=tk.LEFT, padx=5)

        self.exclude_ip_var = tk.BooleanVar(value=False)
        self.exclude_ip_checkbox = ttk.Checkbutton(control_frame, text="Exclude IP", variable=self.exclude_ip_var)
        self.exclude_ip_checkbox.pack(side=tk.LEFT, padx=5)

        self.apply_ip_filter_button = ttk.Button(control_frame, text="Apply Filters", command=self.apply_filters, style="Secondary.TButton")
        self.apply_ip_filter_button.pack(side=tk.LEFT, padx=5)
        
        # Date Filter
        date_filter_frame = ttk.Frame(self.parent, padding="10")
        date_filter_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Label(date_filter_frame, text="Start Date/Time (YYYY-MM-DD [HH:MM:SS]):").pack(side=tk.LEFT, padx=(0, 5))
        self.start_date_entry = ttk.Entry(date_filter_frame, width=25, font=("Inter", 10))
        self.start_date_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(date_filter_frame, text="End Date/Time (YYYY-MM-DD [HH:MM:SS]):").pack(side=tk.LEFT, padx=(20, 5))
        self.end_date_entry = ttk.Entry(date_filter_frame, width=25, font=("Inter", 10))
        self.end_date_entry.pack(side=tk.LEFT, padx=5)
        
        self.apply_date_filter_button = ttk.Button(date_filter_frame, text="Apply Date Filter", command=self.apply_filters, style="Secondary.TButton")
        self.apply_date_filter_button.pack(side=tk.LEFT, padx=5)

        self.clear_filter_button = ttk.Button(date_filter_frame, text="Clear Filters", command=self.clear_filter)
        self.clear_filter_button.pack(side=tk.LEFT, padx=5)
        
        self.view_filters_button = ttk.Button(date_filter_frame, text="View/Manage Filters", command=self.view_applied_filters)
        self.view_filters_button.pack(side=tk.LEFT, padx=(20, 5))

        # Other Buttons
        other_buttons_frame = ttk.Frame(self.parent, padding="10")
        other_buttons_frame.pack(pady=5, padx=10, fill=tk.X)

        self.split_ip_button = ttk.Button(other_buttons_frame, text="Split by IP to CSVs", command=self.split_by_ip)
        self.split_ip_button.pack(side=tk.LEFT, padx=5)
        
        self.export_html_button = ttk.Button(other_buttons_frame, text="Export Filtered Table to HTML", command=self.export_to_html)
        self.export_html_button.pack(side=tk.LEFT, padx=5)

        # HTML Export Options Frame
        html_options_frame = ttk.Frame(self.parent, padding="10")
        html_options_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Label(html_options_frame, text="HTML Report Title:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.html_title_entry = ttk.Entry(html_options_frame, width=40, font=("Inter", 10))
        self.html_title_entry.insert(0, "Audit Log Report") # Default title
        self.html_title_entry.grid(row=0, column=1, sticky="ew", padx=5)

        ttk.Label(html_options_frame, text="Comments for HTML Report:").grid(row=1, column=0, sticky="nw", padx=(0, 5), pady=(5,0))
        self.comments_text = tk.Text(html_options_frame, width=60, height=4, font=("Inter", 9), wrap=tk.WORD,
                                    bg=self.colors['white'], fg=self.colors['text'], relief='flat', borderwidth=0,
                                    highlightthickness=1, highlightcolor=self.colors['border'], highlightbackground=self.colors['border'])
        self.comments_text.grid(row=1, column=1, sticky="nsew", padx=5, pady=(5,0))
        comments_scroll = ttk.Scrollbar(html_options_frame, command=self.comments_text.yview)
        comments_scroll.grid(row=1, column=2, sticky='ns', pady=(5,0))
        self.comments_text['yscrollcommand'] = comments_scroll.set
        
        html_options_frame.grid_columnconfigure(1, weight=1)
        html_options_frame.grid_rowconfigure(1, weight=1) # Make comments text area expandable

        # --- Table Frame ---
        table_frame = ttk.Frame(self.parent, padding="10")
        table_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Treeview for displaying data
        self.tree = ttk.Treeview(table_frame, show="headings")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbars for the Treeview
        ysb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=ysb.set)

        xsb = ttk.Scrollbar(self.tree, orient=tk.HORIZONTAL, command=self.tree.xview)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.configure(xscrollcommand=xsb.set)

        # --- Tooltip Setup ---
        self.tooltip = None
        self.tree.bind("<Motion>", self.on_tree_motion)
        self.tree.bind("<Leave>", self.hide_tooltip)
        self.tree.bind("<Button-1>", self.on_tree_click)
        
        # Add button to send emails to extraction tab
        send_emails_frame = ttk.Frame(self.parent, padding="5")
        send_emails_frame.pack(fill=tk.X, padx=10)
        
        self.send_emails_button = ttk.Button(
            send_emails_frame, 
            text="📧 Send MailItemsAccessed IDs to Extraction Tab", 
            command=self.send_emails_to_extraction_tab
        )
        self.send_emails_button.pack(side=tk.RIGHT, padx=5)

    def convert_utc_to_timezone(self, utc_datetime_str, target_timezone):
        """
        Convert UTC datetime string to target timezone.
        Returns tuple of (formatted_string, datetime_object) or (original, None) if conversion fails.
        """
        if pd.isna(utc_datetime_str) or utc_datetime_str == 'N/A':
            return utc_datetime_str, None
        
        try:
            # Parse the UTC datetime
            if isinstance(utc_datetime_str, str):
                # Handle the format from process_audit_data: "YYYY-MM-DDTHH:MM:SS"
                utc_dt = datetime.fromisoformat(utc_datetime_str.replace('T', ' '))
            else:
                utc_dt = utc_datetime_str
            
            # Make it timezone-aware as UTC
            utc_dt = pytz.UTC.localize(utc_dt) if utc_dt.tzinfo is None else utc_dt
            
            # Convert to target timezone
            if target_timezone == "UTC":
                converted_dt = utc_dt
            else:
                target_tz = pytz.timezone(target_timezone)
                converted_dt = utc_dt.astimezone(target_tz)
            
            # Format the result
            formatted_str = converted_dt.strftime("%Y-%m-%dT%H:%M:%S")
            return formatted_str, converted_dt
            
        except Exception as e:
            print(f"Error converting timezone: {e}")
            return utc_datetime_str, None

    def on_timezone_change(self, event=None):
        """Handle timezone selection change."""
        if self.display_local_time.get():
            self.refresh_display_with_timezone()

    def toggle_timezone_display(self):
        """Toggle between UTC and selected timezone display."""
        self.refresh_display_with_timezone()

    def refresh_display_with_timezone(self):
        """Refresh the display with current timezone settings."""
        if self.df is not None:
            self.update_display_dates()
            self.display_data()

    def update_display_dates(self):
        """Update the CreationDate column based on current timezone settings."""
        if self.df is None or self.original_df is None:
            return
        
        # Update both self.df and self.original_df
        for df in [self.df, self.original_df]:
            if df is None or df.empty:
                continue
                
            if self.display_local_time.get() and self.selected_timezone.get() != "UTC":
                # Convert to selected timezone
                target_tz = self.selected_timezone.get()
                df['CreationDate'] = df['DateTime'].apply(
                    lambda x: self.convert_utc_to_timezone(x, target_tz)[0] if pd.notna(x) else 'N/A'
                )
            else:
                # Show UTC time
                df['CreationDate'] = df['DateTime'].apply(
                    lambda x: x.strftime("%Y-%m-%dT%H:%M:%S") if pd.notna(x) else 'N/A'
                )

    def send_emails_to_extraction_tab(self):
        """Extract MailItemsAccessed IDs from current data and send to email extraction tab."""
        try:
            if self.df is None or self.df.empty:
                messagebox.showwarning("No Data", "Please load audit log data first.")
                return
            
            # Use the CURRENT displayed data (same as HTML export), not original data
            current_data = self.df  # This respects any active filters
            
            # Debug: Print available columns
            print(f"Available columns: {list(current_data.columns)}")
            
            # Find the operations column (could be 'Operations', 'Operation', etc.)
            operations_col = None
            for col in current_data.columns:
                if 'operation' in col.lower():
                    operations_col = col
                    break
            
            if operations_col is None:
                messagebox.showerror("Error", f"No operations column found. Available columns: {list(current_data.columns)}")
                return
            
            print(f"Using operations column: {operations_col}")
            
            # Debug: Count total rows and MailItemsAccessed rows
            total_rows = len(current_data)
            mailaccess_rows = current_data[current_data[operations_col].str.contains('MailItemsAccessed', na=False)]
            mailaccess_count = len(mailaccess_rows)
            
            # Extract MailItemsAccessed IDs using the same logic as HTML export
            mail_item_ids = set()
            debug_audit_entries = 0
            debug_folders_processed = 0
            debug_folder_items_processed = 0
            debug_internetmsgid_found = 0
            debug_itemid_found = 0
            debug_regex_fallback = 0
            
            # Look for MailItemsAccessed operations specifically in CURRENT displayed data
            if operations_col in current_data.columns and 'AuditData' in current_data.columns:
                
                for _, row in mailaccess_rows.iterrows():
                    debug_audit_entries += 1
                    audit_data_str = row['AuditData']
                    if pd.notna(audit_data_str) and isinstance(audit_data_str, str):
                        try:
                            # Parse JSON audit data (same as HTML export)
                            audit_json = json.loads(audit_data_str)
                            folders = audit_json.get('Folders', [])
                            debug_folders_processed += len(folders)
                            
                            for folder in folders:
                                folder_items = folder.get('FolderItems', [])
                                debug_folder_items_processed += len(folder_items)
                                for item in folder_items:
                                    # Extract InternetMessageId first (preferred), then Id
                                    internet_msg_id = item.get('InternetMessageId', '')
                                    item_id = item.get('Id', '')
                                    
                                    if internet_msg_id:
                                        mail_item_ids.add(internet_msg_id)
                                        debug_internetmsgid_found += 1
                                    elif item_id:
                                        mail_item_ids.add(item_id)
                                        debug_itemid_found += 1
                                        
                        except (json.JSONDecodeError, TypeError):
                            # Fallback to regex extraction for malformed JSON
                            debug_regex_fallback += 1
                            ids = re.findall(r'<[A-Za-z0-9@.]+>', audit_data_str)
                            mail_item_ids.update(ids)
            
            # Also check other relevant columns for IDs in brackets format (backup) - BUT ONLY in MailItemsAccessed rows
            debug_backup_ids = 0
            id_columns = ['AuditData', 'ObjectId', 'Item']
            for column in id_columns:
                if column in current_data.columns:
                    # Only search in MailItemsAccessed rows, not all rows!
                    for value in mailaccess_rows[column].dropna():
                        if isinstance(value, str):
                            # Extract mail item IDs in brackets format
                            found_ids = re.findall(r'<[A-Za-z0-9@.]+>', value)
                            if found_ids:
                                debug_backup_ids += len(found_ids)
                            mail_item_ids.update(found_ids)
            
            if mail_item_ids:
                # Update shared data
                self.shared_data['compromised_emails'] = list(mail_item_ids)
                
                # Show detailed debugging confirmation message
                debug_info = (
                    f"=== DEBUGGING EXTRACTION ===\n"
                    f"• Total rows in current view: {total_rows}\n"
                    f"• MailItemsAccessed rows: {mailaccess_count}\n"
                    f"• Audit entries processed: {debug_audit_entries}\n"
                    f"• Folders processed: {debug_folders_processed}\n"
                    f"• Folder items processed: {debug_folder_items_processed}\n"
                    f"• InternetMessageId found: {debug_internetmsgid_found}\n"
                    f"• ItemId found: {debug_itemid_found}\n"
                    f"• JSON parse failures (regex fallback): {debug_regex_fallback}\n"
                    f"• Backup regex IDs: {debug_backup_ids}\n"
                    f"• FINAL UNIQUE IDs: {len(mail_item_ids)}\n\n"
                    f"These have been sent to the Email Extraction tab.\n\n"
                    f"Note: Compare this with HTML Export 'Export IDs' count.\n\n"
                    f"Sample IDs:\n" + "\n".join(list(mail_item_ids)[:3]) + 
                    (f"\n... and {len(mail_item_ids)-3} more" if len(mail_item_ids) > 3 else "")
                )
                
                messagebox.showinfo("MailItemsAccessed IDs Extracted - DEBUG MODE", debug_info)
                
                # Optional: Switch to email extraction tab
                parent_window = self.parent.winfo_toplevel()
                if hasattr(parent_window, 'notebook'):
                    parent_window.notebook.select(1)  # Switch to email extraction tab
            else:
                messagebox.showinfo("No MailItemsAccessed IDs Found", 
                                   f"No MailItemsAccessed IDs were found in the current displayed audit log data.\n\n"
                                   f"DEBUG INFO:\n"
                                   f"• Total rows: {total_rows}\n"
                                   f"• MailItemsAccessed rows: {mailaccess_count}\n"
                                   f"• Audit entries processed: {debug_audit_entries}\n\n"
                                   f"Try clearing any active filters if you expect to see MailItemsAccessed operations.")
        
        except Exception as e:
            print(f"Error in send_emails_to_extraction_tab: {e}")
            messagebox.showerror("Error", f"An error occurred while extracting MailItemsAccessed IDs: {str(e)}")

    def load_csv(self):
        """
        Opens a file dialog to select a CSV file, then loads and processes it.
        """
        file_path = filedialog.askopenfilename(
            title="Select Microsoft Purview Audit Log CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            temp_df = pd.read_csv(file_path)
            self.original_df = temp_df.copy()

            self.process_audit_data()

            self.df = self.original_df.copy()
            self.display_data()
            messagebox.showinfo("Success", "CSV loaded and processed successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load or process CSV: {e}")
            self.df = None
            self.original_df = None

    def process_audit_data(self):
        """
        Parses the 'AuditData' column (expected to be JSON strings)
        to extract 'ClientIPAddress' and 'CreationTime' into new DataFrame columns.
        Also formats 'CreationTime' to 'YYYY-MM-DDTHH:MM:SS' and converts it to datetime objects.
        """
        if 'AuditData' not in self.original_df.columns:
            messagebox.showwarning("Warning", "'AuditData' column not found. Cannot extract IP and CreationDate.")
            self.original_df['ClientIPAddress'] = 'N/A'
            self.original_df['CreationDate'] = 'N/A'
            self.original_df['DateTime'] = pd.NaT # Not a Time for date filtering
            return

        self.original_df['ClientIPAddress'] = 'N/A'
        self.original_df['CreationDate'] = 'N/A'
        self.original_df['DateTime'] = pd.NaT # Initialize new datetime column

        for index, row in self.original_df.iterrows():
            audit_data_str = row['AuditData']
            if pd.notna(audit_data_str):
                try:
                    audit_json = json.loads(audit_data_str)

                    self.original_df.at[index, 'ClientIPAddress'] = audit_json.get('ClientIPAddress', 'N/A')

                    date_str = audit_json.get('CreationTime')
                    if date_str and date_str != 'N/A':
                        try:
                            dt_obj = pd.to_datetime(date_str)
                            # Store as UTC datetime object
                            self.original_df.at[index, 'DateTime'] = dt_obj
                            # Format for display (initially as UTC)
                            formatted_date = dt_obj.strftime("%Y-%m-%dT%H:%M:%S")
                            self.original_df.at[index, 'CreationDate'] = formatted_date
                        except ValueError:
                            pass
                except json.JSONDecodeError:
                    pass
                except AttributeError:
                    pass

    def display_data(self):
        """
        Populates the Treeview with data from self.df.
        """
        if self.df is None:
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self.cell_data_map = {}

        required_cols = ['RecordId', 'Operation', 'CreationDate', 'ClientIPAddress']
        if not all(col in self.df.columns for col in required_cols):
            missing_cols = [col for col in required_cols if col not in self.df.columns]
            messagebox.showerror("Error", f"Missing one or more required columns: {', '.join(missing_cols)}. Please check your CSV.")
            return

        all_entries_by_operation = {}
        # Iterate over the currently filtered DataFrame (self.df)
        for df_index, row in self.df.iterrows():
            operation = row['Operation']
            if pd.isna(operation):
                continue

            if operation not in all_entries_by_operation:
                all_entries_by_operation[operation] = []
            
            # Store the actual row data directly, not just its original_idx
            all_entries_by_operation[operation].append(row)
        
        # Sort entries within each operation by DateTime chronologically (oldest first)
        for operation in all_entries_by_operation:
            # Sort by DateTime column, handling NaT values by putting them at the end
            all_entries_by_operation[operation].sort(
                key=lambda x: x['DateTime'] if pd.notna(x['DateTime']) else pd.Timestamp.max
            )
        
        unique_operations = sorted(all_entries_by_operation.keys())
        max_rows = 0
        for op_list in all_entries_by_operation.values():
            max_rows = max(max_rows, len(op_list))

        if max_rows == 0:
            messagebox.showinfo("No Data", "No valid audit log entries found to display after applying filters.")
            return

        self.tree['columns'] = ('#',) + tuple(unique_operations)
        
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=0, stretch=tk.NO)

        self.tree.heading("#", text="#")
        self.tree.column("#", width=50, stretch=tk.NO, anchor=tk.CENTER)

        for col in unique_operations:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180, anchor=tk.CENTER)

        for row_idx in range(max_rows):
            row_values = [row_idx + 1]
            current_row_tags = [] # To store tags for this row
            current_row_cell_data = []

            for op_col in unique_operations:
                op_entries = all_entries_by_operation.get(op_col, [])
                
                if row_idx < len(op_entries):
                    entry_row_data = op_entries[row_idx] # This is the full row Series from self.df
                    date_str = entry_row_data['CreationDate']
                    
                    row_values.append(date_str)
                    
                    # Check for MailAccessType for tinting
                    if op_col == "MailItemsAccessed":
                        mail_access_type = self._get_mail_access_type_value(entry_row_data.get('AuditData'))
                        if mail_access_type == "Sync":
                            current_row_tags.append("Sync.Treeview") # Apply the defined style tag

                    # Store the df_index from self.df for the specific row
                    current_row_cell_data.append((op_col, entry_row_data.name)) # entry_row_data.name is the actual index from self.df

                else:
                    row_values.append("")
            
            # Apply tags to the entire row if needed
            item_id = self.tree.insert("", tk.END, text="", values=row_values, tags=tuple(current_row_tags))
            
            for col_name, df_actual_idx in current_row_cell_data:
                self.cell_data_map[(item_id, col_name)] = df_actual_idx # Map Treeview item ID to actual DataFrame index

    def apply_filters(self):
        """
        Applies both IP and date range filters to the original_df.
        """
        if self.original_df is None:
            # Only show this warning if a file hasn't been loaded yet.
            # If called from clear_filter, it might be expected to simply reset.
            if not self.df: 
                messagebox.showwarning("No Data", "Please load a CSV file first.")
            return

        filtered_df = self.original_df.copy() # Start with a fresh copy of original data

        # --- Apply IP Filter ---
        ip_filter = self.ip_filter_entry.get().strip()
        exclude_ip = self.exclude_ip_var.get()

        if ip_filter:
            if exclude_ip:
                filtered_df = filtered_df[filtered_df['ClientIPAddress'] != ip_filter]
            else:
                filtered_df = filtered_df[filtered_df['ClientIPAddress'] == ip_filter]

        # --- Apply Date Filter ---
        start_date_str = self.start_date_entry.get().strip()
        end_date_str = self.end_date_entry.get().strip()
        
        start_dt = None
        end_dt = None

        # Helper function for flexible datetime parsing
        def parse_datetime_flexible(dt_str, is_end_date=False):
            if not dt_str:
                return None
            try:
                # Try parsing with full datetime format
                return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    # Fallback to date-only format
                    dt_obj = datetime.strptime(dt_str, "%Y-%m-%d")
                    if is_end_date:
                        return dt_obj.replace(hour=23, minute=59, second=59)
                    else:
                        return dt_obj.replace(hour=0, minute=0, second=0)
                except ValueError:
                    return None # Indicate parsing failure

        start_dt = parse_datetime_flexible(start_date_str, is_end_date=False)
        end_dt = parse_datetime_flexible(end_date_str, is_end_date=True)

        if start_date_str and start_dt is None:
            messagebox.showerror("Input Error", "Invalid Start Date/Time format. Please use ISO format (YYYY-MM-DD) or (YYYY-MM-DD HH:MM:SS).")
            return
        if end_date_str and end_dt is None:
            messagebox.showerror("Input Error", "Invalid End Date/Time format. Please use ISO format (YYYY-MM-DD) or (YYYY-MM-DD HH:MM:SS).")
            return
        
        # Ensure 'DateTime' column is datetime type for comparison
        # Filter out NaT values from 'DateTime' column before comparison to avoid errors
        temp_df_for_date_filter = filtered_df[filtered_df['DateTime'].notna()]
        
        if start_dt:
            temp_df_for_date_filter = temp_df_for_date_filter[temp_df_for_date_filter['DateTime'] >= start_dt]
        if end_dt:
            temp_df_for_date_filter = temp_df_for_date_filter[temp_df_for_date_filter['DateTime'] <= end_dt]

        # Apply the date filter results back to filtered_df by re-indexing
        if start_dt or end_dt:
             filtered_df = temp_df_for_date_filter
        
        if filtered_df.empty:
            # If no results, set df to an empty DataFrame with the original columns
            self.df = pd.DataFrame(columns=self.original_df.columns) 
        else:
            self.df = filtered_df.copy() # Set the main display DataFrame

        self.update_display_dates() # Update CreationDate based on timezone settings
        self.display_data() # Refresh the Treeview
        
    def clear_filter(self):
        """
        Clears all active filters and displays the full processed dataset.
        """
        if self.original_df is None:
            messagebox.showwarning("No Data", "No data loaded to clear filters.")
            return

        self.ip_filter_entry.delete(0, tk.END)
        self.exclude_ip_var.set(False)
        self.start_date_entry.delete(0, tk.END)
        self.end_date_entry.delete(0, tk.END)
        
        # Now apply filters, which will result in no filters being active,
        # effectively showing the full original data.
        self.apply_filters()
        messagebox.showinfo("Filters Cleared", "All filters have been cleared.")

    def view_applied_filters(self):
        """
        Displays a Toplevel window to view and manage (remove) applied filters.
        """
        if self.original_df is None:
            messagebox.showwarning("No Data", "Please load a CSV file first.")
            return

        # Create a new Toplevel window for filter management
        filter_popup = tk.Toplevel(self)
        filter_popup.title("Manage Applied Filters")
        filter_popup.transient(self) # Make it appear on top of the main window
        filter_popup.grab_set() # Make it modal
        filter_popup.configure(bg=self.colors['background'])

        # Center the popup on the screen
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (filter_popup.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (filter_popup.winfo_height() // 2)
        filter_popup.geometry(f"+{x}+{y}")
        
        # Frame for filter list
        filters_frame = ttk.Frame(filter_popup, padding=15)
        filters_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(filters_frame, text="Active Filters:", font=("Inter", 11, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

        row_idx = 1
        filters_present = False

        # --- IP Filter ---
        ip_filter = self.ip_filter_entry.get().strip()
        exclude_ip = self.exclude_ip_var.get()
        if ip_filter:
            filters_present = True
            filter_text = f"IP: '{ip_filter}' ({'Exclude' if exclude_ip else 'Include'})"
            ttk.Label(filters_frame, text=filter_text, font=("Inter", 10)).grid(row=row_idx, column=0, sticky="w", pady=2, padx=5)
            ttk.Button(filters_frame, text="Remove", command=lambda: self._remove_filter('ip', filter_popup)).grid(row=row_idx, column=1, sticky="e", pady=2, padx=5)
            row_idx += 1

        # --- Date Filters ---
        start_date = self.start_date_entry.get().strip()
        end_date = self.end_date_entry.get().strip()

        if start_date:
            filters_present = True
            filter_text = f"Start Date: '{start_date}'"
            ttk.Label(filters_frame, text=filter_text, font=("Inter", 10)).grid(row=row_idx, column=0, sticky="w", pady=2, padx=5)
            ttk.Button(filters_frame, text="Remove", command=lambda: self._remove_filter('start_date', filter_popup)).grid(row=row_idx, column=1, sticky="e", pady=2, padx=5)
            row_idx += 1
        
        if end_date:
            filters_present = True
            filter_text = f"End Date: '{end_date}'"
            ttk.Label(filters_frame, text=filter_text, font=("Inter", 10)).grid(row=row_idx, column=0, sticky="w", pady=2, padx=5)
            ttk.Button(filters_frame, text="Remove", command=lambda: self._remove_filter('end_date', filter_popup)).grid(row=row_idx, column=1, sticky="e", pady=2, padx=5)
            row_idx += 1

        if not filters_present:
            ttk.Label(filters_frame, text="No filters currently applied.", font=("Inter", 10, "italic")).grid(row=row_idx, column=0, columnspan=2, sticky="w", pady=5)
            row_idx += 1

        # Close button
        ttk.Button(filter_popup, text="Close", command=filter_popup.destroy).pack(pady=10)

        # Make columns expandable within the frame
        filters_frame.grid_columnconfigure(0, weight=1)
        # filters_frame.grid_columnconfigure(1, weight=0) # Remove button column fixed size

        filter_popup.wait_window(filter_popup) # Wait until popup is closed

    def _remove_filter(self, filter_type, popup_window):
        """Helper to remove a specific filter and re-apply all filters."""
        if filter_type == 'ip':
            self.ip_filter_entry.delete(0, tk.END)
            self.exclude_ip_var.set(False)
        elif filter_type == 'start_date':
            self.start_date_entry.delete(0, tk.END)
        elif filter_type == 'end_date':
            self.end_date_entry.delete(0, tk.END)
        
        self.apply_filters() # Re-apply all filters (some will now be cleared)
        popup_window.destroy() # Close the current filter management popup
        self.view_applied_filters() # Re-open the popup to show updated filter list

    def _get_subject_from_audit_data(self, audit_data_str):
        """
        Helper to safely extract 'Subject' from AuditData JSON string.
        It checks multiple possible locations: AffectedItems[0].Subject and Item.Subject.
        """
        if pd.notna(audit_data_str):
            try:
                audit_json = json.loads(audit_data_str)
                
                # Try to get Subject from AffectedItems (e.g., SoftDelete operation)
                affected_items = audit_json.get('AffectedItems')
                if isinstance(affected_items, list) and len(affected_items) > 0:
                    subject = affected_items[0].get('Subject')
                    if subject:
                        return subject
                
                # If not found in AffectedItems, try to get Subject from Item (e.g., Send operation)
                item = audit_json.get('Item')
                if isinstance(item, dict):
                    subject = item.get('Subject')
                    if subject:
                        return subject

            except (json.JSONDecodeError, AttributeError):
                pass
        return None

    def _get_mail_access_type_value(self, audit_data_str):
        """
        Helper to safely extract 'MailAccessType' value from AuditData JSON string.
        """
        if pd.notna(audit_data_str):
            try:
                audit_json = json.loads(audit_data_str)
                operation_properties = audit_json.get('OperationProperties')
                if isinstance(operation_properties, list):
                    for prop in operation_properties:
                        if isinstance(prop, dict) and prop.get('Name') == 'MailAccessType':
                            return prop.get('Value')
            except (json.JSONDecodeError, AttributeError):
                pass
        return None

    def on_tree_motion(self, event):
        """
        Handles mouse motion over the Treeview to display comprehensive tooltips,
        including Subject and MailAccessType if available.
        """
        item = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        
        if not item or not column_id or column_id == '#0':
            self.hide_tooltip()
            return

        col_name = self.tree.heading(column_id, 'text')
        
        if col_name == '#' or not col_name:
            self.hide_tooltip()
            return

        # Retrieve the DataFrame index associated with this Treeview cell
        df_actual_idx = self.cell_data_map.get((item, col_name))
        
        if df_actual_idx is not None and df_actual_idx in self.df.index:
            # Get the row data directly from the currently displayed (filtered) DataFrame
            row_data = self.df.loc[df_actual_idx]
            
            tooltip_details = []
            tooltip_details.append(f"Operation: {row_data.get('Operation', 'N/A')}")
            tooltip_details.append(f"Creation Date: {row_data.get('CreationDate', 'N/A')}")
            tooltip_details.append(f"Client IP: {row_data.get('ClientIPAddress', 'N/A')}")
            
            # Add MailAccessType if operation is MailItemsAccessed
            if row_data.get('Operation') == "MailItemsAccessed":
                mail_access_type = self._get_mail_access_type_value(row_data.get('AuditData'))
                if mail_access_type:
                    tooltip_details.append(f"Mail Access Type: {mail_access_type}")

            # Check for Subject in AuditData
            subject = self._get_subject_from_audit_data(row_data.get('AuditData'))
            if subject:
                tooltip_details.append(f"Subject: {subject}")
            
            tooltip_details.append(f"Record ID: {row_data.get('RecordId', 'N/A')}")
            
            tooltip_text = "\n".join(tooltip_details)
            self.show_tooltip(event.x_root, event.y_root, tooltip_text)
        else:
            self.hide_tooltip()

    def on_tree_click(self, event):
        """
        Handles left-click events on the Treeview to display a pop-up with full entry details.
        """
        item = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)

        if not item or not column_id or column_id == '#0':
            return

        col_name = self.tree.heading(column_id, 'text')

        if col_name == '#' or not col_name:
            return
        
        # Retrieve the DataFrame index associated with this Treeview cell
        df_actual_idx = self.cell_data_map.get((item, col_name))

        if df_actual_idx is not None and df_actual_idx in self.df.index:
            # Get the row data directly from the currently displayed (filtered) DataFrame
            row_data = self.df.loc[df_actual_idx]
            self.show_details_popup(row_data)

    def show_details_popup(self, data_row):
        """
        Displays a mid-sized Toplevel window with all details of a specific audit log entry.
        The title of the popup will be the Subject (if found), otherwise "Entry Details".
        """
        popup = tk.Toplevel(self)
        
        # Determine the title for the popup
        subject = self._get_subject_from_audit_data(data_row.get('AuditData'))
        if subject:
            popup.title(f"\"{subject}\"")
        else:
            popup.title("Entry Details")
            
        popup.geometry("600x400")
        popup.transient(self)
        popup.grab_set()

        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (popup.winfo_width() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (popup.winfo_height() // 2)
        popup.geometry(f"+{x}+{y}")

        details_frame = ttk.Frame(popup, padding="15")
        details_frame.pack(expand=True, fill=tk.BOTH)

        row_num = 0
        displayed_keys = [] # Keep track of keys displayed to insert MailAccessType correctly

        # Order of displaying common fields
        common_fields_order = ['Operation', 'CreationDate', 'ClientIPAddress']

        for field in common_fields_order:
            if field in data_row and pd.notna(data_row[field]):
                ttk.Label(details_frame, text=f"{field}:", font=("Inter", 10, "bold")).grid(row=row_num, column=0, sticky="w", pady=2)
                ttk.Label(details_frame, text=str(data_row[field]), font=("Inter", 10)).grid(row=row_num, column=1, sticky="w", pady=2, padx=5)
                displayed_keys.append(field)
                row_num += 1
            
            # Insert MailAccessType after ClientIPAddress
            if field == 'ClientIPAddress' and data_row.get('Operation') == "MailItemsAccessed":
                mail_access_type = self._get_mail_access_type_value(data_row.get('AuditData'))
                if mail_access_type:
                    ttk.Label(details_frame, text="Mail Access Type:", font=("Inter", 10, "bold")).grid(row=row_num, column=0, sticky="w", pady=2)
                    ttk.Label(details_frame, text=mail_access_type, font=("Inter", 10)).grid(row=row_num, column=1, sticky="w", pady=2, padx=5)
                    displayed_keys.append("MailAccessType") # Placeholder to ensure it's not re-added
                    row_num += 1

        # Now add all other fields not already displayed, and handle AuditData specially
        for key, value in data_row.items():
            # Skip internal 'DateTime' and already displayed common fields
            if key == 'DateTime' or key in common_fields_order or key in displayed_keys:
                continue

            if key == 'AuditData':
                ttk.Label(details_frame, text=f"{key}:", font=("Inter", 10, "bold")).grid(row=row_num, column=0, sticky="nw", pady=2)
                text_widget = tk.Text(details_frame, wrap=tk.WORD, height=8, width=50, font=("Inter", 9))
                text_widget.insert(tk.END, str(value))
                text_widget.config(state=tk.DISABLED)
                text_widget.grid(row=row_num, column=1, sticky="nsew", pady=2, padx=5)
                text_scroll = ttk.Scrollbar(details_frame, command=text_widget.yview)
                text_scroll.grid(row=row_num, column=2, sticky='ns')
                text_widget['yscrollcommand'] = text_scroll.set
            else:
                ttk.Label(details_frame, text=f"{key}:", font=("Inter", 10, "bold")).grid(row=row_num, column=0, sticky="w", pady=2)
                ttk.Label(details_frame, text=str(value), font=("Inter", 10)).grid(row=row_num, column=1, sticky="w", pady=2, padx=5)
            row_num += 1
        
        details_frame.grid_columnconfigure(1, weight=1)
        # Configure the AuditData row to expand vertically if it's displayed
        audit_data_key_present = False
        audit_data_row_display_idx = -1 # Find its display row index
        for i in range(len(displayed_keys)):
            if displayed_keys[i] == 'AuditData':
                audit_data_key_present = True
                audit_data_row_display_idx = i # This is not accurate if not a simple linear add
                break
        
        # A simpler way to ensure the last row (or AuditData row) expands
        # Check if AuditData was actually rendered as a Text widget
        # Since we put AuditData at the end if it's not a common field,
        # it will be the last or second to last row.
        # This is a bit of a heuristic. A more robust way would be to get the actual grid position.
        # For simplicity, if AuditData is present, make the last row to grow.
        if 'AuditData' in data_row and pd.notna(data_row['AuditData']):
            details_frame.grid_rowconfigure(row_num - 1, weight=1)
        elif row_num > 0: # If AuditData not present, make the last content row expandable
            details_frame.grid_rowconfigure(row_num - 1, weight=1)
        
        close_button = ttk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack(pady=10)

        popup.wait_window(popup)

    def show_tooltip(self, x, y, text):
        """
        Displays a small Toplevel window as a tooltip.
        """
        if self.tooltip:
            self.tooltip.destroy()

        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x+10}+{y+10}")

        label = ttk.Label(self.tooltip, text=text, background=self.colors['white'], relief=tk.SOLID, borderwidth=1,
                          font=("Inter", 9), padding=5, foreground=self.colors['text'])
        label.pack(ipadx=1, ipady=1)

    def hide_tooltip(self, event=None):
        """
        Hides and destroys the current tooltip.
        """
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def split_by_ip(self):
        """
        Splits the loaded data into separate CSV files, one for each unique IP address,
        and saves them to a user-selected directory.
        """
        if self.original_df is None:
            messagebox.showwarning("No Data", "Please load a CSV file first.")
            return

        output_dir = filedialog.askdirectory(title="Select Output Directory for Split CSVs")
        if not output_dir:
            return

        unique_ips = self.original_df['ClientIPAddress'].dropna().unique()
        unique_ips = [ip for ip in unique_ips if ip != 'N/A']

        if not unique_ips:
            messagebox.showinfo("No IPs", "No valid IP addresses found in the data to split by.")
            return

        for ip in unique_ips:
            ip_df = self.original_df[self.original_df['ClientIPAddress'] == ip].copy()
            sanitized_ip = ip.replace('.', '_').replace(':', '_').replace('/', '_')
            output_file = os.path.join(output_dir, f"audit_log_ip_{sanitized_ip}.csv")
            try:
                ip_df.to_csv(output_file, index=False)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save CSV for IP {ip}: {e}")
                return

        messagebox.showinfo("Split Complete", f"CSV files split by IP and saved to:\n{output_dir}")

    def export_to_html(self):
        """
        Exports the currently displayed data (as it would appear in the Treeview)
        to an HTML file with tabs for both the filtered table, digested information, timeline, and IP breakdown,
        including hover functionality for detailed tooltips and click-for-details popups.
        """
        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "No data to export. Please load and/or apply filters to display data first.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Save Filtered Table HTML As"
        )
        if not file_path:
            return

        try:
            report_title = self.html_title_entry.get().strip()
            if not report_title:
                report_title = "Audit Log Report"

            report_comments = self.comments_text.get("1.0", tk.END).strip()

            # Get current timezone info for HTML
            current_tz = self.selected_timezone.get()
            show_local = self.display_local_time.get()
            timezone_note = f" (Displayed in {current_tz})" if show_local and current_tz != "UTC" else " (UTC)"

            # Generate table data with chronological sorting (same logic as display_data)
            all_entries_by_operation = {}
            for df_index, row_data_from_df in self.df.iterrows():
                operation = row_data_from_df['Operation']
                if pd.isna(operation):
                    continue

                if operation not in all_entries_by_operation:
                    all_entries_by_operation[operation] = []
                
                all_entries_by_operation[operation].append(row_data_from_df)
            
            # Sort entries within each operation by DateTime chronologically (oldest first)
            for operation in all_entries_by_operation:
                # Sort by DateTime column, handling NaT values by putting them at the end
                all_entries_by_operation[operation].sort(
                    key=lambda x: x['DateTime'] if pd.notna(x['DateTime']) else pd.Timestamp.max
                )
            
            unique_operations = sorted(all_entries_by_operation.keys())
            max_rows = 0
            for op_list in all_entries_by_operation.values():
                max_rows = max(max_rows, len(op_list))

            # Generate CSV content
            export_df_for_csv = self.df.drop(columns=['DateTime'], errors='ignore')
            csv_data_string = export_df_for_csv.to_csv(index=False)
            csv_data_string_escaped = json.dumps(csv_data_string)

            # Generate digested information data
            digested_data = self._generate_digested_data()

            # Generate timeline data
            timeline_data = self._generate_timeline_data()

            # Generate IP breakdown data with timezone info
            ip_data = {}
            if self.original_df is not None:
                unique_ips = self.original_df['ClientIPAddress'].dropna().unique()
                unique_ips = [ip for ip in unique_ips if ip != 'N/A']

                for ip in unique_ips:
                    ip_df = self.original_df[self.original_df['ClientIPAddress'] == ip].copy()
                    
                    # Get first appearance in both UTC and local time
                    first_appearance_utc = 'N/A'
                    first_appearance_local = 'N/A'
                    
                    if not ip_df['DateTime'].empty:
                        first_dt = ip_df['DateTime'].min()
                        if pd.notna(first_dt):
                            first_appearance_utc = first_dt.strftime("%Y-%m-%dT%H:%M:%S") + " UTC"
                            if current_tz != "UTC":
                                local_str, _ = self.convert_utc_to_timezone(first_dt, current_tz)
                                first_appearance_local = f"{local_str} {current_tz}"
                    
                    total_entries = len(ip_df)
                    
                    operation_counts = ip_df['Operation'].value_counts()
                    operation_percentages = (operation_counts / total_entries * 100).round(2)
                    
                    labels = json.dumps(operation_percentages.index.tolist())
                    data_values = json.dumps(operation_percentages.values.tolist())
                    
                    ip_data[ip] = {
                        'first_appearance_utc': first_appearance_utc,
                        'first_appearance_local': first_appearance_local,
                        'total_entries': total_entries,
                        'chart_labels': labels,
                        'chart_data': data_values
                    }

            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #F5F5F5; color: #333333; }}
        h1 {{ color: #333333; text-align: center; margin-bottom: 20px; }}
        .header-container {{ display: flex; justify-content: center; align-items: center; margin-bottom: 30px; }}
        .header-container h1 {{ margin: 0; }}
        .timezone-note {{
            text-align: center;
            font-style: italic;
            color: #333333;
            margin-bottom: 20px;
            font-size: 0.9em;
        }}
        .action-button {{
            margin-left: 20px;
            padding: 8px 15px;
            background-color: #607D8B;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background-color 0.2s;
        }}
        .action-button:hover {{
            background-color: #546E7A;
        }}

        /* Tab styles */
        .tab-container {{
            margin-bottom: 20px;
        }}
        .tab-buttons {{
            display: flex;
            border-bottom: 1px solid #CCCCCC;
            background-color: #F5F5F5;
            border-radius: 8px 8px 0 0;
        }}
        .tab-button {{
            padding: 12px 24px;
            background-color: transparent;
            border: none;
            cursor: pointer;
            font-size: 1em;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
            color: #333333;
        }}
        .tab-button.active {{
            background-color: #FFFFFF;
            border-bottom-color: #607D8B;
            color: #607D8B;
            font-weight: bold;
        }}
        .tab-button:hover {{
            background-color: #E0E0E0;
        }}
        .tab-content {{
            display: none;
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 0 0 8px 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}
        .tab-content.active {{
            display: block;
        }}

        /* Operation sub-tabs styles */
        .operation-tabs-container {{
            margin-top: 20px;
        }}
        .operation-tab-buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            border-bottom: 1px solid #CCCCCC;
            background-color: #F5F5F5;
            padding: 10px;
            border-radius: 6px 6px 0 0;
        }}
        .operation-tab-button {{
            padding: 8px 16px;
            background-color: transparent;
            border: 1px solid #CCCCCC;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s ease;
            white-space: nowrap;
            color: #333333;
        }}
        .operation-tab-button.active {{
            background-color: #607D8B;
            color: white;
            border-color: #607D8B;
        }}
        .operation-tab-button:hover {{
            background-color: #E0E0E0;
        }}
        .operation-tab-button.active:hover {{
            background-color: #546E7A;
        }}
        .operation-tab-contents {{
            border: 1px solid #CCCCCC;
            border-top: none;
            background-color: #FFFFFF;
            border-radius: 0 0 6px 6px;
        }}
        .operation-tab-content {{
            display: none;
            padding: 20px;
        }}
        .operation-tab-content.active {{
            display: block;
        }}
        .operation-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            gap: 20px;
            border-bottom: 2px solid #CCCCCC;
        }}
        .operation-header h3 {{
            margin: 0;
            color: #333333;
            font-size: 1.3em;
        }}
        .operation_description {{
            width: 100%;
            text-align: left;
            display: flex;
            position: relative;
        }}
        .operation_description p.operation_description_trigger {{
            display: flex;
            flex-direction: row;
            align-items: center;
            justify-content: center;
            padding: 0.5em;
            border-radius: 50%;
            background-color: #007bff0f;
            cursor: pointer;
            width: 30px;
            height: 30px;
            margin: 0px;
        }}
        .operation_description p.operation_description_text {{
            position: absolute;
            width: 380px;
            background-color: white;
            opacity: 0;
            left: 56px;
            top: -1em;
            transition: opacity 0.3s ease;
            z-index: 100;
            padding: 1em;
        }}
        .operation_description .operation_description_trigger:hover + p {{
            opacity: 1;
        }}
        .export-ids-btn {{
            padding: 6px 12px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
            transition: background-color 0.2s;
        }}
        .export-ids-btn:hover {{
            background-color: #218838;
        }}

        /* Compact tree styles */
        .tree-container {{
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 1px;
            border: 1px solid #e9ecef;
        }}
        .tree-ascii {{
            font-family: 'Courier New', 'Monaco', monospace;
            font-size: 0.85em;
            line-height: 1.1;
        }}
        .tree-line {{
            margin: 0;
            padding: 1px 0;
            display: flex;
            align-items: flex-start;
        }}
        .connector {{
            color: #6c757d;
            font-weight: bold;
            min-width: fit-content;
            margin-right: 6px;
        }}
        .date-title {{
            font-weight: bold;
            color: #495057;
            background-color: #e8f4fd;
            padding: 2px 6px;
            border-radius: 3px;
            border-left: 3px solid #007bff;
            position: relative;
        }}
        .folder-title {{
            color: #6f42c1;
            font-weight: 600;
            background-color: #f8f0ff;
            padding: 1px 0px;
            border-radius: 2px;
        }}
        .subject-title {{
            color: #20c997;
            background-color: #e8f5e8;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .rule-title {{
            color: #fd7e14;
            font-weight: 600;
            background-color: #fff3cd;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .param-title {{
            color: #0dcaf0;
            background-color: #e1f7ff;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .item-id {{
            color: #dc3545;
            font-family: 'Courier New', monospace;
            background-color: #f8d7da;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .info-title {{
            color: #6c757d;
            background-color: #f1f3f4;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .error-title {{
            color: #dc3545;
            font-style: italic;
            background-color: #f8d7da;
            padding: 1px 4px;
            border-radius: 2px;
        }}
        .no-data {{
            color: #6c757d;
            font-style: italic;
            text-align: center;
            padding: 40px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            background-color: #fff;
            border-radius: 8px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px 15px;
            text-align: center;
            vertical-align: top;
            position: relative;
            word-wrap: break-word;
            max-width: 250px;
            cursor: pointer;
        }}
        th {{
            background-color: #34495e;
            color: #ecf0f1;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        tr:nth-child(even) {{
            background-color: #f6f9fc;
        }}
        tr:hover {{
            background-color: #e8f0f3;
        }}

        /* IP Breakdown styles */
        .ip-section {{
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            margin-bottom: 25px;
            padding: 20px;
            display: flex;
            align-items: flex-start;
            gap: 30px;
            flex-wrap: wrap;
        }}
        .ip-info {{
            flex: 1;
            min-width: 250px;
        }}
        .ip-info h3 {{
            color: #34495e;
            margin-top: 0;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 10px;
            font-size: 1.3em;
        }}
        .ip-info p {{
            margin: 8px 0;
            font-size: 1.05em;
        }}
        .timezone-info {{
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }}
        .chart-container {{
            flex: 1;
            min-width: 300px;
            max-width: 400px;
            height: 300px;
        }}
        .operation-list {{
            list-style: none;
            padding: 0;
            margin-top: 15px;
        }}
        .operation-list li {{
            margin-bottom: 5px;
            font-size: 0.95em;
        }}
        .operation-list li strong {{
            display: inline-block;
            min-width: 100px;
        }}

        /* Tooltip and modal styles remain the same */
        [data-tooltip]::before {{
            content: attr(data-tooltip);
            position: absolute;
            top: calc(100% + 5px);
            left: 50%;
            transform: translateX(-50%);
            background-color: rgba(44, 62, 80, 0.95);
            color: #fff;
            padding: 10px 15px;
            border-radius: 6px;
            white-space: pre-wrap;
            z-index: 100;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease-in-out, visibility 0.3s ease-in-out;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            min-width: 280px;
            max-width: 400px;
            text-align: left;
            pointer-events: none;
        }}

        [data-tooltip]:hover::before {{
            opacity: 1;
            visibility: visible;
        }}

        .modal {{
            display: none;
            position: fixed;
            z-index: 200;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }}

        .modal-content {{
            background-color: #fefefe;
            margin: 10% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 700px;
            border-radius: 10px;
            box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2),0 6px 20px 0 rgba(0,0,0,0.19);
            position: relative;
        }}
        
        .modal-header {{
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 15px;
            text-align: center;
        }}
        .modal-header h2 {{
            margin: 0;
            color: #34495e;
        }}

        .modal-body {{
            line-height: 1.6;
        }}
        .modal-body p {{
            margin: 5px 0;
            font-size: 0.95em;
        }}
        .modal-body strong {{
            display: inline-block;
            min-width: 120px;
            color: #2c3e50;
        }}
        .modal-body pre {{
            background-color: #eee;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}

        .modal-footer {{
            padding-top: 15px;
            border-top: 1px solid #eee;
            margin-top: 20px;
            text-align: center;
        }}

        .close-button {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}

        .close-button:hover,
        .close-button:focus {{
            color: black;
            text-decoration: none;
            cursor: pointer;
        }}

        .sync-tint {{
            background-color: #FFEEEE;
        }}
    </style>
</head>
<body>
    <div class="header-container">
        <h1>{report_title}</h1>
        <button class="action-button" onclick="showComments()">View Comments</button>
        <button class="action-button" onclick="downloadCSV()">Download Filtered CSV</button>
    </div>
    
    <div class="timezone-note">All times displayed{timezone_note}</div>

    <div class="tab-container">
        <div class="tab-buttons">
            <button class="tab-button active" onclick="openTab(event, 'tableTab')">Filtered Table</button>
            <button class="tab-button" onclick="openTab(event, 'digestedTab')">Digested Information</button>
            <button class="tab-button" onclick="openTab(event, 'timelineTab')">Timeline</button>
            <button class="tab-button" onclick="openTab(event, 'breakdownTab')">IP Breakdown</button>
        </div>

        <div id="tableTab" class="tab-content active">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
"""
            for header in unique_operations:
                html_content += f"                        <th>{header}</th>\n"
            html_content += """
                    </tr>
                </thead>
                <tbody>
"""
            # Generate table rows (existing logic)
            for row_idx in range(max_rows):
                html_content += "                    <tr>\n"
                html_content += f"                        <td>{row_idx + 1}</td>\n"

                for op_col in unique_operations:
                    op_entries = all_entries_by_operation.get(op_col, [])
                    
                    cell_class = ""
                    current_entry_data = None

                    if row_idx < len(op_entries):
                        current_entry_data = op_entries[row_idx]
                        
                        if op_col == "MailItemsAccessed":
                            mail_access_type = self._get_mail_access_type_value(current_entry_data.get('AuditData'))
                            if mail_access_type == "Sync":
                                cell_class = "sync-tint"
                        
                        tooltip_text = (
                            f"Operation: {current_entry_data.get('Operation', 'N/A')}\n"
                            f"Creation Date: {current_entry_data.get('CreationDate', 'N/A')}{timezone_note}\n"
                            f"Client IP: {current_entry_data.get('ClientIPAddress', 'N/A')}\n"
                        )
                        
                        if current_entry_data.get('Operation') == "MailItemsAccessed":
                            mail_access_type_val = self._get_mail_access_type_value(current_entry_data.get('AuditData'))
                            if mail_access_type_val:
                                tooltip_text += f"Mail Access Type: {mail_access_type_val}\n"

                        subject = self._get_subject_from_audit_data(current_entry_data.get('AuditData'))
                        if subject:
                            tooltip_text += f"Subject: {subject}\n"

                        tooltip_text += f"Record ID: {current_entry_data.get('RecordId', 'N/A')}"
                        
                        tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
                        
                        full_details = {k: str(v) for k, v in current_entry_data.items() if pd.notna(v) and k != 'DateTime'}
                        full_details_json = json.dumps(full_details)
                        full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')

                        html_content += (
                            f"                        <td class=\"{cell_class}\" data-tooltip=\"{tooltip_text_encoded}\" "
                            f"onclick=\"showDetails(this)\" data-fulldetails=\"{full_details_json_encoded}\">{current_entry_data['CreationDate']}</td>\n"
                        )
                    else:
                        html_content += "                        <td></td>\n"
                html_content += "                    </tr>\n"
            
            html_content += """
                </tbody>
            </table>
        </div>

        <div id="digestedTab" class="tab-content">
"""
            # Generate digested information content
            html_content += digested_data

            html_content += """
        </div>

        <div id="timelineTab" class="tab-content">
"""
            # Generate timeline content
            html_content += timeline_data

            html_content += """
        </div>

        <div id="breakdownTab" class="tab-content">
"""
            # Generate IP breakdown content with timezone information
            if ip_data:
                # Add overall IP traffic pie chart at the top
                overall_ip_labels = json.dumps(list(ip_data.keys()))
                overall_ip_data = json.dumps([ip_data[ip]['total_entries'] for ip in ip_data])
                
                html_content += f"""
            <!-- Overall IP traffic distribution -->
            <div class="ip-section" style="flex-direction:column; align-items:center;">
                <h3>Overall IP Traffic Distribution</h3>
                <div class="chart-container" style="max-width:600px;">
                    <canvas id="chart_overall_ip_traffic"></canvas>
                </div>
            </div>
"""

                for ip, data in ip_data.items():
                    sanitized_ip_id = ip.replace('.', '_').replace(':', '_').replace('/', '_')
                    # Create anchor ID for this IP section
                    ip_anchor = f"ip_{sanitized_ip_id}"
                    
                    op_list_html = ""
                    labels_py = json.loads(data['chart_labels'])
                    data_py = json.loads(data['chart_data'])
                    
                    for i in range(len(labels_py)):
                        op_list_html += f"<li><strong>{labels_py[i]}:</strong> {data_py[i]}%</li>"

                    # Prepare first seen display
                    first_seen_display = data['first_appearance_utc']
                    if current_tz != "UTC" and data['first_appearance_local'] != 'N/A':
                        first_seen_display += f"<div class='timezone-info'>{data['first_appearance_local']}</div>"

                    html_content += f"""
            <div class="ip-section" id="{ip_anchor}">
                <div class="ip-info">
                    <h3>IP Address: {ip}</h3>
                    <p><strong>First Seen:</strong><br>{first_seen_display}</p>
                    <p><strong>Total Entries:</strong> {data['total_entries']}</p>
                    <h4>Operations Breakdown:</h4>
                    <ul class="operation-list">
                        {op_list_html}
                    </ul>
                </div>
                <div class="chart-container">
                    <canvas id="chart_{sanitized_ip_id}"></canvas>
                </div>
            </div>
"""
                # ...existing code for else condition...

            html_content += """
        </div>
    </div>

    <!-- Modals remain the same -->
    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close-button" onclick="hideDetails()">&times;</span>
                <h2 id="modalTitle">Entry Details</h2>
            </div>
            <div class="modal-body" id="modalBody">
                </div>
            <div class="modal-footer">
                <button onclick="hideDetails()">Close</button>
            </div>
        </div>
    </div>

    <div id="commentsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close-button" onclick="hideComments()">&times;</span>
                <h2>Report Comments</h2>
            </div>
            <div class="modal-body" id="commentsBody">
"""
            if report_comments:
                formatted_comments = report_comments.replace('\n', '<br>')
                html_content += f"                <p>{formatted_comments}</p>\n"
            else:
                html_content += "                <p>No comments provided for this report.</p>\n"

            html_content += """
            </div>
            <div class="modal-footer">
                <button onclick="hideComments()">Close</button>
            </div>
        </div>
    </div>

    <script>
        const csvData = """ + csv_data_string_escaped + """;

        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("active");
            }
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");

            // Initialize charts when breakdown tab is opened
            if (tabName === 'breakdownTab') {
                setTimeout(initializeCharts, 100);
            }
        }

        function openOperationTab(evt, operationName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("operation-tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            tablinks = document.getElementsByClassName("operation-tab-button");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("active");
            }
            document.getElementById(operationName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }

        function exportIds(operation, ids) {
            const blob = new Blob([ids.join('\\n')], { type: 'text/plain;charset=utf-8;' });
            const link = document.createElement('a');
            if (link.download !== undefined) {
                const url = URL.createObjectURL(blob);
                link.setAttribute('href', url);
                link.setAttribute('download', `${operation}_ids.txt`);
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        }

        function initializeCharts() {
            const backgroundColors = [
                'rgba(255, 99, 132, 0.7)',
                'rgba(54, 162, 235, 0.7)',
                'rgba(255, 206, 86, 0.7)',
                'rgba(75, 192, 192, 0.7)',
                'rgba(153, 102, 255, 0.7)',
                'rgba(255, 159, 64, 0.7)',
                'rgba(199, 199, 199, 0.7)',
                'rgba(83, 102, 169, 0.7)',
                'rgba(214, 96, 126, 0.7)',
                'rgba(140, 193, 82, 0.7)'
            ];
            const borderColors = [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)',
                'rgba(199, 199, 199, 1)',
                'rgba(83, 102, 169, 1)',
                'rgba(214, 96, 126, 1)',
                'rgba(140, 193, 82, 1)'
            ];

            // Initialize the overall IP traffic chart
            const overallIpCtx = document.getElementById('chart_overall_ip_traffic');
            if (overallIpCtx && !overallIpCtx.chart) {
                const overallIpLabels = """ + overall_ip_labels + """;
                const overallIpData = """ + overall_ip_data + """;
                
                overallIpCtx.chart = new Chart(overallIpCtx, {
                    type: 'pie',
                    data: {
                        labels: overallIpLabels,
                        datasets: [{
                            data: overallIpData,
                            backgroundColor: backgroundColors,
                            borderColor: borderColors,
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    font: {
                                        size: 12
                                    }
                                }
                            },
                            title: {
                                display: false,
                                text: 'IP Traffic Distribution',
                                font: {
                                    size: 16
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        let label = context.label || '';
                                        if (label) {
                                            label += ': ';
                                        }
                                        if (context.parsed !== null) {
                                            label += context.parsed + ' entries';
                                        }
                                        return label;
                                    }
                                }
                            }
                        },
                        onClick: function(e, activeElements) {
                            if (activeElements.length > 0) {
                                const clickedIndex = activeElements[0].index;
                                const ip = overallIpLabels[clickedIndex];
                                const sanitizedId = ip.replace(/\\./g, '_').replace(/:/g, '_').replace(/\\//g, '_');
                                const anchorId = `ip_${sanitizedId}`;
                                document.getElementById(anchorId).scrollIntoView({behavior: 'smooth'});
                            }
                        }
                    }
                });
            }

            // Generate Chart.js initialization for each IP
"""

            # Generate Chart.js initialization for each IP
            for ip, data in ip_data.items():
                sanitized_ip_id = ip.replace('.', '_').replace(':', '_').replace('/', '_')
                html_content += f"""
            const chart_{sanitized_ip_id} = document.getElementById('chart_{sanitized_ip_id}');
            if (chart_{sanitized_ip_id} && !chart_{sanitized_ip_id}.chart) {{
                chart_{sanitized_ip_id}.chart = new Chart(chart_{sanitized_ip_id}, {{
                    type: 'pie',
                    data: {{
                        labels: {data['chart_labels']},
                        datasets: [{{
                            data: {data['chart_data']},
                            backgroundColor: backgroundColors,
                            borderColor: borderColors,
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{
                                position: 'right',
                                labels: {{
                                    font: {{
                                        size: 12
                                    }}
                                }}
                            }},
                            title: {{
                                display: true,
                                text: 'Operation Distribution for {ip}',
                                font: {{
                                    size: 14
                                }}
                            }},
                            tooltip: {{
                                callbacks: {{
                                    label: function(context) {{
                                        let label = context.label || '';
                                        if (label) {{
                                            label += ': ';
                                        }}
                                        if (context.parsed !== null) {{
                                            label += context.parsed + '%';
                                        }}
                                        return label;
                                    }}
                                }}
                            }}
                        }}
                    }}
                }});
            }}
"""

            html_content += """
        }

        function downloadCSV() {
            const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            if (link.download !== undefined) {
                const url = URL.createObjectURL(blob);
                link.setAttribute('href', url);
                link.setAttribute('download', 'filtered_audit_log.csv');
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        }

        function showDetails(element) {
            const modal = document.getElementById('detailsModal');
            const modalBody = document.getElementById('modalBody');
            const modalTitle = document.getElementById('modalTitle');
            const detailsJson = element.getAttribute('data-fulldetails');
            
            if (!detailsJson) {
                console.error("No full details found for this element.");
                return;
            }

            try {
                const details = JSON.parse(detailsJson);
                modalBody.innerHTML = '';

                let subject = null;
                let mailAccessType = null;

                if (details.hasOwnProperty('AuditData')) {
                    try {
                        const auditDataObj = JSON.parse(details['AuditData']);
                        
                        if (auditDataObj.hasOwnProperty('AffectedItems') && Array.isArray(auditDataObj.AffectedItems) && auditDataObj.AffectedItems.length > 0) {
                            subject = auditDataObj.AffectedItems[0].Subject;
                        }
                        if (!subject && auditDataObj.hasOwnProperty('Item') && typeof auditDataObj.Item === 'object' && auditDataObj.Item !== null) {
                            subject = auditDataObj.Item.Subject;
                        }

                        if (auditDataObj.hasOwnProperty('OperationProperties') && Array.isArray(auditDataObj.OperationProperties)) {
                            for (const prop of auditDataObj.OperationProperties) {
                                if (prop.Name === 'MailAccessType') {
                                    mailAccessType = prop.Value;
                                    break;
                                }
                            }
                        }

                    } catch (e) {
                        console.warn("Could not parse AuditData for Subject/MailAccessType:", e);
                    }
                }
                modalTitle.textContent = subject ? `"${escapeHtml(subject)}"` : "Entry Details";

                const commonFieldsOrder = ['Operation', 'CreationDate', 'ClientIPAddress'];
                for (const key of commonFieldsOrder) {
                    if (details.hasOwnProperty(key)) {
                        modalBody.innerHTML += `<p><strong>${escapeHtml(key)}:</strong> ${escapeHtml(details[key])}</p>`;
                    }
                    if (key === 'ClientIPAddress' && mailAccessType) {
                        modalBody.innerHTML += `<p><strong>Mail Access Type:</strong> ${escapeHtml(mailAccessType)}</p>`;
                    }
                }

                for (const key in details) {
                    if (details.hasOwnProperty(key) && !commonFieldsOrder.includes(key) && key !== 'DateTime') {
                        let value = details[key];
                        if (key === 'AuditData' && typeof value === 'string') {
                            try {
                                const auditDataObj = JSON.parse(value);
                                value = '<pre>' + JSON.stringify(auditDataObj, null, 2) + '</pre>';
                            } catch (e) {
                                value = '<pre>' + escapeHtml(value) + '</pre>';
                            }
                        } else {
                            value = escapeHtml(value);
                        }
                        modalBody.innerHTML += `<p><strong>${escapeHtml(key)}:</strong> ${value}</p>`;
                    }
                }
                modal.style.display = "block";
            } catch (e) {
                console.error("Error parsing full details JSON:", e);
                modalBody.innerHTML = '<p>Error loading details.</p>';
                modalTitle.textContent = "Error Details";
                modal.style.display = "block";
            }
        }

        function hideDetails() {
            const modal = document.getElementById('detailsModal');
            modal.style.display = "none";
        }

        function showComments() {
            const modal = document.getElementById('commentsModal');
            modal.style.display = "block";
        }

        function hideComments() {
            const modal = document.getElementById('commentsModal');
            modal.style.display = "none";
        }

        window.onclick = function(event) {
            const detailsModal = document.getElementById('detailsModal');
            const commentsModal = document.getElementById('commentsModal');
            if (event.target == detailsModal) {
                detailsModal.style.display = "none";
            }
            if (event.target == commentsModal) {
                commentsModal.style.display = "none";
            }
        }

        function escapeHtml(text) {
            if (text === null || text === undefined) return '';
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
        }
    </script>
</body>
</html>
"""
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            messagebox.showinfo("Export Complete", f"Data successfully exported to HTML with tabs:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export to HTML: {e}")

    def _generate_digested_data(self):
        """
        Generate the digested information content for different operation types with sub-tabs.
        """
        # Group data by operation type
        operations_data = {}
        for _, row in self.df.iterrows():
            operation = row.get('Operation', 'Unknown')
            if operation not in operations_data:
                operations_data[operation] = []
            operations_data[operation].append(row)
        
        if not operations_data:
            return '<div class="no-data">No data available for digested view.</div>'
        
        # Sort operations
        sorted_operations = sorted(operations_data.keys())
        
        html_content = """
            <div class="operation-tabs-container">
                <div class="operation-tab-buttons">
"""
        
        # Generate operation sub-tab buttons
        for i, operation in enumerate(sorted_operations):
            active_class = "active" if i == 0 else ""
            html_content += f"""
                    <button class="operation-tab-button {active_class}" onclick="openOperationTab(event, '{operation}')">{operation}</button>
"""
        
        html_content += """
                </div>
                <div class="operation-tab-contents">
"""
        
        operation_descriptions = {
            'HardDelete': 'Items permanently deleted from the mailbox.',
            'MoveToDeletedItems': 'Items moved to the Deleted Items folder.',
            'Send': 'Items sent from the mailbox.',
            'SoftDelete': 'Items deleted but retained in the mailbox.',
            'Update': 'Items updated in the mailbox.',
            'MailItemsAccessed': 'Items accessed in the mailbox.',
            'New-InboxRule': 'New inbox rules created.',
            'Create': 'New items created in the mailbox.'
        }
        # Generate content for each operation
        for i, operation in enumerate(sorted_operations):
            entries = operations_data[operation]
            
            # Sort entries chronologically
            entries.sort(key=lambda x: x['DateTime'] if pd.notna(x['DateTime']) else pd.Timestamp.max)
            
            all_ids = []  # Collect all IDs for export
            active_class = "active" if i == 0 else ""
            
            html_content += f"""
                <div id="{operation}" class="operation-tab-content {active_class}">
                    <div class="operation-header">
                        <h3>{operation}</h3>
                        <div class="operation_description">
                            <p class="operation_description_trigger">?</p>
                            <p class="operation_description_text">{ operation_descriptions.get(operation, 'No description available.') }</p>
                        </div>
                        <button class="export-ids-btn" onclick="exportIds('{operation}', {json.dumps([])})">Export IDs</button>
                    </div>
                    <div class="tree-container">
"""
            
            if operation in ['HardDelete', 'MoveToDeletedItems', 'Send', 'SoftDelete', 'Update']:
                html_content += self._generate_affected_items_tree_compact(entries, all_ids)
            elif operation == 'MailItemsAccessed':
                html_content += self._generate_mail_items_tree_compact(entries, all_ids)
            elif operation == 'New-InboxRule':
                html_content += self._generate_inbox_rule_tree_compact(entries)
            elif operation == 'Create':
                html_content += self._generate_generic_tree_compact(entries)
            else:
                html_content += self._generate_generic_tree_compact(entries)
            
            # Update the export button with actual IDs
            if all_ids:
                ids_json = json.dumps(all_ids).replace('"', '&quot;')
                html_content = html_content.replace(
                    f'onclick="exportIds(\'{operation}\', {json.dumps([])})"',
                    f'onclick="exportIds(\'{operation}\', {ids_json})"'
                )
            
            html_content += """
                    </div>
                </div>
"""
        
        html_content += """
                </div>
            </div>
"""
        
        return html_content

    def _generate_timeline_data(self):
        """
        Generate chronological timeline view of all entries using tree format.
        """
        # Get all entries and sort chronologically
        all_entries = []
        for _, row in self.df.iterrows():
            all_entries.append(row)
        
        # Sort all entries by DateTime (oldest first)
        all_entries.sort(key=lambda x: x['DateTime'] if pd.notna(x['DateTime']) else pd.Timestamp.max)
        
        if not all_entries:
            return '<div class="no-data">No data available for timeline view.</div>'
        
        html_content = """
            <div class="tree-container">
                <div class="tree-ascii">
"""
        
        for entry_idx, entry in enumerate(all_entries):
            operation = entry.get('Operation', 'Unknown')
            creation_date = entry.get('CreationDate', 'N/A')
            is_last_entry = entry_idx == len(all_entries) - 1
            entry_connector = "└──" if is_last_entry else "├──"
            
            # Prepare tooltip and full details for clickable CreationDate
            tooltip_text = (
                f"Operation: {operation}\n"
                f"Creation Date: {creation_date}\n"
                f"Client IP: {entry.get('ClientIPAddress', 'N/A')}\n"
            )
            
            if operation == "MailItemsAccessed":
                mail_access_type = self._get_mail_access_type_value(entry.get('AuditData'))
                if mail_access_type:
                    tooltip_text += f"Mail Access Type: {mail_access_type}\n"

            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            if subject:
                tooltip_text += f"Subject: {subject}\n"

            tooltip_text += f"Record ID: {entry.get('RecordId', 'N/A')}"
            
            full_details = {k: str(v) for k, v in entry.items() if pd.notna(v) and k != 'DateTime'}
            full_details_json = json.dumps(full_details)
            
            tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
            full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')
            
            html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{entry_connector}</span>
                        <span class="date-title" style="cursor: pointer;" data-tooltip="{tooltip_text_encoded}" onclick="showDetails(this)" data-fulldetails="{full_details_json_encoded}">{creation_date}</span>
                        <span style="margin-left: 10px; color: #666; font-size: 0.9em;">({operation})</span>
                    </div>
"""
            
            # Generate operation-specific tree content
            if operation in ['HardDelete', 'MoveToDeletedItems', 'Send', 'SoftDelete', 'Update']:
                html_content += self._generate_timeline_affected_items_tree(entry, is_last_entry)
            elif operation == 'MailItemsAccessed':
                html_content += self._generate_timeline_mail_items_tree(entry, is_last_entry)
            elif operation == 'New-InboxRule':
                html_content += self._generate_timeline_inbox_rule_tree(entry, is_last_entry)
            elif operation == 'Create':
                html_content += self._generate_timeline_generic_tree(entry, is_last_entry)
            else:
                html_content += self._generate_timeline_generic_tree(entry, is_last_entry)
        
        html_content += """
                </div>
            </div>
"""
        
        return html_content

    def _generate_timeline_affected_items_tree(self, entry, is_last_entry):
        """Generate timeline tree content for operations with AffectedItems"""
        html_content = ""
        audit_data_str = entry.get('AuditData')
        
        if pd.notna(audit_data_str):
            try:
                audit_json = json.loads(audit_data_str)
                affected_items = audit_json.get('AffectedItems', [])
                
                if affected_items:
                    # Group by parent folder path
                    folders = {}
                    for item in affected_items:
                        parent_folder = item.get('ParentFolder', {})
                        path = parent_folder.get('Path', 'Unknown Path')
                        if path not in folders:
                            folders[path] = []
                        folders[path].append(item)
                    
                    folder_list = list(folders.items())
                    for folder_idx, (path, items) in enumerate(folder_list):
                        is_last_folder = folder_idx == len(folder_list) - 1
                        folder_prefix = "    " if is_last_entry else "│   "
                        folder_connector = "└──" if is_last_folder else "├──"
                        
                        html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{folder_prefix}{folder_connector}</span>
                        <span class="folder-title">{path}</span>
                    </div>
"""
                        
                        for item_idx, item in enumerate(items):
                            is_last_item = item_idx == len(items) - 1
                            item_prefix = "    " if is_last_entry else "│   "
                            item_prefix += "    " if is_last_folder else "│   "
                            item_connector = "└──" if is_last_item else "├──"
                            
                            subject = item.get('Subject', 'No Subject')
                            
                            html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{item_prefix}{item_connector}</span>
                        <span class="subject-title">{subject}</span>
                    </div>
"""
                else:
                    # Check for single Item (like in Send operation)
                    item = audit_json.get('Item', {})
                    if item:
                        subject = item.get('Subject', 'No Subject')
                        parent_folder = item.get('ParentFolder', {})
                        path = parent_folder.get('Path', 'Unknown Path')
                        
                        folder_prefix = "    " if is_last_entry else "│   "
                        
                        html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{folder_prefix}├──</span>
                        <span class="folder-title">{path}</span>
                    </div>
                    <div class="tree-line">
                        <span class="connector">{folder_prefix}    └──</span>
                        <span class="subject-title">{subject}</span>
                    </div>
"""
            except (json.JSONDecodeError, TypeError):
                error_prefix = "    " if is_last_entry else "│   "
                html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{error_prefix}└──</span>
                        <span class="error-title">Error parsing audit data</span>
                    </div>
"""
        
        return html_content

    def _generate_timeline_mail_items_tree(self, entry, is_last_entry):
        """Generate timeline tree content for MailItemsAccessed operations"""
        html_content = ""
        audit_data_str = entry.get('AuditData')
        
        if pd.notna(audit_data_str):
            try:
                audit_json = json.loads(audit_data_str)
                folders = audit_json.get('Folders', [])
                
                for folder_idx, folder in enumerate(folders):
                    path = folder.get('Path', 'Unknown Path')
                    folder_items = folder.get('FolderItems', [])
                    
                    is_last_folder = folder_idx == len(folders) - 1
                    folder_prefix = "    " if is_last_entry else "│   "
                    folder_connector = "└──" if is_last_folder else "├──"
                    
                    html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{folder_prefix}{folder_connector}</span>
                        <span class="folder-title">{path}</span>
                    </div>
"""
                    
                    for item_idx, item in enumerate(folder_items):
                        is_last_item = item_idx == len(folder_items) - 1
                        item_prefix = "    " if is_last_entry else "│   "
                        item_prefix += "    " if is_last_folder else "│   "
                        item_connector = "└──" if is_last_item else "├──"
                        
                        item_id = item.get('Id', '')
                        if item_id:
                            # Extract the last part of the ID for display
                            display_id = item_id.split('/')[-1] if '/' in item_id else item_id
                            
                            html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{item_prefix}{item_connector}</span>
                        <span class="item-id">...{display_id}</span>
                    </div>
"""
                    
            except (json.JSONDecodeError, TypeError):
                error_prefix = "    " if is_last_entry else "│   "
                html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{error_prefix}└──</span>
                        <span class="error-title">Error parsing audit data</span>
                    </div>
"""
        
        return html_content

    def _generate_timeline_inbox_rule_tree(self, entry, is_last_entry):
        """Generate timeline tree content for New-InboxRule operations"""
        html_content = ""
        audit_data_str = entry.get('AuditData')
        
        if pd.notna(audit_data_str):
            try:
                audit_json = json.loads(audit_data_str)
                parameters = audit_json.get('Parameters', [])
                
                # Find the Name parameter first
                rule_name = "Unknown Rule"
                for param in parameters:
                    if param.get('Name') == 'Name':
                        rule_name = param.get('Value', 'Unknown Rule')
                        break
                
                rule_prefix = "    " if is_last_entry else "│   "
                html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{rule_prefix}├──</span>
                        <span class="rule-title">Rule: {rule_name}</span>
                    </div>
"""
                
                # Display all parameters
                for param_idx, param in enumerate(parameters):
                    is_last_param = param_idx == len(parameters) - 1
                    param_prefix = "    " if is_last_entry else "│   "
                    param_connector = "└──" if is_last_param else "├──"
                    
                    param_name = param.get('Name', 'Unknown')
                    param_value = param.get('Value', 'Unknown')
                    
                    html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{param_prefix}    {param_connector}</span>
                        <span class="param-title">{param_name}: {param_value}</span>
                    </div>
"""
                    
            except (json.JSONDecodeError, TypeError):
                error_prefix = "    " if is_last_entry else "│   "
                html_content += f"""
                    <div class="tree-line">
                        <span class="connector">{error_prefix}└──</span>
                        <span class="error-title">Error parsing audit data</span>
                    </div>
"""
        
        return html_content

    def _generate_timeline_generic_tree(self, entry, is_last_entry):
        """Generate timeline tree content for unknown operation types"""
        operation = entry.get('Operation', 'Unknown')
        client_ip = entry.get('ClientIPAddress', 'N/A')
        
        info_prefix = "    " if is_last_entry else "│   "
        
        # Special handling for Create operation
        if operation == "Create":
            # Try to get folder path from AuditData
            folder_path = "Unknown Path"
            audit_data_str = entry.get('AuditData')
            if pd.notna(audit_data_str):
                try:
                    audit_json = json.loads(audit_data_str)
                    # Try different possible locations for folder information
                    if 'ParentFolder' in audit_json:
                        folder_path = audit_json['ParentFolder'].get('Path', 'Unknown Path')
                    elif 'Item' in audit_json and 'ParentFolder' in audit_json['Item']:
                        folder_path = audit_json['Item']['ParentFolder'].get('Path', 'Unknown Path')
                    elif 'DestFolder' in audit_json:
                        folder_path = audit_json['DestFolder'].get('Path', 'Unknown Path')
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass
            
            # Get subject for Create operation
            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            create_subject = subject if subject else "No Subject"
            
            html_content = f"""
                    <div class="tree-line">
                        <span class="connector">{info_prefix}├──</span>
                        <span class="folder-title">Parent Folder: {folder_path}</span>
                    </div>
                    <div class="tree-line">
                        <span class="connector">{info_prefix}└──</span>
                        <span class="subject-title">Subject: {create_subject}</span>
                    </div>
"""
        else:
            # Default behavior for other operations
            html_content = f"""
                    <div class="tree-line">
                        <span class="connector">{info_prefix}├──</span>
                        <span class="info-title">Operation: {operation}</span>
                    </div>
                    <div class="tree-line">
                        <span class="connector">{info_prefix}└──</span>
                        <span class="info-title">Client IP: {client_ip}</span>
                    </div>
"""
        
        return html_content

    def _generate_affected_items_tree_compact(self, entries, all_ids):
        """Generate compact tree for operations with AffectedItems using ASCII connectors"""
        html_content = '<div class="tree-ascii">'
        
        for entry_idx, entry in enumerate(entries):
            creation_date = entry.get('CreationDate', 'N/A')
            is_last_entry = entry_idx == len(entries) - 1
            entry_connector = "└──" if is_last_entry else "├──"
            
            # Prepare tooltip and full details for clickable CreationDate
            tooltip_text = (
                f"Operation: {entry.get('Operation', 'N/A')}\n"
                f"Creation Date: {creation_date}\n"
                f"Client IP: {entry.get('ClientIPAddress', 'N/A')}\n"
            )
            
            if entry.get('Operation') == "MailItemsAccessed":
                mail_access_type = self._get_mail_access_type_value(entry.get('AuditData'))
                if mail_access_type:
                    tooltip_text += f"Mail Access Type: {mail_access_type}\n"

            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            if subject:
                tooltip_text += f"Subject: {subject}\n"

            tooltip_text += f"Record ID: {entry.get('RecordId', 'N/A')}"
            
            full_details = {k: str(v) for k, v in entry.items() if pd.notna(v) and k != 'DateTime'}
            full_details_json = json.dumps(full_details)
            
            tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
            full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')
            
            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{entry_connector}</span>
                    <span class="date-title" style="cursor: pointer;" data-tooltip="{tooltip_text_encoded}" onclick="showDetails(this)" data-fulldetails="{full_details_json_encoded}">{creation_date}</span>
                </div>
"""
            
            audit_data_str = entry.get('AuditData')
            if pd.notna(audit_data_str):
                try:
                    audit_json = json.loads(audit_data_str)
                    affected_items = audit_json.get('AffectedItems', [])
                    
                    if affected_items:
                        # Group by parent folder path
                        folders = {}
                        for item in affected_items:
                            parent_folder = item.get('ParentFolder', {})
                            path = parent_folder.get('Path', 'Unknown Path')
                            if path not in folders:
                                folders[path] = []
                            folders[path].append(item)
                        
                        folder_list = list(folders.items())
                        for folder_idx, (path, items) in enumerate(folder_list):
                            is_last_folder = folder_idx == len(folder_list) - 1
                            folder_prefix = "    " if is_last_entry else "│   "
                            folder_connector = "└──" if is_last_folder else "├──"
                            
                            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{folder_prefix}{folder_connector}</span>
                    <span class="folder-title">{path}</span>
                </div>
"""
                            
                            for item_idx, item in enumerate(items):
                                is_last_item = item_idx == len(items) - 1
                                item_prefix = "    " if is_last_entry else "│   "
                                item_prefix += "    " if is_last_folder else "│   "
                                item_connector = "└──" if is_last_item else "├──"
                                
                                subject = item.get('Subject', 'No Subject')
                                
                                # Check for InternetMessageId first, fall back to Id
                                internet_msg_id = item.get('InternetMessageId', '')
                                item_id = item.get('Id', '')
                                
                                if internet_msg_id:
                                    all_ids.append(internet_msg_id)
                                elif item_id:
                                    all_ids.append(item_id)
                                
                                html_content += f"""
                <div class="tree-line">
                    <span class="connector">{item_prefix}{item_connector}</span>
                    <span class="subject-title">{subject}</span>
                </div>
"""
                    else:
                        # Check for single Item (like in Send operation)
                        item = audit_json.get('Item', {})
                        if item:
                            subject = item.get('Subject', 'No Subject')
                            
                            # Check for InternetMessageId first, fall back to Id
                            internet_msg_id = item.get('InternetMessageId', '')
                            item_id = item.get('Id', '')
                            
                            if internet_msg_id:
                                all_ids.append(internet_msg_id)
                            elif item_id:
                                all_ids.append(item_id)
                            
                            parent_folder = item.get('ParentFolder', {})
                            path = parent_folder.get('Path', 'Unknown Path')
                            
                            folder_prefix = "    " if is_last_entry else "│   "
                            
                            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{folder_prefix}├──</span>
                    <span class="folder-title">{path}</span>
                </div>
                <div class="tree-line">
                    <span class="connector">{folder_prefix}    └──</span>
                    <span class="subject-title">{subject}</span>
                </div>
"""
                except (json.JSONDecodeError, TypeError):
                    error_prefix = "    " if is_last_entry else "│   "
                    html_content += f"""
                <div class="tree-line">
                    <span class="connector">{error_prefix}└──</span>
                    <span class="error-title">Error parsing audit data</span>
                </div>
"""
        
        html_content += '</div>'
        return html_content

    def _generate_mail_items_tree_compact(self, entries, all_ids):
        """Generate compact tree for MailItemsAccessed operations using ASCII connectors"""
        html_content = '<div class="tree-ascii">'
        
        for entry_idx, entry in enumerate(entries):
            creation_date = entry.get('CreationDate', 'N/A')
            is_last_entry = entry_idx == len(entries) - 1
            entry_connector = "└──" if is_last_entry else "├──"
            
            # Prepare tooltip and full details for clickable CreationDate
            tooltip_text = (
                f"Operation: {entry.get('Operation', 'N/A')}\n"
                f"Creation Date: {creation_date}\n"
                f"Client IP: {entry.get('ClientIPAddress', 'N/A')}\n"
            )
            
            if entry.get('Operation') == "MailItemsAccessed":
                mail_access_type = self._get_mail_access_type_value(entry.get('AuditData'))
                if mail_access_type:
                    tooltip_text += f"Mail Access Type: {mail_access_type}\n"

            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            if subject:
                tooltip_text += f"Subject: {subject}\n"

            tooltip_text += f"Record ID: {entry.get('RecordId', 'N/A')}"
            
            full_details = {k: str(v) for k, v in entry.items() if pd.notna(v) and k != 'DateTime'}
            full_details_json = json.dumps(full_details)
            
            tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
            full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')
            
            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{entry_connector}</span>
                    <span class="date-title" style="cursor: pointer;" data-tooltip="{tooltip_text_encoded}" onclick="showDetails(this)" data-fulldetails="{full_details_json_encoded}">{creation_date}</span>
                </div>
"""
            
            audit_data_str = entry.get('AuditData')
            if pd.notna(audit_data_str):
                try:
                    audit_json = json.loads(audit_data_str)
                    folders = audit_json.get('Folders', [])
                    
                    for folder_idx, folder in enumerate(folders):
                        path = folder.get('Path', 'Unknown Path')
                        folder_items = folder.get('FolderItems', [])
                        
                        is_last_folder = folder_idx == len(folders) - 1
                        folder_prefix = "    " if is_last_entry else "│   "
                        folder_connector = "└──" if is_last_folder else "├──"
                        
                        html_content += f"""
                <div class="tree-line">
                    <span class="connector">{folder_prefix}{folder_connector}</span>
                    <span class="folder-title">{path}</span>
                </div>
"""
                        
                        for item_idx, item in enumerate(folder_items):
                            is_last_item = item_idx == len(folder_items) - 1
                            item_prefix = "    " if is_last_entry else "│   "
                            item_prefix += "    " if is_last_folder else "│   "
                            item_connector = "└──" if is_last_item else "├──"
                            
                            # Check for InternetMessageId first, fall back to Id
                            internet_msg_id = item.get('InternetMessageId', '')
                            item_id = item.get('Id', '')
                            
                            display_id = ""
                            if internet_msg_id:
                                all_ids.append(internet_msg_id)
                                display_id = internet_msg_id
                            elif item_id:
                                all_ids.append(item_id)
                                # Extract the last part of the ID for display
                                display_id = item_id.split('/')[-1] if '/' in item_id else item_id
                            
                            if display_id:
                                html_content += f"""
                <div class="tree-line">
                    <span class="connector">{item_prefix}{item_connector}</span>
                    <span class="item-id">...{display_id}</span>
                </div>
"""
                        
                except (json.JSONDecodeError, TypeError):
                    error_prefix = "    " if is_last_entry else "│   "
                    html_content += f"""
                <div class="tree-line">
                    <span class="connector">{error_prefix}└──</span>
                    <span class="error-title">Error parsing audit data</span>
                </div>
"""
        
        html_content += '</div>'
        return html_content

    def _generate_inbox_rule_tree_compact(self, entries):
        """Generate compact tree for New-InboxRule operations using ASCII connectors"""
        html_content = '<div class="tree-ascii">'
        
        for entry_idx, entry in enumerate(entries):
            creation_date = entry.get('CreationDate', 'N/A')
            is_last_entry = entry_idx == len(entries) - 1
            entry_connector = "└──" if is_last_entry else "├──"
            
            # Prepare tooltip and full details for clickable CreationDate
            tooltip_text = (
                f"Operation: {entry.get('Operation', 'N/A')}\n"
                f"Creation Date: {creation_date}\n"
                f"Client IP: {entry.get('ClientIPAddress', 'N/A')}\n"
            )
            
            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            if subject:
                tooltip_text += f"Subject: {subject}\n"

            tooltip_text += f"Record ID: {entry.get('RecordId', 'N/A')}"
            
            full_details = {k: str(v) for k, v in entry.items() if pd.notna(v) and k != 'DateTime'}
            full_details_json = json.dumps(full_details)
            
            tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
            full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')
            
            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{entry_connector}</span>
                    <span class="date-title" style="cursor: pointer;" data-tooltip="{tooltip_text_encoded}" onclick="showDetails(this)" data-fulldetails="{full_details_json_encoded}">{creation_date}</span>
                </div>
"""
            
            audit_data_str = entry.get('AuditData')
            if pd.notna(audit_data_str):
                try:
                    audit_json = json.loads(audit_data_str)
                    parameters = audit_json.get('Parameters', [])
                    
                    # Find the Name parameter first
                    rule_name = "Unknown Rule"
                    for param in parameters:
                        if param.get('Name') == 'Name':
                            rule_name = param.get('Value', 'Unknown Rule')
                            break
                    
                    rule_prefix = "    " if is_last_entry else "│   "
                    html_content += f"""
                <div class="tree-line">
                    <span class="connector">{rule_prefix}├──</span>
                    <span class="rule-title">Rule: {rule_name}</span>
                </div>
"""
                    
                    # Display all parameters
                    for param_idx, param in enumerate(parameters):
                        is_last_param = param_idx == len(parameters) - 1
                        param_prefix = "    " if is_last_entry else "│   "
                        param_connector = "└──" if is_last_param else "├──"
                        
                        param_name = param.get('Name', 'Unknown')
                        param_value = param.get('Value', 'Unknown')
                        
                        html_content += f"""
                <div class="tree-line">
                    <span class="connector">{param_prefix}    {param_connector}</span>
                    <span class="param-title">{param_name}: {param_value}</span>
                </div>
"""
                        
                except (json.JSONDecodeError, TypeError):
                    error_prefix = "    " if is_last_entry else "│   "
                    html_content += f"""
                <div class="tree-line">
                    <span class="connector">{error_prefix}└──</span>
                    <span class="error-title">Error parsing audit data</span>
                </div>
"""
        
        html_content += '</div>'
        return html_content

    def _generate_generic_tree_compact(self, entries):
        """Generate compact tree for unknown operation types using ASCII connectors"""
        html_content = '<div class="tree-ascii">'
        
        for entry_idx, entry in enumerate(entries):
            creation_date = entry.get('CreationDate', 'N/A')
            operation = entry.get('Operation', 'Unknown')
            client_ip = entry.get('ClientIPAddress', 'N/A')
            
            is_last_entry = entry_idx == len(entries) - 1
            entry_connector = "└──" if is_last_entry else "├──"
            
            # Prepare tooltip and full details for clickable CreationDate
            tooltip_text = (
                f"Operation: {operation}\n"
                f"Creation Date: {creation_date}\n"
                f"Client IP: {client_ip}\n"
            )
            
            subject = self._get_subject_from_audit_data(entry.get('AuditData'))
            if subject:
                tooltip_text += f"Subject: {subject}\n"

            tooltip_text += f"Record ID: {entry.get('RecordId', 'N/A')}"
            
            full_details = {k: str(v) for k, v in entry.items() if pd.notna(v) and k != 'DateTime'}
            full_details_json = json.dumps(full_details)
            
            tooltip_text_encoded = tooltip_text.replace('"', '&quot;').replace("'", '&#39;')
            full_details_json_encoded = full_details_json.replace('"', '&quot;').replace("'", '&#39;')
            
            html_content += f"""
                <div class="tree-line">
                    <span class="connector">{entry_connector}</span>
                    <span class="date-title" style="cursor: pointer;" data-tooltip="{tooltip_text_encoded}" onclick="showDetails(this)" data-fulldetails="{full_details_json_encoded}">{creation_date}</span>
                </div>
"""
            
            info_prefix = "    " if is_last_entry else "│   "
            
            # Special handling for Create operation
            if operation == "Create":
                # Try to get folder path from AuditData
                folder_path = "Unknown Path"
                audit_data_str = entry.get('AuditData')
                if pd.notna(audit_data_str):
                    try:
                        audit_json = json.loads(audit_data_str)
                        # Try different possible locations for folder information
                        if 'ParentFolder' in audit_json:
                            folder_path = audit_json['ParentFolder'].get('Path', 'Unknown Path')
                        elif 'Item' in audit_json and 'ParentFolder' in audit_json['Item']:
                            folder_path = audit_json['Item']['ParentFolder'].get('Path', 'Unknown Path')
                        elif 'DestFolder' in audit_json:
                            folder_path = audit_json['DestFolder'].get('Path', 'Unknown Path')
                    except (json.JSONDecodeError, TypeError, KeyError):
                        pass
                
                # Get subject for Create operation
                create_subject = subject if subject else "No Subject"
                
                html_content += f"""
                <div class="tree-line">
                    <span class="connector">{info_prefix}├──</span>
                    <span class="folder-title">Parent Folder: {folder_path}</span>
                </div>
                <div class="tree-line">
                    <span class="connector">{info_prefix}└──</span>
                    <span class="subject-title">Subject: {create_subject}</span>
                </div>
"""
            else:
                # Default behavior for other operations
                html_content += f"""
                <div class="tree-line">
                    <span class="connector">{info_prefix}├──</span>
                    <span class="info-title">Operation: {operation}</span>
                </div>
                <div class="tree-line">
                    <span class="connector">{info_prefix}└──</span>
                    <span class="info-title">Client IP: {client_ip}</span>
                </div>
"""
        
        html_content += '</div>'
        return html_content


# ===== EMAIL EXTRACTION COMPONENT =====

class PSTExtractorApp:
    def __init__(self, parent_frame, shared_data, colors, style):
        self.parent = parent_frame
        self.shared_data = shared_data
        self.colors = colors
        self.style = style

        # Create a main frame to hold all widgets
        self.main_frame = tk.Frame(self.parent, bg=self.colors['background'])
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Configure grid for responsiveness on the main_frame
        self.main_frame.grid_rowconfigure(0, weight=0) # PST File row
        self.main_frame.grid_rowconfigure(1, weight=0) # Output Dir row
        self.main_frame.grid_rowconfigure(2, weight=0) # Keywords CSV row
        self.main_frame.grid_rowconfigure(3, weight=0) # Email IDs label
        self.main_frame.grid_rowconfigure(4, weight=1) # Email IDs input (expands)
        self.main_frame.grid_rowconfigure(5, weight=0) # Button row
        self.main_frame.grid_rowconfigure(6, weight=0) # Log label
        self.main_frame.grid_rowconfigure(7, weight=2) # Log area (expands more)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        self.pst_file_path = tk.StringVar()
        self.keywords_csv_path = tk.StringVar()
        self.temp_extract_dir = "" # To store the path of the temporary extraction directory
        self.DISABLE_CLEANUP = tk.BooleanVar(value=False) # New checkbox variable for debugging
        self.keywords_list = []  # Store loaded keywords
        self.email_scan_results = []  # Store scan results for report generation
        self.tree_email_data = {}  # Store email data for tree items
        
        # Use shared output directory
        self.output_dir_path = self.shared_data['output_directory']

        # --- PST File Selection ---
        tk.Label(self.main_frame, text="Select PST File:",
                bg=self.colors['background'], fg=self.colors['text']).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.pst_file_path, width=50,
                bg=self.colors['white'], fg=self.colors['text'], relief='flat', borderwidth=0,
                highlightthickness=1, highlightcolor=self.colors['border'], highlightbackground=self.colors['border']).grid(row=0, column=0, columnspan=1, sticky="ew", padx=(120, 5), pady=5)
        ttk.Button(self.main_frame, text="Browse", command=self.browse_pst_file).grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # --- Output Directory Selection ---
        tk.Label(self.main_frame, text="Select Output Directory:",
                bg=self.colors['background'], fg=self.colors['text']).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.output_dir_entry = tk.Entry(self.main_frame, textvariable=self.output_dir_path, width=50, 
                                        fg='gray', bg=self.colors['white'], relief='flat', borderwidth=0,
                                        highlightthickness=1, highlightcolor=self.colors['border'], highlightbackground=self.colors['border'])
        self.output_dir_entry.grid(row=1, column=0, columnspan=1, sticky="ew", padx=(170, 5), pady=5)
        
        # Set placeholder text and bind events
        self.output_dir_placeholder = "(Investigation Output Directory by default)"
        self.output_dir_entry.bind('<FocusIn>', self.on_output_dir_focus_in)
        self.output_dir_entry.bind('<FocusOut>', self.on_output_dir_focus_out)
        self.update_output_dir_display()
        
        ttk.Button(self.main_frame, text="Browse", command=self.browse_output_dir).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # --- Keywords CSV Selection ---
        tk.Label(self.main_frame, text="Select Keywords CSV File:", 
                bg=self.colors['background'], fg=self.colors['text']).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.keywords_csv_path, width=50,
                bg=self.colors['white'], fg=self.colors['text'], relief='flat', borderwidth=0,
                highlightthickness=1, highlightcolor=self.colors['border'], highlightbackground=self.colors['border']).grid(row=2, column=0, columnspan=1, sticky="ew", padx=(180, 5), pady=5)
        ttk.Button(self.main_frame, text="Browse", command=self.browse_keywords_csv).grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # --- Email IDs Input ---
        email_frame = tk.Frame(self.main_frame, bg=self.colors['background'])
        email_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
        
        tk.Label(email_frame, text="Enter Compromised Email IDs (one per line):",
                bg=self.colors['background'], fg=self.colors['text']).pack(side=tk.LEFT)
        
        # Button to import emails from audit tab
        ttk.Button(
            email_frame, 
            text="📥 Import from Audit Tab", 
            command=self.import_emails_from_audit
        ).pack(side=tk.RIGHT, padx=5)
        
        self.email_ids_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=8,
                                                       bg=self.colors['white'], fg=self.colors['text'],
                                                       relief='flat', borderwidth=0,
                                                       highlightthickness=1, highlightcolor=self.colors['border'], 
                                                       highlightbackground=self.colors['border'])
        self.email_ids_text.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)

        # --- Debugging Option: Disable Cleanup ---
        tk.Checkbutton(self.main_frame, text="Keep temporary files (for debugging)", variable=self.DISABLE_CLEANUP,
                      bg=self.colors['background'], fg=self.colors['text']).grid(row=5, column=0, sticky="w", padx=10, pady=5)

        # --- Action Buttons ---
        self.extract_button = ttk.Button(self.main_frame, text="Extract & Scan Emails", command=self.start_extraction, style="Secondary.TButton")
        self.extract_button.grid(row=5, column=1, sticky="e", pady=15) # Changed column and sticky for layout

        # --- Log Area ---
        tk.Label(self.main_frame, text="Status Log:", bg=self.colors['background'], fg=self.colors['text']).grid(row=6, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=10, state='disabled', 
                                                 bg=self.colors['white'], fg=self.colors['text'],
                                                 relief='flat', borderwidth=0,
                                                 highlightthickness=1, highlightcolor=self.colors['border'], 
                                                 highlightbackground=self.colors['border'])
        self.log_text.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)
        
        # Progress tracking
        self.extraction_start_time = None
        self.progress_timer = None

    def update_output_dir_display(self):
        """Update the output directory display with placeholder or actual value."""
        if not self.output_dir_path.get():
            self.output_dir_entry.config(fg='gray')
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, self.output_dir_placeholder)
        else:
            self.output_dir_entry.config(fg='black')

    def on_output_dir_focus_in(self, event):
        """Handle focus in event for output directory entry."""
        if self.output_dir_entry.get() == self.output_dir_placeholder:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.config(fg='black')

    def on_output_dir_focus_out(self, event):
        """Handle focus out event for output directory entry."""
        if not self.output_dir_entry.get():
            self.update_output_dir_display()

    def log_message(self, message):
        """Inserts a message into the log text area."""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END) # Auto-scroll to the end
        self.log_text.config(state='disabled')
        self.parent.update_idletasks() # Update GUI immediately

    def import_emails_from_audit(self):
        """Import MailItemsAccessed IDs from the audit tab's shared data."""
        if 'compromised_emails' in self.shared_data and self.shared_data['compromised_emails']:
            mail_ids = self.shared_data['compromised_emails']
            
            # Clear current content and add imported IDs
            self.email_ids_text.delete(1.0, tk.END)
            self.email_ids_text.insert(tk.END, '\n'.join(mail_ids))
            
            self.log_message(f"Imported {len(mail_ids)} MailItemsAccessed IDs from Audit Tab")
            messagebox.showinfo(
                "MailItemsAccessed IDs Imported", 
                f"Successfully imported {len(mail_ids)} MailItemsAccessed IDs from the Audit Log Analysis tab."
            )
        else:
            messagebox.showwarning(
                "No IDs Available", 
                "No MailItemsAccessed IDs are available from the Audit Tab.\n\n"
                "Please load audit logs and use the 'Send MailItemsAccessed IDs to Extraction Tab' button first."
            )

    def browse_pst_file(self):
        """Opens a file dialog to select the PST file."""
        file_path = filedialog.askopenfilename(
            title="Select PST File",
            filetypes=[("PST files", "*.pst"), ("All files", "*.*")]
        )
        if file_path:
            self.pst_file_path.set(file_path)
            self.log_message(f"PST file selected: {file_path}")

    def browse_output_dir(self):
        """Opens a directory dialog to select the output folder."""
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        if dir_path:
            self.output_dir_path.set(dir_path)
            self.log_message(f"Output directory selected: {dir_path}")

    def browse_keywords_csv(self):
        """Opens a file dialog to select the keywords CSV file."""
        file_path = filedialog.askopenfilename(
            title="Select Keywords CSV File",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.keywords_csv_path.set(file_path)
            self.log_message(f"Keywords file selected: {file_path}")
            # Automatically load keywords when file is selected
            self.load_keywords()

    def load_keywords(self):
        """Load and parse keywords from the selected file."""
        keywords_file = self.keywords_csv_path.get()
        if not keywords_file or not os.path.exists(keywords_file):
            self.log_message("Error: Keywords file not found.")
            return False
        
        try:
            self.keywords_list = []
            
            # Read the file content
            with open(keywords_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if it's RTF format (like your sample)
            if content.startswith('{\\rtf'):
                self.log_message("Detected RTF format, extracting keywords...")
                # Extract the keywords from RTF (they appear to be after the formatting codes)
                # Look for the actual keyword content
                import re
                # Find content after the RTF formatting
                match = re.search(r'\\strokec2\s+(.+?)(?:\}|$)', content, re.DOTALL)
                if match:
                    keywords_text = match.group(1)
                    # Split by commas and clean up
                    keywords = [kw.strip().strip('"') for kw in keywords_text.split(',')]
                    self.keywords_list = [kw for kw in keywords if kw and len(kw) > 1]
                else:
                    self.log_message("Could not parse RTF keywords file.")
                    return False
            else:
                # Assume it's a regular CSV or text file
                try:
                    # Try CSV format first
                    with open(keywords_file, 'r', encoding='utf-8') as f:
                        csv_reader = csv.reader(f)
                        for row in csv_reader:
                            for item in row:
                                if item.strip():
                                    self.keywords_list.append(item.strip())
                except:
                    # If CSV fails, try line-by-line or comma-separated
                    keywords = content.replace('\n', ',').split(',')
                    self.keywords_list = [kw.strip().strip('"') for kw in keywords if kw.strip()]
            
            # Remove duplicates and empty entries
            self.keywords_list = list(set([kw for kw in self.keywords_list if kw and len(kw) > 1]))
            
            self.log_message(f"Loaded {len(self.keywords_list)} unique keywords for scanning.")
            self.log_message(f"Sample keywords: {', '.join(self.keywords_list[:5])}...")
            return True
            
        except Exception as e:
            self.log_message(f"Error loading keywords file: {e}")
            return False

    def scan_text_for_keywords(self, text, source_name="Unknown"):
        """Scan text content for sensitive keywords and return matches."""
        if not self.keywords_list or not text:
            return {}
        
        text_lower = text.lower()
        matches = defaultdict(int)
        
        for keyword in self.keywords_list:
            keyword_lower = keyword.lower()
            
            # Use regex word boundaries for more precise matching
            # This prevents "ID" from matching within words like "slide", "guide", etc.
            import re
            
            # Escape special regex characters in the keyword
            escaped_keyword = re.escape(keyword_lower)
            
            # Create pattern with word boundaries
            # \b ensures the keyword is matched as a complete word
            pattern = r'\b' + escaped_keyword + r'\b'
            
            try:
                # Find all matches using regex
                regex_matches = re.findall(pattern, text_lower)
                count = len(regex_matches)
                
                if count > 0:
                    matches[keyword] = count
            except re.error as e:
                # If regex fails, fall back to simple substring search
                self.log_message(f"Regex error for keyword '{keyword}': {e}. Using substring search.")
                count = text_lower.count(keyword_lower)
                if count > 0:
                    matches[keyword] = count
        
        if matches:
            self.log_message(f"Found {sum(matches.values())} keyword matches in {source_name}")
        
        return dict(matches)

    def extract_attachment_text(self, attachment_path):
        """Extract text from various file types for keyword scanning."""
        text_content = ""
        file_ext = Path(attachment_path).suffix.lower()
        
        try:
            if file_ext in ['.txt', '.csv', '.log']:
                with open(attachment_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text_content = f.read()
            
            elif file_ext == '.pdf':
                try:
                    import PyPDF2
                    with open(attachment_path, 'rb') as f:
                        pdf_reader = PyPDF2.PdfReader(f)
                        for page_num, page in enumerate(pdf_reader.pages):
                            text_content += f"\n--- Page {page_num + 1} ---\n"
                            text_content += page.extract_text()
                except ImportError:
                    self.log_message(f"PyPDF2 not available for PDF processing: {attachment_path}")
                    return None, "PDF processing library not available"
                except Exception as e:
                    self.log_message(f"Error reading PDF {attachment_path}: {e}")
                    return None, f"PDF read error: {e}"
            
            elif file_ext in ['.doc', '.docx']:
                try:
                    from docx import Document
                    doc = Document(attachment_path)
                    text_content = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
                except ImportError:
                    self.log_message(f"python-docx not available for Word processing: {attachment_path}")
                    return None, "Word processing library not available"
                except Exception as e:
                    self.log_message(f"Error reading Word document {attachment_path}: {e}")
                    return None, f"Word document read error: {e}"
            
            elif file_ext in ['.xls', '.xlsx']:
                try:
                    import pandas as pd
                    df = pd.read_excel(attachment_path, sheet_name=None)
                    for sheet_name, sheet_data in df.items():
                        text_content += f"\n--- Sheet: {sheet_name} ---\n"
                        text_content += sheet_data.to_string()
                except ImportError:
                    self.log_message(f"pandas not available for Excel processing: {attachment_path}")
                    return None, "Excel processing library not available"
                except Exception as e:
                    self.log_message(f"Error reading Excel file {attachment_path}: {e}")
                    return None, f"Excel read error: {e}"
            
            elif file_ext in ['.png', '.jpg', '.jpeg', '.tiff', '.bmp']:
                try:
                    import pytesseract
                    from PIL import Image
                    image = Image.open(attachment_path)
                    text_content = pytesseract.image_to_string(image)
                except ImportError:
                    self.log_message(f"OCR libraries not available for image processing: {attachment_path}")
                    return None, "OCR libraries not available"
                except Exception as e:
                    self.log_message(f"Error performing OCR on {attachment_path}: {e}")
                    return None, f"OCR error: {e}"
            
            else:
                return None, f"Unsupported file type: {file_ext}"
        
        except Exception as e:
            self.log_message(f"General error extracting text from {attachment_path}: {e}")
            return None, f"Extraction error: {e}"
        
        return text_content, None

    def start_extraction(self):
        """Initiates the email extraction process."""
        pst_path = self.pst_file_path.get()
        output_dir = self.output_dir_path.get()
        keywords_path = self.keywords_csv_path.get()
        email_ids_raw = self.email_ids_text.get("1.0", tk.END).strip()

        # Use shared output directory if local one is empty or placeholder
        if not output_dir or output_dir == self.output_dir_placeholder:
            output_dir = self.shared_data['output_directory'].get()

        if not pst_path or not os.path.exists(pst_path):
            messagebox.showerror("Error", "Please select a valid PST file.")
            self.log_message("Error: No valid PST file selected.")
            return
        if not output_dir or not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Please select a valid output directory.")
            self.log_message("Error: No valid output directory selected.")
            return
        if not keywords_path or not os.path.exists(keywords_path):
            messagebox.showerror("Error", "Please select a valid keywords file.")
            self.log_message("Error: No valid keywords file selected.")
            return
        if not email_ids_raw:
            messagebox.showerror("Error", "Please enter at least one email ID.")
            self.log_message("Error: No email IDs entered.")
            return

        # Load keywords if not already loaded
        if not self.keywords_list:
            if not self.load_keywords():
                messagebox.showerror("Error", "Failed to load keywords from file.")
                return

        # Clean and prepare email IDs for lookup
        # Convert to lowercase for case-insensitive matching and strip angle brackets
        compromised_email_ids = set()
        for item_id in email_ids_raw.splitlines():
            cleaned_id = item_id.strip().strip("<>").lower()
            if cleaned_id:
                compromised_email_ids.add(cleaned_id)

        if not compromised_email_ids:
            messagebox.showerror("Error", "No valid email IDs found after cleaning input.")
            self.log_message("Error: No valid email IDs found after cleaning input.")
            return
        
        self.log_message(f"Input IDs to search for ({len(compromised_email_ids)}):")
        for _id in sorted(list(compromised_email_ids))[:5]: # Log first 5 for brevity
            self.log_message(f"  - {_id}")
        if len(compromised_email_ids) > 5:
            self.log_message("  ... (and more)")

        self.log_message("Starting extraction and keyword scanning process...")
        self.extract_button.config(state='disabled', text="Extracting & Scanning...")
        
        # Start progress tracking
        self.extraction_start_time = datetime.now()
        self.start_progress_updates()
        
        # Run extraction in a separate thread to prevent UI freeze
        extraction_thread = threading.Thread(
            target=self.run_extraction_thread,
            args=(pst_path, output_dir, compromised_email_ids)
        )
        extraction_thread.daemon = True
        extraction_thread.start()

    def start_progress_updates(self):
        """Start periodic progress updates."""
        self.update_progress()

    def update_progress(self):
        """Update progress display every minute."""
        if self.extraction_start_time:
            elapsed = datetime.now() - self.extraction_start_time
            minutes = int(elapsed.total_seconds() // 60)
            seconds = int(elapsed.total_seconds() % 60)
            
            if minutes > 0:
                self.log_message(f"{minutes:02d}:{seconds:02d} - Search in progress...")
            
            # Schedule next update in 60 seconds
            self.progress_timer = self.parent.after(60000, self.update_progress)

    def stop_progress_updates(self):
        """Stop progress updates."""
        self.extraction_start_time = None
        if self.progress_timer:
            self.parent.after_cancel(self.progress_timer)
            self.progress_timer = None

    def run_extraction_thread(self, pst_path, output_dir, compromised_email_ids):
        """Run extraction in a separate thread."""
        try:
            self.extract_emails(pst_path, output_dir, compromised_email_ids)
            
            # Update UI in main thread
            self.parent.after(0, self.extraction_complete_success)
            
        except Exception as e:
            # Update UI in main thread
            self.parent.after(0, lambda: self.extraction_complete_error(str(e)))

    def extraction_complete_success(self):
        """Handle successful extraction completion."""
        self.stop_progress_updates()
        self.extract_button.config(state='normal', text="Extract & Scan Emails")
        
        messagebox.showinfo("Success", "Email extraction and keyword scanning complete!")
        self.log_message("Email extraction and keyword scanning complete.")
        
        # Show results window
        self.show_results_window()
        
        # Only clean up if the checkbox is NOT checked
        if not self.DISABLE_CLEANUP.get():
            self.cleanup_temp_dir()

    def extraction_complete_error(self, error_message):
        """Handle extraction error."""
        self.stop_progress_updates()
        self.extract_button.config(state='normal', text="Extract & Scan Emails")
        
        messagebox.showerror("Extraction Error", f"An error occurred: {error_message}")
        self.log_message(f"Extraction Error: {error_message}")
        
        # Only clean up if the checkbox is NOT checked
        if not self.DISABLE_CLEANUP.get():
            self.cleanup_temp_dir()

    def extract_emails(self, pst_path, output_dir, compromised_email_ids):
        """
        Uses readpst to extract all emails to a temporary directory,
        then parses them to find matches and scan for keywords.
        """
        extracted_emails_data = []
        csv_file_path = os.path.join(output_dir, "compromised_emails_report.csv")
        extracted_count = 0
        self.email_scan_results = []  # Reset results

        # Create a temporary directory for readpst output
        self.temp_extract_dir = os.path.join(output_dir, f"temp_pst_extract_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        os.makedirs(self.temp_extract_dir, exist_ok=True)
        self.log_message(f"Temporary extraction directory created: {self.temp_extract_dir}")

        try:
            # Command to extract all emails as .eml files
            # -e: extract emails
            # -o: output directory
            # -D: don't create subdirectories (put all emails directly in output_dir)
            # -M: don't extract attachments as separate files (but they're still in the email)
            # We'll extract attachments from within the email message for keyword scanning
            readpst_command = ["readpst", "-e", "-o", self.temp_extract_dir, "-D", "-M", pst_path]
            self.log_message(f"Running command: {' '.join(readpst_command)}")

            # Execute readpst
            process = subprocess.run(readpst_command, capture_output=True, text=True, check=False)
            
            self.log_message(f"readpst exited with return code: {process.returncode}")
            if process.stdout:
                self.log_message(f"readpst stdout:\n{process.stdout.strip()}")
            if process.stderr:
                self.log_message(f"readpst stderr:\n{process.stderr.strip()}")

            # If readpst failed, raise an error here
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, readpst_command, output=process.stdout, stderr=process.stderr)

            self.log_message("readpst extraction complete. Parsing extracted emails and scanning for keywords...")

            # Iterate through ALL files in the temporary directory, assuming they are .eml content
            eml_files_found = 0
            for root, _, files in os.walk(self.temp_extract_dir):
                for filename in files:
                    # We will now attempt to parse ALL files as email messages
                    # readpst often extracts files without extensions (e.g., "00000001")
                    
                    eml_file_path = os.path.join(root, filename)
                    try:
                        with open(eml_file_path, 'rb') as f: # Open in binary mode for email.message.EmailMessage
                            msg = email.message_from_binary_file(f)
                        
                        # If parsing succeeds, it's likely an email file
                        eml_files_found += 1

                        # Extract relevant headers
                        # Clean < > from Message-ID and convert to lowercase for robust comparison
                        message_id_header = msg.get("Message-ID", "").strip("<>").lower() 
                        
                        # Log every Message-ID found in the PST for debugging
                        if message_id_header:
                            self.log_message(f"  Found Message-ID in PST: {message_id_header} (from file: {filename})")
                        else:
                            self.log_message(f"  Warning: No Message-ID found for file: {filename} in {eml_file_path}")

                        # Check if the extracted Message-ID is in our compromised list
                        if message_id_header and message_id_header in compromised_email_ids:
                            extracted_count += 1
                            self.log_message(f"  *** MATCH FOUND for Message-ID: {message_id_header} ***")

                            # Get email details
                            author = msg.get("From", "N/A")
                            recipients = msg.get("To", "")
                            cc_recipients = msg.get("Cc", "")
                            bcc_recipients = msg.get("Bcc", "")
                            
                            all_recipients = []
                            if recipients:
                                all_recipients.append(recipients)
                            if cc_recipients:
                                all_recipients.append(cc_recipients)
                            if bcc_recipients:
                                all_recipients.append(bcc_recipients)
                            
                            recipients_str = ", ".join(all_recipients) if all_recipients else "N/A"

                            date_time_raw = msg.get("Date", "N/A")
                            try:
                                parsed_dt = email.utils.parsedate_to_datetime(date_time_raw)
                                delivery_time_str = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")
                                email_date = parsed_dt
                            except (TypeError, ValueError):
                                delivery_time_str = date_time_raw
                                email_date = datetime.now()  # Fallback

                            subject = msg.get("Subject", "N/A")

                            # KEYWORD SCANNING SECTION
                            self.log_message(f"  Scanning email for keywords...")
                            email_scan_result = {
                                "message_id": message_id_header,
                                "date": email_date,
                                "subject": subject,
                                "author": author,
                                "recipients": recipients_str,
                                "delivery_time": delivery_time_str,
                                "sensitive_matches": {},
                                "attachment_scan_results": {},
                                "scan_errors": [],
                                "total_matches": 0,
                                "file_paths": {}  # Added to store file paths for opening
                            }

                            # Scan email body
                            email_body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        try:
                                            email_body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                        except:
                                            pass
                            else:
                                try:
                                    email_body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                                except:
                                    pass

                            if email_body:
                                body_matches = self.scan_text_for_keywords(email_body, "Email Body")
                                if body_matches:
                                    email_scan_result["sensitive_matches"]["Email Body"] = body_matches
                                    email_scan_result["total_matches"] += sum(body_matches.values())

                            # Scan attachments
                            attachment_dir = os.path.join(output_dir, f"attachments_{filename}")
                            os.makedirs(attachment_dir, exist_ok=True)
                            
                            for part in msg.walk():
                                filename_att = part.get_filename()
                                if filename_att:
                                    try:
                                        # Save attachment
                                        attachment_path = os.path.join(attachment_dir, filename_att)
                                        attachment_payload = part.get_payload(decode=True)
                                        if attachment_payload:
                                            with open(attachment_path, 'wb') as f:
                                                f.write(attachment_payload)
                                            
                                            # Store file path for opening
                                            email_scan_result["file_paths"][filename_att] = attachment_path
                                            
                                            # Extract text and scan for keywords
                                            self.log_message(f"    Scanning attachment: {filename_att}")
                                            text_content, error = self.extract_attachment_text(attachment_path)
                                            
                                            if error:
                                                email_scan_result["scan_errors"].append(f"{filename_att}: {error}")
                                                self.log_message(f"    Error scanning {filename_att}: {error}")
                                            elif text_content:
                                                att_matches = self.scan_text_for_keywords(text_content, filename_att)
                                                if att_matches:
                                                    email_scan_result["sensitive_matches"][filename_att] = att_matches
                                                    email_scan_result["total_matches"] += sum(att_matches.values())
                                        else:
                                            self.log_message(f"    Warning: No payload found for attachment {filename_att}")
                                        
                                    except Exception as e:
                                        error_msg = f"Failed to process attachment {filename_att}: {e}"
                                        email_scan_result["scan_errors"].append(error_msg)
                                        self.log_message(f"    {error_msg}")

                            # Store the scan result
                            self.email_scan_results.append(email_scan_result)

                            # Create CSV entry
                            extracted_emails_data.append({
                                "Message ID": message_id_header,
                                "Author": author,
                                "Recipients": recipients_str,
                                "Date & Time": delivery_time_str,
                                "Subject": subject,
                                "Keyword Matches": email_scan_result["total_matches"],
                                "Scan Errors": len(email_scan_result["scan_errors"])
                            })

                            # Copy the .eml file to the final output directory as .eml
                            safe_subject = "".join([c for c in subject if c.isalnum() or c in (' ', '-', '_')]).strip()
                            safe_subject = safe_subject[:50] # Limit length
                            if not safe_subject:
                                safe_subject = "Email"
                            
                            # Use the original filename (without path) as a unique identifier if Message-ID is not unique
                            # or combine with Message-ID for robustness
                            final_eml_filename = f"{safe_subject}_{filename}.eml" # Use original filename as part of output name
                            final_eml_file_path = os.path.join(output_dir, final_eml_filename)

                            shutil.copy(eml_file_path, final_eml_file_path)
                            
                            # Store the email file path for opening
                            email_scan_result["file_paths"]["Email Body"] = final_eml_file_path
                            
                            self.log_message(f"  Saved matched email: {final_eml_filename}")

                    except Exception as parse_error:
                        # Log parsing errors but don't stop the whole process
                        self.log_message(f"  Error parsing file {filename} as email: {parse_error}. Skipping.")
                        continue
            
            self.log_message(f"Finished parsing {eml_files_found} potential email files.")

            # Generate CSV report
            if extracted_emails_data:
                with open(csv_file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ["Message ID", "Author", "Recipients", "Date & Time", "Subject", "Keyword Matches", "Scan Errors"]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(extracted_emails_data)
                self.log_message(f"CSV report generated: {csv_file_path}")
            else:
                self.log_message("No matching emails found to generate CSV report.")

            # Generate detailed keyword scan report
            self.generate_keyword_scan_report(output_dir)

            self.log_message(f"Successfully extracted and scanned {extracted_count} matching emails.")

        except FileNotFoundError:
            self.log_message("Error: 'readpst' command not found. Please ensure 'libpst' is installed via Homebrew.")
            messagebox.showerror("Error", "'readpst' command not found. Please install 'libpst' via Homebrew (`brew install libpst`).")
        except subprocess.CalledProcessError as e:
            self.log_message(f"readpst command failed with error: {e.stderr}. Check your PST file or readpst installation.")
            messagebox.showerror("readpst Error", f"readpst command failed: {e.stderr}. Check your PST file or readpst installation.")
        except Exception as e:
            self.log_message(f"An unexpected error occurred during extraction: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        finally:
            # Only clean up if the checkbox is NOT checked
            if not self.DISABLE_CLEANUP.get():
                self.cleanup_temp_dir()

    def generate_keyword_scan_report(self, output_dir):
        """Generate a detailed JSON report of keyword scan results."""
        report_path = os.path.join(output_dir, "keyword_scan_report.json")
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(self.email_scan_results, f, indent=2, default=str)
            self.log_message(f"Detailed keyword scan report generated: {report_path}")
            
            # Also generate HTML report
            self.generate_html_report(output_dir)
            
        except Exception as e:
            self.log_message(f"Error generating keyword scan report: {e}")

    def generate_html_report(self, output_dir):
        """Generate an interactive HTML report with the same functionality as the GUI."""
        html_path = os.path.join(output_dir, "email_scan_results.html")
        
        try:
            # Sort emails by date
            sorted_emails = sorted(self.email_scan_results, key=lambda x: x['date'])
            
            # Count statistics
            total_emails = len(self.email_scan_results)
            emails_with_matches = len([e for e in self.email_scan_results if e['total_matches'] > 0])
            emails_with_errors = len([e for e in self.email_scan_results if e['scan_errors']])
            
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Keyword Scan Results</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }}
        .summary {{
            background-color: #e8f4fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-weight: bold;
        }}
        .email-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .email-table th {{
            background-color: #4CAF50;
            color: white;
            padding: 12px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        .email-table td {{
            padding: 12px;
            border: 1px solid #ddd;
            vertical-align: top;
        }}
        .email-row {{
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .email-row:hover {{
            background-color: #f0f0f0;
        }}
        .sensitive {{
            background-color: #ffcccc;
        }}
        .scan_error {{
            background-color: #ffffcc;
        }}
        .normal {{
            background-color: white;
        }}
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }}
        .modal-content {{
            background-color: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 8px;
            width: 80%;
            max-height: 80%;
            overflow-y: auto;
            position: relative;
        }}
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            position: absolute;
            right: 20px;
            top: 10px;
        }}
        .close:hover {{
            color: black;
        }}
        .email-info {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .email-info h3 {{
            margin-top: 0;
            color: #333;
        }}
        .matches-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        .matches-table th {{
            background-color: #2196F3;
            color: white;
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        .matches-table td {{
            padding: 10px;
            border: 1px solid #ddd;
            vertical-align: top;
        }}
        .file-link {{
            color: #2196F3;
            text-decoration: underline;
            cursor: pointer;
        }}
        .file-link:hover {{
            color: #1976D2;
        }}
        .open-email-btn {{
            background-color: #4CAF50;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
        }}
        .open-email-btn:hover {{
            background-color: #45a049;
        }}
        .errors-section {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
        }}
        .sensitive-matches {{
            white-space: pre-line;
            max-width: 300px;
            word-wrap: break-word;
        }}
        .instruction {{
            text-align: center;
            font-style: italic;
            color: #666;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Email Keyword Scan Results</h1>
        
        <div class="summary">
            Total Emails: {total_emails} | With Sensitive Matches: {emails_with_matches} | With Scan Errors: {emails_with_errors}
        </div>
        
        <div class="instruction">
            Click on any email row to view detailed keyword matches
        </div>
        
        <table class="email-table">
            <thead>
                <tr>
                    <th>Email Date</th>
                    <th>Email Subject</th>
                    <th>Sensitive Matches</th>
                </tr>
            </thead>
            <tbody>
"""

            # Add email rows
            for i, email_data in enumerate(sorted_emails):
                date_str = email_data['date'].strftime("%Y-%m-%d %H:%M") if isinstance(email_data['date'], datetime) else str(email_data['date'])
                subject = email_data['subject'][:60] + "..." if len(email_data['subject']) > 60 else email_data['subject']
                
                # Create aggregated keyword totals across all sources with line breaks for wrapping
                sensitive_text = ""
                if email_data['sensitive_matches']:
                    # Aggregate keywords across all sources
                    keyword_totals = defaultdict(int)
                    for source, keywords_dict in email_data['sensitive_matches'].items():
                        for keyword, count in keywords_dict.items():
                            keyword_totals[keyword] += count
                    
                    # Format as keyword(total_count), with line breaks for better wrapping
                    keyword_list = []
                    for keyword, total_count in keyword_totals.items():
                        keyword_list.append(f"{keyword}({total_count})")
                    
                    # Join with commas and spaces, but insert line breaks every 5 items for better use of space
                    if len(keyword_list) <= 5:
                        sensitive_text = ", ".join(keyword_list)
                    else:
                        # Break into chunks for better wrapping - increased from 3 to 5
                        chunks = []
                        for i in range(0, len(keyword_list), 5):
                            chunk = ", ".join(keyword_list[i:i+5])
                            chunks.append(chunk)
                        sensitive_text = "\n".join(chunks)
                else:
                    sensitive_text = "0"
                
                # Determine row tag based on scan results
                tag = ""
                if email_data['total_matches'] > 0:
                    tag = "sensitive"  # Red for sensitive matches
                elif email_data['scan_errors']:
                    tag = "scan_error"  # Yellow for scan errors
                else:
                    tag = "normal"  # Normal for no issues
                
                # Escape HTML characters
                subject_escaped = subject.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                sensitive_escaped = sensitive_text.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                
                html_content += f"""
                <tr class="email-row {tag}" onclick="showEmailDetails({i})">
                    <td>{date_str}</td>
                    <td>{subject_escaped}</td>
                    <td class="sensitive-matches">{sensitive_escaped}</td>
                </tr>
"""
            
            html_content += """
            </tbody>
        </table>
    </div>

    <!-- Modal for email details -->
    <div id="emailModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <div id="modalContent"></div>
        </div>
    </div>

    <script>
        // Email data
        const emailData = [
"""

            # Add JavaScript email data
            for email_data in sorted_emails:
                # Create safe JavaScript object
                js_email = {
                    'subject': email_data['subject'].replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n'),
                    'delivery_time': email_data['delivery_time'],
                    'author': email_data['author'].replace('\\', '\\\\').replace('"', '\\"'),
                    'recipients': email_data['recipients'].replace('\\', '\\\\').replace('"', '\\"'),
                    'total_matches': email_data['total_matches'],
                    'sensitive_matches': email_data['sensitive_matches'],
                    'scan_errors': email_data['scan_errors'],
                    'file_paths': email_data.get('file_paths', {})
                }
                
                html_content += f"            {json.dumps(js_email, ensure_ascii=False)},\n"
            
            html_content += """
        ];

        function showEmailDetails(index) {
            const email = emailData[index];
            const modal = document.getElementById('emailModal');
            const content = document.getElementById('modalContent');
            
            let html = `
                <div class="email-info">
                    <h3>Email Information</h3>
                    <p><strong>Subject:</strong> ${email.subject}</p>
                    <p><strong>Date:</strong> ${email.delivery_time}</p>
                    <p><strong>From:</strong> ${email.author}</p>
                    <p><strong>To:</strong> ${email.recipients}</p>
                    <p><strong>Total Keyword Matches:</strong> <span style="color: ${email.total_matches > 0 ? 'red' : 'green'}; font-weight: bold;">${email.total_matches}</span></p>
                    <button class="open-email-btn" onclick="openEmailFile('${email.file_paths['Email Body'] || ''}')">Open Email File</button>
                </div>
            `;
            
            if (Object.keys(email.sensitive_matches).length > 0) {
                html += `
                    <div>
                        <h3>Sensitive Keyword Matches</h3>
                        <table class="matches-table">
                            <thead>
                                <tr>
                                    <th>Source File</th>
                                    <th>Sensitive Matches</th>
                                    <th>Total Count</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                for (const [source, keywords] of Object.entries(email.sensitive_matches)) {
                    const keywordList = [];
                    let totalCount = 0;
                    for (const [keyword, count] of Object.entries(keywords)) {
                        keywordList.push(`${keyword} (${count})`);
                        totalCount += count;
                    }
                    const keywordsStr = keywordList.join(', ');
                    const filePath = email.file_paths[source] || '';
                    
                    html += `
                        <tr>
                            <td><span class="file-link" onclick="openFile('${filePath}')">${source}</span></td>
                            <td>${keywordsStr}</td>
                            <td>${totalCount}</td>
                        </tr>
                    `;
                }
                
                html += `
                            </tbody>
                        </table>
                        <p style="font-style: italic; color: #666;">Click on any source file name to open the corresponding file</p>
                    </div>
                `;
            }
            
            if (email.scan_errors.length > 0) {
                html += `
                    <div class="errors-section">
                        <h3>Scan Errors</h3>
                        <ul>
                `;
                for (const error of email.scan_errors) {
                    html += `<li>${error}</li>`;
                }
                html += `
                        </ul>
                    </div>
                `;
            }
            
            content.innerHTML = html;
            modal.style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('emailModal').style.display = 'none';
        }
        
        function openFile(filePath) {
            if (filePath) {
                // Try to open file - this will work if the file exists locally
                const link = document.createElement('a');
                link.href = 'file://' + filePath;
                link.click();
            } else {
                alert('File path not available');
            }
        }
        
        function openEmailFile(filePath) {
            if (filePath) {
                openFile(filePath);
            } else {
                alert('Email file path not available');
            }
        }
        
        // Close modal when clicking outside of it
        window.onclick = function(event) {
            const modal = document.getElementById('emailModal');
            if (event.target === modal) {
                closeModal();
            }
        }
    </script>
</body>
</html>
"""
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log_message(f"Interactive HTML report generated: {html_path}")
            
        except Exception as e:
            self.log_message(f"Error generating HTML report: {e}")

    def show_results_window(self):
        """Show the results window with clickable email table."""
        if not self.email_scan_results:
            messagebox.showinfo("No Results", "No emails were processed for keyword scanning.")
            return
        
        # Create new window
        results_window = tk.Toplevel(self.master)
        results_window.title("Email Keyword Scan Results")
        results_window.geometry("1200x600")
        results_window.resizable(True, True)
        results_window.configure(bg=self.colors['background'])
        
        # Create main frame
        main_frame = ttk.Frame(results_window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add summary label at the top
        total_emails = len(self.email_scan_results)
        emails_with_matches = len([e for e in self.email_scan_results if e['total_matches'] > 0])
        emails_with_errors = len([e for e in self.email_scan_results if e['scan_errors']])
        
        summary_text = f"Total Emails: {total_emails} | With Sensitive Matches: {emails_with_matches} | With Scan Errors: {emails_with_errors}"
        summary_label = ttk.Label(main_frame, text=summary_text, font=("Arial", 10, "bold"))
        summary_label.pack(pady=(0, 5))
        
        # Add instruction label at the top
        instruction_label = ttk.Label(main_frame, text="Double-click on an email to view detailed keyword matches", 
                                     font=("Arial", 10, "italic"))
        instruction_label.pack(pady=(0, 10))
        
        # Create treeview for email list
        columns = ("Date", "Subject", "Sensitive Matches")
        tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=15)
        
        # Define column headings and widths
        tree.heading("Date", text="Email Date")
        tree.heading("Subject", text="Email Subject")
        tree.heading("Sensitive Matches", text="Sensitive Matches")
        
        tree.column("Date", width=110)
        tree.column("Subject", width=360)
        tree.column("Sensitive Matches", width=500)  # Increased from 300 to 500
        
        # Sort emails by date
        sorted_emails = sorted(self.email_scan_results, key=lambda x: x['date'])
        
        # Dictionary to store email data by tree item id
        self.tree_email_data = {}
        
        # Add emails to tree
        for email_data in sorted_emails:
            date_str = email_data['date'].strftime("%Y-%m-%d %H:%M") if isinstance(email_data['date'], datetime) else str(email_data['date'])
            subject = email_data['subject'][:60] + "..." if len(email_data['subject']) > 60 else email_data['subject']
            
            # Create aggregated keyword totals across all sources with line breaks for wrapping
            sensitive_text = ""
            if email_data['sensitive_matches']:
                # Aggregate keywords across all sources
                keyword_totals = defaultdict(int)
                for source, keywords_dict in email_data['sensitive_matches'].items():
                    for keyword, count in keywords_dict.items():
                        keyword_totals[keyword] += count
                
                # Format as keyword(total_count), with line breaks for better wrapping
                keyword_list = []
                for keyword, total_count in keyword_totals.items():
                    keyword_list.append(f"{keyword}({total_count})")
                
                # Join with commas and spaces, but insert line breaks every 5 items for better use of space
                if len(keyword_list) <= 7:
                    sensitive_text = ", ".join(keyword_list)
                else:
                    # Break into chunks for better wrapping - increased from 3 to 5
                    chunks = []
                    for i in range(0, len(keyword_list), 7):
                        chunk = ", ".join(keyword_list[i:i+7])
                        chunks.append(chunk)
                    sensitive_text = "\n".join(chunks)
            else:
                sensitive_text = "0"
            
            # Determine row tag based on scan results
            tag = ""
            if email_data['total_matches'] > 0:
                tag = "sensitive"  # Red for sensitive matches
            elif email_data['scan_errors']:
                tag = "scan_error"  # Yellow for scan errors
            else:
                tag = "normal"  # Normal for no issues
            
            item = tree.insert("", "end", values=(date_str, subject, sensitive_text), tags=(tag,))
            # Store the email data using the tree item id as key
            self.tree_email_data[item] = email_data
        
        # Configure row colors and row height for text wrapping
        tree.tag_configure("sensitive", background="#FFE6E6", foreground=self.colors['text'])  # Very light red with dark text
        tree.tag_configure("scan_error", background="#FFF8E1", foreground=self.colors['text'])  # Very light yellow with dark text
        tree.tag_configure("normal", background=self.colors['white'], foreground=self.colors['text'])  # White with dark text
        
        # Configure the treeview to allow multiline text with reduced row height
        style = ttk.Style()
        style.configure("Treeview", rowheight=40, foreground="black")  # Reduced from 80 to 40
        style.configure("Treeview.Heading", foreground="black")  # Ensure headings stay default color
        
        # Create frame for tree and scrollbar
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill="both", expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind double-click event
        def on_email_double_click(event):
            if tree.selection():
                item = tree.selection()[0]
                # Get the email data using the tree item id
                email_data = self.tree_email_data.get(item)
                
                if email_data:
                    self.show_email_details(email_data)
        
        tree.bind("<Double-1>", on_email_double_click)

    def open_file_with_system(self, file_path):
        """Open a file with the system's default application."""
        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"The file could not be found:\n{file_path}")
            return
        
        try:
            system = platform.system()
            if system == "Darwin":  # macOS
                subprocess.run(["open", file_path], check=True)
            elif system == "Windows":
                os.startfile(file_path)
            elif system == "Linux":
                subprocess.run(["xdg-open", file_path], check=True)
            else:
                messagebox.showwarning("Unsupported System", f"Cannot open files on {system} automatically. Please open manually:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error Opening File", f"Could not open file:\n{file_path}\n\nError: {e}")

    def show_email_details(self, email_data):
        """Show detailed information for a specific email."""
        details_window = tk.Toplevel(self.master)
        details_window.title(f"Email Details: {email_data['subject'][:50]}...")
        details_window.geometry("800x600")
        details_window.resizable(True, True)
        details_window.configure(bg=self.colors['background'])
        
        # Create main frame with scrollbar
        main_frame = ttk.Frame(details_window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Email header information
        header_frame = ttk.LabelFrame(main_frame, text="Email Information", padding=10)
        header_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(header_frame, text=f"Subject: {email_data['subject']}", font=("Arial", 10, "bold")).pack(anchor="w")
        ttk.Label(header_frame, text=f"Date: {email_data['delivery_time']}").pack(anchor="w")
        ttk.Label(header_frame, text=f"From: {email_data['author']}").pack(anchor="w")
        ttk.Label(header_frame, text=f"To: {email_data['recipients']}").pack(anchor="w")
        ttk.Label(header_frame, text=f"Total Keyword Matches: {email_data['total_matches']}", 
                 font=("Arial", 10, "bold"), foreground=self.colors['secondary'] if email_data['total_matches'] > 0 else self.colors['text']).pack(anchor="w")
        
        # Add button to open email file
        def open_email_file():
            email_file_path = email_data.get("file_paths", {}).get("Email Body")
            if email_file_path:
                self.open_file_with_system(email_file_path)
            else:
                messagebox.showwarning("File Not Available", "Email file path not available.")
        
        open_email_button = ttk.Button(header_frame, text="Open Email File", command=open_email_file)
        open_email_button.pack(anchor="w", pady=(5, 0))
        
        # Sensitive matches table
        if email_data['sensitive_matches']:
            matches_frame = ttk.LabelFrame(main_frame, text="Sensitive Keyword Matches (Double-click to open file)", padding=10)
            matches_frame.pack(fill="both", expand=True, pady=(0, 10))
            
            # Create treeview for matches
            columns = ("Source", "Keywords", "Count")
            matches_tree = ttk.Treeview(matches_frame, columns=columns, show="headings", height=8)
            
            matches_tree.heading("Source", text="Source File")
            matches_tree.heading("Keywords", text="Sensitive Matches")
            matches_tree.heading("Count", text="Total Count")
            
            matches_tree.column("Source", width=200)
            matches_tree.column("Keywords", width=500)  # Increased from 400 to 500
            matches_tree.column("Count", width=100)
            
            # Configure matches tree for text wrapping with reduced height
            matches_style = ttk.Style()
            matches_style.configure("Matches.Treeview", rowheight=40, foreground=self.colors['text'], background=self.colors['white'])  # Reduced from 60 to 40
            matches_tree.configure(style="Matches.Treeview")
            
            # Dictionary to store file paths by tree item
            tree_file_paths = {}
            
            for source, keywords_dict in email_data['sensitive_matches'].items():
                keyword_list = []
                total_count = 0
                for keyword, count in keywords_dict.items():
                    keyword_list.append(f"{keyword} ({count})")
                    total_count += count
                
                # Format keywords with line breaks for better wrapping in details view
                if len(keyword_list) <= 4:  # Increased from 2 to 4
                    keywords_str = ", ".join(keyword_list)
                else:
                    # Break into chunks for better wrapping - increased chunk size
                    chunks = []
                    for i in range(0, len(keyword_list), 4):  # Increased from 2 to 4
                        chunk = ", ".join(keyword_list[i:i+4])
                        chunks.append(chunk)
                    keywords_str = "\n".join(chunks)
                
                item = matches_tree.insert("", "end", values=(source, keywords_str, total_count))
                
                # Store the file path for this tree item
                if "file_paths" in email_data and source in email_data["file_paths"]:
                    tree_file_paths[item] = email_data["file_paths"][source]
            
            # Bind double-click event to open files
            def on_match_double_click(event):
                if matches_tree.selection():
                    item = matches_tree.selection()[0]
                    file_path = tree_file_paths.get(item)
                    if file_path:
                        self.open_file_with_system(file_path)
                    else:
                        source_name = matches_tree.item(item)['values'][0]
                        messagebox.showinfo("File Not Available", f"No file path available for: {source_name}")
            
            matches_tree.bind("<Double-1>", on_match_double_click)
            matches_tree.pack(fill="both", expand=True)
            
            # Add instruction label for matches
            ttk.Label(matches_frame, text="Double-click on any row to open the corresponding file", 
                     font=("Arial", 9, "italic")).pack(pady=2)
        
        # Scan errors section
        if email_data['scan_errors']:
            errors_frame = ttk.LabelFrame(main_frame, text="Scan Errors", padding=10)
            errors_frame.pack(fill="x", pady=(0, 10))
            
            errors_text = scrolledtext.ScrolledText(errors_frame, height=4, wrap=tk.WORD)
            errors_text.pack(fill="x")
            
            for error in email_data['scan_errors']:
                errors_text.insert(tk.END, f"• {error}\n")
            errors_text.config(state='disabled')

    def cleanup_temp_dir(self):
        """Removes the temporary directory and its contents."""
        if self.temp_extract_dir and os.path.exists(self.temp_extract_dir):
            try:
                shutil.rmtree(self.temp_extract_dir)
                self.log_message(f"Cleaned up temporary directory: {self.temp_extract_dir}")
                self.temp_extract_dir = "" # Reset
            except Exception as e:
                self.log_message(f"Error cleaning up temporary directory {self.temp_extract_dir}: {e}")

    def on_closing(self):
        """Handles cleanup when the parent application is closed."""
        # Ensure cleanup on close, unless explicitly disabled for debugging
        if not self.DISABLE_CLEANUP.get():
            self.cleanup_temp_dir()


# Main execution block - now uses the tabbed interface
if __name__ == "__main__":
    app = BreachAnalysisApp()
    app.mainloop()

