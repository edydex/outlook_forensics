import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import json
import os
from datetime import datetime
import pytz

class AuditLogViewer(tk.Tk):
    """
    A standalone application to view, filter, and split Microsoft Purview Audit Log CSV files.
    """
    def __init__(self):
        super().__init__()
        self.title("Microsoft Purview Audit Log Viewer")
        self.geometry("1200x800") # Set initial window size
        self.minsize(800, 600) # Set minimum window size

        self.df = None # The DataFrame currently displayed in the Treeview
        self.original_df = None # Stores the initial loaded and processed DataFrame
        self.cell_data_map = {} # Maps (Treeview_item_id, column_name) to original_df_index for tooltips
        
        # Timezone settings
        self.selected_timezone = tk.StringVar(value="UTC")
        self.display_local_time = tk.BooleanVar(value=False)

        self.create_widgets()

    def create_widgets(self):
        """
        Creates all the GUI elements for the application.
        """
        # --- Control Frame ---
        control_frame = ttk.Frame(self, padding="10")
        control_frame.pack(pady=10, padx=10, fill=tk.X)

        self.load_button = ttk.Button(control_frame, text="Load CSV File", command=self.load_csv)
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Timezone Frame
        timezone_frame = ttk.Frame(self, padding="10")
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

        self.apply_ip_filter_button = ttk.Button(control_frame, text="Apply Filters", command=self.apply_filters)
        self.apply_ip_filter_button.pack(side=tk.LEFT, padx=5)
        
        # Date Filter
        date_filter_frame = ttk.Frame(self, padding="10")
        date_filter_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Label(date_filter_frame, text="Start Date/Time (YYYY-MM-DD [HH:MM:SS]):").pack(side=tk.LEFT, padx=(0, 5))
        self.start_date_entry = ttk.Entry(date_filter_frame, width=25, font=("Inter", 10))
        self.start_date_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(date_filter_frame, text="End Date/Time (YYYY-MM-DD [HH:MM:SS]):").pack(side=tk.LEFT, padx=(20, 5))
        self.end_date_entry = ttk.Entry(date_filter_frame, width=25, font=("Inter", 10))
        self.end_date_entry.pack(side=tk.LEFT, padx=5)
        
        self.apply_date_filter_button = ttk.Button(date_filter_frame, text="Apply Date Filter", command=self.apply_filters)
        self.apply_date_filter_button.pack(side=tk.LEFT, padx=5)

        self.clear_filter_button = ttk.Button(date_filter_frame, text="Clear Filters", command=self.clear_filter)
        self.clear_filter_button.pack(side=tk.LEFT, padx=5)
        
        self.view_filters_button = ttk.Button(date_filter_frame, text="View/Manage Filters", command=self.view_applied_filters)
        self.view_filters_button.pack(side=tk.LEFT, padx=(20, 5))

        # Other Buttons
        other_buttons_frame = ttk.Frame(self, padding="10")
        other_buttons_frame.pack(pady=5, padx=10, fill=tk.X)

        self.split_ip_button = ttk.Button(other_buttons_frame, text="Split by IP to CSVs", command=self.split_by_ip)
        self.split_ip_button.pack(side=tk.LEFT, padx=5)
        
        self.export_html_button = ttk.Button(other_buttons_frame, text="Export Filtered Table to HTML", command=self.export_to_html)
        self.export_html_button.pack(side=tk.LEFT, padx=5)

        # HTML Export Options Frame
        html_options_frame = ttk.Frame(self, padding="10")
        html_options_frame.pack(pady=5, padx=10, fill=tk.X)

        ttk.Label(html_options_frame, text="HTML Report Title:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.html_title_entry = ttk.Entry(html_options_frame, width=40, font=("Inter", 10))
        self.html_title_entry.insert(0, "Audit Log Report") # Default title
        self.html_title_entry.grid(row=0, column=1, sticky="ew", padx=5)

        ttk.Label(html_options_frame, text="Comments for HTML Report:").grid(row=1, column=0, sticky="nw", padx=(0, 5), pady=(5,0))
        self.comments_text = tk.Text(html_options_frame, width=60, height=4, font=("Inter", 9), wrap=tk.WORD)
        self.comments_text.grid(row=1, column=1, sticky="nsew", padx=5, pady=(5,0))
        comments_scroll = ttk.Scrollbar(html_options_frame, command=self.comments_text.yview)
        comments_scroll.grid(row=1, column=2, sticky='ns', pady=(5,0))
        self.comments_text['yscrollcommand'] = comments_scroll.set
        
        html_options_frame.grid_columnconfigure(1, weight=1)
        html_options_frame.grid_rowconfigure(1, weight=1) # Make comments text area expandable

        # --- Table Frame ---
        table_frame = ttk.Frame(self, padding="10")
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

        # Configure Treeview style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", font=("Inter", 10, "bold"))
        style.configure("Treeview", font=("Inter", 9), rowheight=25)
        style.map("Treeview", background=[('selected', '#347083')])
        
        # Define a new style for 'Sync' entries
        style.configure("Sync.Treeview", background="#FFEEEE") # Faint red background

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

        self.tooltip = tk.Toplevel(self)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x+10}+{y+10}")

        label = ttk.Label(self.tooltip, text=text, background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                          font=("Inter", 9), padding=5)
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
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f7f6; color: #333; }}
        h1 {{ color: #2c3e50; text-align: center; margin-bottom: 20px; }}
        .header-container {{ display: flex; justify-content: center; align-items: center; margin-bottom: 30px; }}
        .header-container h1 {{ margin: 0; }}
        .timezone-note {{
            text-align: center;
            font-style: italic;
            color: #666;
            margin-bottom: 20px;
            font-size: 0.9em;
        }}
        .action-button {{
            margin-left: 20px;
            padding: 8px 15px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background-color 0.2s;
        }}
        .action-button:hover {{
            background-color: #0056b3;
        }}

        /* Tab styles */
        .tab-container {{
            margin-bottom: 20px;
        }}
        .tab-buttons {{
            display: flex;
            border-bottom: 1px solid #ddd;
            background-color: #f8f9fa;
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
        }}
        .tab-button.active {{
            background-color: #fff;
            border-bottom-color: #007bff;
            color: #007bff;
            font-weight: bold;
        }}
        .tab-button:hover {{
            background-color: #e9ecef;
        }}
        .tab-content {{
            display: none;
            background-color: #fff;
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
            border-bottom: 1px solid #ddd;
            background-color: #f1f3f4;
            padding: 10px;
            border-radius: 6px 6px 0 0;
        }}
        .operation-tab-button {{
            padding: 8px 16px;
            background-color: transparent;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s ease;
            white-space: nowrap;
        }}
        .operation-tab-button.active {{
            background-color: #007bff;
            color: white;
            border-color: #007bff;
        }}
        .operation-tab-button:hover {{
            background-color: #e9ecef;
        }}
        .operation-tab-button.active:hover {{
            background-color: #0056b3;
        }}
        .operation-tab-contents {{
            border: 1px solid #ddd;
            border-top: none;
            background-color: #fff;
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
            border-bottom: 2px solid #e9ecef;
        }}
        .operation-header h3 {{
            margin: 0;
            color: #2c3e50;
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


if __name__ == "__main__":
    app = AuditLogViewer()
    app.mainloop()