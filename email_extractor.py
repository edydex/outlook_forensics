import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import subprocess
import csv
import email
from datetime import datetime
import shutil # For copying files
import re
import zipfile
import tempfile
from pathlib import Path
import threading
from collections import defaultdict, Counter
import json
import platform  # Added for cross-platform file opening

class PSTExtractorApp:
    def __init__(self, master):
        self.master = master
        master.title("PST Email Extractor with Keyword Scanner")
        master.geometry("900x750") # Larger window for new features
        master.resizable(True, True)

        # Create a main frame to hold all widgets
        # This frame will expand to fill the root window
        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10) # Pack the main frame

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
        self.output_dir_path = tk.StringVar()
        self.keywords_csv_path = tk.StringVar()
        self.temp_extract_dir = "" # To store the path of the temporary extraction directory
        self.DISABLE_CLEANUP = tk.BooleanVar(value=False) # New checkbox variable for debugging
        self.keywords_list = []  # Store loaded keywords
        self.email_scan_results = []  # Store scan results for report generation
        self.tree_email_data = {}  # Store email data for tree items

        # --- PST File Selection ---
        tk.Label(self.main_frame, text="Select PST File:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.pst_file_path, width=50).grid(row=0, column=0, columnspan=1, sticky="ew", padx=(120, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_pst_file).grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # --- Output Directory Selection ---
        tk.Label(self.main_frame, text="Select Output Directory:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.output_dir_path, width=50).grid(row=1, column=0, columnspan=1, sticky="ew", padx=(170, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_output_dir).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # --- Keywords CSV Selection ---
        tk.Label(self.main_frame, text="Select Keywords CSV File:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.keywords_csv_path, width=50).grid(row=2, column=0, columnspan=1, sticky="ew", padx=(180, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_keywords_csv).grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # --- Email IDs Input ---
        tk.Label(self.main_frame, text="Enter Compromised Email IDs (one per line):").grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.email_ids_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=8)
        self.email_ids_text.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)

        # --- Debugging Option: Disable Cleanup ---
        tk.Checkbutton(self.main_frame, text="Keep temporary files (for debugging)", variable=self.DISABLE_CLEANUP).grid(row=5, column=0, sticky="w", padx=10, pady=5)

        # --- Action Buttons ---
        self.extract_button = tk.Button(self.main_frame, text="Extract & Scan Emails", command=self.start_extraction, bg="#4CAF50", fg="black", font=("Arial", 12, "bold"), relief="raised", bd=3, padx=10, pady=5)
        self.extract_button.grid(row=5, column=1, sticky="e", pady=15) # Changed column and sticky for layout

        # --- Log Area ---
        tk.Label(self.main_frame, text="Status Log:").grid(row=6, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.log_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=10, state='disabled', bg="#f0f0f0")
        self.log_text.grid(row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)

        # Bind the close event to clean up temporary files
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log_message(self, message):
        """Inserts a message into the log text area."""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END) # Auto-scroll to the end
        self.log_text.config(state='disabled')
        self.master.update_idletasks() # Update GUI immediately

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

    def sanitize_error_message(self, error_message, attachment_path):
        """Remove absolute paths from error messages to prevent path disclosure."""
        filename = os.path.basename(attachment_path)
        # Replace any occurrence of the full path with just the filename
        sanitized = error_message.replace(attachment_path, filename)
        
        return sanitized

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
                    sanitized_error = self.sanitize_error_message(str(e), attachment_path)
                    return None, f"PDF read error: {sanitized_error}"
            
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
                    sanitized_error = self.sanitize_error_message(str(e), attachment_path)
                    return None, f"Word document read error: {sanitized_error}"
            
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
                    sanitized_error = self.sanitize_error_message(str(e), attachment_path)
                    return None, f"Excel read error: {sanitized_error}"
            
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
                    sanitized_error = self.sanitize_error_message(str(e), attachment_path)
                    return None, f"OCR error: {sanitized_error}"
            
            else:
                return None, f"Unsupported file type: {file_ext}"
        
        except Exception as e:
            self.log_message(f"General error extracting text from {attachment_path}: {e}")
            sanitized_error = self.sanitize_error_message(str(e), attachment_path)
            return None, f"Extraction error: {sanitized_error}"
        
        return text_content, None

    def start_extraction(self):
        """Initiates the email extraction process."""
        pst_path = self.pst_file_path.get()
        output_dir = self.output_dir_path.get()
        keywords_path = self.keywords_csv_path.get()
        email_ids_raw = self.email_ids_text.get("1.0", tk.END).strip()

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
        self.master.update_idletasks() # Update button state

        try:
            self.extract_emails(pst_path, output_dir, compromised_email_ids)
            messagebox.showinfo("Success", "Email extraction and keyword scanning complete!")
            self.log_message("Email extraction and keyword scanning complete.")
            
            # Show results window
            self.show_results_window()
            
        except Exception as e:
            messagebox.showerror("Extraction Error", f"An error occurred: {e}")
            self.log_message(f"Extraction Error: {e}")
        finally:
            self.extract_button.config(state='normal', text="Extract & Scan Emails")
            self.master.update_idletasks() # Update button state
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

            # Store email data and generate both table rows and JavaScript data
            email_js_data = []
            
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
                        for chunk_i in range(0, len(keyword_list), 5):
                            chunk = ", ".join(keyword_list[chunk_i:chunk_i+5])
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
                
                # Create safe JavaScript object for this email
                try:
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
                    email_js_data.append(js_email)
                except Exception as e:
                    # If there's an error creating the JS object, create a safe fallback
                    js_email = {
                        'subject': 'Error processing email data',
                        'delivery_time': 'Unknown',
                        'author': 'Unknown',
                        'recipients': 'Unknown',
                        'total_matches': 0,
                        'sensitive_matches': {},
                        'scan_errors': [f'Error processing email: {str(e)}'],
                        'file_paths': {}
                    }
                    email_js_data.append(js_email)
                
                html_content += f"""
                <tr class="email-row {tag}" onclick="showEmailDetails({i})" data-email-index="{i}">
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

            # Add JavaScript email data using the collected array
            for js_email in email_js_data:
                try:
                    html_content += f"            {json.dumps(js_email, ensure_ascii=False)},\n"
                except Exception as e:
                    # If JSON serialization fails, add a safe fallback
                    fallback_email = {
                        'subject': 'JSON serialization error',
                        'delivery_time': 'Unknown',
                        'author': 'Unknown',
                        'recipients': 'Unknown',
                        'total_matches': 0,
                        'sensitive_matches': {},
                        'scan_errors': [f'JSON error: {str(e)}'],
                        'file_paths': {}
                    }
                    html_content += f"            {json.dumps(fallback_email)},\n"
            
            html_content += """
        ];

        function showEmailDetails(index) {
            // Validate index
            if (index < 0 || index >= emailData.length) {
                alert(`Error: Invalid email index ${index}. Total emails: ${emailData.length}`);
                return;
            }
            
            const email = emailData[index];
            if (!email) {
                alert(`Error: No email data found at index ${index}`);
                return;
            }
            
            const modal = document.getElementById('emailModal');
            const content = document.getElementById('modalContent');
            
            let html = `
                <div class="email-info">
                    <h3>Email Information</h3>
                    <p><strong>Subject:</strong> ${email.subject || 'Unknown'}</p>
                    <p><strong>Date:</strong> ${email.delivery_time || 'Unknown'}</p>
                    <p><strong>From:</strong> ${email.author || 'Unknown'}</p>
                    <p><strong>To:</strong> ${email.recipients || 'Unknown'}</p>
                    <p><strong>Total Keyword Matches:</strong> <span style="color: ${email.total_matches > 0 ? 'red' : 'green'}; font-weight: bold;">${email.total_matches || 0}</span></p>
                    <button class="open-email-btn" onclick="openEmailFile('${(email.file_paths && email.file_paths['Email Body']) || ''}')">Open Email File</button>
                </div>
            `;
            
            if (email.sensitive_matches && Object.keys(email.sensitive_matches).length > 0) {
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
                    if (keywords && typeof keywords === 'object') {
                        for (const [keyword, count] of Object.entries(keywords)) {
                            keywordList.push(`${keyword} (${count})`);
                            totalCount += count;
                        }
                    }
                    const keywordsStr = keywordList.join(', ');
                    const filePath = (email.file_paths && email.file_paths[source]) || '';
                    
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
            
            if (email.scan_errors && email.scan_errors.length > 0) {
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
                // Open all attachments in a new tab
                window.open(filePath, '_blank');
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
        tree.tag_configure("sensitive", background="#ffcccc", foreground="black")  # Light red with black text
        tree.tag_configure("scan_error", background="#ffffcc", foreground="black")  # Light yellow with black text
        tree.tag_configure("normal", background="white", foreground="black")  # White with black text
        
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
                 font=("Arial", 10, "bold"), foreground="red" if email_data['total_matches'] > 0 else "green").pack(anchor="w")
        
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
            matches_style.configure("Matches.Treeview", rowheight=40, foreground="black")  # Reduced from 60 to 40
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
        """Handles window closing, ensuring temporary files are cleaned up."""
        # Ensure cleanup on close, unless explicitly disabled for debugging
        if not self.DISABLE_CLEANUP.get():
            self.cleanup_temp_dir()
        self.master.destroy()


# Main execution block
if __name__ == "__main__":
    root = tk.Tk()
    app = PSTExtractorApp(root)
    root.mainloop()

