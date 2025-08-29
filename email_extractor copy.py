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

        # --- PST File Selection ---
        tk.Label(self.main_frame, text="Select PST File:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.pst_file_path, width=50).grid(row=0, column=0, columnspan=1, sticky="ew", padx=(120, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_pst_file).grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # --- Output Directory Selection ---
        tk.Label(self.main_frame, text="Select Output Directory:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.output_dir_path, width=50).grid(row=1, column=0, columnspan=1, sticky="ew", padx=(150, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_output_dir).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # --- Keywords CSV Selection ---
        tk.Label(self.main_frame, text="Select Keywords CSV File:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        tk.Entry(self.main_frame, textvariable=self.keywords_csv_path, width=50).grid(row=2, column=0, columnspan=1, sticky="ew", padx=(150, 5), pady=5)
        tk.Button(self.main_frame, text="Browse", command=self.browse_keywords_csv).grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # --- Email IDs Input ---
        tk.Label(self.main_frame, text="Enter Compromised Email IDs (one per line):").grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=5)
        self.email_ids_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=60, height=8)
        self.email_ids_text.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=5)

        # --- Debugging Option: Disable Cleanup ---
        tk.Checkbutton(self.main_frame, text="Keep temporary files (for debugging)", variable=self.DISABLE_CLEANUP).grid(row=5, column=0, sticky="w", padx=10, pady=5)

        # --- Action Buttons ---
        self.extract_button = tk.Button(self.main_frame, text="Extract & Scan Emails", command=self.start_extraction, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), relief="raised", bd=3, padx=10, pady=5)
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
            # Simple substring search - you might want to enhance this with regex
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
            # Command to extract all emails as .eml files including attachments
            # -e: extract emails
            # -o: output directory
            # -D: don't create subdirectories (put all emails directly in output_dir)
            # Removed -M flag to include attachments for keyword scanning
            readpst_command = ["readpst", "-e", "-o", self.temp_extract_dir, "-D", pst_path]
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

            # Iterate through ALL files in the temporary directory
            eml_files_found = 0
            for root, _, files in os.walk(self.temp_extract_dir):
                for filename in files:
                    eml_file_path = os.path.join(root, filename)
                    try:
                        with open(eml_file_path, 'rb') as f:
                            msg = email.message_from_binary_file(f)
                        
                        # If parsing succeeds, it's likely an email file
                        eml_files_found += 1

                        # Extract relevant headers
                        message_id_header = msg.get("Message-ID", "").strip("<>").lower() 
                        
                        if message_id_header:
                            self.log_message(f"  Found Message-ID in PST: {message_id_header} (from file: {filename})")
                        else:
                            self.log_message(f"  Warning: No Message-ID found for file: {filename}")

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
                                "total_matches": 0
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
                                        with open(attachment_path, 'wb') as f:
                                            f.write(part.get_payload(decode=True))
                                        
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

                            # Copy the .eml file to the output directory
                            safe_subject = "".join([c for c in subject if c.isalnum() or c in (' ', '-', '_')]).strip()
                            safe_subject = safe_subject[:50] if safe_subject else "Email"
                            
                            final_eml_filename = f"{safe_subject}_{filename}.eml"
                            final_eml_file_path = os.path.join(output_dir, final_eml_filename)

                            shutil.copy(eml_file_path, final_eml_file_path)
                            self.log_message(f"  Saved matched email: {final_eml_filename}")

                    except Exception as parse_error:
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

