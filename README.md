# Mayo's Outlook Forensics tool

## What This Tool Does For You

**If you're investigating a potential email breach**, this tool helps you:

1. **Find the smoking gun** - Load Microsoft Purview audit logs and quickly spot suspicious email access patterns
2. **Get the actual compromised emails** - Extract specific emails from PST files based on the audit trail
3. **Scan for sensitive data** - Automatically search through emails and attachments for keywords like "password", "SSN", etc.
4. **Create interactable reports** - Generate HTML reports you can actually share with management or law enforcement

**Bottom line:** You go from "we think someone accessed emails" to "here are the exact 47 emails they viewed, and 12 of them contained sensitive customer data."

## What You'll Actually Get

When you're done with an investigation, you'll have:
- **Sortable HTML reports** showing exactly when suspicious access happened
- **Individual email files** (.eml format) for each compromised message  
- **A summary** of what sensitive keywords were found and where
- **Interactive documentation** suitable for incident reports and maybe legal proceedings

The HTML reports are really the main output - they're interactive, sortable, and you can actually send them to people who need to understand what happened.

## Two Tools in One

This combines two separate investigation workflows:

**Tab 1: Audit Log Analysis**
- Load those massive CSV files from Microsoft Purview
- Filter out the noise to focus on actual suspicious activity
- Export clean, readable reports instead of spreadsheet hell

**Tab 2: Email Extraction** 
- Pull specific emails from PST files using the IDs you found in the audit logs
- Scan through email content and attachments for sensitive data
- Generate keyword match reports

The tabs talk to each other - you can send email IDs directly from the audit analysis to the extraction tool.

## Installation

**Works best on Mac, okay on Linux. Windows is... complicated.**

### Mac Setup (Easiest)
```bash
# Download/clone this repo, then:
cd outlook_forensics
chmod +x setup_mac.sh
./setup_mac.sh

# When it's done:
source venv/bin/activate
python forensics_app.py
```

### Linux Setup
```bash
cd AuditApp
chmod +x setup_linux.sh
./setup_linux.sh

source forensics_app_env/bin/activate
python forensics_app.py
```

### If the setup scripts break
Sometimes they do. Here's the manual way:

```bash
# Install the system stuff (Mac)
brew install libpst tesseract

# Install the system stuff (Linux)
sudo apt-get install pst-utils tesseract-ocr

# Python environment
python3 -m venv forensics_app_env
source forensics_app_env/bin/activate
pip install -r requirements.txt
```

## How to Actually Use This

### Step 1: Start with the audit logs
1. Get your Microsoft Purview audit log CSV file
     * Purview -> Audit -> Seatch -> Activities - friendly names -> *select everything under "Exchange mailbox activities"* 
2. Load it in the first tab
3. *(Optional)* Set your timezone so timestamps make sense
4. Filter by suspicious IP addresses or date ranges
5. Export to HTML to see what you're dealing with 
6. Refine the filters to filter out as much "friendly" activity as possible

### Step 2: Get the compromised email IDs
- Click "Send MailItemsAccessed IDs to Extraction Tab" 
    - This finds all the email Message-IDs that were accessed suspiciously
    - They automatically get loaded into the second tab
- *(Optional)* "HardDelete", "Send", and other message ID's can also be extracted from the HTML from "Digested Information" tab

### Step 3: Extract and scan the actual emails
1. Switch to the Email Extraction tab
2. Browse for affected PST file (usually huge)
3. Pick an output folder
4. Load a keywords file (one keyword per line - "password", "ssn", etc.)
    * feel free to add your own, or remove any keywords
5. Click "Import from Audit Tab" to load those email IDs
6. Hit "Extract & Scan Emails" and wait

### Step 4: Check your results
The HTML reports are what you actually want to look at. They're sortable and you can send them to people who need to understand what happened.

## What Files You'll Get

**From audit log analysis:**
- HTML report with sortable timeline of suspicious access
- CSV files split by IP address (if you want them)
- Filtered data exports

**From email extraction:**
- Individual .eml files for each compromised email
- Folders with extracted attachments 
- CSV summary showing which emails had sensitive keywords
- HTML report with keyword match details. Each email and attachment gets opened when double-clicked on.

## File Types It Can Scan

**Emails:** Regular email body text (plain and HTML)
**Attachments:** PDF, Word docs, Excel sheets, images (needs OCR), text files

## Keywords File Format

Edit the existing CSV ("sample_keywords.csv"), or make your own based on the existing format.

## Common Problems

**"readpst command not found"**
- The setup script probably failed to install libpst
- On Mac: `brew install libpst`
- On Linux: `sudo apt-get install pst-utils`

**App crashes when loading big PST files**
- PST files can be huge (10GB+). Make sure you have enough disk space
- Close other programs to free up memory
- If it's really huge, consider splitting the PST first

**Keyword scanning finds too much junk**
- Be more specific with keywords
- "password" will match "password123" and "passwordreset" 
- Use exact phrases if needed

**HTML reports won't open**
- Make sure the file fully exported (check file size)
- Try a different browser
- Check that your antivirus isn't blocking it

## Important Security Notes

This tool processes potentially sensitive breach data:
- Only run it on secure, trusted computers
- Don't leave extracted emails sitting around afterward
- Be careful who you share the HTML reports with
- Follow your organization's data handling policies
- Consider encrypting the output folder

## Performance Tips

- **Large PST files:** Extract to a local drive, not network storage
- **Lots of keywords:** Start with a few specific ones first
- **Memory issues:** Close other apps, especially browsers with lots of tabs
- **Network drives:** Copy PST files locally before processing

---

**The HTML reports are really the main output here.** They're what you'll actually look at and share with others. The individual email files are there if you need to dig deeper into specific messages.
